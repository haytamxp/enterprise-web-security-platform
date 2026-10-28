from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
from datetime import datetime, timedelta, timezone
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "modules" / "p4-assurance"))

from scan_orchestrator import (
    InMemoryScanJobStore,
    ScanAuditEvent,
    ScanOrchestrationError,
    ScanOrchestrator,
    ScanPrincipal,
    SlidingWindowRateLimiter,
    UtcExecutionWindow,
)

NOW = datetime(2026, 10, 22, 10, 0, tzinfo=timezone.utc)
TENANT = "tenant-demo"
ASSET_ID = "asset-web-001"
TARGET = "https://staging.example.com/products"
REQUESTER = ScanPrincipal("analyst-demo", TENANT, frozenset({"scan:request"}))
WORKER = ScanPrincipal("worker-demo", TENANT, frozenset({"scan:execute"}))


def sample_asset():
    return {
        "schema_version": "1.0", "asset_id": ASSET_ID, "tenant_id": TENANT,
        "name": "Demo storefront", "asset_type": "web_application", "environment": "staging",
        "owner_team": "team-p3", "criticality": "high",
        "authorization": {
            "status": "approved", "approved_by": "security-owner-demo",
            "approved_at": "2026-10-20T09:00:00Z", "expires_at": "2026-12-31T23:59:59Z",
            "allowed_targets": ["https://staging.example.com"],
            "excluded_targets": ["https://staging.example.com/admin"],
            "rules_of_engagement_ref": "roe-demo-v1",
        },
    }


class OpenWindow:
    def is_open(self, now):
        return True


class Harness:
    def __init__(self, *, schedule_limit=5, execution_limit=2, audit=None, window=None, lease_seconds=60, max_attempts=3):
        self.assets = {(TENANT, ASSET_ID): sample_asset()}
        self.jobs = InMemoryScanJobStore()
        self.events: list[ScanAuditEvent] = []
        self.audit = audit if audit is not None else self.events.append
        self.limiter = SlidingWindowRateLimiter(
            schedule_limit=schedule_limit, execution_limit=execution_limit,
        )
        self.window = window if window is not None else OpenWindow()
        self.service = ScanOrchestrator(
            asset_loader=lambda tenant, asset: self.assets.get((tenant, asset)),
            jobs=self.jobs, audit_sink=lambda event: self.audit(event), rate_limiter=self.limiter,
            execution_window=self.window, lease_seconds=lease_seconds, max_attempts=max_attempts,
            clock=lambda: NOW,
        )

    def submit(self, *, key="scan-key-0001", target=TARGET, principal=REQUESTER, profile="web_baseline", now=NOW):
        return self.service.submit_scan(
            principal, asset_id=ASSET_ID, target_url=target,
            idempotency_key=key, profile=profile, now=now,
        )


class ScanOrchestratorTests(unittest.TestCase):
    def test_valid_request_is_queued_and_audited_without_network_access(self):
        h = Harness()
        job = h.submit()
        self.assertEqual("queued", job.status)
        self.assertEqual(ASSET_ID, job.asset_id)
        self.assertTrue(h.events)
        self.assertEqual("scan.job.admission_allowed", h.events[-1].event_type)
        self.assertFalse(hasattr(h.service, "http_client"))

    def test_requester_without_permission_is_denied(self):
        h = Harness()
        principal = ScanPrincipal("viewer", TENANT, frozenset())
        with self.assertRaises(ScanOrchestrationError) as ctx:
            h.submit(principal=principal)
        self.assertEqual("permission_denied", ctx.exception.code)

    def test_scope_is_checked_again_when_request_is_submitted(self):
        h = Harness()
        h.assets[(TENANT, ASSET_ID)]["authorization"]["status"] = "revoked"
        with self.assertRaises(ScanOrchestrationError) as ctx:
            h.submit()
        self.assertEqual("not_approved", ctx.exception.code)

    def test_idempotent_retry_returns_same_job_without_consuming_another_slot(self):
        h = Harness(schedule_limit=1)
        first = h.submit()
        second = h.submit()
        self.assertEqual(first.job_id, second.job_id)
        with self.assertRaises(ScanOrchestrationError) as ctx:
            h.submit(key="scan-key-0002")
        self.assertEqual("schedule_rate_limited", ctx.exception.code)

    def test_reusing_idempotency_key_for_different_request_is_denied(self):
        h = Harness()
        h.submit()
        with self.assertRaises(ScanOrchestrationError) as ctx:
            h.submit(target="https://staging.example.com/account")
        self.assertEqual("idempotency_conflict", ctx.exception.code)

    def test_unconfigured_profile_is_denied(self):
        h = Harness()
        with self.assertRaises(ScanOrchestrationError) as ctx:
            h.submit(profile="active")
        self.assertEqual("profile_not_allowed", ctx.exception.code)

    def test_pending_audit_retry_revalidates_scope_before_queuing(self):
        def broken_audit(_event):
            raise RuntimeError("audit unavailable")

        h = Harness(audit=broken_audit)

        with self.assertRaises(ScanOrchestrationError) as first_error:
            h.submit()

        self.assertEqual("audit_unavailable", first_error.exception.code)

        pending = h.jobs.get_by_idempotency_key(
            TENANT, REQUESTER.subject_id, "scan-key-0001"
        )
        self.assertIsNotNone(pending)
        self.assertEqual("pending_audit", pending.status)

        h.assets[(TENANT, ASSET_ID)]["authorization"]["status"] = "revoked"
        h.audit = h.events.append

        with self.assertRaises(ScanOrchestrationError) as retry_error:
            h.submit()

        self.assertEqual("not_approved", retry_error.exception.code)
        self.assertEqual("pending_audit", h.jobs.get(pending.job_id).status)
    def test_create_race_revalidates_scope_before_activating_pending_job(self):
        h = Harness()
        real_create = h.jobs.create

        def racing_create(job):
            # Simulate a concurrent request winning the idempotency-key race.
            raced_job = replace(job, job_id=f"racing-{job.job_id}")
            self.assertTrue(real_create(raced_job))

            # Revoke authorization before the losing request recovers.
            h.assets[(TENANT, ASSET_ID)]["authorization"]["status"] = "revoked"
            return False

        h.jobs.create = racing_create

        with self.assertRaises(ScanOrchestrationError) as ctx:
            h.submit()

        self.assertEqual("not_approved", ctx.exception.code)

        raced = h.jobs.get_by_idempotency_key(
            TENANT, REQUESTER.subject_id, "scan-key-0001"
        )
        self.assertIsNotNone(raced)
        self.assertEqual("pending_audit", raced.status)


    def test_execution_requires_worker_permission(self):
        h = Harness()
        job = h.submit()
        with self.assertRaises(ScanOrchestrationError) as ctx:
            h.service.claim_for_execution(REQUESTER, job_id=job.job_id, now=NOW)
        self.assertEqual("permission_denied", ctx.exception.code)

    def test_execution_revalidates_scope_and_blocks_revoked_asset(self):
        h = Harness()
        job = h.submit()
        h.assets[(TENANT, ASSET_ID)]["authorization"]["status"] = "revoked"
        with self.assertRaises(ScanOrchestrationError) as ctx:
            h.service.claim_for_execution(WORKER, job_id=job.job_id, now=NOW)
        self.assertEqual("not_approved", ctx.exception.code)
        self.assertEqual("blocked", h.jobs.get(job.job_id).status)

    def test_outside_execution_window_defers_job_without_claiming_it(self):
        h = Harness(window=UtcExecutionWindow(start_hour=13, end_hour=17, weekdays=frozenset({0,1,2,3,4,5,6})))
        job = h.submit()
        with self.assertRaises(ScanOrchestrationError) as ctx:
            h.service.claim_for_execution(WORKER, job_id=job.job_id, now=NOW)
        self.assertEqual("outside_execution_window", ctx.exception.code)
        self.assertEqual("queued", h.jobs.get(job.job_id).status)

    def test_execution_rate_limit_is_checked_before_claim(self):
        h = Harness(execution_limit=1)
        first = h.submit(key="scan-key-0001")
        second = h.submit(key="scan-key-0002")
        h.service.claim_for_execution(WORKER, job_id=first.job_id, now=NOW)
        with self.assertRaises(ScanOrchestrationError) as ctx:
            h.service.claim_for_execution(WORKER, job_id=second.job_id, now=NOW)
        self.assertEqual("execution_rate_limited", ctx.exception.code)
        self.assertEqual("queued", h.jobs.get(second.job_id).status)

    def test_only_one_active_worker_can_claim_a_job(self):
        h = Harness()
        job = h.submit()
        permit = h.service.claim_for_execution(WORKER, job_id=job.job_id, now=NOW)
        self.assertEqual("running", h.jobs.get(job.job_id).status)
        self.assertEqual(1, h.jobs.get(job.job_id).attempt)
        with self.assertRaises(ScanOrchestrationError) as ctx:
            h.service.claim_for_execution(WORKER, job_id=job.job_id, now=NOW + timedelta(seconds=10))
        self.assertEqual("job_not_claimable", ctx.exception.code)
        self.assertEqual(36, len(permit.lease_id))

    def test_expired_lease_can_be_reclaimed_and_attempt_increments(self):
        h = Harness(lease_seconds=5)
        job = h.submit()
        first = h.service.claim_for_execution(WORKER, job_id=job.job_id, now=NOW)
        second = h.service.claim_for_execution(WORKER, job_id=job.job_id, now=NOW + timedelta(seconds=6))
        self.assertNotEqual(first.lease_id, second.lease_id)
        self.assertEqual(2, h.jobs.get(job.job_id).attempt)

    def test_claim_attempts_are_bounded(self):
        h = Harness(lease_seconds=5, max_attempts=2)
        job = h.submit()
        h.service.claim_for_execution(WORKER, job_id=job.job_id, now=NOW)
        h.service.claim_for_execution(WORKER, job_id=job.job_id, now=NOW + timedelta(seconds=6))
        with self.assertRaises(ScanOrchestrationError) as ctx:
            h.service.claim_for_execution(WORKER, job_id=job.job_id, now=NOW + timedelta(seconds=12))
        self.assertEqual("max_attempts_exceeded", ctx.exception.code)
        self.assertEqual("blocked", h.jobs.get(job.job_id).status)

    def test_stale_worker_cannot_complete_reclaimed_job(self):
        h = Harness(lease_seconds=5)
        job = h.submit()
        old = h.service.claim_for_execution(WORKER, job_id=job.job_id, now=NOW)
        h.service.claim_for_execution(WORKER, job_id=job.job_id, now=NOW + timedelta(seconds=6))
        with self.assertRaises(ScanOrchestrationError) as ctx:
            h.service.finish_job(WORKER, job_id=job.job_id, lease_id=old.lease_id, succeeded=True, now=NOW + timedelta(seconds=7))
        self.assertEqual("stale_or_invalid_lease", ctx.exception.code)

    def test_valid_completion_transitions_to_succeeded_and_is_idempotent(self):
        h = Harness()
        job = h.submit()
        permit = h.service.claim_for_execution(WORKER, job_id=job.job_id, now=NOW)
        completed = h.service.finish_job(WORKER, job_id=job.job_id, lease_id=permit.lease_id, succeeded=True, now=NOW + timedelta(seconds=5))
        self.assertEqual("succeeded", completed.status)
        again = h.service.finish_job(WORKER, job_id=job.job_id, lease_id=permit.lease_id, succeeded=True, now=NOW + timedelta(seconds=6))
        self.assertEqual(completed.job_id, again.job_id)

    def test_failed_completion_requires_bounded_reason_code(self):
        h = Harness()
        job = h.submit()
        permit = h.service.claim_for_execution(WORKER, job_id=job.job_id, now=NOW)
        with self.assertRaises(ScanOrchestrationError) as ctx:
            h.service.finish_job(WORKER, job_id=job.job_id, lease_id=permit.lease_id, succeeded=False, now=NOW + timedelta(seconds=1))
        self.assertEqual("invalid_reason_code", ctx.exception.code)

    def test_audit_failure_leaves_new_job_non_executable(self):
        def broken_audit(_event):
            raise RuntimeError("audit unavailable")
        h = Harness(audit=broken_audit)
        with self.assertRaises(ScanOrchestrationError) as ctx:
            h.submit()
        self.assertEqual("audit_unavailable", ctx.exception.code)
        pending = h.jobs.get_by_idempotency_key(TENANT, REQUESTER.subject_id, "scan-key-0001")
        self.assertIsNotNone(pending)
        self.assertEqual("pending_audit", pending.status)

    def test_audit_failure_during_claim_does_not_return_permit_and_rolls_back(self):
        h = Harness()
        job = h.submit()
        h.audit = lambda _event: (_ for _ in ()).throw(RuntimeError("audit unavailable"))
        with self.assertRaises(ScanOrchestrationError) as ctx:
            h.service.claim_for_execution(WORKER, job_id=job.job_id, now=NOW)
        self.assertEqual("audit_unavailable", ctx.exception.code)
        self.assertEqual("queued", h.jobs.get(job.job_id).status)

    def test_audit_event_does_not_include_target_url(self):
        h = Harness()
        h.submit(target="https://staging.example.com/products?token=not-for-audit")
        serialized = repr(h.events)
        self.assertNotIn("token=not-for-audit", serialized)

    def test_cross_tenant_worker_cannot_claim_job(self):
        h = Harness()
        job = h.submit()
        other = ScanPrincipal("worker-other", "tenant-other", frozenset({"scan:execute"}))
        with self.assertRaises(ScanOrchestrationError) as ctx:
            h.service.claim_for_execution(other, job_id=job.job_id, now=NOW)
        self.assertEqual("job_not_found", ctx.exception.code)


    def test_completion_audit_failure_keeps_job_running(self):
        h = Harness()
        job = h.submit()
        permit = h.service.claim_for_execution(
            WORKER, job_id=job.job_id, now=NOW
        )

        h.audit = lambda _event: (_ for _ in ()).throw(
            RuntimeError("audit unavailable")
        )

        with self.assertRaises(ScanOrchestrationError) as ctx:
            h.service.finish_job(
                WORKER,
                job_id=job.job_id,
                lease_id=permit.lease_id,
                succeeded=True,
                now=NOW + timedelta(seconds=5),
            )

        self.assertEqual("audit_unavailable", ctx.exception.code)
        current = h.jobs.get(job.job_id)
        self.assertEqual("running", current.status)
        self.assertEqual(permit.lease_id, current.lease_id)

    def test_cross_tenant_worker_cannot_complete_job(self):
        h = Harness()
        job = h.submit()
        permit = h.service.claim_for_execution(
            WORKER, job_id=job.job_id, now=NOW
        )
        other_worker = ScanPrincipal(
            "worker-other",
            "tenant-other",
            frozenset({"scan:execute"}),
        )

        with self.assertRaises(ScanOrchestrationError) as ctx:
            h.service.finish_job(
                other_worker,
                job_id=job.job_id,
                lease_id=permit.lease_id,
                succeeded=True,
                now=NOW + timedelta(seconds=5),
            )

        self.assertEqual("job_not_found", ctx.exception.code)
        current = h.jobs.get(job.job_id)
        self.assertEqual("running", current.status)
        self.assertEqual(permit.lease_id, current.lease_id)

    def test_audit_events_omit_target_url_across_lifecycle(self):
        h = Harness()
        target = (
            "https://staging.example.com/products"
            "?fixture=p4-06-synthetic-secret-marker"
        )

        job = h.submit(target=target)
        permit = h.service.claim_for_execution(
            WORKER, job_id=job.job_id, now=NOW
        )
        h.service.finish_job(
            WORKER,
            job_id=job.job_id,
            lease_id=permit.lease_id,
            succeeded=True,
            now=NOW + timedelta(seconds=5),
        )

        serialized_events = repr(h.events)
        self.assertNotIn(
            "p4-06-synthetic-secret-marker", serialized_events
        )
        self.assertNotIn("staging.example.com", serialized_events)
if __name__ == "__main__":
    unittest.main()
