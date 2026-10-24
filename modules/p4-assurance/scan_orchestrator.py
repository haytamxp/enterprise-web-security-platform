"""Fail-closed scan-job orchestration primitives; no network scanner is invoked."""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import threading
from typing import Any, Callable, Mapping, Protocol
from uuid import uuid4

from scan_scope import evaluate_target_scope


@dataclass(frozen=True)
class ScanPrincipal:
    """Identity and permissions supplied by trusted authentication middleware."""

    subject_id: str
    tenant_id: str
    permissions: frozenset[str]


@dataclass(frozen=True)
class ScanJob:
    """Persistable scan job state; target URLs are not copied into audit events."""

    schema_version: str
    job_id: str
    tenant_id: str
    asset_id: str
    requested_by: str
    target_url: str
    profile: str
    idempotency_key: str
    request_fingerprint: str
    status: str
    created_at: datetime
    updated_at: datetime
    attempt: int = 0
    lease_id: str | None = None
    lease_expires_at: datetime | None = None
    last_reason_code: str | None = None


@dataclass(frozen=True)
class ExecutionPermit:
    """Short-lived claim returned to a worker after current policy checks pass."""

    job_id: str
    tenant_id: str
    asset_id: str
    target_url: str
    profile: str
    lease_id: str
    authorized_at: datetime
    lease_expires_at: datetime


@dataclass(frozen=True)
class ScanAuditEvent:
    """Minimal audit envelope; excludes target URLs, query strings, and secrets."""

    event_type: str
    occurred_at: datetime
    actor_id: str
    tenant_id: str
    asset_id: str
    job_id: str | None
    outcome: str
    reason_code: str


class ScanOrchestrationError(Exception):
    """Expected policy, state, or dependency error with a stable machine code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class ScanJobStore(Protocol):
    def get_by_idempotency_key(
        self, tenant_id: str, requested_by: str, idempotency_key: str
    ) -> ScanJob | None: ...

    def get(self, job_id: str) -> ScanJob | None: ...

    def create(self, job: ScanJob) -> bool: ...

    def compare_and_set(
        self,
        job_id: str,
        expected_status: str,
        expected_lease_id: str | None,
        replacement: ScanJob,
    ) -> bool: ...


class ExecutionWindowPolicy(Protocol):
    def is_open(self, now: datetime) -> bool: ...


class RateLimiter(Protocol):
    def consume(self, tenant_id: str, asset_id: str, stage: str, now: datetime) -> bool: ...


class InMemoryScanJobStore:
    """Thread-safe development/test adapter; replace with durable storage in production."""

    def __init__(self) -> None:
        self._jobs: dict[str, ScanJob] = {}
        self._keys: dict[tuple[str, str, str], str] = {}
        self._lock = threading.RLock()

    def get_by_idempotency_key(
        self, tenant_id: str, requested_by: str, idempotency_key: str
    ) -> ScanJob | None:
        with self._lock:
            job_id = self._keys.get((tenant_id, requested_by, idempotency_key))
            return self._jobs.get(job_id) if job_id else None

    def get(self, job_id: str) -> ScanJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def create(self, job: ScanJob) -> bool:
        with self._lock:
            key = (job.tenant_id, job.requested_by, job.idempotency_key)
            if key in self._keys or job.job_id in self._jobs:
                return False
            self._jobs[job.job_id] = job
            self._keys[key] = job.job_id
            return True

    def compare_and_set(
        self,
        job_id: str,
        expected_status: str,
        expected_lease_id: str | None,
        replacement: ScanJob,
    ) -> bool:
        with self._lock:
            current = self._jobs.get(job_id)
            if current is None:
                return False
            if current.status != expected_status or current.lease_id != expected_lease_id:
                return False
            self._jobs[job_id] = replacement
            return True


class SlidingWindowRateLimiter:
    """Process-local rate limiter for development; production needs shared atomic state."""

    def __init__(
        self,
        *,
        schedule_limit: int = 5,
        execution_limit: int = 2,
        window: timedelta = timedelta(minutes=1),
    ) -> None:
        if schedule_limit < 1 or execution_limit < 1 or window.total_seconds() <= 0:
            raise ValueError("Rate limits and window must be positive")
        self._limits = {"schedule": schedule_limit, "execution": execution_limit}
        self._window = window
        self._events: dict[tuple[str, str, str], deque[datetime]] = defaultdict(deque)
        self._lock = threading.Lock()

    def consume(self, tenant_id: str, asset_id: str, stage: str, now: datetime) -> bool:
        limit = self._limits.get(stage)
        if limit is None:
            return False
        key = (tenant_id, asset_id, stage)
        cutoff = now - self._window
        with self._lock:
            events = self._events[key]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                return False
            events.append(now)
            return True


@dataclass(frozen=True)
class UtcExecutionWindow:
    """Allow execution only during a configured UTC hour range and weekdays."""

    start_hour: int = 8
    end_hour: int = 18
    weekdays: frozenset[int] = frozenset({0, 1, 2, 3, 4})

    def __post_init__(self) -> None:
        if not 0 <= self.start_hour < self.end_hour <= 24:
            raise ValueError("Execution window must satisfy 0 <= start < end <= 24")
        if not self.weekdays or any(day not in range(7) for day in self.weekdays):
            raise ValueError("At least one valid weekday (0=Monday) is required")

    def is_open(self, now: datetime) -> bool:
        instant = _as_utc(now)
        return instant.weekday() in self.weekdays and self.start_hour <= instant.hour < self.end_hour


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ScanOrchestrationError("invalid_clock", "A timezone-aware timestamp is required")
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return _as_utc(value).isoformat().replace("+00:00", "Z")


class ScanOrchestrator:
    """Admission and execution-claim gates; deliberately contains no network client."""

    TERMINAL_STATES = frozenset({"blocked", "succeeded", "failed"})

    def __init__(
        self,
        *,
        asset_loader: Callable[[str, str], Mapping[str, Any] | None],
        jobs: ScanJobStore,
        audit_sink: Callable[[ScanAuditEvent], None],
        rate_limiter: RateLimiter,
        execution_window: ExecutionWindowPolicy,
        allowed_profiles: frozenset[str] = frozenset({"passive", "web_baseline"}),
        lease_seconds: int = 60,
        max_attempts: int = 3,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if not allowed_profiles or any(not p or p.strip() != p for p in allowed_profiles):
            raise ValueError("allowed_profiles must contain non-empty, normalized names")
        if lease_seconds < 1 or max_attempts < 1:
            raise ValueError("lease_seconds and max_attempts must be positive")
        self._asset_loader = asset_loader
        self._jobs = jobs
        self._audit_sink = audit_sink
        self._rate_limiter = rate_limiter
        self._execution_window = execution_window
        self._allowed_profiles = allowed_profiles
        self._lease_duration = timedelta(seconds=lease_seconds)
        self._max_attempts = max_attempts
        self._clock = clock

    def _now(self, supplied: datetime | None) -> datetime:
        return _as_utc(supplied if supplied is not None else self._clock())

    def _emit(
        self,
        *,
        event_type: str,
        now: datetime,
        actor_id: str,
        tenant_id: str,
        asset_id: str,
        job_id: str | None,
        outcome: str,
        reason_code: str,
    ) -> None:
        event = ScanAuditEvent(
            event_type=event_type,
            occurred_at=now,
            actor_id=actor_id,
            tenant_id=tenant_id,
            asset_id=asset_id,
            job_id=job_id,
            outcome=outcome,
            reason_code=reason_code,
        )
        try:
            self._audit_sink(event)
        except Exception as exc:
            raise ScanOrchestrationError(
                "audit_unavailable", "Audit sink failed; operation was not authorized"
            ) from exc

    def _deny_request(
        self,
        *,
        principal: ScanPrincipal,
        asset_id: str,
        job_id: str | None,
        now: datetime,
        code: str,
        message: str,
        event_type: str,
    ) -> None:
        self._emit(
            event_type=event_type,
            now=now,
            actor_id=principal.subject_id,
            tenant_id=principal.tenant_id,
            asset_id=asset_id,
            job_id=job_id,
            outcome="denied",
            reason_code=code,
        )
        raise ScanOrchestrationError(code, message)

    def _asset_and_scope(
        self, *, tenant_id: str, asset_id: str, target_url: str, now: datetime
    ) -> tuple[Mapping[str, Any] | None, Any]:
        try:
            asset = self._asset_loader(tenant_id, asset_id)
        except Exception as exc:
            raise ScanOrchestrationError(
                "asset_store_unavailable", "Current asset record could not be loaded"
            ) from exc
        if asset is None:
            return None, None
        decision = evaluate_target_scope(
            asset,
            target_url,
            requested_tenant_id=tenant_id,
            requested_asset_id=asset_id,
            now=now,
        )
        return asset, decision

    @staticmethod
    def _fingerprint(
        *, tenant_id: str, requested_by: str, asset_id: str, target_url: str, profile: str
    ) -> str:
        payload = {
            "tenant_id": tenant_id,
            "requested_by": requested_by,
            "asset_id": asset_id,
            "target_url": target_url,
            "profile": profile,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def submit_scan(
        self,
        principal: ScanPrincipal,
        *,
        asset_id: str,
        target_url: str,
        idempotency_key: str,
        profile: str = "web_baseline",
        now: datetime | None = None,
    ) -> ScanJob:
        instant = self._now(now)
        if not isinstance(principal, ScanPrincipal) or not principal.subject_id or not principal.tenant_id:
            raise ScanOrchestrationError("invalid_principal", "Trusted principal identity is required")
        if "scan:request" not in principal.permissions:
            self._deny_request(
                principal=principal, asset_id=asset_id if isinstance(asset_id, str) else "",
                job_id=None, now=instant, code="permission_denied",
                message="Principal lacks scan:request permission", event_type="scan.request.denied",
            )
        if (
            not isinstance(asset_id, str) or not asset_id or len(asset_id) > 128
            or asset_id != asset_id.strip()
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in asset_id)
        ):
            raise ScanOrchestrationError("invalid_asset_id", "asset_id must be a normalized string up to 128 characters")
        if not isinstance(target_url, str) or not target_url or len(target_url) > 4096:
            raise ScanOrchestrationError("invalid_target_url", "target_url must be a non-empty URL up to 4096 characters")
        if (
            not isinstance(idempotency_key, str) or len(idempotency_key) < 8
            or len(idempotency_key) > 256 or idempotency_key != idempotency_key.strip()
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in idempotency_key)
        ):
            raise ScanOrchestrationError(
                "invalid_idempotency_key", "idempotency_key must be 8-256 characters without surrounding whitespace"
            )
        if not isinstance(profile, str) or profile not in self._allowed_profiles:
            self._deny_request(
                principal=principal, asset_id=asset_id, job_id=None, now=instant,
                code="profile_not_allowed", message="Requested scan profile is not enabled",
                event_type="scan.request.denied",
            )

        fingerprint = self._fingerprint(
            tenant_id=principal.tenant_id, requested_by=principal.subject_id,
            asset_id=asset_id, target_url=target_url, profile=profile,
        )
        existing = self._jobs.get_by_idempotency_key(
            principal.tenant_id, principal.subject_id, idempotency_key
        )
        if existing is not None:
            if existing.request_fingerprint != fingerprint:
                self._deny_request(
                    principal=principal, asset_id=asset_id, job_id=existing.job_id, now=instant,
                    code="idempotency_conflict",
                    message="Idempotency key was already used with different request parameters",
                    event_type="scan.request.denied",
                )
            if existing.status == "pending_audit":
                try:
                    _, decision = self._asset_and_scope(
                        tenant_id=principal.tenant_id,
                        asset_id=asset_id,
                        target_url=target_url,
                        now=instant,
                    )
                except ScanOrchestrationError as exc:
                    self._deny_request(
                        principal=principal,
                        asset_id=asset_id,
                        job_id=existing.job_id,
                        now=instant,
                        code=exc.code,
                        message=exc.message,
                        event_type="scan.request.denied",
                    )

                if decision is None or not decision.allowed:
                    code = decision.code if decision is not None else "asset_not_found"
                    self._deny_request(
                        principal=principal,
                        asset_id=asset_id,
                        job_id=existing.job_id,
                        now=instant,
                        code=code,
                        message="Asset is missing or the target is no longer authorized",
                        event_type="scan.request.denied",
                    )

                return self._activate_pending(existing, principal=principal, now=instant)
            self._emit(
                event_type="scan.request.idempotent_replay", now=instant,
                actor_id=principal.subject_id, tenant_id=principal.tenant_id,
                asset_id=asset_id, job_id=existing.job_id, outcome="allowed",
                reason_code="existing_request_returned",
            )
            return existing

        try:
            _, decision = self._asset_and_scope(
                tenant_id=principal.tenant_id, asset_id=asset_id,
                target_url=target_url, now=instant,
            )
        except ScanOrchestrationError as exc:
            self._deny_request(
                principal=principal, asset_id=asset_id, job_id=None, now=instant,
                code=exc.code, message=exc.message, event_type="scan.request.denied",
            )
        if decision is None or not decision.allowed:
            code = decision.code if decision is not None else "asset_not_found"
            self._deny_request(
                principal=principal, asset_id=asset_id, job_id=None, now=instant,
                code=code, message="Asset is missing or the target is not authorized",
                event_type="scan.request.denied",
            )
        if not self._rate_limiter.consume(principal.tenant_id, asset_id, "schedule", instant):
            self._deny_request(
                principal=principal, asset_id=asset_id, job_id=None, now=instant,
                code="schedule_rate_limited", message="Scan scheduling rate limit exceeded",
                event_type="scan.request.rate_limited",
            )

        job = ScanJob(
            schema_version="1.0", job_id=str(uuid4()), tenant_id=principal.tenant_id,
            asset_id=asset_id, requested_by=principal.subject_id, target_url=target_url,
            profile=profile, idempotency_key=idempotency_key,
            request_fingerprint=fingerprint, status="pending_audit",
            created_at=instant, updated_at=instant,
        )
        if not self._jobs.create(job):
            existing = self._jobs.get_by_idempotency_key(
                principal.tenant_id, principal.subject_id, idempotency_key
            )
            if existing and existing.request_fingerprint == fingerprint:
                if existing.status == "pending_audit":
                    try:
                        _, decision = self._asset_and_scope(
                            tenant_id=principal.tenant_id,
                            asset_id=asset_id,
                            target_url=target_url,
                            now=instant,
                        )
                    except ScanOrchestrationError as exc:
                        self._deny_request(
                            principal=principal,
                            asset_id=asset_id,
                            job_id=existing.job_id,
                            now=instant,
                            code=exc.code,
                            message=exc.message,
                            event_type="scan.request.denied",
                        )

                    if decision is None or not decision.allowed:
                        code = decision.code if decision is not None else "asset_not_found"
                        self._deny_request(
                            principal=principal,
                            asset_id=asset_id,
                            job_id=existing.job_id,
                            now=instant,
                            code=code,
                            message="Asset is missing or the target is no longer authorized",
                            event_type="scan.request.denied",
                        )

                    return self._activate_pending(existing, principal=principal, now=instant)
                return existing
            self._deny_request(
                principal=principal, asset_id=asset_id,
                job_id=existing.job_id if existing else None, now=instant,
                code="idempotency_conflict", message="Idempotency key is already in use",
                event_type="scan.request.denied",
            )
        return self._activate_pending(job, principal=principal, now=instant)

    def _activate_pending(
        self, job: ScanJob, *, principal: ScanPrincipal, now: datetime
    ) -> ScanJob:
        self._emit(
            event_type="scan.job.admission_allowed", now=now,
            actor_id=principal.subject_id, tenant_id=job.tenant_id,
            asset_id=job.asset_id, job_id=job.job_id, outcome="allowed",
            reason_code="scope_and_request_policy_passed",
        )
        queued = replace(job, status="queued", updated_at=now, last_reason_code=None)
        if self._jobs.compare_and_set(job.job_id, "pending_audit", None, queued):
            return queued
        current = self._jobs.get(job.job_id)
        if current is not None and current.status == "queued":
            return current
        raise ScanOrchestrationError("job_state_conflict", "Could not activate admitted scan job")

    def claim_for_execution(
        self, worker: ScanPrincipal, *, job_id: str, now: datetime | None = None
    ) -> ExecutionPermit:
        instant = self._now(now)
        if not isinstance(worker, ScanPrincipal) or not worker.subject_id or not worker.tenant_id:
            raise ScanOrchestrationError("invalid_principal", "Trusted worker identity is required")
        if not isinstance(job_id, str) or not job_id or len(job_id) > 128 or any(ord(ch) < 32 or ord(ch) == 127 for ch in job_id):
            raise ScanOrchestrationError("invalid_job_id", "job_id must be a normalized string up to 128 characters")
        if "scan:execute" not in worker.permissions:
            self._deny_request(
                principal=worker, asset_id="", job_id=job_id, now=instant,
                code="permission_denied", message="Worker lacks scan:execute permission",
                event_type="scan.execution.denied",
            )
        job = self._jobs.get(job_id)
        if job is None or job.tenant_id != worker.tenant_id:
            self._deny_request(
                principal=worker, asset_id="", job_id=job_id, now=instant,
                code="job_not_found", message="Scan job was not found in the worker's tenant",
                event_type="scan.execution.denied",
            )
        if job.status == "queued":
            expected_status, expected_lease_id = "queued", None
        elif (
            job.status == "running" and job.lease_expires_at is not None
            and job.lease_expires_at <= instant and job.lease_id is not None
        ):
            expected_status, expected_lease_id = "running", job.lease_id
        else:
            self._deny_request(
                principal=worker, asset_id=job.asset_id, job_id=job.job_id, now=instant,
                code="job_not_claimable", message="Scan job is not queued or has an active lease",
                event_type="scan.execution.denied",
            )

        if job.attempt >= self._max_attempts:
            self._emit(
                event_type="scan.execution.denied", now=instant,
                actor_id=worker.subject_id, tenant_id=job.tenant_id,
                asset_id=job.asset_id, job_id=job.job_id, outcome="denied",
                reason_code="max_attempts_exceeded",
            )
            blocked = replace(
                job, status="blocked", updated_at=instant, lease_id=None,
                lease_expires_at=None, last_reason_code="max_attempts_exceeded",
            )
            if not self._jobs.compare_and_set(job.job_id, expected_status, expected_lease_id, blocked):
                raise ScanOrchestrationError("job_state_conflict", "Job changed while retry limit was checked")
            raise ScanOrchestrationError("max_attempts_exceeded", "Maximum scan claim attempts reached")

        try:
            _, decision = self._asset_and_scope(
                tenant_id=job.tenant_id, asset_id=job.asset_id,
                target_url=job.target_url, now=instant,
            )
        except ScanOrchestrationError as exc:
            self._deny_request(
                principal=worker, asset_id=job.asset_id, job_id=job.job_id, now=instant,
                code=exc.code, message=exc.message, event_type="scan.execution.denied",
            )
        if decision is None or not decision.allowed:
            code = decision.code if decision is not None else "asset_not_found"
            self._emit(
                event_type="scan.execution.denied", now=instant,
                actor_id=worker.subject_id, tenant_id=job.tenant_id,
                asset_id=job.asset_id, job_id=job.job_id, outcome="denied", reason_code=code,
            )
            blocked = replace(
                job, status="blocked", updated_at=instant, lease_id=None,
                lease_expires_at=None, last_reason_code=code,
            )
            if not self._jobs.compare_and_set(job.job_id, expected_status, expected_lease_id, blocked):
                raise ScanOrchestrationError("job_state_conflict", "Job changed while authorization was checked")
            raise ScanOrchestrationError(code, "Current asset authorization no longer permits execution")

        if not self._execution_window.is_open(instant):
            self._deny_request(
                principal=worker, asset_id=job.asset_id, job_id=job.job_id, now=instant,
                code="outside_execution_window", message="Execution is deferred until an approved window",
                event_type="scan.execution.deferred",
            )
        if not self._rate_limiter.consume(job.tenant_id, job.asset_id, "execution", instant):
            self._deny_request(
                principal=worker, asset_id=job.asset_id, job_id=job.job_id, now=instant,
                code="execution_rate_limited", message="Scan execution rate limit exceeded",
                event_type="scan.execution.rate_limited",
            )

        lease_id = str(uuid4())
        lease_expiry = instant + self._lease_duration
        running = replace(
            job, status="running", updated_at=instant, attempt=job.attempt + 1,
            lease_id=lease_id, lease_expires_at=lease_expiry, last_reason_code=None,
        )
        if not self._jobs.compare_and_set(job.job_id, expected_status, expected_lease_id, running):
            self._deny_request(
                principal=worker, asset_id=job.asset_id, job_id=job.job_id, now=instant,
                code="job_state_conflict", message="Another worker claimed or changed this job",
                event_type="scan.execution.denied",
            )
        try:
            self._emit(
                event_type="scan.execution.claimed", now=instant,
                actor_id=worker.subject_id, tenant_id=job.tenant_id,
                asset_id=job.asset_id, job_id=job.job_id, outcome="allowed",
                reason_code="scope_revalidated_and_lease_created",
            )
        except ScanOrchestrationError:
            # No permit is returned when audit fails. Roll back if this lease is still ours.
            self._jobs.compare_and_set(job.job_id, "running", lease_id, job)
            raise
        return ExecutionPermit(
            job_id=job.job_id, tenant_id=job.tenant_id, asset_id=job.asset_id,
            target_url=job.target_url, profile=job.profile, lease_id=lease_id,
            authorized_at=instant, lease_expires_at=lease_expiry,
        )

    def finish_job(
        self,
        worker: ScanPrincipal,
        *,
        job_id: str,
        lease_id: str,
        succeeded: bool,
        reason_code: str | None = None,
        now: datetime | None = None,
    ) -> ScanJob:
        instant = self._now(now)
        if not isinstance(worker, ScanPrincipal) or not worker.subject_id or not worker.tenant_id:
            raise ScanOrchestrationError("invalid_principal", "Trusted worker identity is required")
        if not isinstance(job_id, str) or not job_id or len(job_id) > 128 or any(ord(ch) < 32 or ord(ch) == 127 for ch in job_id):
            raise ScanOrchestrationError("invalid_job_id", "job_id must be a normalized string up to 128 characters")
        if not isinstance(lease_id, str) or not lease_id or len(lease_id) > 128:
            raise ScanOrchestrationError("invalid_lease_id", "lease_id is required")
        if not isinstance(succeeded, bool):
            raise ScanOrchestrationError("invalid_completion", "succeeded must be a boolean")
        if "scan:execute" not in worker.permissions:
            self._deny_request(
                principal=worker, asset_id="", job_id=job_id, now=instant,
                code="permission_denied", message="Worker lacks scan:execute permission",
                event_type="scan.completion.denied",
            )
        job = self._jobs.get(job_id)
        if job is None or job.tenant_id != worker.tenant_id:
            self._deny_request(
                principal=worker, asset_id="", job_id=job_id, now=instant,
                code="job_not_found", message="Scan job was not found in the worker's tenant",
                event_type="scan.completion.denied",
            )
        desired_status = "succeeded" if succeeded else "failed"
        if job.status == desired_status and job.lease_id == lease_id:
            return job  # Idempotent retry of the same completion.
        if (
            job.status != "running" or job.lease_id != lease_id
            or job.lease_expires_at is None or job.lease_expires_at <= instant
        ):
            self._deny_request(
                principal=worker, asset_id=job.asset_id, job_id=job.job_id, now=instant,
                code="stale_or_invalid_lease", message="Worker lease is invalid or expired",
                event_type="scan.completion.denied",
            )
        if not succeeded and (
            not isinstance(reason_code, str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,127}", reason_code)
        ):
            raise ScanOrchestrationError(
                "invalid_reason_code", "A bounded lowercase reason code is required for failure"
            )
        self._emit(
            event_type="scan.job.completion_requested", now=instant,
            actor_id=worker.subject_id, tenant_id=job.tenant_id,
            asset_id=job.asset_id, job_id=job.job_id,
            outcome="success" if succeeded else "failure",
            reason_code="completed" if succeeded else reason_code or "execution_failed",
        )
        final_job = replace(
            job, status=desired_status, updated_at=instant,
            lease_expires_at=None,
            last_reason_code=None if succeeded else reason_code,
        )
        if not self._jobs.compare_and_set(job.job_id, "running", lease_id, final_job):
            raise ScanOrchestrationError("job_state_conflict", "Job changed before completion was recorded")
        return final_job
