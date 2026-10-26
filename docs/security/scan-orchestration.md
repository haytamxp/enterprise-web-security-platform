# P4-04 — Controlled Scan Orchestration

## Objective

Provide the policy and job-state boundary between an authenticated API and a future worker. This milestone does **not** implement an HTTP client or run a scanner.

## Request admission

1. The caller must be represented by a trusted `ScanPrincipal` from authentication middleware. The orchestrator does not authenticate passwords or tokens.
2. `scan:request` permission is required. Tenant identity comes from the principal; callers do not choose a tenant ID.
3. The requested profile must be explicitly enabled. The defaults are `passive` and `web_baseline`; no network-executing profile is enabled by default.
4. The current asset is loaded and passed to `evaluate_target_scope`. Missing assets, tenant/asset mismatches, expired/revoked approval, out-of-scope targets, and malformed policy data fail closed.
5. Idempotency is scoped to tenant + requester + key. Repeating the same request returns the existing job without consuming a second scheduling slot. Reusing the key with different parameters is rejected.
6. A scheduling rate limit is consumed before a job is admitted.
7. The job begins in `pending_audit`, which workers cannot claim. Only after the admission audit event succeeds is the state atomically changed to `queued`. Audit failure therefore does not produce an executable job.

## Execution claim

A worker must have `scan:execute` permission and match the job tenant. Claiming checks the current job state, reloads the current asset, re-evaluates `evaluate_target_scope`, verifies the configured execution window, and consumes the execution-stage rate limit. Only then does an atomic compare-and-set transition move the job to `running` and issue a short-lived lease.

The default implementation allows three claim attempts. Expired leases can be reclaimed; the old lease ID becomes stale and cannot complete the new attempt. A scope failure blocks the job. A closed execution window or rate-limit denial leaves the job pending for a later attempt.

`finish_job` accepts completion only from the tenant-scoped worker that holds the current, unexpired lease. Completion requests are audited before the terminal state transition. Success produces `succeeded`; a bounded reason code is required for `failed`.

## Rate limit and execution-window defaults

The reference sliding-window limiter is process-local and defaults to five scheduled requests per tenant/asset per minute and two execution claims per tenant/asset per minute. Idempotent replays do not consume another scheduling slot. `UtcExecutionWindow` defaults to 08:00–18:00 UTC, Monday through Friday. Configure the intended rules explicitly before deployment; the reference limiter is not a distributed control.

## Audit and sensitive data

Audit events include event type, timestamp, actor, tenant, asset, job, outcome and a bounded reason code. They intentionally omit target URLs and query strings because those may contain identifiers or secrets. The job record still contains the target URL and therefore requires access control and appropriate retention. Audit-sink failure is treated as a denial, and a job that cannot complete the admission audit remains `pending_audit`.

## Current implementation boundaries

- `InMemoryScanJobStore` is a thread-safe test/development adapter, not durable production storage.
- `SlidingWindowRateLimiter` is process-local. Multi-worker deployments require a shared atomic limiter (for example Redis or a database-backed equivalent).
- The API must create `ScanPrincipal` only from verified identity/session context; never deserialize permissions or tenant identity directly from an untrusted request body.
- The job store needs durable uniqueness on `(tenant_id, requested_by, idempotency_key)`, transactional state changes, and an audit outbox/transactional integration for production reliability.
- The orchestrator does not resolve DNS, open sockets, send HTTP requests, follow redirects, or enforce egress. Before a network runner is implemented, validate every resolved address and every redirect target against the authorization policy and network restrictions (including loopback, private, link-local, reserved and cloud-metadata destinations unless explicitly approved). Revalidate immediately before each request, set strict timeouts and redirect limits, and implement emergency stop controls.
- The module contains no scanner dispatch, so a `running` state/permit authorizes a future worker claim only; it does not prove that target traffic was sent.

## Verification

From the repository root in PowerShell:

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests/security -p "test_*.py" -v
.venv\Scripts\python.exe scripts/validate_contracts.py
```

The tests use synthetic `example.com` asset records and do not make network requests.
