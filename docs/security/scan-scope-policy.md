# P4-03 — Scan Authorization and Scope Policy

## Purpose

This policy evaluator is a security boundary for future scan-request
processing. It evaluates an asset record and requested target. It does
not execute scans or replace requester authentication.

## Authorization preconditions

A request is denied unless all of these conditions hold:

1. The requested asset ID matches the asset record.
2. The request tenant ID matches the asset tenant ID.
3. `authorization.status` is exactly `approved`.
4. The approver is present, the approval timestamp is valid, and the
   expiry timestamp is valid.
5. The approval is not future-dated or expired.
6. Expiry occurs after approval.
7. The allowlist and exclusions have valid URL scope entries.
8. The target matches an approved scope and no exclusion.

Missing or malformed policy data is denied rather than ignored.

## URL matching rules

- Only absolute HTTP and HTTPS URLs are supported.
- Origin comparisons include scheme, normalized hostname, and effective port.
- An explicit default port is normalized (HTTPS 443, HTTP 80).
- Approved scope entries cannot contain query strings.
- Scope entries define exact origins plus optional path prefixes.
- Path-prefix matching respects segment boundaries: `/app` matches
  `/app` and `/app/users`, but not `/application`.
- Exclusions take precedence over allowlist matches.
- User information in URLs, fragments, malformed encodings, encoded path
  separators, dot segments, and ambiguous backslash paths are rejected.
- Wildcard hosts, CIDR notation and implicit subdomain matching are not
  supported. Add such behavior only through an explicit, tested policy.

## Security concepts

- **Fail closed:** policy ambiguity must not produce permission.
- **Least privilege:** allow only the origins and paths required for the
  approved assessment.
- **Tenant isolation:** a request cannot select an asset belonging to
  another tenant by substituting an identifier.
- **Defense in depth:** authentication, RBAC, authorization scope, network
  egress restrictions and auditing are separate controls.
- **Time-bounded authorization:** a previous approval is not permanent.
- **Exclusion precedence:** an excluded route remains denied even if a
  broader allowlist entry matches.

## Integration requirements

The future orchestrator must call this policy before scheduling work.
A passing decision alone is not a complete scan authorization system.
The service must also authenticate the requester, check their role,
validate the current asset record, enforce execution windows and rate
limits, audit the decision, and revalidate at the point of execution.

Redirects must not be followed blindly. Every redirect destination must
be checked against approved scope before following it.

DNS rebinding and resolution changes are not solved by URL comparison.
The execution layer must apply appropriate address validation and network
egress controls, including protection against loopback, private, link-local
and cloud metadata destinations unless specifically and explicitly approved.

## Testing and limitations

The unit tests use synthetic asset records and no network access. They
validate policy decisions, not real HTTP-client behavior, backend identity,
database consistency, DNS safety or deployment enforcement.

Run them from the repository root:

    .venv\Scripts\python.exe -m unittest discover -s tests/security -p "test_*.py" -v

The policy is one component of the authorization boundary, not a substitute
for written rules of engagement or approval by the asset owner.
