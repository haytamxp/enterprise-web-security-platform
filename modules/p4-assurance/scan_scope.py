"""Fail-closed authorization and URL-scope checks for scan requests.

This module evaluates policy only. It does not start network scans,
resolve DNS, follow redirects, or authorize actions outside this policy.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import re
import unicodedata
from typing import Any, Mapping
from urllib.parse import unquote, urlsplit


@dataclass(frozen=True)
class ScopeDecision:
    """A deterministic decision that can be checked and audited."""

    allowed: bool
    code: str
    reason: str


@dataclass(frozen=True)
class _CanonicalURL:
    """Canonical URL fields used only for scope comparisons."""

    scheme: str
    hostname: str
    port: int
    path: str

    @property
    def origin(self) -> tuple[str, str, int]:
        return self.scheme, self.hostname, self.port


def _deny(code: str, reason: str) -> ScopeDecision:
    return ScopeDecision(allowed=False, code=code, reason=reason)


def _parse_utc_timestamp(value: object) -> datetime | None:
    """Parse an ISO-8601 timestamp that explicitly contains a time zone."""
    if not isinstance(value, str) or not value.strip():
        return None

    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None

    return parsed.astimezone(timezone.utc)


def _canonicalize_url(raw: object, *, scope_entry: bool) -> _CanonicalURL:
    """Parse a URL conservatively so ambiguous forms fail closed."""
    if not isinstance(raw, str) or not raw or raw != raw.strip():
        raise ValueError("URL must be a non-empty string without surrounding whitespace")

    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        raise ValueError("URL contains whitespace or control characters")

    if "\\" in raw or "#" in raw:
        raise ValueError("Backslashes and fragments are not accepted")

    try:
        parts = urlsplit(raw)
        scheme = parts.scheme.lower()
        hostname_raw = parts.hostname
        port_raw = parts.port
        username = parts.username
        password = parts.password
    except ValueError as exc:
        raise ValueError("Malformed URL authority") from exc

    if scheme not in {"http", "https"} or not parts.netloc or not hostname_raw:
        raise ValueError("Only absolute HTTP or HTTPS URLs are supported")

    if username is not None or password is not None:
        raise ValueError("URLs containing user information are not accepted")

    if scope_entry and ("?" in raw or parts.query):
        raise ValueError("Scope definitions must not contain query strings")

    # Percent encodings in a path are checked before decoding so that
    # encoded separators and encoded percent signs cannot alter boundaries.
    raw_path = parts.path or "/"

    if re.search(r"%(?:2f|5c|25)", raw_path, flags=re.IGNORECASE):
        raise ValueError("Encoded separators or double-encoded paths are not accepted")

    if re.search(r"%(?![0-9a-fA-F]{2})", raw_path):
        raise ValueError("Path contains an invalid percent encoding")

    try:
        path = unquote(raw_path, encoding="utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("Path is not valid UTF-8") from exc

    path = unicodedata.normalize("NFC", path)

    if not path.startswith("/") or "\\" in path or "//" in path:
        raise ValueError("Ambiguous path representation")

    if any(segment in {".", ".."} for segment in path.split("/")):
        raise ValueError("Dot-segment path traversal is not accepted")

    if any(ord(ch) < 32 or ord(ch) == 127 for ch in path):
        raise ValueError("Path contains control characters")

    # Normalize DNS names and IP literals for comparisons.
    if "%" in hostname_raw:
        raise ValueError("Percent encoding or zone identifiers in hostnames are not accepted")

    try:
        ip_value = ipaddress.ip_address(hostname_raw)
    except ValueError:
        try:
            hostname = hostname_raw.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("Hostname cannot be normalized") from exc

        if not hostname or len(hostname) > 253:
            raise ValueError("Invalid hostname length")

        labels = hostname.split(".")
        for label in labels:
            if (
                len(label) > 63
                or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            ):
                raise ValueError("Invalid hostname label")
    else:
        hostname = ip_value.compressed.lower()

    if port_raw is not None and not 1 <= port_raw <= 65535:
        raise ValueError("Port must be between 1 and 65535")

    default_port = 443 if scheme == "https" else 80
    effective_port = port_raw if port_raw is not None else default_port

    return _CanonicalURL(
        scheme=scheme,
        hostname=hostname,
        port=effective_port,
        path=path,
    )


def _path_is_within(candidate_path: str, scope_path: str) -> bool:
    """Match an exact path or descendant on a path-segment boundary."""
    if scope_path == "/":
        return True

    base = scope_path.rstrip("/")
    return candidate_path == base or candidate_path.startswith(base + "/")


def evaluate_target_scope(
    asset: Mapping[str, Any],
    target_url: str,
    *,
    requested_tenant_id: str,
    requested_asset_id: str,
    now: datetime | None = None,
) -> ScopeDecision:
    """Return an allow/deny decision for a scan target and asset.

    The caller must authenticate the requester independently. The request's
    tenant and asset IDs must match the supplied asset record. A URL must
    match an approved origin/path scope and must not match an exclusion.
    """
    if not isinstance(asset, Mapping):
        return _deny("invalid_asset", "Asset record is not an object")

    asset_id = asset.get("asset_id")
    tenant_id = asset.get("tenant_id")

    if not isinstance(asset_id, str) or not asset_id:
        return _deny("invalid_asset", "Asset record has no valid asset ID")

    if not isinstance(tenant_id, str) or not tenant_id:
        return _deny("invalid_asset", "Asset record has no valid tenant ID")

    if requested_asset_id != asset_id:
        return _deny("asset_mismatch", "Requested asset does not match the asset record")

    if requested_tenant_id != tenant_id:
        return _deny("tenant_mismatch", "Requested tenant does not own this asset")

    if now is None:
        current_time = datetime.now(timezone.utc)
    elif now.tzinfo is None or now.utcoffset() is None:
        return _deny("invalid_clock", "Policy evaluation requires a time-zone-aware clock")
    else:
        current_time = now.astimezone(timezone.utc)

    authorization = asset.get("authorization")
    if not isinstance(authorization, Mapping):
        return _deny("invalid_authorization", "Asset authorization object is missing")

    if authorization.get("status") != "approved":
        return _deny("not_approved", "Asset authorization status is not approved")

    approved_by = authorization.get("approved_by")
    approved_at_raw = authorization.get("approved_at")
    expires_at_raw = authorization.get("expires_at")

    if (
        not isinstance(approved_by, str)
        or not approved_by.strip()
        or not isinstance(approved_at_raw, str)
        or not isinstance(expires_at_raw, str)
    ):
        return _deny(
            "missing_approval_metadata",
            "Approver, approval timestamp, and expiry are required",
        )

    approved_at = _parse_utc_timestamp(approved_at_raw)
    expires_at = _parse_utc_timestamp(expires_at_raw)

    if approved_at is None or expires_at is None:
        return _deny(
            "invalid_approval_metadata",
            "Approval and expiry must be valid ISO-8601 timestamps with time zones",
        )

    if expires_at <= approved_at:
        return _deny("invalid_authorization_window", "Authorization expiry must follow approval")

    if approved_at > current_time:
        return _deny("approval_not_yet_active", "Authorization approval is not active yet")

    if expires_at <= current_time:
        return _deny("authorization_expired", "Authorization has expired")

    try:
        target = _canonicalize_url(target_url, scope_entry=False)
    except ValueError:
        return _deny("invalid_target_url", "Target URL is malformed or ambiguous")

    allowed_raw = authorization.get("allowed_targets")
    excluded_raw = authorization.get("excluded_targets")

    if not isinstance(allowed_raw, list) or not allowed_raw:
        return _deny("invalid_scope_configuration", "No approved target scopes are configured")

    if not isinstance(excluded_raw, list):
        return _deny("invalid_scope_configuration", "Excluded targets must be a list")

    try:
        allowed_scopes = [
            _canonicalize_url(value, scope_entry=True)
            for value in allowed_raw
        ]
        excluded_scopes = [
            _canonicalize_url(value, scope_entry=True)
            for value in excluded_raw
        ]
    except ValueError:
        return _deny(
            "invalid_scope_configuration",
            "A configured allowlist or exclusion contains an invalid scope URL",
        )

    # Exclusions always take precedence over an allowlist match.
    for excluded in excluded_scopes:
        if (
            target.origin == excluded.origin
            and _path_is_within(target.path, excluded.path)
        ):
            return _deny("target_excluded", "Target matches an explicitly excluded scope")

    for allowed in allowed_scopes:
        if (
            target.origin == allowed.origin
            and _path_is_within(target.path, allowed.path)
        ):
            return ScopeDecision(
                allowed=True,
                code="authorized",
                reason="Target matches an approved, unexpired asset scope",
            )

    return _deny("target_outside_scope", "Target is outside the approved allowlist")
