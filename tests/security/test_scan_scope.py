"""Unit tests for the P4 scan authorization policy."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "modules" / "p4-assurance"))

from scan_scope import evaluate_target_scope  # noqa: E402


NOW = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)
ASSET_ID = "asset-web-001"
TENANT_ID = "tenant-demo"


def sample_asset() -> dict:
    """Return synthetic authorization data matching the repository contract."""
    return {
        "asset_id": ASSET_ID,
        "tenant_id": TENANT_ID,
        "authorization": {
            "status": "approved",
            "approved_by": "security-owner-demo",
            "approved_at": "2026-10-20T09:00:00Z",
            "expires_at": "2026-12-31T23:59:59Z",
            "allowed_targets": ["https://staging.example.com"],
            "excluded_targets": ["https://staging.example.com/admin"],
            "rules_of_engagement_ref": "roe-demo-v1",
        },
    }


class ScanScopePolicyTests(unittest.TestCase):
    def decide(
        self,
        target: str,
        *,
        asset: dict | None = None,
        tenant_id: str = TENANT_ID,
        asset_id: str = ASSET_ID,
        now: datetime = NOW,
    ):
        record = asset if asset is not None else sample_asset()
        return evaluate_target_scope(
            record,
            target,
            requested_tenant_id=tenant_id,
            requested_asset_id=asset_id,
            now=now,
        )

    def test_allows_approved_origin_root(self):
        result = self.decide("https://staging.example.com/")
        self.assertTrue(result.allowed)
        self.assertEqual("authorized", result.code)

    def test_allows_path_on_approved_origin(self):
        result = self.decide("https://staging.example.com/products?id=123")
        self.assertTrue(result.allowed)

    def test_excluded_path_is_denied(self):
        result = self.decide("https://staging.example.com/admin")
        self.assertFalse(result.allowed)
        self.assertEqual("target_excluded", result.code)

    def test_descendant_of_excluded_path_is_denied(self):
        result = self.decide("https://staging.example.com/admin/users")
        self.assertEqual("target_excluded", result.code)

    def test_exclusion_does_not_match_similar_sibling_path(self):
        result = self.decide("https://staging.example.com/administrator")
        self.assertTrue(result.allowed)

    def test_exclusion_takes_precedence_over_allowlist(self):
        record = sample_asset()
        record["authorization"]["allowed_targets"] = [
            "https://staging.example.com",
            "https://staging.example.com/admin",
        ]
        result = self.decide("https://staging.example.com/admin", asset=record)
        self.assertEqual("target_excluded", result.code)

    def test_unapproved_statuses_are_denied(self):
        for status in ("pending", "expired", "revoked", "not_authorized"):
            with self.subTest(status=status):
                record = sample_asset()
                record["authorization"]["status"] = status
                result = self.decide("https://staging.example.com/", asset=record)
                self.assertFalse(result.allowed)
                self.assertEqual("not_approved", result.code)

    def test_expired_approval_is_denied(self):
        record = sample_asset()
        record["authorization"]["expires_at"] = "2026-10-21T11:59:59Z"
        result = self.decide("https://staging.example.com/", asset=record)
        self.assertEqual("authorization_expired", result.code)

    def test_missing_approver_is_denied(self):
        record = sample_asset()
        record["authorization"]["approved_by"] = ""
        result = self.decide("https://staging.example.com/", asset=record)
        self.assertEqual("missing_approval_metadata", result.code)

    def test_missing_expiry_is_denied(self):
        record = sample_asset()
        del record["authorization"]["expires_at"]
        result = self.decide("https://staging.example.com/", asset=record)
        self.assertEqual("missing_approval_metadata", result.code)

    def test_naive_timestamp_is_denied(self):
        record = sample_asset()
        record["authorization"]["expires_at"] = "2026-12-31T23:59:59"
        result = self.decide("https://staging.example.com/", asset=record)
        self.assertEqual("invalid_approval_metadata", result.code)

    def test_future_approval_is_denied(self):
        record = sample_asset()
        record["authorization"]["approved_at"] = "2026-10-22T09:00:00Z"
        result = self.decide("https://staging.example.com/", asset=record)
        self.assertEqual("approval_not_yet_active", result.code)

    def test_invalid_authorization_window_is_denied(self):
        record = sample_asset()
        record["authorization"]["expires_at"] = "2026-10-19T09:00:00Z"
        result = self.decide("https://staging.example.com/", asset=record)
        self.assertEqual("invalid_authorization_window", result.code)

    def test_cross_tenant_request_is_denied(self):
        result = self.decide(
            "https://staging.example.com/",
            tenant_id="tenant-another",
        )
        self.assertEqual("tenant_mismatch", result.code)

    def test_cross_asset_request_is_denied(self):
        result = self.decide(
            "https://staging.example.com/",
            asset_id="asset-another",
        )
        self.assertEqual("asset_mismatch", result.code)

    def test_lookalike_attacker_hostname_is_denied(self):
        result = self.decide("https://staging.example.com.attacker.test/")
        self.assertEqual("target_outside_scope", result.code)

    def test_wrong_scheme_is_denied(self):
        result = self.decide("http://staging.example.com/")
        self.assertEqual("target_outside_scope", result.code)

    def test_wrong_port_is_denied(self):
        result = self.decide("https://staging.example.com:8443/")
        self.assertEqual("target_outside_scope", result.code)

    def test_default_https_port_is_equivalent(self):
        result = self.decide("https://staging.example.com:443/")
        self.assertTrue(result.allowed)

    def test_user_information_in_target_is_denied(self):
        result = self.decide("https://staging.example.com@attacker.test/")
        self.assertEqual("invalid_target_url", result.code)

    def test_unsupported_scheme_is_denied(self):
        result = self.decide("ftp://staging.example.com/")
        self.assertEqual("invalid_target_url", result.code)

    def test_subpath_allowlist_uses_segment_boundaries(self):
        record = sample_asset()
        record["authorization"]["allowed_targets"] = [
            "https://staging.example.com/app"
        ]
        self.assertTrue(
            self.decide("https://staging.example.com/app/users", asset=record).allowed
        )
        result = self.decide("https://staging.example.com/application", asset=record)
        self.assertEqual("target_outside_scope", result.code)

    def test_dot_segment_traversal_is_denied(self):
        result = self.decide("https://staging.example.com/app/../admin")
        self.assertEqual("invalid_target_url", result.code)

    def test_encoded_slash_is_denied(self):
        result = self.decide("https://staging.example.com/app%2fadmin")
        self.assertEqual("invalid_target_url", result.code)

    def test_double_encoded_path_is_denied(self):
        result = self.decide("https://staging.example.com/app%252fadmin")
        self.assertEqual("invalid_target_url", result.code)

    def test_empty_allowlist_is_denied(self):
        record = sample_asset()
        record["authorization"]["allowed_targets"] = []
        result = self.decide("https://staging.example.com/", asset=record)
        self.assertEqual("invalid_scope_configuration", result.code)

    def test_malformed_exclusion_fails_closed(self):
        record = sample_asset()
        record["authorization"]["excluded_targets"] = [
            "https://staging.example.com/admin?unexpected=true"
        ]
        result = self.decide("https://staging.example.com/products", asset=record)
        self.assertEqual("invalid_scope_configuration", result.code)

    def test_wildcard_scope_is_not_implicitly_supported(self):
        record = sample_asset()
        record["authorization"]["allowed_targets"] = [
            "https://*.staging.example.com"
        ]
        result = self.decide("https://one.staging.example.com/", asset=record)
        self.assertEqual("invalid_scope_configuration", result.code)

    def test_fragment_is_denied(self):
        result = self.decide("https://staging.example.com/products#fragment")
        self.assertEqual("invalid_target_url", result.code)


if __name__ == "__main__":
    unittest.main()
