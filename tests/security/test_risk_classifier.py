from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "modules" / "p4-assurance"))

from risk_classifier import RiskClassificationError, classify_finding

NOW = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)
SHA256 = "a" * 64


def sample_finding(**changes):
    finding = {
        "schema_version": "1.0",
        "finding_id": "finding-demo-001",
        "asset_id": "asset-web-001",
        "tenant_id": "tenant-demo",
        "source": "p1_offensive",
        "title": "Missing object-level authorization check",
        "description": "Synthetic test finding.",
        "status": "confirmed",
        "severity": "high",
        "confidence": 0.98,
        "cvss": {"version": "4.0", "score": 8.1, "vector": None},
        "cwe_ids": ["CWE-862"],
        "references": [],
        "evidence_refs": [{
            "evidence_id": "evidence-demo-001",
            "classification": "internal",
            "redacted": True,
            "sha256": SHA256,
        }],
        "detected_at": "2026-10-24T11:00:00Z",
    }
    finding.update(changes)
    return finding


def full_context(**changes):
    context = {
        "internet_exposed": True,
        "known_exploited": False,
        "asset_criticality": "high",
        "sensitive_data": True,
    }
    context.update(changes)
    return context


class RiskClassifierTests(unittest.TestCase):
    def classify(self, finding=None, **kwargs):
        kwargs.setdefault("assessed_at", NOW)
        kwargs.setdefault("asset_context", full_context())
        return classify_finding(
            sample_finding() if finding is None else finding,
            **kwargs,
        )

    def test_source_confirmed_hash_metadata_requires_evidence_verification(self):
        assessment = self.classify()
        self.assertEqual("potential_vulnerability", assessment["classification"])
        self.assertEqual("hash_present_unverified", assessment["evidence_quality"])
        self.assertEqual("A01:2025", assessment["owasp"]["category_id"])
        self.assertEqual("cwe_rule", assessment["owasp"]["mapping_method"])
        self.assertEqual("P2", assessment["priority"])
        self.assertTrue(assessment["needs_analyst_review"])
        self.assertIn("evidence_hash_not_verified", assessment["review_reasons"])
        self.assertIn("finding_not_evidence_confirmed", assessment["review_reasons"])

    def test_source_confidence_alone_does_not_confirm_vulnerability(self):
        finding = sample_finding(
            status="detected", confidence=1.0, evidence_refs=[], cwe_ids=[], cvss=None
        )
        assessment = self.classify(finding)
        self.assertEqual("security_observation", assessment["classification"])
        self.assertEqual("UNASSESSED", assessment["priority"])
        self.assertTrue(assessment["needs_analyst_review"])

    def test_confirmed_status_without_evidence_or_cwe_is_insufficient(self):
        assessment = self.classify(sample_finding(evidence_refs=[], cwe_ids=[]))
        self.assertEqual("insufficient_evidence", assessment["classification"])
        self.assertIn("insufficient_evidence", assessment["review_reasons"])

    def test_unhashed_evidence_is_not_enough_for_confirmation(self):
        finding = sample_finding(evidence_refs=[{
            "evidence_id": "evidence-1",
            "classification": "internal",
            "redacted": True,
        }])
        assessment = self.classify(finding)
        self.assertEqual("potential_vulnerability", assessment["classification"])
        self.assertEqual("referenced_unhashed", assessment["evidence_quality"])
        self.assertIn("evidence_integrity_not_proven", assessment["review_reasons"])
        self.assertTrue(assessment["needs_analyst_review"])

    def test_nonconfirmed_finding_with_hash_remains_potential(self):
        assessment = self.classify(sample_finding(status="detected"))
        self.assertEqual("potential_vulnerability", assessment["classification"])
        self.assertTrue(assessment["needs_analyst_review"])

    def test_cvss_v4_score_maps_without_calculating_score(self):
        finding = sample_finding(
            cvss={"version": "4.0", "score": 8.1, "vector": None}
        )
        assessment = self.classify(finding)
        self.assertEqual("cvss_v4_0", assessment["severity"]["basis"])
        self.assertEqual(8.1, assessment["severity"]["cvss_v4_score"])
        self.assertEqual("high", assessment["severity"]["value"])

    def test_source_severity_is_preserved_when_cvss_is_missing(self):
        finding = sample_finding(cvss=None, severity="medium")
        assessment = self.classify(finding)
        self.assertEqual("medium", assessment["severity"]["value"])
        self.assertEqual("source_reported", assessment["severity"]["basis"])
        self.assertIsNone(assessment["severity"]["cvss_v4_score"])

    def test_cvss_severity_conflict_requires_review(self):
        finding = sample_finding(
            severity="low",
            cvss={"version": "4.0", "score": 8.1, "vector": None},
        )
        assessment = self.classify(finding)
        self.assertEqual("high", assessment["severity"]["value"])
        self.assertTrue(assessment["severity"]["conflict"])
        self.assertIn("cvss_severity_mismatch", assessment["review_reasons"])

    def test_cvss_v4_qualitative_boundaries(self):
        cases = [
            (0.0, "info"), (3.9, "low"), (4.0, "medium"), (6.9, "medium"),
            (7.0, "high"), (8.9, "high"), (9.0, "critical"), (10.0, "critical"),
        ]
        for score, expected in cases:
            with self.subTest(score=score):
                finding = sample_finding(
                    cvss={"version": "4.0", "score": score, "vector": None}
                )
                assessment = self.classify(finding)
                self.assertEqual(expected, assessment["severity"]["value"])

    def test_cwe_maps_to_a05_injection(self):
        assessment = self.classify(sample_finding(cwe_ids=["CWE-89"]))
        self.assertEqual("A05:2025", assessment["owasp"]["category_id"])
        self.assertEqual("Injection", assessment["owasp"]["category_name"])

    def test_path_traversal_maps_to_a01(self):
        assessment = self.classify(sample_finding(cwe_ids=["CWE-22"]))
        self.assertEqual("A01:2025", assessment["owasp"]["category_id"])

    def test_dependency_failure_maps_to_a03(self):
        assessment = self.classify(sample_finding(cwe_ids=["CWE-1104"]))
        self.assertEqual("A03:2025", assessment["owasp"]["category_id"])

    def test_untrusted_functionality_maps_to_a08(self):
        assessment = self.classify(sample_finding(cwe_ids=["CWE-829"]))
        self.assertEqual("A08:2025", assessment["owasp"]["category_id"])

    def test_closed_finding_does_not_receive_active_priority(self):
        assessment = self.classify(sample_finding(status="closed"))
        self.assertEqual("UNASSESSED", assessment["priority"])
        self.assertEqual("not_applicable", assessment["priority_basis"])

    def test_multiple_mapped_cwes_are_ambiguous(self):
        finding = sample_finding(cwe_ids=["CWE-862", "CWE-89"])
        assessment = self.classify(finding)
        self.assertEqual("UNMAPPED", assessment["owasp"]["category_id"])
        self.assertEqual(
            "ambiguous_cwe_mapping", assessment["owasp"]["mapping_method"]
        )
        self.assertEqual(
            ["A01:2025", "A05:2025"],
            assessment["owasp"]["candidate_category_ids"],
        )
        self.assertIn("multiple_owasp_categories", assessment["review_reasons"])

    def test_unknown_cwe_is_not_guessed_from_title(self):
        finding = sample_finding(
            title="SQL injection detected",
            cwe_ids=["CWE-999999"],
        )
        assessment = self.classify(finding)
        self.assertEqual("UNMAPPED", assessment["owasp"]["category_id"])
        self.assertEqual(
            "no_supported_cwe_mapping", assessment["owasp"]["mapping_method"]
        )
        self.assertEqual(["CWE-999999"], assessment["owasp"]["unmapped_cwe_ids"])

    def test_missing_cwe_sets_review_reason(self):
        assessment = self.classify(sample_finding(cwe_ids=[]))
        self.assertIn("no_cwe_ids_supplied", assessment["review_reasons"])

    def test_known_exploited_high_severity_gets_p1(self):
        assessment = self.classify(
            asset_context=full_context(known_exploited=True)
        )
        self.assertEqual("P1", assessment["priority"])
        self.assertEqual("known_exploited", assessment["priority_basis"])

    def test_source_confirmed_critical_internet_exposed_stays_p2_pending_verification(self):
        finding = sample_finding(
            severity="critical",
            cvss={"version": "4.0", "score": 9.5, "vector": None},
        )
        assessment = self.classify(finding)
        self.assertEqual("potential_vulnerability", assessment["classification"])
        self.assertEqual("P2", assessment["priority"])
        self.assertEqual("critical_severity", assessment["priority_basis"])
        self.assertTrue(assessment["needs_analyst_review"])
        self.assertIn("evidence_hash_not_verified", assessment["review_reasons"])

    def test_critical_potential_finding_gets_p2_not_p1(self):
        finding = sample_finding(
            status="detected",
            severity="critical",
            cvss={"version": "4.0", "score": 9.5, "vector": None},
        )
        assessment = self.classify(finding)
        self.assertEqual("potential_vulnerability", assessment["classification"])
        self.assertEqual("P2", assessment["priority"])

    def test_medium_finding_gets_p3(self):
        finding = sample_finding(
            severity="medium",
            cvss={"version": "4.0", "score": 5.5, "vector": None},
        )
        self.assertEqual("P3", self.classify(finding)["priority"])

    def test_low_finding_gets_p4(self):
        finding = sample_finding(
            severity="low",
            cvss={"version": "4.0", "score": 2.0, "vector": None},
        )
        self.assertEqual("P4", self.classify(finding)["priority"])

    def test_incomplete_high_severity_context_requires_review(self):
        assessment = self.classify(asset_context={"internet_exposed": True})
        self.assertEqual("P2", assessment["priority"])
        self.assertIn("risk_context_incomplete", assessment["review_reasons"])
        self.assertTrue(assessment["needs_analyst_review"])

    def test_false_positive_disposition_is_preserved(self):
        assessment = self.classify(sample_finding(status="false_positive"))
        self.assertEqual("false_positive", assessment["classification"])
        self.assertEqual("UNASSESSED", assessment["priority"])
        self.assertIn("disposition_requires_review", assessment["review_reasons"])

    def test_accepted_risk_disposition_is_preserved(self):
        assessment = self.classify(sample_finding(status="accepted_risk"))
        self.assertEqual("accepted_risk", assessment["classification"])
        self.assertEqual("UNASSESSED", assessment["priority"])
        self.assertIn("disposition_requires_review", assessment["review_reasons"])

    def test_invalid_evidence_hash_fails_closed(self):
        finding = sample_finding(evidence_refs=[{
            "evidence_id": "evidence-1",
            "classification": "internal",
            "redacted": True,
            "sha256": "not-a-hash",
        }])
        with self.assertRaises(RiskClassificationError):
            self.classify(finding)

    def test_invalid_cvss_version_is_rejected(self):
        finding = sample_finding(
            cvss={"version": "3.1", "score": 8.1, "vector": None}
        )
        with self.assertRaises(RiskClassificationError):
            self.classify(finding)

    def test_invalid_context_type_is_rejected(self):
        with self.assertRaises(RiskClassificationError):
            self.classify(asset_context={"internet_exposed": "yes"})

    def test_invalid_asset_criticality_type_is_rejected(self):
        with self.assertRaises(RiskClassificationError):
            self.classify(asset_context={"asset_criticality": ["high"]})

    def test_timezone_naive_assessment_time_is_rejected(self):
        with self.assertRaises(RiskClassificationError):
            self.classify(assessed_at="2026-10-24T12:00:00")

    def test_assessment_id_is_deterministic_for_same_inputs(self):
        first = self.classify()
        second = self.classify()
        self.assertEqual(first["assessment_id"], second["assessment_id"])


if __name__ == "__main__":
    unittest.main()