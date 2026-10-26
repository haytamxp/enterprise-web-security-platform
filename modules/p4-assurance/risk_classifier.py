"""Evidence-aware, deterministic OWASP Top 10:2025 triage helpers.

This module classifies supplied finding metadata. It does not perform
network requests, retrieve evidence, verify evidence hashes, calculate CVSS,
or replace an analyst's confirmation and risk-acceptance decisions.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import math
import re
from typing import Any


OWASP_TAXONOMY_VERSION = "2025"

OWASP_CATEGORIES: dict[str, str] = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software or Data Integrity Failures",
    "A09:2025": "Security Logging and Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}

UNMAPPED_CATEGORY_ID = "UNMAPPED"
UNMAPPED_CATEGORY_NAME = "Unmapped / analyst classification required"

# This is a curated implementation subset, not an official exhaustive mapping.
# Ambiguous or unsupported cases deliberately require analyst classification.
CWE_TO_OWASP: dict[str, str] = {
    "CWE-22": "A01:2025",
    "CWE-23": "A01:2025",
    "CWE-200": "A01:2025",
    "CWE-284": "A01:2025",
    "CWE-285": "A01:2025",
    "CWE-352": "A01:2025",
    "CWE-639": "A01:2025",
    "CWE-732": "A01:2025",
    "CWE-862": "A01:2025",
    "CWE-863": "A01:2025",
    "CWE-918": "A01:2025",
    "CWE-922": "A01:2025",
    "CWE-942": "A01:2025",
    "CWE-16": "A02:2025",
    "CWE-1104": "A03:2025",
    "CWE-1329": "A03:2025",
    "CWE-1395": "A03:2025",
    "CWE-319": "A04:2025",
    "CWE-326": "A04:2025",
    "CWE-327": "A04:2025",
    "CWE-328": "A04:2025",
    "CWE-78": "A05:2025",
    "CWE-79": "A05:2025",
    "CWE-89": "A05:2025",
    "CWE-90": "A05:2025",
    "CWE-94": "A05:2025",
    "CWE-657": "A06:2025",
    "CWE-287": "A07:2025",
    "CWE-306": "A07:2025",
    "CWE-521": "A07:2025",
    "CWE-798": "A07:2025",
    "CWE-345": "A08:2025",
    "CWE-353": "A08:2025",
    "CWE-494": "A08:2025",
    "CWE-502": "A08:2025",
    "CWE-829": "A08:2025",
    "CWE-117": "A09:2025",
    "CWE-778": "A09:2025",
    "CWE-248": "A10:2025",
    "CWE-703": "A10:2025",
    "CWE-754": "A10:2025",
    "CWE-755": "A10:2025",
}

FINDING_STATUSES = {
    "detected", "triaged", "confirmed", "false_positive", "remediating",
    "fixed_pending_retest", "retest_passed", "accepted_risk", "closed",
}
SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
CWE_RE = re.compile(r"^CWE-[0-9]+$")


class RiskClassificationError(ValueError):
    """Raised when finding metadata is malformed or ambiguous."""


def _aware_utc(value: datetime | str | None) -> str:
    if value is None:
        parsed = datetime.now(timezone.utc)
    elif isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError as exc:
            raise RiskClassificationError(
                "assessed_at must be a valid ISO-8601 timestamp"
            ) from exc
    else:
        raise RiskClassificationError(
            "assessed_at must be a datetime, ISO-8601 string, or None"
        )

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise RiskClassificationError("assessed_at must include a timezone")

    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_finding(
    finding: Mapping[str, Any],
) -> tuple[str, str, float, list[Mapping[str, Any]], list[str], bool, float | None]:
    if not isinstance(finding, Mapping):
        raise RiskClassificationError("finding must be an object")

    finding_id = finding.get("finding_id")
    status = finding.get("status")
    severity = finding.get("severity")
    confidence = finding.get("confidence")
    evidence_refs = finding.get("evidence_refs")
    cwe_ids = finding.get("cwe_ids", [])

    if (
        not isinstance(finding_id, str)
        or not finding_id.strip()
        or len(finding_id) > 128
    ):
        raise RiskClassificationError(
            "finding_id must be a non-empty string of at most 128 characters"
        )

    if not isinstance(status, str) or status not in FINDING_STATUSES:
        raise RiskClassificationError("status is not a supported finding status")

    if not isinstance(severity, str) or severity not in SEVERITIES:
        raise RiskClassificationError("severity is not a supported severity value")

    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise RiskClassificationError("confidence must be a number in the range 0..1")

    if not math.isfinite(float(confidence)) or not 0 <= float(confidence) <= 1:
        raise RiskClassificationError(
            "confidence must be a finite number in the range 0..1"
        )

    if not isinstance(evidence_refs, list):
        raise RiskClassificationError("evidence_refs must be a list")

    if not isinstance(cwe_ids, list) or any(
        not isinstance(item, str) or not CWE_RE.fullmatch(item)
        for item in cwe_ids
    ):
        raise RiskClassificationError(
            "cwe_ids must contain canonical identifiers such as CWE-862"
        )

    if len(set(cwe_ids)) != len(cwe_ids):
        raise RiskClassificationError("cwe_ids must not contain duplicates")

    # This only checks whether a digest-shaped string was supplied.
    # It does NOT retrieve evidence or verify the digest against actual bytes.
    has_hash_metadata = False

    for reference in evidence_refs:
        if not isinstance(reference, Mapping):
            raise RiskClassificationError("each evidence reference must be an object")

        evidence_id = reference.get("evidence_id")
        if not isinstance(evidence_id, str) or not evidence_id.strip():
            raise RiskClassificationError(
                "each evidence reference must include a non-empty evidence_id"
            )

        digest = reference.get("sha256")
        if digest is not None:
            if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
                raise RiskClassificationError(
                    "provided evidence sha256 must contain 64 hexadecimal characters"
                )
            has_hash_metadata = True

    cvss = finding.get("cvss")
    cvss_score: float | None = None

    if cvss is not None:
        if not isinstance(cvss, Mapping) or cvss.get("version") != "4.0":
            raise RiskClassificationError(
                "only a CVSS v4.0 score object is supported"
            )

        score = cvss.get("score")
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise RiskClassificationError(
                "CVSS v4.0 score must be a number between 0 and 10"
            )

        if not math.isfinite(float(score)) or not 0 <= float(score) <= 10:
            raise RiskClassificationError(
                "CVSS v4.0 score must be a finite number between 0 and 10"
            )

        cvss_score = float(score)

    return (
        finding_id, status, float(confidence), evidence_refs,
        list(cwe_ids), has_hash_metadata, cvss_score,
    )


def _normalise_context(
    asset_context: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if asset_context is None:
        values: Mapping[str, Any] = {}
    elif isinstance(asset_context, Mapping):
        values = asset_context
    else:
        raise RiskClassificationError("asset_context must be an object or None")

    allowed = {
        "internet_exposed", "known_exploited",
        "asset_criticality", "sensitive_data",
    }
    extra = set(values) - allowed
    if extra:
        raise RiskClassificationError(
            f"unsupported asset_context key(s): {', '.join(sorted(extra))}"
        )

    result: dict[str, Any] = {}

    for key in ("internet_exposed", "known_exploited", "sensitive_data"):
        value = values.get(key)
        if value is not None and type(value) is not bool:
            raise RiskClassificationError(
                f"asset_context.{key} must be true, false, or null"
            )
        result[key] = value

    criticality = values.get("asset_criticality", "unknown")
    if criticality is None:
        criticality = "unknown"

    if not isinstance(criticality, str) or criticality not in {
        "critical", "high", "medium", "low", "unknown",
    }:
        raise RiskClassificationError("asset_context.asset_criticality is invalid")

    result["asset_criticality"] = criticality
    return result


def _severity_assessment(
    reported_severity: str,
    cvss_score: float | None,
) -> dict[str, Any]:
    if cvss_score is None:
        value = reported_severity
        basis = "source_reported" if value != "unknown" else "unknown"
        return {
            "value": value,
            "basis": basis,
            "source_reported": reported_severity,
            "cvss_v4_score": None,
            "conflict": False,
        }

    # Qualitative mapping of a supplied CVSS v4.0 score; no score is calculated.
    if cvss_score == 0:
        value = "info"  # The existing finding contract has no "none" value.
    elif cvss_score < 4.0:
        value = "low"
    elif cvss_score < 7.0:
        value = "medium"
    elif cvss_score < 9.0:
        value = "high"
    else:
        value = "critical"

    conflict = reported_severity not in {"unknown", value}

    return {
        "value": value,
        "basis": "cvss_v4_0",
        "source_reported": reported_severity,
        "cvss_v4_score": cvss_score,
        "conflict": conflict,
    }


def _owasp_assessment(cwe_ids: list[str]) -> dict[str, Any]:
    matched = [cwe for cwe in cwe_ids if cwe in CWE_TO_OWASP]
    unmapped = [cwe for cwe in cwe_ids if cwe not in CWE_TO_OWASP]
    candidates = sorted({CWE_TO_OWASP[cwe] for cwe in matched})

    if len(candidates) == 1:
        category_id = candidates[0]
        method = "cwe_rule"
        category_name = OWASP_CATEGORIES[category_id]
    elif len(candidates) > 1:
        category_id = UNMAPPED_CATEGORY_ID
        method = "ambiguous_cwe_mapping"
        category_name = UNMAPPED_CATEGORY_NAME
    else:
        category_id = UNMAPPED_CATEGORY_ID
        method = "no_supported_cwe_mapping"
        category_name = UNMAPPED_CATEGORY_NAME

    return {
        "taxonomy_version": OWASP_TAXONOMY_VERSION,
        "category_id": category_id,
        "category_name": category_name,
        "mapping_method": method,
        "matched_cwe_ids": matched,
        "unmapped_cwe_ids": unmapped,
        "candidate_category_ids": candidates,
    }


def _priority(
    classification: str,
    severity: str,
    context: Mapping[str, Any],
    source_status: str,
) -> tuple[str, str]:
    active_statuses = {
        "detected", "triaged", "confirmed",
        "remediating", "fixed_pending_retest",
    }

    if (
        classification not in {"confirmed_vulnerability", "potential_vulnerability"}
        or source_status not in active_statuses
    ):
        return "UNASSESSED", "not_applicable"

    if severity == "unknown":
        return "UNASSESSED", "unknown_severity"

    if context["known_exploited"] is True and severity in {"critical", "high"}:
        return "P1", "known_exploited"

    if (
        classification == "confirmed_vulnerability"
        and severity == "critical"
        and context["internet_exposed"] is True
    ):
        return "P1", "confirmed_critical_internet_exposed"

    if severity == "critical":
        return "P2", "critical_severity"

    if severity == "high" and (
        context["internet_exposed"] is True
        or context["asset_criticality"] in {"critical", "high"}
        or context["sensitive_data"] is True
    ):
        return "P2", "high_severity_contextual"

    if severity in {"high", "medium"}:
        return "P3", "severity_only"

    return "P4", "low_severity"


def classify_finding(
    finding: Mapping[str, Any],
    *,
    asset_context: Mapping[str, Any] | None = None,
    assessed_at: datetime | str | None = None,
    assessment_id: str | None = None,
) -> dict[str, Any]:
    """Return an explainable triage assessment for an existing finding.

    Source confidence is preserved but never proves vulnerability confirmation.
    This helper cannot verify a digest against stored evidence bytes, so even a
    source status of "confirmed" remains unverified by this classifier.
    """
    (
        finding_id, status, confidence, evidence_refs,
        cwe_ids, has_hash_metadata, cvss_score,
    ) = _validate_finding(finding)

    timestamp = _aware_utc(assessed_at)
    context = _normalise_context(asset_context)
    reported_severity = finding["severity"]

    if status == "false_positive":
        classification = "false_positive"
    elif status == "accepted_risk":
        classification = "accepted_risk"
    elif status == "confirmed" and (evidence_refs or cwe_ids):
        # A hash-shaped value is not proof that stored evidence was verified.
        classification = "potential_vulnerability"
    elif status == "confirmed":
        classification = "insufficient_evidence"
    elif evidence_refs or cwe_ids:
        classification = "potential_vulnerability"
    else:
        classification = "security_observation"

    if has_hash_metadata:
        evidence_quality = "hash_present_unverified"
    elif evidence_refs:
        evidence_quality = "referenced_unhashed"
    elif cwe_ids:
        evidence_quality = "taxonomy_only"
    else:
        evidence_quality = "none"

    severity = _severity_assessment(reported_severity, cvss_score)
    owasp = _owasp_assessment(cwe_ids)
    priority, priority_basis = _priority(
        classification, severity["value"], context, status
    )

    reasons: list[str] = []

    if classification == "potential_vulnerability":
        reasons.append("finding_not_evidence_confirmed")
    elif classification == "insufficient_evidence":
        reasons.append("insufficient_evidence")
    elif classification == "security_observation":
        reasons.append("observation_only")
    elif classification in {"false_positive", "accepted_risk"}:
        reasons.append("disposition_requires_review")

    if has_hash_metadata:
        # This module checks syntax only. A separate trusted component must
        # compare the digest with the stored evidence bytes.
        reasons.append("evidence_hash_not_verified")
    elif evidence_refs and classification not in {"false_positive", "accepted_risk"}:
        reasons.append("evidence_integrity_not_proven")

    if not cwe_ids:
        reasons.append("no_cwe_ids_supplied")
    else:
        if owasp["mapping_method"] == "no_supported_cwe_mapping":
            reasons.append("no_supported_cwe_mapping")
        elif owasp["mapping_method"] == "ambiguous_cwe_mapping":
            reasons.append("multiple_owasp_categories")
        if owasp["unmapped_cwe_ids"]:
            reasons.append("some_cwe_ids_unmapped")

    if severity["conflict"]:
        reasons.append("cvss_severity_mismatch")

    if severity["value"] == "unknown":
        reasons.append("severity_unknown")

    if severity["value"] in {"critical", "high"} and priority != "UNASSESSED":
        context_complete = (
            context["internet_exposed"] is not None
            and context["known_exploited"] is not None
            and context["asset_criticality"] != "unknown"
            and context["sensitive_data"] is not None
        )
        if not context_complete:
            reasons.append("risk_context_incomplete")

    reasons = sorted(set(reasons))
    needs_review = bool(reasons)

    if assessment_id is None:
        identity = hashlib.sha256(
            f"{finding_id}|{timestamp}".encode("utf-8")
        ).hexdigest()[:24]
        assessment_id = f"risk-{identity}"

    if (
        not isinstance(assessment_id, str)
        or not assessment_id.strip()
        or len(assessment_id) > 128
    ):
        raise RiskClassificationError(
            "assessment_id must be a non-empty string of at most 128 characters"
        )

    if owasp["mapping_method"] == "cwe_rule":
        category_reason = (
            f"OWASP Top 10:2025 category {owasp['category_id']} "
            f"({owasp['category_name']}) was mapped from "
            f"{', '.join(owasp['matched_cwe_ids'])}."
        )
    else:
        category_reason = (
            "OWASP Top 10:2025 category could not be assigned unambiguously "
            "from the supplied CWE identifiers."
        )

    if severity["basis"] == "cvss_v4_0":
        severity_reason = (
            f"Severity {severity['value']} was mapped from the supplied "
            f"CVSS v4.0 score {severity['cvss_v4_score']:.1f}; "
            "no score was calculated."
        )
    elif severity["basis"] == "source_reported":
        severity_reason = (
            f"Severity {severity['value']} was preserved from the source "
            "finding because no CVSS v4.0 score was supplied."
        )
    else:
        severity_reason = (
            "Severity remains unknown because neither a known source severity "
            "nor a CVSS v4.0 score was available."
        )

    if classification == "confirmed_vulnerability":
        classification_reason = (
            "The source status is confirmed and a SHA-256-shaped value is "
            "supplied; this helper has not verified it against stored evidence "
            "bytes and does not independently establish the finding's truth."
        )
    elif classification == "potential_vulnerability":
        classification_reason = (
            "Evidence references or CWE identifiers exist, but this helper "
            "does not independently verify the evidence bytes or establish "
            "that the finding is true."
        )
    elif classification == "insufficient_evidence":
        classification_reason = (
            "The source labels the finding confirmed, but no evidence reference "
            "or CWE identifier was supplied; analyst validation is required."
        )
    elif classification == "security_observation":
        classification_reason = (
            "No evidence reference or CWE identifier was supplied; this remains "
            "an observation, not a confirmed vulnerability."
        )
    elif classification == "false_positive":
        classification_reason = (
            "The source disposition is false_positive; this helper preserves "
            "that disposition but does not independently validate it."
        )
    else:
        classification_reason = (
            "The source disposition is accepted_risk; approval and expiry must "
            "be validated by the risk-governance process."
        )

    if priority == "P1":
        priority_reason = f"Priority P1 follows the explicit rule {priority_basis}."
    elif priority == "P2":
        priority_reason = f"Priority P2 follows the explicit rule {priority_basis}."
    elif priority == "P3":
        priority_reason = (
            "Priority P3 follows the severity-only triage rule; "
            "the organization should apply its approved SLA."
        )
    elif priority == "P4":
        priority_reason = (
            "Priority P4 follows the low/info severity triage rule; "
            "this is not a substitute for business-owner review."
        )
    else:
        priority_reason = (
            "No active remediation priority was assigned because the finding "
            "is a disposition/observation, outside active triage, or severity is unknown."
        )

    rationale = " ".join(
        (classification_reason, category_reason, severity_reason, priority_reason)
    )
    if len(rationale) > 3000:
        rationale = rationale[:2997] + "..."

    return {
        "schema_version": "1.0",
        "assessment_id": assessment_id,
        "finding_id": finding_id,
        "source_status": status,
        "assessed_at": timestamp,
        "source_confidence": confidence,
        "classification": classification,
        "evidence_quality": evidence_quality,
        "owasp": owasp,
        "severity": severity,
        "priority": priority,
        "priority_basis": priority_basis,
        "context": context,
        "needs_analyst_review": needs_review,
        "review_reasons": reasons,
        "rationale": rationale,
    }