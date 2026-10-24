# P4-05 — Evidence-Based OWASP Risk Classification

## Objective

Produce a deterministic and explainable triage assessment from an existing WebShield finding. This component does not execute scans, independently prove a real-world vulnerability, calculate CVSS, or replace analyst decisions.

## Data flow

1. A finding that conforms to the shared finding schema is passed to `classify_finding`.
2. Exact CWE identifiers are looked up in a curated OWASP Top 10:2025 mapping table. The classifier does not guess categories from titles or descriptions.
3. Evidence references and SHA-256-shaped metadata are examined. A source status of `confirmed` plus supplied hash metadata is preserved as `confirmed_vulnerability`; however, this helper cannot load evidence bytes or verify that a digest matches them. It emits `evidence_hash_not_verified` and requests analyst review.
4. A supplied CVSS v4.0 score is mapped to a qualitative severity band. No score is calculated. If CVSS is missing, the source-reported severity is preserved.
5. Rule-based P1–P4 priority is assigned only to active vulnerability classifications. Missing or ambiguous mapping, weak evidence, severity conflicts, and incomplete context create review reasons.

## Classification semantics

| Classification | Rule | Interpretation |
|---|---|---|
| `confirmed_vulnerability` | Reserved for a trusted evidence-verification integration | This helper does not emit this classification because it does not verify stored evidence bytes |
| `potential_vulnerability` | Evidence references or CWE identifiers exist, but the source-confirmation rule is not met | Requires analyst validation |
| `security_observation` | No evidence reference and no CWE identifier supplied, and source status is not `confirmed` | Observation only; do not report as a confirmed vulnerability |
| `insufficient_evidence` | Source status says `confirmed`, but no evidence reference or CWE identifier was supplied | Requires review |
| `false_positive` | Source status is `false_positive` | Preserves the source disposition; this helper does not independently validate it |
| `accepted_risk` | Source status is `accepted_risk` | Approval and expiry require the risk-governance process |

Even when the source status is `confirmed` and a SHA-256-shaped value is present, this helper emits `potential_vulnerability` because it does not retrieve and hash the stored evidence bytes. A trusted evidence-verification integration and analyst confirmation are required before a separate component should classify the vulnerability as confirmed.

A P1–P4 priority is only emitted for active triage statuses (`detected`, `triaged`, `confirmed`, `remediating`, or `fixed_pending_retest`). Records in `false_positive`, `accepted_risk`, `retest_passed`, or `closed` status receive `UNASSESSED`.

`source_confidence` is preserved for reviewers but never upgrades an observation into a confirmed vulnerability.

## OWASP Top 10:2025 mapping

The category labels follow the [official OWASP Top 10:2025](https://top10.owasp.org/2025/0x00_2025-Introduction/). The mapping table in `risk_classifier.py` is a curated subset, not an exhaustive or official CWE-to-OWASP mapping. It uses exact CWE identifiers. Unsupported CWE identifiers remain unmapped. If supplied CWE identifiers resolve to more than one category, the result is `UNMAPPED` with `ambiguous_cwe_mapping`. Do not arbitrarily select one category. Multiple separate issues should normally be represented as separate findings.

## Severity and CVSS

CVSS v4.0 qualitative severity bands follow the [FIRST CVSS v4.0 specification](https://www.first.org/cvss/v4.0/specification-document): 0.0 is None; 0.1–3.9 Low; 4.0–6.9 Medium; 7.0–8.9 High; and 9.0–10.0 Critical. The current finding contract lacks a separate `none` severity, so a supplied score of 0.0 is represented as `info`. These are qualitative mappings of a supplied score, not a CVSS calculator.

If the score-derived severity differs from the source-reported severity, the result requires analyst review.

## Priority rules

- `P1`: a known-exploited context is explicitly true for a high/critical finding, or a confirmed critical vulnerability is explicitly internet-exposed.
- `P2`: critical severity, or high severity with at least one explicit contextual indicator (internet exposure, critical/high asset criticality, or sensitive data).
- `P3`: high/medium severity when the P1/P2 rules do not apply.
- `P4`: low/info severity.
- `UNASSESSED`: observations, dispositions, inactive statuses, or unknown severity.

These are project triage rules, not universal service-level objectives. Asset context must come from a trusted inventory or reviewed source. Missing boolean context is `null`, not `false`. High/critical assessments with incomplete context require review even when a provisional priority is assigned. Organizations must map P1–P4 to approved remediation SLAs before operational use.

## Evidence-integrity boundary

The module validates that a provided digest has 64 hexadecimal characters. It does not retrieve evidence, hash the evidence bytes, compare the calculated digest with the stored digest, or prove that an evidence object has not been replaced. Therefore, `hash_present_unverified` is intentionally not called `integrity_bound`, and `needs_analyst_review` remains true until an appropriate trusted integration validates the evidence hash and the finding is reviewed.

## Limitations and production requirements

- This is a transparent rules engine, not an AI model or vulnerability scanner.
- CWE mappings are deliberately incomplete. Add mappings only when reviewed, documented, and tested.
- Validate input findings against their shared JSON Schema before calling this helper.
- Asset context and exploitation intelligence must come from authenticated, traceable, timestamped sources.
- Preserve the original finding unchanged. Store the returned assessment as a separate record with access controls and audit history.
- Do not treat a CWE match, source confidence, or hash-shaped string as proof that a vulnerability exists.

## Local verification (PowerShell)

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests/security -p "test_*.py" -v
.venv\Scripts\python.exe scripts/validate_contracts.py