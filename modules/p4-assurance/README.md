# P4 — DevSecOps & AppSec Assurance

## Mission
Rendre la sécurité reproductible dans la chaîne logicielle et développer l'assurance automatisée des actifs web déjà existants.

## Responsabilités
- CI avec security gates, SAST, SCA, secret scanning et validation de contrats.
- Scans de conteneurs/IaC et SBOM lorsque ces artefacts sont introduits.
- Orchestrateur de scans externes avec contrôle de périmètre, fenêtre et débit.
- Modèle de risque fondé sur les preuves, les référentiels et le contexte métier.
- Threat modeling et tests adversariaux de la plateforme et du RAG en coopération avec P2/P3.

## Distinction
Les dépôts source de WebShield peuvent être soumis au SAST ; les sites externes de l'entreprise ne le sont pas automatiquement. Sans accès au code source, les évaluations externes utilisent les contrôles dynamiques et de configuration adaptés et autorisés.

## Critères d'acceptation
Aucun scan ne démarre sans vérification de périmètre et de l'autorisation active. Les findings automatiques distinguent une observation, un risque potentiel et une vulnérabilité confirmée.

## Scan-scope policy evaluator

`scan_scope.py` provides a pure, fail-closed policy function for future
scan-request orchestration. It checks tenant and asset identity, approved
status, approval metadata, expiry, allowlisted origins and path scope, and
exclusions. Unit tests are in `tests/security/test_scan_scope.py`.

The policy does not start scans, authenticate users, resolve DNS, police
redirects, or apply network egress restrictions. Those controls must be
implemented at integration and execution boundaries before active scanning
is enabled. See `docs/security/scan-scope-policy.md`.
## P4-04 — Controlled scan orchestration

`scan_orchestrator.py` adds tenant-scoped scan-job admission, idempotency, scheduling/execution rate limits, execution-window checks, current-scope revalidation, short-lived worker leases, retry bounds, completion transitions, and audit events. The default profile allowlist is `passive` and `web_baseline`; this module contains no network client and starts no scan. See `docs/security/scan-orchestration.md` for deployment limitations and the worker integration boundary.

## P4-05 — Evidence-Based OWASP Risk Classification

`risk_classifier.py` produces an explainable triage assessment from an existing finding: curated CWE-to-OWASP Top 10:2025 mapping, evidence-aware source-status classification, CVSS v4.0 qualitative severity mapping when a score is supplied, priority rules, and analyst-review reasons. It never calculates CVSS. Evidence hashes are not verified by this module; see `docs/security/risk-classification.md` for rules and limitations.
