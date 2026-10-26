# P4 — CI Security Baseline

## Purpose

This document describes the automated security controls for the
Enterprise Web Security and Threat Response Platform repository.

These controls complement the contract-validation workflow. They
analyze repository content and declared dependencies; they do not
authorize or perform active scans against external company websites.

## Security controls

| Control | Tool | Scope |
|---|---|---|
| Secret scanning | Gitleaks | Git history |
| Static Application Security Testing (SAST) | Semgrep CE | Supported source files and configured rules |
| Software Composition Analysis (SCA) | pip-audit | Python dependencies in `requirements-dev.txt` |
| Software Bill of Materials (SBOM) | pip-audit / CycloneDX JSON | Resolved Python development dependencies |
| Dependency update monitoring | Dependabot | GitHub Actions and Python package definitions |
| Contract validation | Existing GitHub Actions workflow | JSON schemas and example payloads |

## Workflow triggers

The P4 workflow runs on configured pushes, pull requests, manual
dispatch, and a weekly schedule.

The Python dependency audit produces a CycloneDX JSON document in
addition to checking the dependency set for known vulnerabilities.
The workflow summarizes its component and vulnerability counts and
uploads the SBOM as a GitHub Actions artifact with a 14-day retention
period.

The SBOM-generation and upload steps run even if the audit step fails,
so a generated report can help investigate a failed security gate.

## SBOM scope and limitations

The current SBOM represents dependencies resolved from
`requirements-dev.txt`. It is **not** a complete inventory of the
platform's production software.

Until the corresponding manifests and deployment artifacts exist,
this workflow does not claim to cover:

- Go modules or production Go dependencies.
- Node.js packages or frontend production dependencies.
- Container images, operating-system packages, or image-layer contents.
- Terraform, Kubernetes manifests, Helm charts, or other infrastructure-as-code.
- The complete set of components running in a deployed environment.

When these assets are added, introduce ecosystem-specific dependency
audits, container scanning, infrastructure configuration scanning,
and appropriate SBOM generation. Prefer lockfiles and reproducible
dependency resolution for application builds.

## Dependency updates

Dependabot checks GitHub Actions and Python package definitions weekly.
It can propose update pull requests; each change still requires review
and appropriate CI validation. Do not assume that a newer version is
automatically safe or compatible.

## Handling failures

### Secret detection

Investigate every finding. If an actual credential is exposed, revoke
or rotate it first, then investigate the exposure. Deleting the text
from the latest file does not invalidate the credential or erase it
from Git history.

### Static analysis

Review the rule, location, severity, confidence, and execution context.
Fix confirmed weaknesses or document an approved, time-limited exception.

### Dependency audit

Identify the affected package and advisory. Upgrade to a fixed,
compatible version where possible, then rerun the audit and tests.
Review dependency provenance and avoid installing arbitrary replacement
packages to silence findings.

A dependency audit identifies known vulnerabilities in dependencies.
It does not prove that those vulnerabilities are exploitable in this
application, nor does a clean result prove that the application is secure.

### SBOM generation

Inspect the uploaded CycloneDX JSON artifact from the relevant Actions
run. If the artifact is missing, examine the generation and upload steps.
Do not present this development-dependency SBOM as a production inventory.

### Contract validation

Update schemas, examples, and producer/consumer tests together.
Do not bypass validation merely to make CI pass.

## Local verification

Run contract validation from the repository root:

    .venv\Scripts\python.exe scripts\validate_contracts.py

Review the security-gate results and SBOM artifact under the repository's
GitHub Actions tab.

## Authorized testing boundary

- Never commit tokens, passwords, private keys, session cookies, or
  unredacted client evidence.
- Example domains do not constitute authorization to test a real target.
- Active external scanning requires written authorization, approved
  targets, exclusions, rate limits, and execution windows.
- Do not trigger destructive response actions solely from an LLM output
  or an unvalidated detection rule.
