# P4 — CI Security Baseline

## Purpose

This document describes automated security checks for the WebShield
platform repository. These checks complement the contract-validation
workflow and do not scan external company websites.

## Security gates

| Gate | Tool | Scope |
|---|---|---|
| Secret scanning | Gitleaks | Git history |
| Static analysis (SAST) | Semgrep CE | Supported source files and configured rules |
| Software composition analysis (SCA) | pip-audit | Python dependencies in requirements-dev.txt |
| Contract validation | Existing GitHub Actions workflow | JSON schemas and example payloads |

## Triggers

The P4 workflow runs on configured pushes, pull requests, manual dispatch,
and a weekly schedule.

## Handling failures

### Secret detection

Investigate any finding. If a real credential is exposed, revoke or rotate
it first, then investigate the exposure. Removing the text from the latest
file does not invalidate the credential or remove it from Git history.

### Static analysis

Review the rule, code location, severity, confidence, and execution path.
Fix confirmed weaknesses or document an approved, time-limited exception.

### Dependency audit

Identify the affected package and dependency path. Update to a safe
compatible version or document an approved mitigation.

### Contract validation

Update the schema, examples, and producer/consumer tests together.
Do not bypass validation to make CI pass.

## Limitations

- SAST coverage depends on supported languages and configured rules.
- SCA currently audits Python development dependencies only.
- Go, JavaScript, container, and infrastructure checks must be added
  when their manifests and artifacts are introduced.
- A clean scan does not prove that an application is secure.
- External scans require explicit authorization, approved targets,
  exclusions, rate limits, and execution windows.

## Local verification

Run contract validation with:

    .venv\Scripts\python.exe scripts\validate_contracts.py

Review workflow results under the repository's GitHub Actions tab.
