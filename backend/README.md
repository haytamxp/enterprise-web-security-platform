# Backend — Security API (P3)

Ce dossier accueillera l'API de contrôle, la logique métier, les adaptateurs de stockage et les tests. La technologie Go et PostgreSQL est proposée, mais la version du langage, la structure de packages et le schéma physique doivent être approuvés dans un ADR avant implémentation.

Découpage fonctionnel recommandé :

- `cmd/api/` — point d'entrée du serveur.
- `internal/auth/` — authentification et autorisation.
- `internal/assets/` — registre d'actifs et statut d'autorisation.
- `internal/findings/` — import, déduplication et cycle de vie.
- `internal/events/` — ingestion idempotente.
- `internal/incidents/` — corrélation référencée, affectation et workflow.
- `internal/remediation/` — tâches et validation.
- `internal/audit/` — traces d'opérations sensibles.
- `migrations/` — migrations de base de données.

N'exposez jamais de preuves brutes à travers une référence d'évidence sans une vérification d'autorisation dédiée.

## Current Backend Capabilities

- Human authentication with bcrypt password hashing and JWT Bearer tokens.
- `POST /api/v1/auth/login` and protected `GET /api/v1/auth/me`.
- Tenant identity included in verified user tokens.
- RBAC policy for `admin`, `analyst`, `responder`, and `viewer`.
- Machine-to-machine connector authentication through `X-Connector-Key`.
- Connector scopes: `events:ingest` and `incidents:create`.
- Tenant-scoped event and incident persistence.
- Transactional incident and event associations.
- Connector provisioning and revocation commands under `cmd/connector-create` and `cmd/connector-revoke`.

Ingestion endpoints accept connector credentials, not human JWTs. Connector API keys are stored as SHA-256 hashes. The raw key is returned only during creation.

The RBAC permission middleware and policy tests are implemented. Resource-specific user and asset endpoints remain planned.

## Validation

Run from the backend directory:

`go test -count=1 ./...`

`go vet ./...`

`git diff --check`

PostgreSQL integration tests use `TEST_DATABASE_URL` and must target the isolated `ewstrp_test` database.
