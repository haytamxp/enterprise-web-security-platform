# P3 — Platform Backend & Response

## Mission
Posséder le plan de contrôle : Security API, identité/permissions, isolation des tenants, gestion des actifs/findings/incidents, remédiation, orchestration et audit.

## Responsabilités
- Implémenter et documenter les endpoints de `contracts/openapi/openapi.yaml`.
- Authentifier utilisateurs et connecteurs ; appliquer les permissions côté serveur sur chaque objet.
- Refuser par défaut les opérations non autorisées ; valider l'appartenance tenant/actif.
- Gérer pagination, limites de taille/débit, erreurs, idempotence et conflits concurrents.
- Enregistrer décisions, approbations, résultats d'action et transitions d'état.
- Fournir tests positifs/négatifs, contrat et reprise après panne.

## Critères d'acceptation
Un utilisateur d'un tenant ne peut consulter/modifier aucune ressource d'un autre tenant en changeant un identifiant. Les actions sensibles ont un périmètre, une approbation conforme à la politique, une clé d'idempotence et une trace d'audit.

## Current Backend Implementation Status

The backend currently provides:

- Human login using bcrypt password verification and JWT Bearer authentication.
- Tenant-aware user identity in verified JWT claims.
- A current-user endpoint returning the user ID, tenant ID, and role.
- RBAC policy definitions and authorization middleware for `admin`, `analyst`, `responder`, and `viewer`.
- Tenant-scoped machine connectors authenticated through `X-Connector-Key`.
- Connector scopes for event ingestion and incident creation.
- Connector key hashing, optional expiration, and revocation.
- Tenant-aware event and incident persistence with transactional event associations.

### Authentication Boundaries

- `POST /api/v1/auth/login`: public human-user login.
- `GET /api/v1/auth/me`: protected by human Bearer JWT.
- `POST /api/v1/events`: connector key with `events:ingest`.
- `POST /api/v1/incidents`: connector key with `incidents:create`.

The RBAC policy middleware is implemented and tested. Planned resource endpoints must apply the appropriate permission middleware and tenant ownership checks when implemented.

The shared HTTP contract is `contracts/openapi/openapi.yaml`.

### Remaining Scope

Asset and finding management, incident read and update workflows, remediation, response orchestration, and audit modules remain separate implementation work. Their presence in the architecture or OpenAPI contract does not mean their handlers are already available.
