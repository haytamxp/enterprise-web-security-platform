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
