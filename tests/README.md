# Tests

Les tests sont organisés par couche :

- **Contrat** : JSON Schema, payloads, OpenAPI, compatibilité producteur/consommateur.
- **Unitaire** : règles de scoring, déduplication, transitions d'état, validations.
- **Intégration** : API, base, connecteurs et stockage des références de preuve.
- **Sécurité** : séparation inter-tenant, RBAC, limites de débit, idempotence, autorisation des actions.
- **Résilience** : duplication, interruption du worker, timeout, file indisponible et reprise.
- **RAG** : qualité des sources, prompt injection, filtrage tenant/permission et citation de sources.

Les fixtures doivent rester synthétiques et ne pas contenir de données réelles de l'entreprise.
