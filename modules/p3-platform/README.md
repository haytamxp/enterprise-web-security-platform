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
