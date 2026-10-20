# ADR-0001 — Monorepo et contrats partagés

- **Statut :** proposé, à approuver par les quatre membres.
- **Date :** 2026-10-20

## Contexte

Quatre étudiants développent des modules étroitement liés et doivent intégrer des données structurées sans dépendre de l'implémentation interne de chaque équipe.

## Décision proposée

Démarrer avec un monorepo contenant `backend/`, `frontend/`, `modules/`, `integrations/`, `contracts/`, `database/`, `deploy/`, `docs/` et `.github/`. Les contrats sont versionnés et validés en CI. Chaque dossier a un propriétaire principal, mais les contrats sont partagés.

## Conséquences positives

- Une seule source pour les schémas et la documentation.
- Revue inter-équipes plus simple.
- Tests de contrat et intégration dans une CI commune.
- Historique cohérent des changements d'interface.

## Coûts et risques

- Risque de conflits si les propriétaires modifient les mêmes dossiers sans coordination.
- La CI peut devenir lente ; les jobs devront être séparés par composant lorsque le code grandira.
- Un monorepo ne signifie pas que les modules peuvent se coupler directement ou partager toutes les tables SQL.

## Alternatives

- Un dépôt par équipe : isolation plus nette, mais intégration, versions des contrats et configuration CI plus difficiles.
- Microservices dès le début : séparation opérationnelle plus forte, mais coûts de déploiement et de débogage disproportionnés avant validation des contrats.

## À revoir lorsque

L'équipe atteint des besoins indépendants de livraison, des frontières de données bien établies ou une charge qui justifie des déploiements séparés.
