# Politique de sécurité

## Versions concernées

Pendant la phase de développement, seule la branche `main` est considérée comme la base d'intégration. Aucune garantie de support ou de SLA n'est fournie pour le scaffolding.

## Signaler une vulnérabilité

**Avant toute publication publique, remplacez les instructions ci-dessous par un canal réellement surveillé.** Utilisez de préférence la fonction *Private vulnerability reporting* de GitHub si elle est disponible dans les paramètres du dépôt, ou contactez directement les mainteneurs via un canal privé convenu par l'équipe. Ne mettez pas les détails d'une vulnérabilité exploitable dans une issue publique.

Lors du rapport, incluez : composant/version, impact, préconditions, étapes de reproduction minimales dans un environnement autorisé, preuve expurgée et suggestion éventuelle de mitigation. N'incluez aucun secret, donnée réelle de client ou preuve de production non autorisée.

## Principes de sécurité du projet

- Moindre privilège et vérification des autorisations côté serveur.
- Isolation stricte des tenants et des actifs.
- Secret management hors du dépôt.
- Audit des actions sensibles et approbations pour les actions à impact élevé.
- Tests uniquement sur les actifs explicitement autorisés.
- Validation des données non fiables et protection contre l'injection de prompt dans les flux RAG.
