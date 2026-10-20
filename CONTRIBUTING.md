# Contribuer au projet

## Workflow Git

- Branche stable : `main`.
- Une branche par sujet : `feature/<sujet>`, `fix/<sujet>`, `docs/<sujet>` ou `security/<sujet>`.
- Ne poussez pas directement sur `main` une fois la protection de branche activée.
- Ouvrez une pull request (PR), décrivez le risque et le test exécuté, et demandez une revue au propriétaire du module.
- Gardez les PR petites et atomiques. Les changements de contrats doivent être coordonnés avec P1–P4.

## Convention de commit proposée

Utilisez des messages explicites, par exemple :

- `feat(contracts): add incident schema`
- `fix(api): enforce tenant authorization`
- `test(detection): cover duplicate event handling`
- `docs(security): clarify scan authorization`

## Contrat obligatoire pour une modification de données

1. Modifier le JSON Schema concerné.
2. Mettre à jour les fixtures d'exemple.
3. Exécuter `python scripts/validate_contracts.py`.
4. Documenter la compatibilité, la provenance et les implications de sécurité.
5. Ajouter ou mettre à jour des tests côté producteur et consommateur.

## Définition de terminé

Une tâche est terminée quand le code et les tests sont revus, les erreurs sont gérées, les permissions et données sensibles sont vérifiées, la documentation est mise à jour et la CI réussit. Voir [`docs/process/definition-of-done.md`](docs/process/definition-of-done.md).

## Politique de sécurité

Ne publiez pas de secrets, d'exploits réutilisables contre une cible réelle, ni de preuves contenant des données personnelles. Pour signaler une vulnérabilité dans la plateforme, suivez `SECURITY.md` et évitez de publier les détails dans une issue publique.
