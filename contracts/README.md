# Contrats d'intégration

Les contrats sont la frontière stable entre les équipes. Ils décrivent les données échangées, pas l'implémentation interne d'un module.

## Répertoires

- `json-schema/` : schémas JSON Draft 2020-12.
- `examples/` : payloads fictifs utilisés par la validation CI. Ils ne constituent ni des preuves ni une autorisation d'évaluation.
- `openapi/` : contrat HTTP proposé pour la Security API.

## Règles de conception

- `schema_version` identifie la version du schéma de données.
- Les identifiants sont stables et opaques ; évitez d'y encoder des informations sensibles.
- Gardez la provenance (`source`, timestamp, IDs de corrélation) et séparez les observations des conclusions.
- Les preuves sensibles devraient être stockées dans un espace protégé. Le contrat conserve des références et des métadonnées, pas des dumps bruts.
- Ne faites pas confiance aux identifiants d'actif, de tenant ou aux scores fournis par un producteur avant validation côté serveur.
- Toute modification incompatible exige une nouvelle stratégie de version et une mise à jour des tests de contrat.

## Valider

```powershell
python -m pip install -r requirements-dev.txt
python scripts/validate_contracts.py
```
