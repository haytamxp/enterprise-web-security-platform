# Tests de contrat

La validation de base utilise `scripts/validate_contracts.py`. À mesure que l'API et les connecteurs seront implémentés, ajouter des tests contractuels dans les deux sens : exemple émis par chaque producteur et exemple accepté/rejeté par chaque consommateur.

Cas négatifs obligatoires à ajouter : champ requis absent, champ inconnu, format d'horodatage invalide, confiance hors plage, actif appartenant à un autre tenant, doublon rejoué et champ de sévérité fourni sans provenance de confiance.
