# P1 — Offensive Security

## Mission
Évaluer uniquement les actifs dont le périmètre et l'autorisation écrite sont valides, confirmer les faiblesses et produire des findings reproductibles.

## Responsabilités
- Inventaire de surface d'attaque lié à `asset_id`.
- Règles d'engagement, plan de tests et exclusions.
- Tests autorisés, validation manuelle, expurgation et gestion de preuves.
- Export conforme à `contracts/json-schema/finding.schema.json`.
- Retest et documentation du résultat.

## Ne pas faire
- Scanner une cible uniquement parce qu'elle figure dans un nom de domaine ou dans un ticket.
- Stocker des cookies, tokens ou données personnelles dans le dépôt.
- Conclure qu'une vulnérabilité est confirmée sur la seule sortie d'un scanner.

## Critères d'acceptation
Chaque finding doit indiquer l'actif autorisé, la méthode, la provenance, une preuve minimale expurgée, la confiance, la sévérité justifiée, la remédiation et le statut du retest.
