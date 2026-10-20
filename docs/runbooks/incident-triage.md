# Runbook — triage d'un incident web

1. **Confirmer le contexte** : vérifier l'identifiant incident, le tenant, les actifs concernés et leur criticité.
2. **Préserver les éléments** : récupérer les références d'événements/preuves avec les permissions adaptées ; éviter de copier des secrets dans les notes.
3. **Reconstituer la chronologie** : normaliser les timestamps, identifier les sources présentes/absentes et marquer les lacunes de visibilité.
4. **Évaluer la confiance** : séparer événements observés, hypothèses et conclusions ; documenter les faux positifs possibles.
5. **Vérifier le périmètre** : confirmer qu'une éventuelle action touche seulement les actifs approuvés.
6. **Choisir le playbook** : appliquer les préconditions, l'approbation et le niveau de risque prévus.
7. **Exécuter ou escalader** : toute action ayant un impact de production doit respecter les approbations de l'organisation ; commencer par un dry-run lorsque possible.
8. **Vérifier le résultat** : consigner statut, erreurs, horodatage, opérateur, corrélation et preuve de résultat.
9. **Remédier et retester** : créer une tâche assignée et ne clôturer qu'après validation documentée.
10. **Améliorer** : enregistrer les lacunes de détection et les tests de non-régression.

Ce runbook est un modèle pédagogique ; adaptez-le à votre procédure d'urgence réelle avant toute utilisation opérationnelle.
