# Roadmap proposée — 12 semaines

## S1–S2 — Fondations

- P1 : périmètre, règles d'engagement, format de finding et méthode de retest.
- P2 : sources de télémétrie, schéma événement et premières fixtures normalisées.
- P3 : modèle de domaine, stratégie d'authentification, RBAC et contrats API.
- P4 : modèle de menace, CI, security gates et registre des actifs.
- **Jalon :** contrats approuvés et validés automatiquement.

## S3–S5 — Capacités initiales

- P1 : première chaîne de résultats de test autorisé et preuve expurgée.
- P2 : ingestion de données d'exemple puis connecteurs Wazuh/Suricata.
- P3 : Security API, authz, isolation tenant et audit de base.
- P4 : CI/SAST/SCA/secrets et orchestrateur d'évaluation hors production en premier.
- **Jalon :** les modules fonctionnent indépendamment et leurs contrats sont testés.

## S6–S8 — Intégration

- Corrélation, déduplication et contexte actif.
- Workflow de vulnérabilité, affectation, remédiation et retest.
- Premiers playbooks avec approbation humaine et mode simulation.
- RAG à sources approuvées avec contrôles d'accès.
- **Jalon :** findings et événements alimentent le même workflow central.

## S9–S10 — Résilience et sécurité adversariale

- Tests d'accès croisés tenant/actif, concurrence, reprise et idempotence.
- Tests de perte de logs, déduplication, faux positifs et limites des capteurs.
- Tests RAG : injections, données non fiables et fuite inter-tenant.
- **Jalon :** scénarios de panne et résultats négatifs documentés.

## S11–S12 — Validation

- Scénario complet : observation/finding, triage, correction, retest et clôture.
- Rapports techniques et exécutifs, installation et risques résiduels.
- Démonstration reproductible sur des données fictives ou un périmètre explicitement autorisé.
- **Jalon :** démonstration de bout en bout et soutenance.

Les dates et métriques exactes doivent être fixées par l'équipe. Ne déclarez jamais un taux de détection/couverture sans un jeu de tests et une mesure reproductibles.
