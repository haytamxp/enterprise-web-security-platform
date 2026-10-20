# Modèle de menace initial — STRIDE

## Actifs à protéger

- Identités, sessions, rôles et appartenance aux tenants.
- Inventaire des applications et décisions d'autorisation de test.
- Événements bruts, findings, preuves, rapports et données de remédiation.
- Connecteurs et identités de service Wazuh/Suricata/scanners.
- Playbooks, demandes d'action et journaux d'audit.
- Sources documentaires, prompts, embeddings, résultats et données RAG.
- Secrets CI/CD, artefacts, images et configuration d'infrastructure.

## Scénarios STRIDE de départ

| Catégorie | Scénario | Contrôles attendus |
|---|---|---|
| Spoofing | Un faux connecteur soumet des événements comme s'ils venaient de Wazuh | Identité de service, clés gérées hors du code, rotation, provenance vérifiée |
| Tampering | Un client modifie `tenant_id`, `severity` ou `asset_id` dans un POST | Autorité côté serveur, validation de propriété, schéma strict, journaux d'audit |
| Repudiation | Un opérateur nie avoir lancé une action de confinement | Audit append-only/protégé, identité, horodatage, ID de corrélation et résultat |
| Information disclosure | Un utilisateur d'un tenant lit une preuve d'un autre tenant | Autorisation par objet, contrôle sur les références de stockage, tests inter-tenant |
| Denial of service | Un flux d'événements ou un scanner génère un volume excessif | Quotas, limites de taille/débit, files bornées, backpressure et arrêt d'urgence |
| Elevation of privilege | Un développeur appelle un endpoint réservé à un analyste/admin | RBAC/permissions côté serveur, refus par défaut, tests négatifs |

## Risques propres aux scans externes

Le registre d'actifs peut contenir une cible erronée, des exclusions incomplètes ou une autorisation expirée. L'orchestrateur doit revalider le périmètre juste avant chaque exécution ; une simple valeur fournie par le navigateur ne suffit pas.

## Risques du RAG/LLM

Les documents ingérés sont des données non fiables, même s'ils semblent provenir de documentation. Séparer données et instructions, filtrer les documents par tenant et permissions, traiter les réponses comme des recommandations, afficher les sources, et exiger une autorisation non-LLM pour toute action sensible.

## Plan de validation

- Tests d'accès inter-tenant pour chaque ressource et référence de preuve.
- Tests de falsification de champs du producteur et d'événement dupliqué.
- Tests de reprise, de limites de débit et de files saturées.
- Tests d'approbation, d'idempotence et de refus pour les actions sensibles.
- Tests d'injection de prompt directe/indirecte et de fuite inter-tenant.
- Revue des secrets, permissions CI et privilèges des conteneurs.

Ce document est initial et doit être mis à jour avec les diagrammes détaillés, hypothèses, responsables, vraisemblance, impact et décisions de traitement du risque.
