# P4-06 — Modèle de menace de la plateforme

**Statut :** modèle initial à revoir avec P1, P2, P3 et l'équipe infrastructure.
**Portée :** monorepo, CI/CD, API de contrôle, orchestration des scans,
données de sécurité, connecteurs et intégrations IA prévues.

## 1. Objectif et limites

Ce modèle identifie les actifs, frontières de confiance, scénarios de menace,
contrôles attendus et preuves de validation de la plateforme.

Les états doivent être distingués :
- **Implémenté et testé** : comportement exercé par des tests identifiés.
- **Partiel** : contrôle présent, mais intégration ou garantie supplémentaire absente.
- **Planifié** : exigence qui reste à implémenter.

Un contrôle documenté ne prouve pas son application. Les niveaux de risque
sont préliminaires : ils devront être revus avec le contexte métier, le
déploiement réel et les propriétaires d'actifs.

### État technique observé

- Le serveur Go actuel expose `GET /healthz`. Les autres routes décrites
  dans le contrat OpenAPI ne sont pas pour autant réputées implémentées.
- `scan_scope.py` vérifie la politique d'autorisation et le périmètre URL ;
  il ne résout pas le DNS, n'envoie aucune requête et ne contrôle pas les redirections.
- `scan_orchestrator.py` contrôle l'admission et le cycle de vie des jobs.
  Le stockage de référence et le limiteur de débit sont locaux au processus.
  Aucun scanner réseau n'est exécuté par ce module.
- `risk_classifier.py` ne récupère pas les octets d'une preuve et n'en vérifie
  pas lui-même l'empreinte cryptographique.
- Une authentification de production, un stockage d'audit durable, des
  connecteurs opérationnels et un pipeline RAG complet ne sont pas démontrés
  par les composants examinés.

## 2. Actifs à protéger

| ID | Actif | Propriétés attendues |
|---|---|---|
| A-01 | Identités, sessions, rôles et tenants | Confidentialité, intégrité, moindre privilège |
| A-02 | Inventaire, approbations et règles d'engagement | Intégrité, authenticité, fraîcheur |
| A-03 | Jobs, profils, leases et décisions de scope | Autorisation, intégrité, disponibilité |
| A-04 | Findings, incidents, événements et preuves | Confidentialité, intégrité, provenance |
| A-05 | Identités de service et connecteurs | Authenticité, rotation, révocation |
| A-06 | Actions sensibles et journal d'audit | Autorisation, traçabilité |
| A-07 | Documents RAG, prompts, embeddings et réponses | Isolation, provenance, résistance à l'injection |
| A-08 | Secrets, dépendances, workflows et artefacts CI/CD | Confidentialité, intégrité |
| A-09 | API, workers et files de traitement | Disponibilité, limitation des ressources |

Les preuves brutes peuvent contenir des informations internes ou des secrets.
Une référence de preuve ne doit jamais conférer automatiquement l'accès à
l'objet référencé.

## 3. Frontières de confiance

1. **Navigateur → API :** les identifiants d'objet, tenant, sévérité et permissions
   du client sont des entrées non fiables.
2. **Producteur → API :** vérifier l'identité du producteur, le schéma, les droits
   sur l'actif et la provenance de l'événement.
3. **API → stockage :** appliquer l'autorisation par objet et l'isolation tenant.
4. **Orchestrateur → worker :** vérifier le principal, le scope courant, le lease
   et les conditions d'exécution avant de fournir un permis.
5. **Worker → réseau externe :** contrôler les adresses résolues, les redirections
   et l'egress indépendamment de la validation URL.
6. **Documents → RAG/LLM :** traiter le contenu importé comme non fiable ; un
   modèle ne peut pas accorder de permission ni autoriser une action sensible.
7. **Dépôt → CI/CD → artefacts :** limiter les permissions, vérifier les
   dépendances et protéger les secrets.

## 4. Échelle de risque préliminaire

La vraisemblance (L) et l'impact (I) sont évalués de 1 à 5. Le score
indicatif est `L × I`. Ce score est une aide au triage, pas une mesure
statistique ni une décision d'acceptation du risque.

| Score | Niveau |
|---|---|
| 1–7 | Faible |
| 8–14 | Modéré |
| 15–19 | Élevé |
| 20–25 | Critique |

Les scores doivent être revus lorsque davantage d'informations sont
disponibles. La présence d'un test unitaire ne prouve pas la sécurité
de l'intégration ou du déploiement.

## 5. Registre initial des menaces

| ID | STRIDE / scénario | L×I | Niveau initial | Contrôle et état à vérifier | Propriétaire |
|---|---|---:|---|---|---|
| TM-01 | Un tenant lit ou modifie l'objet d'un autre tenant | 4×5 | Critique | Tests de scope P4 présents ; API métier avec autorisation par objet à vérifier | P3 |
| TM-02 | Une cible de scan contourne le périmètre via DNS ou redirection | 4×5 | Critique | Comparaison d'URL présente ; DNS, redirections et egress à intégrer | P4 + Infrastructure |
| TM-03 | Un utilisateur ou worker sans permission déclenche une opération | 3×5 | Élevé | Contrôles de permission dans l'orchestrateur ; authentification de production à vérifier | P3 |
| TM-04 | Un faux connecteur soumet un événement falsifié | 3×5 | Élevé | Contrats disponibles ; identité et provenance des connecteurs à intégrer | P2 + P3 |
| TM-05 | Une injection RAG provoque une fuite de données entre tenants | 4×4 | Élevé | Exigences documentées ; pipeline et tests d'isolation à construire | P2 + P3 |
| TM-06 | Un volume excessif sature jobs, workers ou API | 4×4 | Élevé | Limites locales et bornes de tentatives ; contrôle distribué et backpressure à intégrer | P3 + P4 |
| TM-07 | Une panne d'audit laisse une transition sensible non traçable | 3×4 | Modéré | Refus sur échec d'audit présent dans l'orchestrateur ; durabilité à construire | P3 |
| TM-08 | Une empreinte déclarée est confondue avec une preuve vérifiée | 3×5 | Élevé | Classificateur conservateur ; vérification des octets et du hash à intégrer | P4 + P3 |
| TM-09 | La répétition d'une requête crée des jobs ou actions incohérents | 3×4 | Modéré | Idempotence locale des jobs testée ; unicité durable et concurrence multi-instance à intégrer | P3 |
| TM-10 | Secret divulgué, dépendance vulnérable ou workflow trop privilégié | 3×5 | Élevé | Gitleaks, Semgrep et pip-audit présents ; couverture complète des artefacts à revoir | P4 |
| TM-11 | Une action de confinement est exécutée sans approbation valable | 3×5 | Élevé | Principes documentés ; workflow complet et audit à intégrer | P2 + P3 |
| TM-12 | Une URL ou un paramètre sensible fuit dans les journaux | 3×4 | Modéré | L'URL est omise des événements d'audit P4 ; tests à étendre | P4 |
| TM-13 | L'API de développement est exposée sans protections de production | 3×4 | Modéré | Timeouts HTTP et adresse locale par défaut ; TLS, proxy et contrôle réseau à définir | P3 + Infrastructure |

Les niveaux ci-dessus sont des estimations initiales et doivent être approuvés.
Ne pas déclarer un risque traité uniquement parce qu'une exigence est écrite.

## 6. Conditions préalables à tout scan réseau

Un worker de scan réseau ne doit pas être activé avant vérification de ces points :

- Autorisation écrite, actif et tenant corrects, exclusions et fenêtre valides.
- Vérification de chaque adresse DNS résolue ; blocage par défaut des adresses
  loopback, privées, link-local, réservées et métadonnées cloud, sauf exception
  explicitement approuvée et testée.
- Validation de chaque destination de redirection avant de la suivre.
- Egress réseau limité indépendamment du contrôle applicatif.
- Timeouts stricts, limite de redirections, quotas et arrêt d'urgence.
- Identité de worker authentifiée et privilèges minimaux.
- Stockage durable, unicité d'idempotence et transitions concurrentes sûres.
- Audit durable ou mécanisme transactionnel adapté.

## 7. Exigences transverses

### Identité et données

- Dériver le tenant d'une identité vérifiée, pas d'un champ contrôlé par le client.
- Autoriser chaque lecture et mutation au niveau de l'objet.
- Contrôler séparément l'accès aux références d'évidence.
- Conserver provenance, horodatage et identifiants de corrélation utiles.
- Ne pas confondre hash syntaxiquement valide, intégrité vérifiée et vulnérabilité confirmée.
- Ne pas écrire les URLs complètes ou paramètres secrets dans l'audit.

### RAG et actions automatisées

- Filtrer les documents par tenant et permissions avant de construire le contexte.
- Traiter les documents comme des données non fiables et conserver leur provenance.
- Le LLM peut recommander, mais ne peut pas autoriser une action sensible.
- Toute action doit passer par un contrôle déterministe côté serveur.

### CI/CD

- Appliquer le moindre privilège à chaque workflow et jeton.
- Épingler les actions externes et revoir leurs mises à jour.
- Conserver secret scanning, SAST, SCA et validation des contrats.
- Ajouter les tests de build des langages et les scans d'images/IaC lorsqu'ils s'appliquent.
- Protéger les secrets et artefacts ; éviter les permissions d'écriture inutiles.

## 8. Responsabilités et preuves attendues

| Équipe | Responsabilité | Preuve attendue |
|---|---|---|
| P1 | Tests offensifs autorisés, validation et preuves expurgées | Scope approuvé, rapports reproductibles, retest |
| P2 | Connecteurs, provenance, détection et RAG | Tests d'authenticité, duplication, injection et isolation |
| P3 | API, identité, RBAC, données, isolation et audit | Tests d'intégration et tests négatifs d'accès objet |
| P4 | CI, scope/orchestration, classification et assurance | Gates CI, tests déterministes, matrice de traçabilité |
| Infrastructure | TLS, DNS, egress, secrets et durabilité | Tests de configuration et de frontières réseau |

## 9. Revue obligatoire

Mettre à jour le modèle à chaque ajout d'endpoint, connecteur, worker,
stockage de preuve, intégration RAG ou action sensible. Le revoir aussi
après un incident ou un changement important de permissions.

Chaque menace élevée ou critique doit avoir un responsable, une décision
de traitement, une preuve vérifiable ou une tâche d'intégration explicite.
Toute exception doit être justifiée, approuvée et assortie d'une date de revue.