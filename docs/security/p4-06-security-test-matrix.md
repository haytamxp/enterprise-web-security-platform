# P4-06 — Matrice de traçabilité des tests de sécurité

## 1. Objectif et règle de preuve

Cette matrice relie les menaces de `threat-model.md` aux tests, contrôles et
travaux d'intégration nécessaires pour vérifier la posture de sécurité.

**Présent** signifie qu'un test ou contrôle correspondant existe dans le dépôt.
Cela ne signifie pas que toutes les garanties d'intégration ou de production
sont acquises.

**À intégrer** signifie que le composant opérationnel ou le test d'intégration
n'est pas encore démontré. Ne pas présenter ces éléments comme validés.

## 2. Menaces, tests et propriétaires

| Menace | Test ou contrôle de référence | État | Travail restant | Propriétaire |
|---|---|---|---|---|
| TM-01 — Accès inter-tenant | `test_cross_tenant_request_is_denied`, `test_cross_asset_request_is_denied` dans `test_scan_scope.py` | Tests unitaires présents | Tester l'autorisation par objet sur chaque endpoint API réel | P3 |
| TM-01 — Worker inter-tenant | `test_cross_tenant_worker_cannot_claim_job`, `test_cross_tenant_worker_cannot_complete_job` | Tests unitaires présents | Vérifier aussi le principal créé par le middleware réel | P3 + P4 |
| TM-02 — Contournement du scope URL | Tests de hostname trompeur, mauvais port, traversal, slash encodé et exclusions dans `test_scan_scope.py` | Tests unitaires présents | Tester DNS, redirections et egress dans un environnement isolé avant tout scanner réseau | P4 + Infrastructure |
| TM-03 — Permission de scan insuffisante | `test_requester_without_permission_is_denied`, `test_execution_requires_worker_permission` | Tests unitaires présents | Tester authentification et attribution réelle du principal par l'API | P3 |
| TM-04 — Producteur falsifié | Schémas des événements et findings dans `contracts/json-schema/` | Contrats présents | Tester authentification du connecteur, provenance et rejet d'un faux producteur | P2 + P3 |
| TM-05 — Injection RAG / fuite inter-tenant | Exigences documentées dans `threat-model.md` | Intégration à construire | Fixtures hostiles, filtrage tenant/permissions, validation des citations et tests de fuite | P2 + P3 |
| TM-06 — Saturation des ressources | Tests de limite de débit, fenêtre d'exécution, leases et tentatives dans `test_scan_orchestrator.py` | Tests unitaires présents | Tester backpressure, concurrence multi-instance et limites distribuées | P3 + P4 |
| TM-07 — Panne d'audit | `test_audit_failure_leaves_new_job_non_executable`, `test_audit_failure_during_claim_does_not_return_permit_and_rolls_back` | Tests unitaires présents | Tester audit durable, panne de stockage et outbox transactionnelle | P3 |
| TM-08 — Preuve non vérifiée présentée comme confirmée | Tests de `test_risk_classifier.py` sur confirmation et hash non vérifié | Tests unitaires présents | Récupérer les octets et comparer l'empreinte dans une intégration de confiance | P4 + P3 |
| TM-09 — Répétition et concurrence | `test_idempotent_retry_returns_same_job_without_consuming_another_slot`, `test_reusing_idempotency_key_for_different_request_is_denied` | Tests unitaires présents | Tester unicité durable et requêtes concurrentes sur plusieurs instances | P3 |
| TM-10 — Secrets / supply chain | Workflow P4 : Gitleaks, Semgrep et audit des dépendances Python | Gates CI présents | Revoir les permissions des workflows et la couverture Go, images et IaC | P4 + Infrastructure |
| TM-11 — Action sensible sans approbation | Contrats et exigences d'architecture | Conception documentée | Tester refus, approbation, idempotence et audit dans le workflow opérationnel | P2 + P3 |
| TM-12 — Données sensibles dans les logs | `test_audit_event_does_not_include_target_url`, `test_audit_events_omit_target_url_across_lifecycle` | Tests unitaires présents | Vérifier également les logs des workers et connecteurs | P4 + P2 |
| TM-13 — Exposition de l'API | `backend/internal/httpapi/server_test.go` teste `/healthz` | Test de santé uniquement | Tester authentification, autorisation, transport et configuration de déploiement | P3 + Infrastructure |

## 3. Régressions ajoutées et validées dans P4-06

Les trois tests ci-dessous sont implémentés et ont réussi lors de la suite ciblée des 25 tests d'orchestration ainsi que dans la suite complète des 85 tests de sécurité Python. Après toute modification pertinente, ces validations doivent être rejouées.

- `test_completion_audit_failure_keeps_job_running` :
  une panne du sink d'audit ne doit pas faire passer le job à un état terminal.
- `test_cross_tenant_worker_cannot_complete_job` :
  un worker d'un autre tenant ne doit pas finaliser le job d'un autre tenant.
- `test_audit_events_omit_target_url_across_lifecycle` :
  les événements d'audit ne doivent contenir ni URL de cible ni marqueur
  synthétique de paramètre sensible pendant l'admission, le claim et la complétion.

## 4. Commandes de validation locale

Depuis la racine du monorepo, exécuter les contrôles dans cet ordre :

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests/security -p "test_*.py" -v
.venv\Scripts\python.exe scripts/validate_contracts.py
Push-Location backend
go test ./...
go vet ./...
Pop-Location
```

## 5. Critères de clôture P4-06

1. Le threat model décrit les actifs, frontières, menaces, niveaux indicatifs et propriétaires.
2. Chaque menace élevée ou critique renvoie à une preuve ou à une tâche d'intégration ouverte.
3. Les trois tests de régression ajoutés sont implémentés et ont été exécutés avec succès.
4. Tous les tests de sécurité Python et la validation des contrats réussissent.
5. Les tests Go et `go vet` réussissent.
6. Le diff est relu, propre et limité aux fichiers attendus.
7. Après commit et push autorisés, les workflows distants sont vérifiés sur le SHA exact.

## 6. Limites de cette matrice

Cette matrice n'affirme pas que les protections P2, P3 ou infrastructure sont terminées. Une suite unitaire réussie ne remplace pas une validation d'intégration avec stockage durable, identité réelle, réseau isolé, connecteurs ou service RAG. Les tests d'intégration restent nécessaires lorsque les composants
opérationnels correspondants seront disponibles.