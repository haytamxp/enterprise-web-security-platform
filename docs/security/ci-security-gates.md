# Security gates — politique initiale

Les seuils ci-dessous doivent être validés par l'équipe et ajustés à partir des résultats mesurés ; ce sont des règles de départ, pas des niveaux de couverture déjà atteints.

| Contrôle | Résultat bloquant proposé | Traitement des exceptions |
|---|---|---|
| Secrets | Secret confirmé ajouté au dépôt | Rotation/révocation immédiate, retrait sécurisé, analyse de l'historique si nécessaire |
| Tests | Test critique en échec | Correction avant merge, sauf exception documentée et approuvée |
| SAST | Faiblesse critique/high confiance | Triaged par le propriétaire, correction ou exception courte documentée |
| SCA | Dépendance vulnérable critique exploitable dans le chemin de production | Mettre à jour, atténuer ou accorder une exception avec responsable et date d'expiration |
| Conteneur/IaC | Configuration privilégiée ou exposition majeure non justifiée | Refuser par défaut ; analyser tout besoin d'exception |
| Contrats | Schéma invalide ou fixture incompatible | Bloquer le merge jusqu'à correction |
| Scans externes | Autorisation manquante/expirée ou cible hors périmètre | Ne pas démarrer le scan |

Chaque finding de CI doit contenir l'outil/version, le commit, le composant, le résultat, la sévérité, la confiance et la décision. Les exceptions doivent avoir un propriétaire, une justification, des mesures compensatoires et une date d'expiration. Ne désactivez pas un contrôle sans laisser de trace.
