# Intégration Wazuh

Définir l'authentification vers l'API ou le mécanisme d'export autorisé selon la version déployée. Ne jamais supposer un endpoint ou une forme de réponse sans confirmer la version/configuration.

Exigences : pagination/reprise, contrôle d'accès de service, watermark ou fenêtre temporelle, gestion des doublons, mapping vers `security-event.schema.json`, métriques de dernière collecte et erreurs sans secrets. Garder les événements d'origine et leurs identifiants pour l'investigation.
