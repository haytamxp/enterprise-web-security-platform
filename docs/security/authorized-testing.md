# Politique d'évaluation autorisée

Cette politique est une base de travail ; elle ne remplace pas une autorisation écrite de l'organisation propriétaire des systèmes.

## Avant tout test actif

- Confirmer par écrit le propriétaire, les domaines/IP, les environnements, les dates, les sources d'origine autorisées et les exclusions.
- Définir les limites de débit, les fenêtres d'exécution, les contacts d'urgence et les conditions d'arrêt.
- S'assurer que les comptes de test et les jeux de données sont approuvés.
- Vérifier que le registre des actifs indique `authorization.status = approved`, que la période n'est pas expirée et que la cible se trouve dans `allowed_targets` sans correspondre à une exclusion.
- Utiliser d'abord des contrôles passifs ou un environnement de staging lorsque possible.

## Pendant le test

- Arrêter en cas d'impact opérationnel inattendu, d'accès à des données réelles non prévues ou de sortie du périmètre.
- Minimiser la collecte de données ; expurger les cookies, tokens, identifiants, données personnelles et payloads sensibles.
- Conserver le nom et la version de l'outil, la date, les paramètres, le compte utilisé et les limites de test.
- Ne pas exploiter davantage une vulnérabilité que nécessaire pour démontrer l'impact autorisé.

## Après le test

- Nettoyer les artefacts temporaires selon le plan approuvé.
- Transmettre les findings via le contrat versionné.
- Séparer fait observé, hypothèse et recommandation.
- Retester après correction et documenter la preuve de résolution.

## Arrêt immédiat

Interrompre le test si l'autorisation est incertaine, expirée ou révoquée, si une cible non déclarée est touchée, si la disponibilité est menacée ou si un incident réel est suspecté. Escalader au contact prévu par les règles d'engagement.
