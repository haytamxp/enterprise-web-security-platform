# P2 — Detection Engineering & AI

## Mission
Ingérer des événements autorisés, préserver leur provenance, les normaliser, détecter et corréler des comportements, puis fournir aux analystes des incidents et recommandations vérifiables.

## Responsabilités
- Connecteurs vers Wazuh et événements EVE JSON de Suricata.
- Normalisation vers `security-event.schema.json`.
- Déduplication, fenêtres temporelles, enrichissement et règles testées.
- Association entre événements et actifs ; gestion des retards et pertes de capteurs.
- Playbooks explicables et RAG sourcé avec filtrage des permissions.

## Limites
Wazuh, Suricata et un EDR ne sont pas interchangeables. La plateforme consomme leurs capacités et ajoute l'intégration/corrélation spécifique ; elle ne se présente pas comme un remplacement complet.

## Critères d'acceptation
Chaque incident conserve les ID des événements sources, les règles qui ont contribué à la corrélation, la confiance et les limites connues. Le LLM ne décide ni n'exécute seul une action sensible.
