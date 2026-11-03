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

## HTTP Integration with the P3 Security API

P2 sends normalized events and correlated incidents to P3 over HTTP. P2 must not connect directly to the P3 PostgreSQL database or modify its tables.

### Connector Authentication

Supply the connector key in the following request header:

`X-Connector-Key: <connector-api-key>`

Human-user `Authorization: Bearer` tokens are not accepted on ingestion endpoints.

P3 provisions the connector for the intended tenant and securely provides the API key to P2. The raw key is shown only once during creation. Store it in a secrets manager or protected environment variable. Never commit it or write it to application logs.

### Endpoints and Required Scopes

| Endpoint | Required scope | Successful response |
|---|---|---|
| `POST /api/v1/events` | `events:ingest` | `201 Created` |
| `POST /api/v1/incidents` | `incidents:create` | `201 Created` |

A connector may be provisioned with both scopes when P2 needs to submit both event and incident data.

### Ingestion Order

1. Submit normalized events to `POST /api/v1/events`.
2. Confirm successful storage (`201 Created`) and retain each `event_id`.
3. Submit the correlated incident to `POST /api/v1/incidents`.
4. Include the existing event IDs in `event_ids`.
5. All referenced events must belong to the connector tenant.

### Security and Error Responses

- `401`: connector key is missing, invalid, expired, or revoked.
- `403`: connector does not have the required scope.
- `409`: duplicate event or incident identifier.
- `422`: an incident references an event unavailable in the connector tenant.
- `500` or `503`: storage or connector-authentication service failure.

Use HTTPS outside local development. P3 derives the tenant from the authenticated connector record. P2 must not select a tenant by supplying a tenant ID in the payload.
