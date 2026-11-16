# P2 → P3 Security API Integration

**Contract:** P2-to-P3 ingestion v1.0
**Owner:** P3 Backend Security API
**Consumers:** P2 detection and correlation
**Endpoints:** `POST /api/v1/events`, `POST /api/v1/incidents`

## 1. Authentication

P2 must authenticate using a connector API key, not a human JWT.

HTTP header:

```http
X-Connector-Key: <connector-api-key>
Content-Type: application/json
Accept: application/json
```

The connector provisioned for P2 has these scopes:

- `events:ingest`
- `incidents:create`

Never commit the connector key to GitHub, source code, test fixtures, logs, screenshots, or this document. Store it in the P2 machine's environment or approved secret manager.

Environment variables:

```text
P3_API_BASE_URL=https://<private-p3-host>
P3_CONNECTOR_KEY=<secret-from-p3>
P3_TIMEOUT_SECONDS=15
P3_CA_BUNDLE=<optional-trusted-private-ca-file>
```

`P3_CA_BUNDLE` is optional. TLS certificate verification must remain enabled. Do not use `verify=False`.

## 2. Endpoints

| Method | Path | Required scope |
|---|---|---|
| POST | `/api/v1/events` | `events:ingest` |
| POST | `/api/v1/incidents` | `incidents:create` |

### Event contract

Required fields:

- `event_id`: unique event identifier.
- `schema_version`: `"1.0"`.
- `source_product`: `wazuh`, `suricata`, or `application_log`.
- `event_type`: `alert`, `flow`, `http`, `auth_failure`, or `anomaly`.
- `timestamp`: UTC timestamp ending in `Z`.
- `severity`: integer from 1 to 5.
- `confidence`: number from 0 to 1.

Optional fields include:

- `asset_id`: nullable; when provided, it must identify an asset belonging to the connector tenant.
- `correlation_id`
- `src_ip`
- `dest_ip`
- `rule_id`
- `signature`
- `description`
- `raw_ref`: an opaque evidence reference, not raw evidence or a secret.

Example:

```json
{
  "event_id": "f2ca23d0-a8bf-4b42-90f6-6d23ddc54f41",
  "schema_version": "1.0",
  "source_product": "wazuh",
  "event_type": "auth_failure",
  "asset_id": null,
  "timestamp": "2026-11-16T14:00:00Z",
  "severity": 3,
  "confidence": 0.95,
  "correlation_id": "corr-example-001",
  "src_ip": "192.0.2.10",
  "dest_ip": "192.0.2.20",
  "rule_id": "10001",
  "signature": "Failed SSH login",
  "description": "Multiple failed SSH authentication attempts",
  "raw_ref": null
}
```

### Event type mapping

P2 must map its internal labels to the P3 contract before submission.

| P2 label | P3 `event_type` |
|---|---|
| `login_failure` | `auth_failure` |
| `failed_login` | `auth_failure` |
| `authentication_failure` | `auth_failure` |
| `network_flow` | `flow` |
| `http_request` | `http` |
| `security_alert` | `alert` |
| `behavior_anomaly` | `anomaly` |

Do not send additional event types without agreeing a contract change with P3.

### Incident contract

An incident must reference events that have already been successfully stored by P3.

Required fields:

- `incident_id`: unique incident identifier.
- `schema_version`: `"1.0"`.
- `asset_id`: required registered asset UUID belonging to the connector tenant.
- `timestamp`: UTC timestamp ending in `Z`.
- `severity`: `critical`, `high`, `medium`, or `low`.
- `confidence`: number from 0 to 1.
- `title`
- `correlation_id`
- `event_ids`: 1–1000 unique event IDs already stored in P3.
- `description`
- `status`: use `"open"` when creating an incident.

`playbook_ref` is optional.

Example:

```json
{
  "incident_id": "7b6b23e0-8ff9-4385-a5b7-80d1fe88ef34",
  "schema_version": "1.0",
  "asset_id": "<REGISTERED_ASSET_UUID>",
  "timestamp": "2026-11-16T14:02:00Z",
  "severity": "high",
  "confidence": 0.95,
  "title": "Repeated SSH authentication failures",
  "correlation_id": "corr-example-001",
  "event_ids": [
    "f2ca23d0-a8bf-4b42-90f6-6d23ddc54f41"
  ],
  "description": "Correlated failed SSH authentication activity",
  "status": "open",
  "playbook_ref": null
}
```

Replace `<REGISTERED_ASSET_UUID>` with an asset registered in P3 for the same tenant. Do not submit the placeholder literally.

## 3. Response handling

| HTTP | Meaning | P2 action |
|---|---|---|
| `201` | Event or incident stored | Record success |
| `400` | Invalid payload | Fix the payload |
| `401` | Missing, invalid, expired, or revoked connector key | Check secret configuration |
| `403` | Connector lacks the required scope | Ask P3 to correct connector scopes |
| `409` | Duplicate event or incident ID | Treat as duplicate; do not invent a new ID to hide it |
| `422` | Invalid references, such as unknown event IDs | Store events first and correct references |
| `503` | Authentication or storage unavailable | Retry later using the same stable IDs |

Use stable IDs across retries. Do not automatically retry a POST with a newly generated identifier after an uncertain network result.

## 4. Python client

P3 provides `modules/p2-detection/p3_ingestion_client.py`.

Example:

```python
from p3_ingestion_client import P3Client

with P3Client() as p3:
    event = {
        "event_id": "f2ca23d0-a8bf-4b42-90f6-6d23ddc54f41",
        "schema_version": "1.0",
        "source_product": "wazuh",
        "event_type": "login_failure",
        "asset_id": None,
        "timestamp": "2026-11-16T14:00:00Z",
        "severity": 3,
        "confidence": 0.95,
        "correlation_id": "corr-example-001",
        "description": "Multiple failed SSH authentication attempts"
    }

    p3.create_event(event)

    # Submit an incident only after its referenced event has been stored.
    incident = {
        "incident_id": "7b6b23e0-8ff9-4385-a5b7-80d1fe88ef34",
        "schema_version": "1.0",
        "asset_id": "<REGISTERED_ASSET_UUID>",
        "timestamp": "2026-11-16T14:02:00Z",
        "severity": "high",
        "confidence": 0.95,
        "title": "Repeated SSH authentication failures",
        "correlation_id": "corr-example-001",
        "event_ids": [event["event_id"]],
        "description": "Correlated failed SSH authentication activity",
        "status": "open"
    }

    # Replace the asset placeholder before calling this method.
    # p3.create_incident(incident)
```

Install the existing P2 dependency if needed:

```powershell
python -m pip install requests
```

## 5. Network requirement

The P3 development API currently listens on:

`http://127.0.0.1:18082`

This is loopback-only and can be used only by processes on the P3 machine. A separate P2 machine cannot connect to that address.

For remote integration, P3 must provide a reachable private endpoint behind HTTPS, with certificate verification enabled and network access restricted to the required systems. Do not expose the development HTTP listener directly to the public internet.

## 6. P2 implementation checklist

- [ ] Configure `P3_API_BASE_URL` and `P3_CONNECTOR_KEY` outside source control.
- [ ] Use the `X-Connector-Key` header.
- [ ] Normalize P2 event types to the P3 v1.0 vocabulary.
- [ ] Submit events before incidents.
- [ ] Use registered tenant-owned asset IDs for incidents.
- [ ] Preserve stable event and incident IDs.
- [ ] Handle `201`, `401`, `403`, `409`, and `422`.
- [ ] Keep TLS certificate verification enabled.
- [ ] Never commit credentials or raw evidence to GitHub.
