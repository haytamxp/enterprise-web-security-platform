-- 000001_create_events_incidents (up)
-- Module 2: persistence for P2 security events and correlated incidents.

CREATE TABLE events (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id       TEXT             NOT NULL,
    schema_version TEXT             NOT NULL,
    source_product TEXT             NOT NULL,
    event_type     TEXT             NOT NULL,
    asset_id       TEXT,                          -- nullable by contract
    occurred_at    TIMESTAMPTZ      NOT NULL,     -- P2 "timestamp" (UTC)
    severity       SMALLINT         NOT NULL,
    confidence     DOUBLE PRECISION NOT NULL,
    correlation_id TEXT,                          -- nullable; need not match an incident yet
    src_ip         TEXT,
    dest_ip        TEXT,
    rule_id        TEXT,
    signature      TEXT,
    description    TEXT,
    raw_ref        TEXT,
    received_at    TIMESTAMPTZ      NOT NULL DEFAULT now(),

    -- Duplicate protection enforced by the database, safe under concurrent requests.
    CONSTRAINT events_event_id_key UNIQUE (event_id),
    CONSTRAINT events_schema_version_check CHECK (schema_version = '1.0'),
    CONSTRAINT events_source_product_check CHECK (source_product IN ('wazuh', 'suricata', 'application_log')),
    CONSTRAINT events_event_type_check CHECK (event_type IN ('alert', 'flow', 'http', 'auth_failure', 'anomaly')),
    CONSTRAINT events_severity_check CHECK (severity BETWEEN 1 AND 5),
    CONSTRAINT events_confidence_check CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE INDEX events_correlation_id_idx ON events (correlation_id);
CREATE INDEX events_asset_id_idx ON events (asset_id);

CREATE TABLE incidents (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id    TEXT             NOT NULL,
    schema_version TEXT             NOT NULL,
    asset_id       TEXT             NOT NULL,     -- required, never null
    occurred_at    TIMESTAMPTZ      NOT NULL,
    severity       TEXT             NOT NULL,
    confidence     DOUBLE PRECISION NOT NULL,
    title          TEXT             NOT NULL,
    correlation_id TEXT             NOT NULL,
    description    TEXT             NOT NULL,
    playbook_ref   TEXT,
    status         TEXT             NOT NULL DEFAULT 'open',
    received_at    TIMESTAMPTZ      NOT NULL DEFAULT now(),

    CONSTRAINT incidents_incident_id_key UNIQUE (incident_id),
    CONSTRAINT incidents_schema_version_check CHECK (schema_version = '1.0'),
    CONSTRAINT incidents_severity_check CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    CONSTRAINT incidents_confidence_check CHECK (confidence >= 0 AND confidence <= 1),
    -- Only 'open' exists at creation. The lifecycle module will replace this constraint.
    CONSTRAINT incidents_status_check CHECK (status IN ('open'))
);

CREATE INDEX incidents_correlation_id_idx ON incidents (correlation_id);
CREATE INDEX incidents_asset_id_idx ON incidents (asset_id);

CREATE TABLE incident_events (
    incident_id BIGINT NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    event_id    BIGINT NOT NULL REFERENCES events (id) ON DELETE RESTRICT,
    PRIMARY KEY (incident_id, event_id)
);

CREATE INDEX incident_events_event_id_idx ON incident_events (event_id);