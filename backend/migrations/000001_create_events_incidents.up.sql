CREATE TABLE events (
    event_id VARCHAR(128) PRIMARY KEY,
    schema_version VARCHAR(10) NOT NULL CHECK (schema_version = '1.0'),
    source_product VARCHAR(32) NOT NULL CHECK (
        source_product IN ('wazuh', 'suricata', 'application_log')
    ),
    event_type VARCHAR(32) NOT NULL CHECK (
        event_type IN ('alert', 'flow', 'http', 'auth_failure', 'anomaly')
    ),
    asset_id VARCHAR(128),
    occurred_at TIMESTAMPTZ NOT NULL,
    severity SMALLINT NOT NULL CHECK (severity BETWEEN 1 AND 5),
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    correlation_id VARCHAR(128),
    src_ip INET,
    dest_ip INET,
    rule_id VARCHAR(1024),
    signature VARCHAR(1024),
    description TEXT,
    raw_ref VARCHAR(1024),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_events_occurred_at ON events (occurred_at DESC);
CREATE INDEX idx_events_asset_id ON events (asset_id);
CREATE INDEX idx_events_correlation_id ON events (correlation_id);

CREATE TABLE incidents (
    incident_id VARCHAR(128) PRIMARY KEY,
    schema_version VARCHAR(10) NOT NULL CHECK (schema_version = '1.0'),
    asset_id VARCHAR(128) NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    severity VARCHAR(10) NOT NULL CHECK (
        severity IN ('critical', 'high', 'medium', 'low')
    ),
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    title VARCHAR(1024) NOT NULL,
    correlation_id VARCHAR(128) NOT NULL,
    description TEXT NOT NULL,
    playbook_ref VARCHAR(1024),
    status VARCHAR(20) NOT NULL CHECK (
        status IN ('open', 'investigating', 'closed')
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_incidents_occurred_at ON incidents (occurred_at DESC);
CREATE INDEX idx_incidents_asset_id ON incidents (asset_id);
CREATE INDEX idx_incidents_status ON incidents (status);

CREATE TABLE incident_events (
    incident_id VARCHAR(128) NOT NULL
        REFERENCES incidents (incident_id) ON DELETE RESTRICT,
    event_id VARCHAR(128) NOT NULL
        REFERENCES events (event_id) ON DELETE RESTRICT,
    PRIMARY KEY (incident_id, event_id)
);

CREATE INDEX idx_incident_events_event_id ON incident_events (event_id);
