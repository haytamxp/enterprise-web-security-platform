-- 000004_create_connectors (up)
-- Store tenant-scoped machine identities. Never store raw API keys.

BEGIN;

CREATE TABLE connectors (
    connector_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants (tenant_id) ON DELETE RESTRICT,
    name VARCHAR(120) NOT NULL,
    key_id VARCHAR(32) NOT NULL UNIQUE,
    key_hash BYTEA NOT NULL,
    scopes JSONB NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,

    CONSTRAINT connectors_key_hash_length_check
        CHECK (octet_length(key_hash) = 32),

    CONSTRAINT connectors_scopes_check
        CHECK (
            jsonb_typeof(scopes) = 'array'
            AND jsonb_array_length(scopes) BETWEEN 1 AND 2
            AND scopes <@ '["events:ingest", "incidents:create"]'::jsonb
        ),

    CONSTRAINT connectors_expiry_check
        CHECK (expires_at IS NULL OR expires_at > created_at),

    CONSTRAINT connectors_revocation_check
        CHECK (revoked_at IS NULL OR is_active = FALSE)
);

CREATE INDEX connectors_tenant_active_idx
    ON connectors (tenant_id, is_active);

CREATE INDEX connectors_expiry_idx
    ON connectors (expires_at)
    WHERE expires_at IS NOT NULL;

COMMIT;