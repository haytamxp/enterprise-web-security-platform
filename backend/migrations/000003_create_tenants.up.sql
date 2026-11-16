-- 000003_create_tenants (up)
-- Introduce tenant ownership for existing users, events and incidents.
-- Existing records are assigned to the Default Organization.

BEGIN;

CREATE TABLE tenants (
    tenant_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(120) NOT NULL,
    slug VARCHAR(63) NOT NULL UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO tenants (name, slug)
VALUES ('Default Organization', 'default');

ALTER TABLE users
    ADD COLUMN tenant_id UUID;

ALTER TABLE events
    ADD COLUMN tenant_id UUID;

ALTER TABLE incidents
    ADD COLUMN tenant_id UUID;

UPDATE users
SET tenant_id = (
    SELECT tenant_id FROM tenants WHERE slug = 'default'
);

UPDATE events
SET tenant_id = (
    SELECT tenant_id FROM tenants WHERE slug = 'default'
);

UPDATE incidents
SET tenant_id = (
    SELECT tenant_id FROM tenants WHERE slug = 'default'
);

ALTER TABLE users
    ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE events
    ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE incidents
    ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE users
    ADD CONSTRAINT users_tenant_id_fkey
    FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id)
    ON DELETE RESTRICT;

ALTER TABLE events
    ADD CONSTRAINT events_tenant_id_fkey
    FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id)
    ON DELETE RESTRICT;

ALTER TABLE incidents
    ADD CONSTRAINT incidents_tenant_id_fkey
    FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id)
    ON DELETE RESTRICT;

-- Required as referenced composite keys for tenant-safe relationships.
ALTER TABLE events
    ADD CONSTRAINT events_tenant_id_id_key
    UNIQUE (tenant_id, id);

ALTER TABLE incidents
    ADD CONSTRAINT incidents_tenant_id_id_key
    UNIQUE (tenant_id, id);

-- Backfill the tenant ownership of existing incident-event relationships.
ALTER TABLE incident_events
    ADD COLUMN tenant_id UUID;

UPDATE incident_events AS ie
SET tenant_id = i.tenant_id
FROM incidents AS i
WHERE i.id = ie.incident_id;

ALTER TABLE incident_events
    ALTER COLUMN tenant_id SET NOT NULL;

-- Replace the original single-column relationships with tenant-aware FKs.
ALTER TABLE incident_events
    DROP CONSTRAINT incident_events_incident_id_fkey;

ALTER TABLE incident_events
    DROP CONSTRAINT incident_events_event_id_fkey;

ALTER TABLE incident_events
    ADD CONSTRAINT incident_events_tenant_incident_fkey
    FOREIGN KEY (tenant_id, incident_id)
    REFERENCES incidents (tenant_id, id)
    ON DELETE CASCADE;

ALTER TABLE incident_events
    ADD CONSTRAINT incident_events_tenant_event_fkey
    FOREIGN KEY (tenant_id, event_id)
    REFERENCES events (tenant_id, id)
    ON DELETE RESTRICT;

CREATE INDEX users_tenant_id_idx
    ON users (tenant_id);

CREATE INDEX events_tenant_occurred_at_idx
    ON events (tenant_id, occurred_at DESC);

CREATE INDEX incidents_tenant_occurred_at_idx
    ON incidents (tenant_id, occurred_at DESC);

CREATE INDEX incident_events_tenant_incident_id_idx
    ON incident_events (tenant_id, incident_id);

CREATE INDEX incident_events_tenant_event_id_idx
    ON incident_events (tenant_id, event_id);

COMMIT;