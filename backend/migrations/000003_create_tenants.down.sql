-- 000003_create_tenants (down)
-- Remove tenant ownership and restore the original relationships.
-- This rollback removes tenant assignments from all records.

BEGIN;

ALTER TABLE incident_events
    DROP CONSTRAINT incident_events_tenant_incident_fkey;

ALTER TABLE incident_events
    DROP CONSTRAINT incident_events_tenant_event_fkey;

ALTER TABLE incident_events
    ADD CONSTRAINT incident_events_incident_id_fkey
    FOREIGN KEY (incident_id)
    REFERENCES incidents (id)
    ON DELETE CASCADE;

ALTER TABLE incident_events
    ADD CONSTRAINT incident_events_event_id_fkey
    FOREIGN KEY (event_id)
    REFERENCES events (id)
    ON DELETE RESTRICT;

DROP INDEX IF EXISTS incident_events_tenant_incident_id_idx;
DROP INDEX IF EXISTS incident_events_tenant_event_id_idx;
DROP INDEX IF EXISTS users_tenant_id_idx;
DROP INDEX IF EXISTS events_tenant_occurred_at_idx;
DROP INDEX IF EXISTS incidents_tenant_occurred_at_idx;

ALTER TABLE incident_events
    DROP COLUMN tenant_id;

ALTER TABLE users
    DROP CONSTRAINT users_tenant_id_fkey;

ALTER TABLE events
    DROP CONSTRAINT events_tenant_id_fkey;

ALTER TABLE incidents
    DROP CONSTRAINT incidents_tenant_id_fkey;

ALTER TABLE events
    DROP CONSTRAINT events_tenant_id_id_key;

ALTER TABLE incidents
    DROP CONSTRAINT incidents_tenant_id_id_key;

ALTER TABLE users
    DROP COLUMN tenant_id;

ALTER TABLE events
    DROP COLUMN tenant_id;

ALTER TABLE incidents
    DROP COLUMN tenant_id;

DROP TABLE tenants;

COMMIT;