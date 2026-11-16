-- 000004_create_connectors (down)
-- This removes connector identities and their credential records.

BEGIN;

DROP TABLE connectors;

COMMIT;