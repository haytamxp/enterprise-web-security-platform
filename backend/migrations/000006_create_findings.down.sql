-- 000006_create_findings (down)
-- WARNING: deletes ALL Finding data.
-- Roll back dependent migrations before dropping this table.

BEGIN;

DROP TABLE IF EXISTS findings;

COMMIT;