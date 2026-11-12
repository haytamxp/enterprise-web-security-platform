-- 000008_create_remediations_retests (down)
-- WARNING: rolling back removes all remediation task and retest data.

BEGIN;
DROP TABLE IF EXISTS retest_results;
DROP TABLE IF EXISTS remediation_tasks;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_tenant_user_id_key;
COMMIT;