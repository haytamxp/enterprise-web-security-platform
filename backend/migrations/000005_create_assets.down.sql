-- 000005_create_assets (down)
-- WARNING: deletes ALL asset data. Later migrations that reference assets
-- (findings) must be rolled back first.

BEGIN;

DROP TABLE IF EXISTS assets;

COMMIT;