-- 000009_create_response_orchestration (down)
-- Removes M7 response orchestration tables and their data.

BEGIN;

DROP TABLE IF EXISTS response_approvals;
DROP TABLE IF EXISTS response_action_executions;
DROP TABLE IF EXISTS response_runs;
DROP TABLE IF EXISTS response_playbook_actions;
DROP TABLE IF EXISTS response_playbooks;

COMMIT;