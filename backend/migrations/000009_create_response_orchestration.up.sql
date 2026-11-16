-- 000009_create_response_orchestration (up)
-- M7: tenant-scoped response playbooks, runs, approvals, and action execution records.
-- Action configuration must contain non-secret, allowlisted parameters only.

BEGIN;

CREATE TABLE response_playbooks (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    playbook_id     VARCHAR(128) NOT NULL,
    name            VARCHAR(200) NOT NULL,
    description     TEXT,
    is_active       BOOLEAN NOT NULL DEFAULT FALSE,
    created_by      UUID NOT NULL,
    updated_by      UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT response_playbooks_tenant_playbook_id_key
        UNIQUE (tenant_id, playbook_id),
    CONSTRAINT response_playbooks_tenant_id_id_key
        UNIQUE (tenant_id, id),
    CONSTRAINT response_playbooks_tenant_fkey
        FOREIGN KEY (tenant_id)
        REFERENCES tenants (tenant_id) ON DELETE RESTRICT,
    CONSTRAINT response_playbooks_creator_fkey
        FOREIGN KEY (tenant_id, created_by)
        REFERENCES users (tenant_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT response_playbooks_updater_fkey
        FOREIGN KEY (tenant_id, updated_by)
        REFERENCES users (tenant_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT response_playbooks_id_not_blank_check
        CHECK (char_length(btrim(playbook_id)) BETWEEN 1 AND 128),
    CONSTRAINT response_playbooks_name_not_blank_check
        CHECK (char_length(btrim(name)) BETWEEN 1 AND 200),
    CONSTRAINT response_playbooks_description_length_check
        CHECK (description IS NULL OR char_length(description) <= 10000)
);

CREATE TABLE response_playbook_actions (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    response_action_id  VARCHAR(128) NOT NULL,
    playbook_id         VARCHAR(128) NOT NULL,
    action_key          VARCHAR(128) NOT NULL,
    step_order          INTEGER NOT NULL,
    action_type         VARCHAR(32) NOT NULL,
    requires_approval   BOOLEAN NOT NULL DEFAULT TRUE,
    is_enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    config              JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT response_playbook_actions_tenant_action_id_key
        UNIQUE (tenant_id, response_action_id),
    CONSTRAINT response_playbook_actions_tenant_id_id_key
        UNIQUE (tenant_id, id),
    CONSTRAINT response_playbook_actions_playbook_action_id_key
        UNIQUE (tenant_id, playbook_id, response_action_id),
    CONSTRAINT response_playbook_actions_playbook_action_key
        UNIQUE (tenant_id, playbook_id, action_key),
    CONSTRAINT response_playbook_actions_playbook_step_key
        UNIQUE (tenant_id, playbook_id, step_order),
    CONSTRAINT response_playbook_actions_playbook_fkey
        FOREIGN KEY (tenant_id, playbook_id)
        REFERENCES response_playbooks (tenant_id, playbook_id) ON DELETE RESTRICT,
    CONSTRAINT response_playbook_actions_id_not_blank_check
        CHECK (char_length(btrim(response_action_id)) BETWEEN 1 AND 128),
    CONSTRAINT response_playbook_actions_action_key_check
        CHECK (char_length(btrim(action_key)) BETWEEN 1 AND 128),
    CONSTRAINT response_playbook_actions_step_order_check
        CHECK (step_order BETWEEN 1 AND 1000),
    CONSTRAINT response_playbook_actions_action_type_check
        CHECK (action_type IN ('notify', 'block_ip', 'isolate_host', 'disable_account', 'collect_evidence')),
    CONSTRAINT response_playbook_actions_config_object_check
        CHECK (jsonb_typeof(config) = 'object')
);

CREATE TABLE response_runs (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    response_run_id     VARCHAR(128) NOT NULL,
    incident_db_id      BIGINT NOT NULL,
    playbook_id         VARCHAR(128) NOT NULL,
    requested_by        UUID NOT NULL,
    idempotency_key     VARCHAR(128) NOT NULL,
    request_reason      TEXT,
    requires_approval   BOOLEAN NOT NULL DEFAULT TRUE,
    status              VARCHAR(24) NOT NULL DEFAULT 'queued',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at          TIMESTAMPTZ,
    finished_at         TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT response_runs_tenant_run_id_key
        UNIQUE (tenant_id, response_run_id),
    CONSTRAINT response_runs_tenant_id_id_key
        UNIQUE (tenant_id, id),
    CONSTRAINT response_runs_tenant_id_playbook_key
        UNIQUE (tenant_id, id, playbook_id),
    CONSTRAINT response_runs_tenant_id_requester_key
        UNIQUE (tenant_id, id, requested_by),
    CONSTRAINT response_runs_tenant_idempotency_key
        UNIQUE (tenant_id, idempotency_key),
    CONSTRAINT response_runs_tenant_fkey
        FOREIGN KEY (tenant_id)
        REFERENCES tenants (tenant_id) ON DELETE RESTRICT,
    CONSTRAINT response_runs_incident_fkey
        FOREIGN KEY (tenant_id, incident_db_id)
        REFERENCES incidents (tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT response_runs_playbook_fkey
        FOREIGN KEY (tenant_id, playbook_id)
        REFERENCES response_playbooks (tenant_id, playbook_id) ON DELETE RESTRICT,
    CONSTRAINT response_runs_requester_fkey
        FOREIGN KEY (tenant_id, requested_by)
        REFERENCES users (tenant_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT response_runs_id_not_blank_check
        CHECK (char_length(btrim(response_run_id)) BETWEEN 1 AND 128),
    CONSTRAINT response_runs_idempotency_key_check
        CHECK (char_length(btrim(idempotency_key)) BETWEEN 1 AND 128),
    CONSTRAINT response_runs_reason_length_check
        CHECK (request_reason IS NULL OR char_length(request_reason) <= 2000),
    CONSTRAINT response_runs_status_check
        CHECK (status IN ('pending_approval', 'queued', 'running', 'succeeded', 'partially_failed', 'failed', 'rejected', 'cancelled', 'timed_out')),
    CONSTRAINT response_runs_finished_at_check
        CHECK (
            (status IN ('succeeded', 'partially_failed', 'failed', 'rejected', 'cancelled', 'timed_out') AND finished_at IS NOT NULL)
            OR (status IN ('pending_approval', 'queued', 'running') AND finished_at IS NULL)
        ),
    CONSTRAINT response_runs_started_at_check
        CHECK (status <> 'running' OR started_at IS NOT NULL),
    CONSTRAINT response_runs_time_order_check
        CHECK (finished_at IS NULL OR started_at IS NULL OR finished_at >= started_at)
);

CREATE TABLE response_action_executions (
    id                      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id               UUID NOT NULL,
    action_execution_id     VARCHAR(128) NOT NULL,
    response_run_db_id      BIGINT NOT NULL,
    playbook_id             VARCHAR(128) NOT NULL,
    response_action_id      VARCHAR(128) NOT NULL,
    step_order              INTEGER NOT NULL,
    action_type             VARCHAR(32) NOT NULL,
    status                  VARCHAR(16) NOT NULL DEFAULT 'pending',
    attempt_count           SMALLINT NOT NULL DEFAULT 0,
    config_snapshot         JSONB NOT NULL DEFAULT '{}'::jsonb,
    result_summary          TEXT,
    error_code              VARCHAR(64),
    external_reference      VARCHAR(255),
    started_at              TIMESTAMPTZ,
    finished_at             TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT response_action_executions_tenant_execution_id_key
        UNIQUE (tenant_id, action_execution_id),
    CONSTRAINT response_action_executions_run_action_key
        UNIQUE (tenant_id, response_run_db_id, response_action_id),
    CONSTRAINT response_action_executions_run_fkey
        FOREIGN KEY (tenant_id, response_run_db_id, playbook_id)
        REFERENCES response_runs (tenant_id, id, playbook_id) ON DELETE RESTRICT,
    CONSTRAINT response_action_executions_playbook_action_fkey
        FOREIGN KEY (tenant_id, playbook_id, response_action_id)
        REFERENCES response_playbook_actions (tenant_id, playbook_id, response_action_id) ON DELETE RESTRICT,
    CONSTRAINT response_action_executions_id_not_blank_check
        CHECK (char_length(btrim(action_execution_id)) BETWEEN 1 AND 128),
    CONSTRAINT response_action_executions_step_order_check
        CHECK (step_order BETWEEN 1 AND 1000),
    CONSTRAINT response_action_executions_action_type_check
        CHECK (action_type IN ('notify', 'block_ip', 'isolate_host', 'disable_account', 'collect_evidence')),
    CONSTRAINT response_action_executions_status_check
        CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'skipped', 'timed_out', 'cancelled')),
    CONSTRAINT response_action_executions_attempt_count_check
        CHECK (attempt_count BETWEEN 0 AND 10),
    CONSTRAINT response_action_executions_config_object_check
        CHECK (jsonb_typeof(config_snapshot) = 'object'),
    CONSTRAINT response_action_executions_summary_length_check
        CHECK (result_summary IS NULL OR char_length(result_summary) <= 5000),
    CONSTRAINT response_action_executions_lifecycle_check
        CHECK (
            (status = 'pending' AND started_at IS NULL AND finished_at IS NULL)
            OR (status = 'running' AND started_at IS NOT NULL AND finished_at IS NULL)
            OR (status IN ('succeeded', 'failed', 'skipped', 'timed_out', 'cancelled') AND finished_at IS NOT NULL)
        ),
    CONSTRAINT response_action_executions_time_order_check
        CHECK (finished_at IS NULL OR started_at IS NULL OR finished_at >= started_at)
);

CREATE TABLE response_approvals (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    approval_id         VARCHAR(128) NOT NULL,
    response_run_db_id  BIGINT NOT NULL,
    requested_by        UUID NOT NULL,
    decided_by          UUID,
    status              VARCHAR(16) NOT NULL DEFAULT 'pending',
    decision_note       TEXT,
    requested_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at          TIMESTAMPTZ,

    CONSTRAINT response_approvals_tenant_approval_id_key
        UNIQUE (tenant_id, approval_id),
    CONSTRAINT response_approvals_one_per_run_key
        UNIQUE (tenant_id, response_run_db_id),
    CONSTRAINT response_approvals_run_requester_fkey
        FOREIGN KEY (tenant_id, response_run_db_id, requested_by)
        REFERENCES response_runs (tenant_id, id, requested_by) ON DELETE RESTRICT,
    CONSTRAINT response_approvals_decider_fkey
        FOREIGN KEY (tenant_id, decided_by)
        REFERENCES users (tenant_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT response_approvals_id_not_blank_check
        CHECK (char_length(btrim(approval_id)) BETWEEN 1 AND 128),
    CONSTRAINT response_approvals_status_check
        CHECK (status IN ('pending', 'approved', 'rejected')),
    CONSTRAINT response_approvals_decision_check
        CHECK (
            (status = 'pending' AND decided_by IS NULL AND decided_at IS NULL)
            OR (status IN ('approved', 'rejected') AND decided_by IS NOT NULL AND decided_at IS NOT NULL)
        ),
    CONSTRAINT response_approvals_note_length_check
        CHECK (decision_note IS NULL OR char_length(decision_note) <= 2000)
);

CREATE INDEX response_playbooks_tenant_active_updated_idx
    ON response_playbooks (tenant_id, is_active, updated_at DESC);

CREATE INDEX response_playbook_actions_tenant_playbook_order_idx
    ON response_playbook_actions (tenant_id, playbook_id, step_order);

CREATE INDEX response_runs_tenant_created_idx
    ON response_runs (tenant_id, created_at DESC, id DESC);

CREATE INDEX response_runs_tenant_status_created_idx
    ON response_runs (tenant_id, status, created_at DESC);

CREATE INDEX response_runs_tenant_incident_idx
    ON response_runs (tenant_id, incident_db_id, created_at DESC);

CREATE INDEX response_action_executions_tenant_run_idx
    ON response_action_executions (tenant_id, response_run_db_id, step_order);

CREATE INDEX response_action_executions_tenant_status_idx
    ON response_action_executions (tenant_id, status, created_at DESC);

CREATE INDEX response_approvals_tenant_status_requested_idx
    ON response_approvals (tenant_id, status, requested_at DESC);

COMMIT;
