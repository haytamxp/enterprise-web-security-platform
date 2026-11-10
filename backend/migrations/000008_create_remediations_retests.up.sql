-- 000008_create_remediations_retests (up)
-- M6: tenant-scoped remediation tasks and immutable retest records.

BEGIN;

-- Composite key required for tenant-safe user assignment and authorship.
ALTER TABLE users
    ADD CONSTRAINT users_tenant_user_id_key UNIQUE (tenant_id, user_id);

CREATE TABLE remediation_tasks (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    remediation_id  VARCHAR(128) NOT NULL,
    finding_id      VARCHAR(128) NOT NULL,
    title           VARCHAR(512) NOT NULL,
    description     TEXT,
    priority        VARCHAR(16) NOT NULL,
    status          VARCHAR(24) NOT NULL DEFAULT 'open',
    assigned_to     UUID,
    due_at          TIMESTAMPTZ,
    created_by      UUID NOT NULL,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT remediation_tasks_tenant_remediation_id_key
        UNIQUE (tenant_id, remediation_id),
    CONSTRAINT remediation_tasks_tenant_remediation_finding_key
        UNIQUE (tenant_id, remediation_id, finding_id),
    CONSTRAINT remediation_tasks_tenant_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id) ON DELETE RESTRICT,
    CONSTRAINT remediation_tasks_finding_fkey
        FOREIGN KEY (tenant_id, finding_id)
        REFERENCES findings (tenant_id, finding_id) ON DELETE RESTRICT,
    CONSTRAINT remediation_tasks_assignee_fkey
        FOREIGN KEY (tenant_id, assigned_to)
        REFERENCES users (tenant_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT remediation_tasks_creator_fkey
        FOREIGN KEY (tenant_id, created_by)
        REFERENCES users (tenant_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT remediation_tasks_id_not_blank_check
        CHECK (char_length(btrim(remediation_id)) > 0),
    CONSTRAINT remediation_tasks_title_not_blank_check
        CHECK (char_length(btrim(title)) > 0),
    CONSTRAINT remediation_tasks_description_length_check
        CHECK (description IS NULL OR char_length(description) <= 10000),
    CONSTRAINT remediation_tasks_priority_check
        CHECK (priority IN ('critical', 'high', 'medium', 'low')),
    CONSTRAINT remediation_tasks_status_check
        CHECK (status IN ('open', 'in_progress', 'blocked', 'completed', 'cancelled')),
    CONSTRAINT remediation_tasks_completion_check
        CHECK ((status = 'completed' AND completed_at IS NOT NULL)
            OR (status <> 'completed' AND completed_at IS NULL))
);

CREATE INDEX remediation_tasks_tenant_id_id_idx
    ON remediation_tasks (tenant_id, id);
CREATE INDEX remediation_tasks_tenant_finding_idx
    ON remediation_tasks (tenant_id, finding_id, id);
CREATE INDEX remediation_tasks_tenant_assignee_idx
    ON remediation_tasks (tenant_id, assigned_to, status);

CREATE TABLE retest_results (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    retest_id       VARCHAR(128) NOT NULL,
    remediation_id  VARCHAR(128) NOT NULL,
    finding_id      VARCHAR(128) NOT NULL,
    status          VARCHAR(24) NOT NULL,
    summary         TEXT NOT NULL,
    evidence_refs   JSONB NOT NULL DEFAULT '[]'::jsonb,
    performed_by    UUID NOT NULL,
    tested_at       TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT retest_results_tenant_retest_id_key
        UNIQUE (tenant_id, retest_id),
    CONSTRAINT retest_results_task_fkey
        FOREIGN KEY (tenant_id, remediation_id, finding_id)
        REFERENCES remediation_tasks (tenant_id, remediation_id, finding_id)
        ON DELETE RESTRICT,
    CONSTRAINT retest_results_performer_fkey
        FOREIGN KEY (tenant_id, performed_by)
        REFERENCES users (tenant_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT retest_results_status_check
        CHECK (status IN ('fixed', 'still_present', 'inconclusive')),
    CONSTRAINT retest_results_summary_length_check
        CHECK (char_length(btrim(summary)) BETWEEN 1 AND 10000),
    CONSTRAINT retest_results_evidence_refs_check
        CHECK (jsonb_typeof(evidence_refs) = 'array')
);

CREATE INDEX retest_results_tenant_task_tested_idx
    ON retest_results (tenant_id, remediation_id, tested_at DESC, id DESC);

COMMIT;