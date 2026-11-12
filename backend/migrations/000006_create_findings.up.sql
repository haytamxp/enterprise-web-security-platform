-- 000006_create_findings (up)
-- Findings are tenant-scoped and must reference an Asset
-- belonging to the same tenant.

BEGIN;

CREATE TABLE findings (
    id                       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    tenant_id                UUID         NOT NULL,
    schema_version           VARCHAR(16)  NOT NULL,
    finding_id               VARCHAR(128) NOT NULL,
    asset_id                 VARCHAR(128) NOT NULL,

    source                   VARCHAR(32)  NOT NULL,
    title                    VARCHAR(512) NOT NULL,
    description              TEXT,

    status                   VARCHAR(32)  NOT NULL,
    severity                 VARCHAR(16)  NOT NULL,
    confidence               DOUBLE PRECISION NOT NULL,

    cvss_version             VARCHAR(8),
    cvss_score               DOUBLE PRECISION,
    cvss_vector              VARCHAR(512),

    cwe_ids                  JSONB NOT NULL DEFAULT '[]'::jsonb,
    references_json          JSONB NOT NULL DEFAULT '[]'::jsonb,
    evidence_refs            JSONB NOT NULL DEFAULT '[]'::jsonb,

    remediation_guidance     TEXT,

    detected_at              TIMESTAMPTZ NOT NULL,
    last_observed_at         TIMESTAMPTZ,

    deduplication_key        VARCHAR(256),
    references_to_incidents JSONB NOT NULL DEFAULT '[]'::jsonb,

    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Schema and identifiers.
    CONSTRAINT findings_schema_version_check
        CHECK (schema_version = '1.0'),

    CONSTRAINT findings_finding_id_not_blank_check
        CHECK (char_length(btrim(finding_id)) > 0),

    CONSTRAINT findings_asset_id_not_blank_check
        CHECK (char_length(btrim(asset_id)) > 0),

    CONSTRAINT findings_title_not_blank_check
        CHECK (char_length(btrim(title)) > 0),

    CONSTRAINT findings_description_length_check
        CHECK (
            description IS NULL
            OR char_length(description) BETWEEN 1 AND 10000
        ),

    -- Contract enumerations.
    CONSTRAINT findings_source_check
        CHECK (source IN (
            'p1_offensive',
            'p4_assurance',
            'manual',
            'scanner',
            'other'
        )),

    CONSTRAINT findings_status_check
        CHECK (status IN (
            'detected',
            'triaged',
            'confirmed',
            'false_positive',
            'remediating',
            'fixed_pending_retest',
            'retest_passed',
            'accepted_risk',
            'closed'
        )),

    CONSTRAINT findings_severity_check
        CHECK (severity IN (
            'critical',
            'high',
            'medium',
            'low',
            'info',
            'unknown'
        )),

    CONSTRAINT findings_confidence_check
        CHECK (confidence BETWEEN 0 AND 1),

    -- CVSS is either absent or a complete CVSS v4.0 object.
    CONSTRAINT findings_cvss_check
        CHECK (
            (
                cvss_version IS NULL
                AND cvss_score IS NULL
                AND cvss_vector IS NULL
            )
            OR
            (
                cvss_version = '4.0'
                AND cvss_score IS NOT NULL
                AND cvss_score BETWEEN 0 AND 10
            )
        ),

    -- JSON fields must contain arrays.
    CONSTRAINT findings_cwe_ids_check
        CHECK (jsonb_typeof(cwe_ids) = 'array'),

    CONSTRAINT findings_references_check
        CHECK (jsonb_typeof(references_json) = 'array'),

    CONSTRAINT findings_evidence_refs_check
        CHECK (jsonb_typeof(evidence_refs) = 'array'),

    CONSTRAINT findings_references_to_incidents_check
        CHECK (jsonb_typeof(references_to_incidents) = 'array'),

    -- Duplicate protection inside one tenant.
    CONSTRAINT findings_tenant_finding_id_key
        UNIQUE (tenant_id, finding_id),

    -- Tenant must exist.
    CONSTRAINT findings_tenant_id_fkey
        FOREIGN KEY (tenant_id)
        REFERENCES tenants (tenant_id)
        ON DELETE RESTRICT,

    -- The referenced Asset must belong to the same tenant.
    CONSTRAINT findings_tenant_asset_id_fkey
        FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, asset_id)
        ON DELETE RESTRICT
);

-- Tenant-scoped keyset pagination.
CREATE INDEX findings_tenant_id_id_idx
    ON findings (tenant_id, id);

-- Efficient lookup of findings belonging to one Asset.
CREATE INDEX findings_tenant_asset_id_id_idx
    ON findings (tenant_id, asset_id, id);

-- Useful for tenant-scoped status and severity filtering.
CREATE INDEX findings_tenant_status_severity_idx
    ON findings (tenant_id, status, severity);

COMMIT;