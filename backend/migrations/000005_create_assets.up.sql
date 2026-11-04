-- 000005_create_assets (up)
-- Tenant-scoped asset inventory aligned with contracts/json-schema/asset.schema.json.

BEGIN;

CREATE TABLE assets (
    id                           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id                    UUID         NOT NULL REFERENCES tenants (tenant_id) ON DELETE RESTRICT,
    schema_version               VARCHAR(16)  NOT NULL DEFAULT '1.0',
    asset_id                     VARCHAR(128) NOT NULL,
    name                         VARCHAR(256) NOT NULL,
    asset_type                   VARCHAR(32)  NOT NULL,
    environment                  VARCHAR(32)  NOT NULL,
    owner_team                   VARCHAR(128) NOT NULL,
    criticality                  VARCHAR(32)  NOT NULL,
    tags                         JSONB        NOT NULL DEFAULT '[]'::jsonb,

    -- Flattened "authorization" object from the contract.
    auth_status                  VARCHAR(32)  NOT NULL,
    auth_approved_by             VARCHAR(128),
    auth_approved_at             TIMESTAMPTZ,
    auth_expires_at              TIMESTAMPTZ,
    auth_allowed_targets         JSONB        NOT NULL DEFAULT '[]'::jsonb,
    auth_excluded_targets        JSONB        NOT NULL DEFAULT '[]'::jsonb,
    auth_rules_of_engagement_ref VARCHAR(512),

    created_at                   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at                   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    -- Duplicate protection per tenant, safe under concurrent requests.
    -- Also the referenced key for tenant-safe finding -> asset relationships.
    CONSTRAINT assets_schema_version_check CHECK (schema_version = '1.0'),
    CONSTRAINT assets_tenant_asset_id_key UNIQUE (tenant_id, asset_id),

    CONSTRAINT assets_asset_id_not_blank_check CHECK (char_length(btrim(asset_id)) > 0),
    CONSTRAINT assets_name_not_blank_check CHECK (char_length(btrim(name)) > 0),
    CONSTRAINT assets_owner_team_not_blank_check CHECK (char_length(btrim(owner_team)) > 0),

    CONSTRAINT assets_asset_type_check
        CHECK (asset_type IN ('web_application', 'api', 'host', 'network_device', 'cloud_resource', 'other')),
    CONSTRAINT assets_environment_check
        CHECK (environment IN ('development', 'test', 'staging', 'production', 'unknown')),
    CONSTRAINT assets_criticality_check
        CHECK (criticality IN ('critical', 'high', 'medium', 'low', 'unknown')),
    CONSTRAINT assets_auth_status_check
        CHECK (auth_status IN ('pending', 'approved', 'expired', 'revoked', 'not_authorized')),

    CONSTRAINT assets_tags_check CHECK (jsonb_typeof(tags) = 'array'),
    CONSTRAINT assets_allowed_targets_check CHECK (jsonb_typeof(auth_allowed_targets) = 'array'),
    CONSTRAINT assets_excluded_targets_check CHECK (jsonb_typeof(auth_excluded_targets) = 'array')
);

-- Keyset pagination: WHERE tenant_id = $1 AND id > $2 ORDER BY id.
CREATE INDEX assets_tenant_id_id_idx
    ON assets (tenant_id, id);

COMMIT;