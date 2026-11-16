package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/contract"
)

var (
	ErrAssetNotFound     = errors.New("asset not found")
	ErrTenantMismatch    = errors.New("asset tenant does not match authenticated tenant")
	ErrInvalidPagination = errors.New("invalid asset pagination parameters")
)

const maxAssetPageSize = 100

// AssetRecord represents an Asset together with its internal database ID.
type AssetRecord struct {
	ID    int64
	Asset contract.Asset
}

type assetScanner interface {
	Scan(dest ...any) error
}

// These columns must stay in the same order as scanAsset.
const assetSelectColumns = `
id,
tenant_id::text,
schema_version,
asset_id,
name,
asset_type,
environment,
owner_team,
criticality,
tags,
auth_status,
auth_approved_by,
auth_approved_at,
auth_expires_at,
auth_allowed_targets,
auth_excluded_targets,
auth_rules_of_engagement_ref,
created_at,
updated_at
`

func normalizeStringSlice(values []string) []string {
	if values == nil {
		return []string{}
	}

	return values
}

// scanAsset converts one database row into an AssetRecord.
func scanAsset(row assetScanner) (AssetRecord, error) {
	var record AssetRecord
	asset := &record.Asset

	var tagsJSON []byte
	var allowedTargetsJSON []byte
	var excludedTargetsJSON []byte

	var approvedBy sql.NullString
	var approvedAt sql.NullTime
	var expiresAt sql.NullTime
	var rulesOfEngagementRef sql.NullString

	var createdAt time.Time
	var updatedAt time.Time

	err := row.Scan(
		&record.ID,
		&asset.TenantID,
		&asset.SchemaVersion,
		&asset.AssetID,
		&asset.Name,
		&asset.AssetType,
		&asset.Environment,
		&asset.OwnerTeam,
		&asset.Criticality,
		&tagsJSON,
		&asset.Authorization.Status,
		&approvedBy,
		&approvedAt,
		&expiresAt,
		&allowedTargetsJSON,
		&excludedTargetsJSON,
		&rulesOfEngagementRef,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return AssetRecord{}, err
	}

	if err := json.Unmarshal(tagsJSON, &asset.Tags); err != nil {
		return AssetRecord{}, fmt.Errorf("decode asset tags: %w", err)
	}

	if err := json.Unmarshal(
		allowedTargetsJSON,
		&asset.Authorization.AllowedTargets,
	); err != nil {
		return AssetRecord{}, fmt.Errorf("decode allowed targets: %w", err)
	}

	if err := json.Unmarshal(
		excludedTargetsJSON,
		&asset.Authorization.ExcludedTargets,
	); err != nil {
		return AssetRecord{}, fmt.Errorf("decode excluded targets: %w", err)
	}

	if approvedBy.Valid {
		value := approvedBy.String
		asset.Authorization.ApprovedBy = &value
	}

	if approvedAt.Valid {
		value := approvedAt.Time
		asset.Authorization.ApprovedAt = &value
	}

	if expiresAt.Valid {
		value := expiresAt.Time
		asset.Authorization.ExpiresAt = &value
	}

	if rulesOfEngagementRef.Valid {
		value := rulesOfEngagementRef.String
		asset.Authorization.RulesOfEngagementRef = &value
	}

	asset.CreatedAt = &createdAt
	asset.UpdatedAt = &updatedAt

	return record, nil
}

// InsertAsset creates an Asset inside the authenticated tenant.
// The database owns created_at and updated_at.
func (s *Store) InsertAsset(
	ctx context.Context,
	tenantID string,
	asset contract.Asset,
) (AssetRecord, error) {
	tenantID = strings.TrimSpace(tenantID)

	if tenantID == "" {
		return AssetRecord{}, ErrTenantRequired
	}

	if strings.TrimSpace(asset.TenantID) != tenantID {
		return AssetRecord{}, ErrTenantMismatch
	}

	// Always use the authenticated tenant ID internally.
	asset.TenantID = tenantID

	tagsJSON, err := json.Marshal(normalizeStringSlice(asset.Tags))
	if err != nil {
		return AssetRecord{}, fmt.Errorf("encode asset tags: %w", err)
	}

	allowedTargetsJSON, err := json.Marshal(
		normalizeStringSlice(asset.Authorization.AllowedTargets),
	)
	if err != nil {
		return AssetRecord{}, fmt.Errorf("encode allowed targets: %w", err)
	}

	excludedTargetsJSON, err := json.Marshal(
		normalizeStringSlice(asset.Authorization.ExcludedTargets),
	)
	if err != nil {
		return AssetRecord{}, fmt.Errorf("encode excluded targets: %w", err)
	}

	var record AssetRecord
	record.Asset = asset

	var createdAt, updatedAt time.Time

	err = s.DB.QueryRowContext(ctx, `
INSERT INTO assets (
tenant_id,
schema_version,
asset_id,
name,
asset_type,
environment,
owner_team,
criticality,
tags,
auth_status,
auth_approved_by,
auth_approved_at,
auth_expires_at,
auth_allowed_targets,
auth_excluded_targets,
auth_rules_of_engagement_ref
)
VALUES (
$1::uuid,
$2,
$3,
$4,
$5,
$6,
$7,
$8,
$9::jsonb,
$10,
$11,
$12,
$13,
$14::jsonb,
$15::jsonb,
$16
)
RETURNING id, created_at, updated_at
`,
		tenantID,
		asset.SchemaVersion,
		asset.AssetID,
		asset.Name,
		asset.AssetType,
		asset.Environment,
		asset.OwnerTeam,
		asset.Criticality,
		string(tagsJSON),
		asset.Authorization.Status,
		asset.Authorization.ApprovedBy,
		asset.Authorization.ApprovedAt,
		asset.Authorization.ExpiresAt,
		string(allowedTargetsJSON),
		string(excludedTargetsJSON),
		asset.Authorization.RulesOfEngagementRef,
	).Scan(
		&record.ID,
		&createdAt,
		&updatedAt,
	)

	if err != nil {
		var pgErr interface {
			SQLState() string
		}

		if errors.As(err, &pgErr) && pgErr.SQLState() == "23505" {
			return AssetRecord{}, ErrDuplicate
		}

		return AssetRecord{}, fmt.Errorf("insert asset: %w", err)
	}

	// Use timestamps returned by PostgreSQL in the same INSERT operation.
	record.Asset.CreatedAt = &createdAt
	record.Asset.UpdatedAt = &updatedAt

	record.Asset.Tags = normalizeStringSlice(record.Asset.Tags)
	record.Asset.Authorization.AllowedTargets = normalizeStringSlice(
		record.Asset.Authorization.AllowedTargets,
	)
	record.Asset.Authorization.ExcludedTargets = normalizeStringSlice(
		record.Asset.Authorization.ExcludedTargets,
	)

	return record, nil
}

// GetAssetByID retrieves an Asset using its external asset_id.
// The query is always restricted to the supplied tenant.
func (s *Store) GetAssetByID(
	ctx context.Context,
	tenantID string,
	assetID string,
) (AssetRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	assetID = strings.TrimSpace(assetID)

	if tenantID == "" {
		return AssetRecord{}, ErrTenantRequired
	}

	if assetID == "" {
		return AssetRecord{}, ErrAssetNotFound
	}

	query := `SELECT ` + assetSelectColumns + `
FROM assets
WHERE tenant_id = $1::uuid
  AND asset_id = $2
`

	record, err := scanAsset(
		s.DB.QueryRowContext(ctx, query, tenantID, assetID),
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AssetRecord{}, ErrAssetNotFound
		}

		return AssetRecord{}, fmt.Errorf("get asset: %w", err)
	}

	return record, nil
}

// ListAssets returns a tenant-scoped page using keyset pagination.
// afterID is the internal database ID of the last item in the previous page.
// A zero value starts from the first page.
func (s *Store) ListAssets(
	ctx context.Context,
	tenantID string,
	afterID int64,
	limit int,
) ([]AssetRecord, bool, error) {
	tenantID = strings.TrimSpace(tenantID)

	if tenantID == "" {
		return nil, false, ErrTenantRequired
	}

	if afterID < 0 || limit < 1 || limit > maxAssetPageSize {
		return nil, false, ErrInvalidPagination
	}

	query := `SELECT ` + assetSelectColumns + `
FROM assets
WHERE tenant_id = $1::uuid
  AND id > $2
ORDER BY id ASC
LIMIT $3
`

	rows, err := s.DB.QueryContext(
		ctx,
		query,
		tenantID,
		afterID,
		limit+1,
	)
	if err != nil {
		return nil, false, fmt.Errorf("list assets: %w", err)
	}
	defer rows.Close()

	records := make([]AssetRecord, 0, limit+1)

	for rows.Next() {
		record, err := scanAsset(rows)
		if err != nil {
			return nil, false, fmt.Errorf("scan listed asset: %w", err)
		}

		records = append(records, record)
	}

	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate assets: %w", err)
	}

	hasMore := len(records) > limit

	if hasMore {
		records = records[:limit]
	}

	return records, hasMore, nil
}
