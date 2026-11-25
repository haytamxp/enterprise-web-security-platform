package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/database"
)

type AssetAuthorization struct {
	Status               string     `json:"status"`
	ApprovedBy           *string    `json:"approved_by,omitempty"`
	ApprovedAt           *time.Time `json:"approved_at,omitempty"`
	ExpiresAt            *time.Time `json:"expires_at,omitempty"`
	AllowedTargets       []string   `json:"allowed_targets"`
	ExcludedTargets      []string   `json:"excluded_targets"`
	RulesOfEngagementRef *string    `json:"rules_of_engagement_ref,omitempty"`
}

type AssetRequest struct {
	SchemaVersion string             `json:"schema_version"`
	TenantID      string             `json:"tenant_id,omitempty"`
	AssetID       string             `json:"asset_id"`
	Name          string             `json:"name"`
	AssetType     string             `json:"asset_type"`
	Environment   string             `json:"environment"`
	OwnerTeam     string             `json:"owner_team"`
	Criticality   string             `json:"criticality"`
	Tags          []string           `json:"tags"`
	Authorization AssetAuthorization `json:"authorization"`
}

type AssetResponse struct {
	TenantID      string             `json:"tenant_id"`
	SchemaVersion string             `json:"schema_version"`
	AssetID       string             `json:"asset_id"`
	Name          string             `json:"name"`
	AssetType     string             `json:"asset_type"`
	Environment   string             `json:"environment"`
	OwnerTeam     string             `json:"owner_team"`
	Criticality   string             `json:"criticality"`
	Tags          []string           `json:"tags"`
	Authorization AssetAuthorization `json:"authorization"`
	CreatedAt     time.Time          `json:"created_at"`
	UpdatedAt     time.Time          `json:"updated_at"`
}

const assetSelectColumns = `
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

type assetRowScanner interface {
	Scan(dest ...any) error
}

func scanAsset(row assetRowScanner) (AssetResponse, error) {
	var asset AssetResponse

	var (
		tagsJSON     []byte
		allowedJSON  []byte
		excludedJSON []byte
		approvedBy   sql.NullString
		approvedAt   sql.NullTime
		expiresAt    sql.NullTime
		rulesRef     sql.NullString
	)

	err := row.Scan(
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
		&allowedJSON,
		&excludedJSON,
		&rulesRef,
		&asset.CreatedAt,
		&asset.UpdatedAt,
	)
	if err != nil {
		return asset, err
	}

	if err := json.Unmarshal(tagsJSON, &asset.Tags); err != nil {
		return asset, err
	}
	if err := json.Unmarshal(allowedJSON, &asset.Authorization.AllowedTargets); err != nil {
		return asset, err
	}
	if err := json.Unmarshal(excludedJSON, &asset.Authorization.ExcludedTargets); err != nil {
		return asset, err
	}

	if asset.Tags == nil {
		asset.Tags = []string{}
	}
	if asset.Authorization.AllowedTargets == nil {
		asset.Authorization.AllowedTargets = []string{}
	}
	if asset.Authorization.ExcludedTargets == nil {
		asset.Authorization.ExcludedTargets = []string{}
	}

	if approvedBy.Valid {
		asset.Authorization.ApprovedBy = &approvedBy.String
	}
	if approvedAt.Valid {
		asset.Authorization.ApprovedAt = &approvedAt.Time
	}
	if expiresAt.Valid {
		asset.Authorization.ExpiresAt = &expiresAt.Time
	}
	if rulesRef.Valid {
		asset.Authorization.RulesOfEngagementRef = &rulesRef.String
	}

	return asset, nil
}

func assetIdentity(w http.ResponseWriter, r *http.Request, adminOnly bool) (AuthIdentity, bool) {
	identity, ok := AuthIdentityFromContext(r.Context())
	if !ok {
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return AuthIdentity{}, false
	}

	if adminOnly && identity.Role != "admin" {
		http.Error(w, "Administrator access required", http.StatusForbidden)
		return AuthIdentity{}, false
	}

	return identity, true
}

func decodeAssetRequest(w http.ResponseWriter, r *http.Request) (AssetRequest, error) {
	var req AssetRequest

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024*1024))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		return req, err
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return req, errors.New("request must contain one JSON object")
	}

	return req, nil
}

func containsValue(values []string, value string) bool {
	for _, current := range values {
		if current == value {
			return true
		}
	}
	return false
}

func validateAssetTarget(target string) bool {
	parsed, err := url.ParseRequestURI(target)
	return err == nil &&
		parsed.IsAbs() &&
		parsed.Host != "" &&
		(parsed.Scheme == "http" || parsed.Scheme == "https")
}

func validateAssetRequest(req *AssetRequest, tenantID, adminEmail string) error {
	req.SchemaVersion = strings.TrimSpace(req.SchemaVersion)
	req.AssetID = strings.TrimSpace(req.AssetID)
	req.Name = strings.TrimSpace(req.Name)
	req.AssetType = strings.TrimSpace(req.AssetType)
	req.Environment = strings.TrimSpace(req.Environment)
	req.OwnerTeam = strings.TrimSpace(req.OwnerTeam)
	req.Criticality = strings.TrimSpace(req.Criticality)

	if req.TenantID != "" && req.TenantID != tenantID {
		return errors.New("tenant_id must match the authenticated administrator tenant")
	}

	if req.SchemaVersion == "" {
		req.SchemaVersion = "1.0"
	}
	if req.SchemaVersion != "1.0" {
		return errors.New("schema_version must be 1.0")
	}

	if req.AssetID == "" || len(req.AssetID) > 128 {
		return errors.New("asset_id is required and must not exceed 128 characters")
	}
	if req.Name == "" || len(req.Name) > 256 {
		return errors.New("name is required and must not exceed 256 characters")
	}
	if req.OwnerTeam == "" || len(req.OwnerTeam) > 128 {
		return errors.New("owner_team is required and must not exceed 128 characters")
	}

	if !oneOf(req.AssetType, "web_application", "api", "host", "network_device", "cloud_resource", "other") {
		return errors.New("invalid asset_type")
	}
	if !oneOf(req.Environment, "development", "test", "staging", "production", "unknown") {
		return errors.New("invalid environment")
	}
	if !oneOf(req.Criticality, "critical", "high", "medium", "low", "unknown") {
		return errors.New("invalid criticality")
	}

	if !oneOf(req.Authorization.Status, "pending", "approved", "expired", "revoked", "not_authorized") {
		return errors.New("invalid authorization.status")
	}

	if req.Tags == nil {
		req.Tags = []string{}
	}
	if req.Authorization.AllowedTargets == nil {
		req.Authorization.AllowedTargets = []string{}
	}
	if req.Authorization.ExcludedTargets == nil {
		req.Authorization.ExcludedTargets = []string{}
	}

	seenTags := make(map[string]bool)
	for _, tag := range req.Tags {
		if len(tag) > 64 || strings.TrimSpace(tag) == "" || seenTags[tag] {
			return errors.New("tags must be non-empty, unique strings no longer than 64 characters")
		}
		seenTags[tag] = true
	}

	for _, target := range req.Authorization.AllowedTargets {
		if !validateAssetTarget(target) {
			return fmt.Errorf("invalid allowed target URI: %s", target)
		}
	}
	for _, target := range req.Authorization.ExcludedTargets {
		if !validateAssetTarget(target) {
			return fmt.Errorf("invalid excluded target URI: %s", target)
		}
		if containsValue(req.Authorization.AllowedTargets, target) {
			return errors.New("a target cannot be both allowed and excluded")
		}
	}

	if req.Authorization.ExpiresAt != nil && !req.Authorization.ExpiresAt.After(time.Now()) {
		return errors.New("authorization.expires_at must be in the future")
	}

	// Approval identity and time are set by the server, never trusted from the request.
	if req.Authorization.Status == "approved" {
		if len(req.Authorization.AllowedTargets) == 0 {
			return errors.New("approved assets require at least one allowed target")
		}
		if adminEmail == "" {
			return errors.New("administrator identity is missing")
		}

		now := time.Now().UTC()
		req.Authorization.ApprovedBy = &adminEmail
		req.Authorization.ApprovedAt = &now
	} else {
		req.Authorization.ApprovedBy = nil
		req.Authorization.ApprovedAt = nil
	}

	return nil
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func assetJSONValues(req AssetRequest) (string, string, string, error) {
	tags, err := json.Marshal(req.Tags)
	if err != nil {
		return "", "", "", err
	}
	allowed, err := json.Marshal(req.Authorization.AllowedTargets)
	if err != nil {
		return "", "", "", err
	}
	excluded, err := json.Marshal(req.Authorization.ExcludedTargets)
	if err != nil {
		return "", "", "", err
	}

	return string(tags), string(allowed), string(excluded), nil
}

func writeAssetJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// CreateAssetHandler registers an asset in the authenticated administrator's tenant.
//
// @Summary      Create asset
// @Description  Registers an asset and its authorization scope in the administrator's tenant
// @Tags         Assets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        asset body AssetRequest true "Asset information and authorization"
// @Success      201 {object} AssetResponse
// @Failure      400 {string} string "Invalid asset"
// @Failure      401 {string} string "Authentication required"
// @Failure      403 {string} string "Administrator access required"
// @Failure      409 {string} string "Asset already exists"
// @Router       /assets [post]
func CreateAssetHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := assetIdentity(w, r, true)
	if !ok {
		return
	}

	req, err := decodeAssetRequest(w, r)
	if err != nil {
		http.Error(w, "Invalid JSON request: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := validateAssetRequest(&req, identity.TenantID, identity.Email); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tags, allowed, excluded, err := assetJSONValues(req)
	if err != nil {
		http.Error(w, "Could not encode asset data", http.StatusInternalServerError)
		return
	}

	query := `
		INSERT INTO assets (
			tenant_id, schema_version, asset_id, name,
			asset_type, environment, owner_team, criticality,
			tags, auth_status, auth_approved_by, auth_approved_at,
			auth_expires_at, auth_allowed_targets, auth_excluded_targets,
			auth_rules_of_engagement_ref
		)
		VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9::jsonb, $10, $11, $12, $13,
			$14::jsonb, $15::jsonb, $16
		)
		RETURNING ` + assetSelectColumns

	asset, err := scanAsset(database.DB.QueryRow(
		query,
		identity.TenantID,
		req.SchemaVersion,
		req.AssetID,
		req.Name,
		req.AssetType,
		req.Environment,
		req.OwnerTeam,
		req.Criticality,
		tags,
		req.Authorization.Status,
		req.Authorization.ApprovedBy,
		req.Authorization.ApprovedAt,
		req.Authorization.ExpiresAt,
		allowed,
		excluded,
		req.Authorization.RulesOfEngagementRef,
	))

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			http.Error(w, "Asset already exists in this tenant", http.StatusConflict)
			return
		}
		http.Error(w, "Could not create asset", http.StatusInternalServerError)
		return
	}

	writeAssetJSON(w, http.StatusCreated, asset)
}

// ListAssetsHandler returns assets belonging to the authenticated tenant.
//
// @Summary      List assets
// @Description  Returns paginated assets belonging to the authenticated tenant
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        limit query int false "Maximum results (1-100)"
// @Param        offset query int false "Results to skip"
// @Param        asset_type query string false "Filter by asset type"
// @Param        environment query string false "Filter by environment"
// @Param        criticality query string false "Filter by criticality"
// @Param        auth_status query string false "Filter by authorization status"
// @Success      200 {object} map[string]interface{}
// @Router       /assets [get]
func ListAssetsHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := assetIdentity(w, r, false)
	if !ok {
		return
	}

	params := r.URL.Query()
	limit, offset := 20, 0

	if value := params.Get("limit"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 100 {
			http.Error(w, "limit must be between 1 and 100", http.StatusBadRequest)
			return
		}
		limit = n
	}
	if value := params.Get("offset"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 {
			http.Error(w, "offset must be a non-negative integer", http.StatusBadRequest)
			return
		}
		offset = n
	}

	args := []any{identity.TenantID}
	where := "tenant_id = $1"

	filters := []struct {
		column string
		value  string
	}{
		{"asset_type", params.Get("asset_type")},
		{"environment", params.Get("environment")},
		{"criticality", params.Get("criticality")},
		{"auth_status", params.Get("auth_status")},
	}

	for _, filter := range filters {
		if strings.TrimSpace(filter.value) == "" {
			continue
		}
		args = append(args, strings.TrimSpace(filter.value))
		where += fmt.Sprintf(" AND %s = $%d", filter.column, len(args))
	}

	var total int64
	if err := database.DB.QueryRow(
		"SELECT COUNT(*) FROM assets WHERE "+where,
		args...,
	).Scan(&total); err != nil {
		http.Error(w, "Could not count assets", http.StatusInternalServerError)
		return
	}

	listArgs := append([]any(nil), args...)
	listArgs = append(listArgs, limit, offset)

	query := fmt.Sprintf(`
		SELECT %s
		FROM assets
		WHERE %s
		ORDER BY id DESC
		LIMIT $%d OFFSET $%d
	`, assetSelectColumns, where, len(listArgs)-1, len(listArgs))

	rows, err := database.DB.Query(query, listArgs...)
	if err != nil {
		http.Error(w, "Could not retrieve assets", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	items := make([]AssetResponse, 0)
	for rows.Next() {
		asset, err := scanAsset(rows)
		if err != nil {
			http.Error(w, "Could not read asset data", http.StatusInternalServerError)
			return
		}
		items = append(items, asset)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "Could not read asset data", http.StatusInternalServerError)
		return
	}

	writeAssetJSON(w, http.StatusOK, map[string]any{
		"data": items,
		"pagination": map[string]any{
			"limit": limit, "offset": offset, "total": total,
		},
	})
}

// GetAssetHandler retrieves one asset within the authenticated tenant.
//
// @Summary      Get asset
// @Description  Retrieves one asset by its public asset ID
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Asset ID"
// @Success      200 {object} AssetResponse
// @Failure      404 {string} string "Asset not found"
// @Router       /assets/{id} [get]
func GetAssetHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := assetIdentity(w, r, false)
	if !ok {
		return
	}

	assetID := strings.TrimSpace(r.PathValue("id"))
	if assetID == "" {
		http.Error(w, "Asset ID is required", http.StatusBadRequest)
		return
	}

	asset, err := scanAsset(database.DB.QueryRow(
		"SELECT "+assetSelectColumns+" FROM assets WHERE tenant_id = $1 AND asset_id = $2",
		identity.TenantID, assetID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "Asset not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Could not retrieve asset", http.StatusInternalServerError)
		return
	}

	writeAssetJSON(w, http.StatusOK, asset)
}

// UpdateAssetHandler updates an asset owned by the administrator's tenant.
//
// @Summary      Update asset
// @Description  Updates an asset without changing its tenant or public asset ID
// @Tags         Assets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Asset ID"
// @Param        asset body AssetRequest true "Updated asset information"
// @Success      200 {object} AssetResponse
// @Failure      400 {string} string "Invalid asset"
// @Failure      403 {string} string "Administrator access required"
// @Failure      404 {string} string "Asset not found"
// @Router       /assets/{id} [put]
func UpdateAssetHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := assetIdentity(w, r, true)
	if !ok {
		return
	}

	assetID := strings.TrimSpace(r.PathValue("id"))
	if assetID == "" {
		http.Error(w, "Asset ID is required", http.StatusBadRequest)
		return
	}

	req, err := decodeAssetRequest(w, r)
	if err != nil {
		http.Error(w, "Invalid JSON request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.AssetID != "" && req.AssetID != assetID {
		http.Error(w, "asset_id cannot be changed", http.StatusBadRequest)
		return
	}
	req.AssetID = assetID

	if err := validateAssetRequest(&req, identity.TenantID, identity.Email); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tags, allowed, excluded, err := assetJSONValues(req)
	if err != nil {
		http.Error(w, "Could not encode asset data", http.StatusInternalServerError)
		return
	}

	query := `
		UPDATE assets SET
			schema_version = $3,
			name = $4,
			asset_type = $5,
			environment = $6,
			owner_team = $7,
			criticality = $8,
			tags = $9::jsonb,
			auth_status = $10,
			auth_approved_by = $11,
			auth_approved_at = $12,
			auth_expires_at = $13,
			auth_allowed_targets = $14::jsonb,
			auth_excluded_targets = $15::jsonb,
			auth_rules_of_engagement_ref = $16,
			updated_at = NOW()
		WHERE tenant_id = $1 AND asset_id = $2
		RETURNING ` + assetSelectColumns

	asset, err := scanAsset(database.DB.QueryRow(
		query,
		identity.TenantID, assetID, req.SchemaVersion, req.Name,
		req.AssetType, req.Environment, req.OwnerTeam, req.Criticality,
		tags, req.Authorization.Status, req.Authorization.ApprovedBy,
		req.Authorization.ApprovedAt, req.Authorization.ExpiresAt,
		allowed, excluded, req.Authorization.RulesOfEngagementRef,
	))

	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "Asset not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Could not update asset", http.StatusInternalServerError)
		return
	}

	writeAssetJSON(w, http.StatusOK, asset)
}

// DeleteAssetHandler deletes an asset only if no finding references it.
//
// @Summary      Delete asset
// @Description  Deletes an asset from the authenticated tenant when it is not referenced by findings
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Asset ID"
// @Success      200 {object} map[string]string
// @Failure      403 {string} string "Administrator access required"
// @Failure      404 {string} string "Asset not found"
// @Failure      409 {string} string "Asset is referenced by findings"
// @Router       /assets/{id} [delete]
func DeleteAssetHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := assetIdentity(w, r, true)
	if !ok {
		return
	}

	assetID := strings.TrimSpace(r.PathValue("id"))
	if assetID == "" {
		http.Error(w, "Asset ID is required", http.StatusBadRequest)
		return
	}

	var deletedID string
	err := database.DB.QueryRow(
		"DELETE FROM assets WHERE tenant_id = $1 AND asset_id = $2 RETURNING asset_id",
		identity.TenantID, assetID,
	).Scan(&deletedID)

	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "Asset not found", http.StatusNotFound)
		return
	}

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			http.Error(w, "Asset cannot be deleted because findings reference it", http.StatusConflict)
			return
		}
		http.Error(w, "Could not delete asset", http.StatusInternalServerError)
		return
	}

	writeAssetJSON(w, http.StatusOK, map[string]string{
		"status":   "success",
		"asset_id": deletedID,
	})
}
