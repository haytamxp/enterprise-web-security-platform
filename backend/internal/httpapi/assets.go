package httpapi

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/auth"
	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/authz"
	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/contract"
	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/storage"
)

type AssetsAPI struct {
	Store *storage.Store
}

type assetAuthorizationResponse struct {
	Status               string     `json:"status"`
	ApprovedBy           *string    `json:"approved_by,omitempty"`
	ApprovedAt           *time.Time `json:"approved_at,omitempty"`
	ExpiresAt            *time.Time `json:"expires_at,omitempty"`
	AllowedTargets       []string   `json:"allowed_targets"`
	ExcludedTargets      []string   `json:"excluded_targets"`
	RulesOfEngagementRef *string    `json:"rules_of_engagement_ref,omitempty"`
}

type assetResponse struct {
	SchemaVersion string                     `json:"schema_version"`
	AssetID       string                     `json:"asset_id"`
	TenantID      string                     `json:"tenant_id"`
	Name          string                     `json:"name"`
	AssetType     string                     `json:"asset_type"`
	Environment   string                     `json:"environment"`
	OwnerTeam     string                     `json:"owner_team"`
	Criticality   string                     `json:"criticality"`
	Tags          []string                   `json:"tags"`
	Authorization assetAuthorizationResponse `json:"authorization"`
	CreatedAt     *time.Time                 `json:"created_at,omitempty"`
	UpdatedAt     *time.Time                 `json:"updated_at,omitempty"`
}

type assetListResponse struct {
	Items       []assetResponse `json:"items"`
	HasMore     bool            `json:"has_more"`
	NextAfterID *int64          `json:"next_after_id"`
}

// canonicalUUID validates a UUID and normalizes its hexadecimal characters.
// UUID comparison is case-insensitive.
func canonicalUUID(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))

	if len(value) != 36 {
		return "", false
	}

	if value[8] != '-' ||
		value[13] != '-' ||
		value[18] != '-' ||
		value[23] != '-' {
		return "", false
	}

	raw := strings.ReplaceAll(value, "-", "")

	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != 16 {
		return "", false
	}

	return value, true
}

func assetToResponse(asset contract.Asset) assetResponse {
	tags := asset.Tags
	if tags == nil {
		tags = []string{}
	}

	allowedTargets := asset.Authorization.AllowedTargets
	if allowedTargets == nil {
		allowedTargets = []string{}
	}

	excludedTargets := asset.Authorization.ExcludedTargets
	if excludedTargets == nil {
		excludedTargets = []string{}
	}

	return assetResponse{
		SchemaVersion: asset.SchemaVersion,
		AssetID:       asset.AssetID,
		TenantID:      asset.TenantID,
		Name:          asset.Name,
		AssetType:     asset.AssetType,
		Environment:   asset.Environment,
		OwnerTeam:     asset.OwnerTeam,
		Criticality:   asset.Criticality,
		Tags:          tags,
		Authorization: assetAuthorizationResponse{
			Status:               asset.Authorization.Status,
			ApprovedBy:           asset.Authorization.ApprovedBy,
			ApprovedAt:           asset.Authorization.ApprovedAt,
			ExpiresAt:            asset.Authorization.ExpiresAt,
			AllowedTargets:       allowedTargets,
			ExcludedTargets:      excludedTargets,
			RulesOfEngagementRef: asset.Authorization.RulesOfEngagementRef,
		},
		CreatedAt: asset.CreatedAt,
		UpdatedAt: asset.UpdatedAt,
	}
}

func authenticatedUserTenantID(
	w http.ResponseWriter,
	r *http.Request,
) (string, bool) {
	principal, ok := PrincipalFromContext(r.Context())

	if !ok || strings.TrimSpace(principal.UserID) == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "authenticated user identity required",
		})
		return "", false
	}

	tenantID, valid := canonicalUUID(principal.TenantID)
	if !valid {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "authenticated tenant identity is invalid",
		})
		return "", false
	}

	return tenantID, true
}

func (a *AssetsAPI) CreateAsset(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := authenticatedUserTenantID(w, r)
	if !ok {
		return
	}

	var req contract.AssetRequest

	if !decodeBody(w, r, &req) {
		return
	}

	asset, validationErrors := req.Validate()
	if len(validationErrors) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":   "invalid asset payload",
			"details": validationErrors,
		})
		return
	}

	bodyTenantID, valid := canonicalUUID(asset.TenantID)
	if !valid {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "tenant_id must be a valid UUID",
		})
		return
	}

	if bodyTenantID != tenantID {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "tenant_id does not match authenticated tenant",
		})
		return
	}

	// Never use a tenant identity supplied only by the request body.
	asset.TenantID = tenantID

	record, err := a.Store.InsertAsset(r.Context(), tenantID, asset)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrDuplicate):
			writeJSON(w, http.StatusConflict, map[string]string{
				"error": "duplicate asset_id",
			})
		case errors.Is(err, storage.ErrTenantRequired):
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "authenticated tenant identity required",
			})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "failed to store asset",
			})
		}
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"asset":  assetToResponse(record.Asset),
		"stored": true,
	})
}

func (a *AssetsAPI) GetAsset(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := authenticatedUserTenantID(w, r)
	if !ok {
		return
	}

	assetID := strings.TrimSpace(r.PathValue("asset_id"))
	if assetID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "asset_id is required",
		})
		return
	}

	record, err := a.Store.GetAssetByID(r.Context(), tenantID, assetID)
	if err != nil {
		if errors.Is(err, storage.ErrAssetNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{
				"error": "asset not found",
			})
			return
		}

		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to retrieve asset",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"asset": assetToResponse(record.Asset),
	})
}

func (a *AssetsAPI) ListAssets(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := authenticatedUserTenantID(w, r)
	if !ok {
		return
	}

	query := r.URL.Query()

	var afterID int64
	if rawAfterID := query.Get("after_id"); rawAfterID != "" {
		parsed, err := strconv.ParseInt(rawAfterID, 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "after_id must be a valid integer",
			})
			return
		}
		afterID = parsed
	}

	limit := 50
	if rawLimit := query.Get("limit"); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "limit must be a valid integer",
			})
			return
		}
		limit = parsed
	}

	records, hasMore, err := a.Store.ListAssets(
		r.Context(),
		tenantID,
		afterID,
		limit,
	)
	if err != nil {
		if errors.Is(err, storage.ErrInvalidPagination) {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "invalid pagination parameters",
			})
			return
		}

		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to list assets",
		})
		return
	}

	items := make([]assetResponse, 0, len(records))
	for _, record := range records {
		items = append(items, assetToResponse(record.Asset))
	}

	var nextAfterID *int64
	if hasMore && len(records) > 0 {
		value := records[len(records)-1].ID
		nextAfterID = &value
	}

	writeJSON(w, http.StatusOK, assetListResponse{
		Items:       items,
		HasMore:     hasMore,
		NextAfterID: nextAfterID,
	})
}

// RegisterAssets registers human-user Asset endpoints protected by JWT and RBAC.
func RegisterAssets(
	mux *http.ServeMux,
	store *storage.Store,
	tokens *auth.TokenManager,
) {
	api := &AssetsAPI{Store: store}

	mux.Handle(
		"POST /api/v1/assets",
		AuthMiddleware(
			tokens,
			AuthorizationMiddleware(
				authz.PermissionAssetsManage,
				http.HandlerFunc(api.CreateAsset),
			),
		),
	)

	mux.Handle(
		"GET /api/v1/assets",
		AuthMiddleware(
			tokens,
			AuthorizationMiddleware(
				authz.PermissionAssetsRead,
				http.HandlerFunc(api.ListAssets),
			),
		),
	)

	mux.Handle(
		"GET /api/v1/assets/{asset_id}",
		AuthMiddleware(
			tokens,
			AuthorizationMiddleware(
				authz.PermissionAssetsRead,
				http.HandlerFunc(api.GetAsset),
			),
		),
	)
}
