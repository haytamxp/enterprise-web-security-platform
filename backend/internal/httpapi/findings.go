package httpapi

import (
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

type FindingsAPI struct {
	Store *storage.Store
}

type findingCVSSResponse struct {
	Version string  `json:"version"`
	Score   float64 `json:"score"`
	Vector  *string `json:"vector,omitempty"`
}

// This response intentionally excludes storage_ref.
// Evidence access requires a separate authorization check.
type findingEvidenceResponse struct {
	EvidenceID     string  `json:"evidence_id"`
	Classification string  `json:"classification"`
	Redacted       bool    `json:"redacted"`
	SHA256         *string `json:"sha256,omitempty"`
	MediaType      *string `json:"media_type,omitempty"`
}

type findingResponse struct {
	SchemaVersion         string                    `json:"schema_version"`
	FindingID             string                    `json:"finding_id"`
	AssetID               string                    `json:"asset_id"`
	TenantID              string                    `json:"tenant_id"`
	Source                string                    `json:"source"`
	Title                 string                    `json:"title"`
	Description           *string                   `json:"description,omitempty"`
	Status                string                    `json:"status"`
	Severity              string                    `json:"severity"`
	Confidence            float64                   `json:"confidence"`
	CVSS                  *findingCVSSResponse      `json:"cvss,omitempty"`
	CWEIDs                []string                  `json:"cwe_ids"`
	References            []string                  `json:"references"`
	EvidenceRefs          []findingEvidenceResponse `json:"evidence_refs"`
	RemediationGuidance   *string                   `json:"remediation_guidance,omitempty"`
	DetectedAt            time.Time                 `json:"detected_at"`
	LastObservedAt        *time.Time                `json:"last_observed_at,omitempty"`
	DeduplicationKey      *string                   `json:"deduplication_key,omitempty"`
	ReferencesToIncidents []string                  `json:"references_to_incidents"`
	CreatedAt             time.Time                 `json:"created_at"`
	UpdatedAt             time.Time                 `json:"updated_at"`
}

type findingListResponse struct {
	Items       []findingResponse `json:"items"`
	HasMore     bool              `json:"has_more"`
	NextAfterID *int64            `json:"next_after_id"`
}

func findingToResponse(record storage.FindingRecord) findingResponse {
	finding := record.Finding

	tenantID := ""
	if finding.TenantID != nil {
		tenantID = *finding.TenantID
	}

	cweIDs := finding.CWEIDs
	if cweIDs == nil {
		cweIDs = []string{}
	}

	references := finding.References
	if references == nil {
		references = []string{}
	}

	incidentReferences := finding.ReferencesToIncidents
	if incidentReferences == nil {
		incidentReferences = []string{}
	}

	evidenceRefs := make(
		[]findingEvidenceResponse,
		0,
		len(finding.EvidenceRefs),
	)

	for _, evidence := range finding.EvidenceRefs {
		evidenceRefs = append(evidenceRefs, findingEvidenceResponse{
			EvidenceID:     evidence.EvidenceID,
			Classification: evidence.Classification,
			Redacted:       evidence.Redacted,
			SHA256:         evidence.SHA256,
			MediaType:      evidence.MediaType,
		})
	}

	var cvss *findingCVSSResponse

	if finding.CVSS != nil {
		cvss = &findingCVSSResponse{
			Version: finding.CVSS.Version,
			Score:   finding.CVSS.Score,
			Vector:  finding.CVSS.Vector,
		}
	}

	return findingResponse{
		SchemaVersion:         finding.SchemaVersion,
		FindingID:             finding.FindingID,
		AssetID:               finding.AssetID,
		TenantID:              tenantID,
		Source:                finding.Source,
		Title:                 finding.Title,
		Description:           finding.Description,
		Status:                finding.Status,
		Severity:              finding.Severity,
		Confidence:            finding.Confidence,
		CVSS:                  cvss,
		CWEIDs:                cweIDs,
		References:            references,
		EvidenceRefs:          evidenceRefs,
		RemediationGuidance:   finding.RemediationGuidance,
		DetectedAt:            finding.DetectedAt,
		LastObservedAt:        finding.LastObservedAt,
		DeduplicationKey:      finding.DeduplicationKey,
		ReferencesToIncidents: incidentReferences,
		CreatedAt:             record.CreatedAt,
		UpdatedAt:             record.UpdatedAt,
	}
}

func (a *FindingsAPI) CreateFinding(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := authenticatedUserTenantID(w, r)
	if !ok {
		return
	}

	var req contract.FindingRequest

	if !decodeBody(w, r, &req) {
		return
	}

	finding, validationErrors := req.Validate()
	if len(validationErrors) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":   "invalid finding payload",
			"details": validationErrors,
		})
		return
	}

	// tenant_id is optional in the contract. If supplied, it must
	// match the authenticated principal and must never override it.
	if finding.TenantID != nil {
		bodyTenantID, valid := canonicalUUID(*finding.TenantID)
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
	}

	finding.TenantID = &tenantID

	record, err := a.Store.InsertFinding(
		r.Context(),
		tenantID,
		finding,
	)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrDuplicate):
			writeJSON(w, http.StatusConflict, map[string]string{
				"error": "duplicate finding_id",
			})

		case errors.Is(err, storage.ErrUnknownAsset):
			writeJSON(w, http.StatusNotFound, map[string]string{
				"error": "referenced asset not found",
			})

		case errors.Is(err, storage.ErrFindingTenantMismatch):
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "finding tenant does not match authenticated tenant",
			})

		case errors.Is(err, storage.ErrTenantRequired):
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "authenticated tenant identity required",
			})

		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "failed to store finding",
			})
		}
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"finding": findingToResponse(record),
		"stored":  true,
	})
}

func (a *FindingsAPI) GetFinding(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := authenticatedUserTenantID(w, r)
	if !ok {
		return
	}

	findingID := strings.TrimSpace(r.PathValue("finding_id"))
	if findingID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "finding_id is required",
		})
		return
	}

	record, err := a.Store.GetFindingByID(
		r.Context(),
		tenantID,
		findingID,
	)
	if err != nil {
		if errors.Is(err, storage.ErrFindingNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{
				"error": "finding not found",
			})
			return
		}

		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to retrieve finding",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"finding": findingToResponse(record),
	})
}

func (a *FindingsAPI) ListFindings(w http.ResponseWriter, r *http.Request) {
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

	records, hasMore, err := a.Store.ListFindings(
		r.Context(),
		tenantID,
		afterID,
		limit,
	)
	if err != nil {
		if errors.Is(err, storage.ErrInvalidFindingPagination) {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "invalid pagination parameters",
			})
			return
		}

		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to list findings",
		})
		return
	}

	items := make([]findingResponse, 0, len(records))

	for _, record := range records {
		items = append(items, findingToResponse(record))
	}

	var nextAfterID *int64

	if hasMore && len(records) > 0 {
		value := records[len(records)-1].ID
		nextAfterID = &value
	}

	writeJSON(w, http.StatusOK, findingListResponse{
		Items:       items,
		HasMore:     hasMore,
		NextAfterID: nextAfterID,
	})
}

// RegisterFindings registers human-user Finding endpoints protected by JWT and RBAC.
func RegisterFindings(
	mux *http.ServeMux,
	store *storage.Store,
	tokens *auth.TokenManager,
) {
	api := &FindingsAPI{Store: store}

	mux.Handle(
		"POST /api/v1/findings",
		AuthMiddleware(
			tokens,
			AuthorizationMiddleware(
				authz.PermissionFindingsReview,
				http.HandlerFunc(api.CreateFinding),
			),
		),
	)

	mux.Handle(
		"GET /api/v1/findings",
		AuthMiddleware(
			tokens,
			AuthorizationMiddleware(
				authz.PermissionFindingsRead,
				http.HandlerFunc(api.ListFindings),
			),
		),
	)

	mux.Handle(
		"GET /api/v1/findings/{finding_id}",
		AuthMiddleware(
			tokens,
			AuthorizationMiddleware(
				authz.PermissionFindingsRead,
				http.HandlerFunc(api.GetFinding),
			),
		),
	)
}
