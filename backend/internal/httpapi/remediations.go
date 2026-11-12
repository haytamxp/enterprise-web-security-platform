package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/auth"
	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/authz"
	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/storage"
)

type RemediationsAPI struct{ Store *storage.Store }

type createRemediationRequest struct {
	RemediationID string     `json:"remediation_id"`
	FindingID     string     `json:"finding_id"`
	Title         string     `json:"title"`
	Description   *string    `json:"description,omitempty"`
	Priority      string     `json:"priority"`
	AssignedTo    *string    `json:"assigned_to,omitempty"`
	DueAt         *time.Time `json:"due_at,omitempty"`
}

type updateRemediationRequest struct {
	Status     *string    `json:"status,omitempty"`
	AssignedTo *string    `json:"assigned_to,omitempty"`
	DueAt      *time.Time `json:"due_at,omitempty"`
}

type createRetestRequest struct {
	RetestID     string    `json:"retest_id"`
	Status       string    `json:"status"`
	Summary      string    `json:"summary"`
	EvidenceRefs []string  `json:"evidence_refs"`
	TestedAt     time.Time `json:"tested_at"`
}

type remediationListResponse struct {
	Items       []storage.RemediationRecord `json:"items"`
	HasMore     bool                        `json:"has_more"`
	NextAfterID *int64                      `json:"next_after_id"`
}

func authenticatedPrincipal(w http.ResponseWriter, r *http.Request) (Principal, string, string, bool) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok || strings.TrimSpace(principal.UserID) == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authenticated user identity required"})
		return Principal{}, "", "", false
	}
	tenantID, valid := canonicalUUID(principal.TenantID)
	if !valid {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authenticated tenant identity is invalid"})
		return Principal{}, "", "", false
	}
	userID, valid := canonicalUUID(principal.UserID)
	if !valid {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authenticated user identity is invalid"})
		return Principal{}, "", "", false
	}
	return principal, tenantID, userID, true
}

func remediationError(w http.ResponseWriter, err error, action string) {
	switch {
	case errors.Is(err, storage.ErrRemediationNotFound), errors.Is(err, storage.ErrFindingNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "remediation or finding not found"})
	case errors.Is(err, storage.ErrFindingNotActionable), errors.Is(err, storage.ErrInvalidRemediationState):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "operation is not valid for the current finding or remediation state"})
	case errors.Is(err, storage.ErrInvalidAssignee):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "assigned user must be active and belong to this tenant"})
	case errors.Is(err, storage.ErrDuplicate), errors.Is(err, storage.ErrDuplicateRetest):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "duplicate remediation_id or retest_id"})
	case errors.Is(err, storage.ErrInvalidRemediation), errors.Is(err, storage.ErrInvalidRetest):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid " + action + " payload"})
	case errors.Is(err, storage.ErrInvalidRemediationPage):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid pagination parameters"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to " + action})
	}
}

func (a *RemediationsAPI) CreateRemediation(w http.ResponseWriter, r *http.Request) {
	_, tenantID, userID, ok := authenticatedPrincipal(w, r)
	if !ok {
		return
	}
	var req createRemediationRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.AssignedTo != nil {
		id, valid := canonicalUUID(*req.AssignedTo)
		if !valid {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "assigned_to must be a valid UUID"})
			return
		}
		req.AssignedTo = &id
	}
	record, err := a.Store.CreateRemediation(r.Context(), tenantID, userID, storage.CreateRemediationParams{
		RemediationID: req.RemediationID, FindingID: req.FindingID, Title: req.Title,
		Description: req.Description, Priority: req.Priority, AssignedTo: req.AssignedTo, DueAt: req.DueAt,
	})
	if err != nil {
		remediationError(w, err, "create remediation")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"remediation": record, "stored": true})
}

func (a *RemediationsAPI) GetRemediation(w http.ResponseWriter, r *http.Request) {
	_, tenantID, _, ok := authenticatedPrincipal(w, r)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.PathValue("remediation_id"))
	record, err := a.Store.GetRemediationByID(r.Context(), tenantID, id)
	if err != nil {
		remediationError(w, err, "retrieve remediation")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"remediation": record})
}

func (a *RemediationsAPI) ListRemediations(w http.ResponseWriter, r *http.Request) {
	_, tenantID, _, ok := authenticatedPrincipal(w, r)
	if !ok {
		return
	}
	query := r.URL.Query()
	var afterID int64
	if raw := query.Get("after_id"); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "after_id must be a valid integer"})
			return
		}
		afterID = value
	}
	limit := 50
	if raw := query.Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be a valid integer"})
			return
		}
		limit = value
	}
	records, hasMore, err := a.Store.ListRemediations(r.Context(), tenantID, afterID, limit)
	if err != nil {
		remediationError(w, err, "list remediations")
		return
	}
	var next *int64
	if hasMore && len(records) > 0 {
		value := records[len(records)-1].ID
		next = &value
	}
	writeJSON(w, http.StatusOK, remediationListResponse{Items: records, HasMore: hasMore, NextAfterID: next})
}

func (a *RemediationsAPI) UpdateRemediation(w http.ResponseWriter, r *http.Request) {
	_, tenantID, _, ok := authenticatedPrincipal(w, r)
	if !ok {
		return
	}
	var req updateRemediationRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Status == nil && req.AssignedTo == nil && req.DueAt == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provide status, assigned_to, or due_at"})
		return
	}
	if req.AssignedTo != nil {
		id, valid := canonicalUUID(*req.AssignedTo)
		if !valid {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "assigned_to must be a valid UUID"})
			return
		}
		req.AssignedTo = &id
	}
	record, err := a.Store.UpdateRemediation(r.Context(), tenantID, r.PathValue("remediation_id"), storage.UpdateRemediationParams{
		Status: req.Status, AssignedTo: req.AssignedTo, DueAt: req.DueAt,
	})
	if err != nil {
		remediationError(w, err, "update remediation")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"remediation": record})
}

func (a *RemediationsAPI) CreateRetest(w http.ResponseWriter, r *http.Request) {
	_, tenantID, userID, ok := authenticatedPrincipal(w, r)
	if !ok {
		return
	}
	var req createRetestRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.TestedAt.IsZero() {
		req.TestedAt = time.Now().UTC()
	}
	if req.EvidenceRefs == nil {
		req.EvidenceRefs = []string{}
	}
	record, err := a.Store.CreateRetest(r.Context(), tenantID, userID, r.PathValue("remediation_id"), storage.CreateRetestParams{
		RetestID: req.RetestID, Status: req.Status, Summary: req.Summary,
		EvidenceRefs: req.EvidenceRefs, TestedAt: req.TestedAt,
	})
	if err != nil {
		remediationError(w, err, "create retest")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"retest": record, "stored": true})
}

func (a *RemediationsAPI) ListRetests(w http.ResponseWriter, r *http.Request) {
	_, tenantID, _, ok := authenticatedPrincipal(w, r)
	if !ok {
		return
	}
	records, err := a.Store.ListRetests(r.Context(), tenantID, r.PathValue("remediation_id"))
	if err != nil {
		remediationError(w, err, "list retests")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": records})
}

func RegisterRemediations(mux *http.ServeMux, store *storage.Store, tokens *auth.TokenManager) {
	api := &RemediationsAPI{Store: store}
	mux.Handle("POST /api/v1/remediations", AuthMiddleware(tokens, AuthorizationMiddleware(authz.PermissionRemediationManage, http.HandlerFunc(api.CreateRemediation))))
	mux.Handle("GET /api/v1/remediations", AuthMiddleware(tokens, AuthorizationMiddleware(authz.PermissionRemediationRead, http.HandlerFunc(api.ListRemediations))))
	mux.Handle("GET /api/v1/remediations/{remediation_id}", AuthMiddleware(tokens, AuthorizationMiddleware(authz.PermissionRemediationRead, http.HandlerFunc(api.GetRemediation))))
	mux.Handle("PATCH /api/v1/remediations/{remediation_id}", AuthMiddleware(tokens, AuthorizationMiddleware(authz.PermissionRemediationManage, http.HandlerFunc(api.UpdateRemediation))))
	mux.Handle("POST /api/v1/remediations/{remediation_id}/retests", AuthMiddleware(tokens, AuthorizationMiddleware(authz.PermissionRemediationExecute, http.HandlerFunc(api.CreateRetest))))
	mux.Handle("GET /api/v1/remediations/{remediation_id}/retests", AuthMiddleware(tokens, AuthorizationMiddleware(authz.PermissionRemediationRead, http.HandlerFunc(api.ListRetests))))
}
