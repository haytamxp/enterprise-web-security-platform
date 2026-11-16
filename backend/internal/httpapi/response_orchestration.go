package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/auth"
	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/authz"
	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/storage"
)

const (
	responseOrchestrationDefaultLimit = 50
	responseOrchestrationMaxLimit     = 100
	responseOrchestrationMaxBody      = 1 << 20
)

type ResponseOrchestrationAPI struct {
	Store *storage.Store
}

// RegisterResponseOrchestration registers tenant-scoped response orchestration
// endpoints. Human callers can request and manage runs, but cannot submit action
// execution results; completion must be reported by a trusted executor.
func RegisterResponseOrchestration(mux *http.ServeMux, store *storage.Store, tokens *auth.TokenManager) {
	api := &ResponseOrchestrationAPI{Store: store}
	register := func(pattern string, permission authz.Permission, handler http.HandlerFunc) {
		mux.Handle(pattern, AuthMiddleware(tokens, AuthorizationMiddleware(permission, handler)))
	}

	// Playbook definitions are security-sensitive configuration. Only platform
	// administrators can create or modify them with the current permission model.
	register("POST /api/v1/response-playbooks", authz.PermissionPlatformManage, api.CreatePlaybook)
	register("GET /api/v1/response-playbooks", authz.PermissionIncidentsRead, api.ListPlaybooks)
	register("GET /api/v1/response-playbooks/{playbook_id}", authz.PermissionIncidentsRead, api.GetPlaybook)
	register("PATCH /api/v1/response-playbooks/{playbook_id}", authz.PermissionPlatformManage, api.UpdatePlaybook)
	register("POST /api/v1/response-playbooks/{playbook_id}/actions", authz.PermissionPlatformManage, api.CreatePlaybookAction)
	register("GET /api/v1/response-playbooks/{playbook_id}/actions", authz.PermissionIncidentsRespond, api.ListPlaybookActions)
	register("PATCH /api/v1/response-playbook-actions/{response_action_id}", authz.PermissionPlatformManage, api.UpdatePlaybookAction)

	register("POST /api/v1/response-runs", authz.PermissionIncidentsRespond, api.CreateRun)
	register("GET /api/v1/response-runs", authz.PermissionIncidentsRead, api.ListRuns)
	register("GET /api/v1/response-runs/{response_run_id}", authz.PermissionIncidentsRead, api.GetRun)
	register("POST /api/v1/response-runs/{response_run_id}/start", authz.PermissionIncidentsRespond, api.StartRun)
	register("POST /api/v1/response-runs/{response_run_id}/finalize", authz.PermissionIncidentsRespond, api.FinalizeRun)
	register("POST /api/v1/response-runs/{response_run_id}/cancel", authz.PermissionIncidentsRespond, api.CancelRun)

	register("GET /api/v1/response-approvals", authz.PermissionIncidentsRead, api.ListApprovals)
	register("GET /api/v1/response-approvals/{approval_id}", authz.PermissionIncidentsRead, api.GetApproval)
	register("POST /api/v1/response-approvals/{approval_id}/decision", authz.PermissionActionsApprove, api.DecideApproval)

	// Execution records can contain operational config snapshots, so only responders
	// and administrators may inspect them. Execution transitions remain internal to
	// the trusted executor and are deliberately not exposed as human HTTP actions.
	register("GET /api/v1/response-runs/{response_run_id}/executions", authz.PermissionIncidentsRespond, api.ListExecutions)
	register("GET /api/v1/response-action-executions/{action_execution_id}", authz.PermissionIncidentsRespond, api.GetExecution)
}

func responsePrincipal(w http.ResponseWriter, r *http.Request) (Principal, bool) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok || strings.TrimSpace(principal.UserID) == "" || strings.TrimSpace(principal.TenantID) == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authenticated principal is unavailable"})
		return Principal{}, false
	}
	return principal, true
}

func readResponseJSON(w http.ResponseWriter, r *http.Request, dst any) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, responseOrchestrationMaxBody))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or oversized JSON request body"})
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON request body"})
		return nil, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request body must contain one JSON value"})
		return nil, false
	}
	return body, true
}

func decodeResponseJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	_, ok := readResponseJSON(w, r, dst)
	return ok
}

func decodeResponseJSONWithRaw(w http.ResponseWriter, r *http.Request, dst any) (map[string]json.RawMessage, bool) {
	body, ok := readResponseJSON(w, r, dst)
	if !ok {
		return nil, false
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON request body"})
		return nil, false
	}
	return raw, true
}

func responsePagination(r *http.Request) (int64, int, error) {
	afterID := int64(0)
	limit := responseOrchestrationDefaultLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("cursor")); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value < 0 {
			return 0, 0, storage.ErrInvalidPagination
		}
		afterID = value
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > responseOrchestrationMaxLimit {
			return 0, 0, storage.ErrInvalidPagination
		}
		limit = value
	}
	return afterID, limit, nil
}

func writeResponsePage[T any](w http.ResponseWriter, records []T, hasMore bool, nextCursor string) {
	if records == nil {
		records = []T{}
	}
	var cursor any
	if hasMore && nextCursor != "" {
		cursor = nextCursor
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":       records,
		"has_more":    hasMore,
		"next_cursor": cursor,
	})
}

func writeResponseOrchestrationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, storage.ErrResponsePlaybookNotFound),
		errors.Is(err, storage.ErrResponseActionNotFound),
		errors.Is(err, storage.ErrResponseRunNotFound),
		errors.Is(err, storage.ErrResponseIncidentNotFound),
		errors.Is(err, storage.ErrResponseApprovalNotFound),
		errors.Is(err, storage.ErrResponseExecutionNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "response orchestration resource not found"})
	case errors.Is(err, storage.ErrInvalidResponsePlaybook),
		errors.Is(err, storage.ErrInvalidResponseAction),
		errors.Is(err, storage.ErrInvalidResponseRun),
		errors.Is(err, storage.ErrInvalidResponseExecution),
		errors.Is(err, storage.ErrInvalidResponseExecutionState),
		errors.Is(err, storage.ErrInvalidPagination):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid response orchestration input"})
	case errors.Is(err, storage.ErrDuplicateResponsePlaybook),
		errors.Is(err, storage.ErrDuplicateResponseAction),
		errors.Is(err, storage.ErrDuplicateResponseRun),
		errors.Is(err, storage.ErrResponseIdempotencyConflict),
		errors.Is(err, storage.ErrResponsePlaybookActive),
		errors.Is(err, storage.ErrResponsePlaybookNoActions),
		errors.Is(err, storage.ErrResponseApprovalAlreadyDecided),
		errors.Is(err, storage.ErrResponseRunNotQueued),
		errors.Is(err, storage.ErrResponseRunNotRunning),
		errors.Is(err, storage.ErrResponseExecutionAttemptsLimit),
		errors.Is(err, storage.ErrResponseRunHasPendingActions),
		errors.Is(err, storage.ErrResponseRunAlreadyFinished):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "response orchestration state conflict"})
	case errors.Is(err, storage.ErrInvalidResponseActor), errors.Is(err, storage.ErrInvalidResponseApprover), errors.Is(err, storage.ErrResponseSelfApproval):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "user is not authorized for this tenant operation"})
	case errors.Is(err, storage.ErrTenantRequired):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "tenant context is required"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "response orchestration operation failed"})
	}
}

func (api *ResponseOrchestrationAPI) CreatePlaybook(w http.ResponseWriter, r *http.Request) {
	principal, ok := responsePrincipal(w, r)
	if !ok {
		return
	}
	var body struct {
		PlaybookID  string  `json:"playbook_id"`
		Name        string  `json:"name"`
		Description *string `json:"description"`
	}
	if !decodeResponseJSON(w, r, &body) {
		return
	}
	record, err := api.Store.CreateResponsePlaybook(r.Context(), principal.TenantID, principal.UserID, storage.CreateResponsePlaybookParams{
		PlaybookID: body.PlaybookID, Name: body.Name, Description: body.Description,
	})
	if err != nil {
		writeResponseOrchestrationError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, record)
}

func (api *ResponseOrchestrationAPI) ListPlaybooks(w http.ResponseWriter, r *http.Request) {
	principal, ok := responsePrincipal(w, r)
	if !ok {
		return
	}
	afterID, limit, err := responsePagination(r)
	if err != nil {
		writeResponseOrchestrationError(w, err)
		return
	}
	records, hasMore, err := api.Store.ListResponsePlaybooks(r.Context(), principal.TenantID, afterID, limit)
	if err != nil {
		writeResponseOrchestrationError(w, err)
		return
	}
	cursor := ""
	if hasMore && len(records) > 0 {
		cursor = strconv.FormatInt(records[len(records)-1].ID, 10)
	}
	writeResponsePage(w, records, hasMore, cursor)
}

func (api *ResponseOrchestrationAPI) GetPlaybook(w http.ResponseWriter, r *http.Request) {
	principal, ok := responsePrincipal(w, r)
	if !ok {
		return
	}
	record, err := api.Store.GetResponsePlaybookByID(r.Context(), principal.TenantID, r.PathValue("playbook_id"))
	if err != nil {
		writeResponseOrchestrationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (api *ResponseOrchestrationAPI) UpdatePlaybook(w http.ResponseWriter, r *http.Request) {
	principal, ok := responsePrincipal(w, r)
	if !ok {
		return
	}
	var body struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		IsActive    *bool   `json:"is_active"`
	}
	raw, ok := decodeResponseJSONWithRaw(w, r, &body)
	if !ok {
		return
	}
	_, descriptionSet := raw["description"]
	record, err := api.Store.UpdateResponsePlaybook(r.Context(), principal.TenantID, r.PathValue("playbook_id"), principal.UserID, storage.UpdateResponsePlaybookParams{
		Name: body.Name, Description: body.Description, DescriptionSet: descriptionSet, IsActive: body.IsActive,
	})
	if err != nil {
		writeResponseOrchestrationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (api *ResponseOrchestrationAPI) CreatePlaybookAction(w http.ResponseWriter, r *http.Request) {
	principal, ok := responsePrincipal(w, r)
	if !ok {
		return
	}
	var body struct {
		ResponseActionID string          `json:"response_action_id"`
		ActionKey        string          `json:"action_key"`
		StepOrder        int             `json:"step_order"`
		ActionType       string          `json:"action_type"`
		RequiresApproval bool            `json:"requires_approval"`
		IsEnabled        bool            `json:"is_enabled"`
		Config           json.RawMessage `json:"config"`
	}
	if !decodeResponseJSON(w, r, &body) {
		return
	}
	record, err := api.Store.CreateResponsePlaybookAction(r.Context(), principal.TenantID, storage.CreateResponsePlaybookActionParams{
		ResponseActionID: body.ResponseActionID, PlaybookID: r.PathValue("playbook_id"), ActionKey: body.ActionKey,
		StepOrder: body.StepOrder, ActionType: body.ActionType, RequiresApproval: body.RequiresApproval,
		IsEnabled: body.IsEnabled, Config: body.Config,
	})
	if err != nil {
		writeResponseOrchestrationError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, record)
}

func (api *ResponseOrchestrationAPI) ListPlaybookActions(w http.ResponseWriter, r *http.Request) {
	principal, ok := responsePrincipal(w, r)
	if !ok {
		return
	}
	records, err := api.Store.ListResponsePlaybookActions(r.Context(), principal.TenantID, r.PathValue("playbook_id"))
	if err != nil {
		writeResponseOrchestrationError(w, err)
		return
	}
	if records == nil {
		records = []storage.ResponsePlaybookActionRecord{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": records})
}

func (api *ResponseOrchestrationAPI) UpdatePlaybookAction(w http.ResponseWriter, r *http.Request) {
	principal, ok := responsePrincipal(w, r)
	if !ok {
		return
	}
	var body struct {
		ActionKey        *string         `json:"action_key"`
		StepOrder        *int            `json:"step_order"`
		ActionType       *string         `json:"action_type"`
		RequiresApproval *bool           `json:"requires_approval"`
		IsEnabled        *bool           `json:"is_enabled"`
		Config           json.RawMessage `json:"config"`
	}
	raw, ok := decodeResponseJSONWithRaw(w, r, &body)
	if !ok {
		return
	}
	_, configSet := raw["config"]
	record, err := api.Store.UpdateResponsePlaybookAction(r.Context(), principal.TenantID, r.PathValue("response_action_id"), storage.UpdateResponsePlaybookActionParams{
		ActionKey: body.ActionKey, StepOrder: body.StepOrder, ActionType: body.ActionType,
		RequiresApproval: body.RequiresApproval, IsEnabled: body.IsEnabled, Config: body.Config, ConfigSet: configSet,
	})
	if err != nil {
		writeResponseOrchestrationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (api *ResponseOrchestrationAPI) CreateRun(w http.ResponseWriter, r *http.Request) {
	principal, ok := responsePrincipal(w, r)
	if !ok {
		return
	}
	var body struct {
		ResponseRunID  string  `json:"response_run_id"`
		IncidentID     string  `json:"incident_id"`
		PlaybookID     string  `json:"playbook_id"`
		IdempotencyKey string  `json:"idempotency_key"`
		RequestReason  *string `json:"request_reason"`
	}
	if !decodeResponseJSON(w, r, &body) {
		return
	}
	if body.IdempotencyKey == "" {
		body.IdempotencyKey = r.Header.Get("Idempotency-Key")
	}
	record, err := api.Store.CreateResponseRun(r.Context(), principal.TenantID, principal.UserID, storage.CreateResponseRunParams{
		ResponseRunID: body.ResponseRunID, IncidentID: body.IncidentID, PlaybookID: body.PlaybookID,
		IdempotencyKey: body.IdempotencyKey, RequestReason: body.RequestReason,
	})
	if err != nil {
		writeResponseOrchestrationError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, record)
}

func (api *ResponseOrchestrationAPI) ListRuns(w http.ResponseWriter, r *http.Request) {
	principal, ok := responsePrincipal(w, r)
	if !ok {
		return
	}
	afterID, limit, err := responsePagination(r)
	if err != nil {
		writeResponseOrchestrationError(w, err)
		return
	}
	records, hasMore, err := api.Store.ListResponseRuns(r.Context(), principal.TenantID, afterID, limit)
	if err != nil {
		writeResponseOrchestrationError(w, err)
		return
	}
	cursor := ""
	if hasMore && len(records) > 0 {
		cursor = strconv.FormatInt(records[len(records)-1].ID, 10)
	}
	writeResponsePage(w, records, hasMore, cursor)
}

func (api *ResponseOrchestrationAPI) GetRun(w http.ResponseWriter, r *http.Request) {
	principal, ok := responsePrincipal(w, r)
	if !ok {
		return
	}
	record, err := api.Store.GetResponseRunByID(r.Context(), principal.TenantID, r.PathValue("response_run_id"))
	if err != nil {
		writeResponseOrchestrationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (api *ResponseOrchestrationAPI) StartRun(w http.ResponseWriter, r *http.Request) {
	principal, ok := responsePrincipal(w, r)
	if !ok {
		return
	}
	record, err := api.Store.StartResponseRun(r.Context(), principal.TenantID, r.PathValue("response_run_id"))
	if err != nil {
		writeResponseOrchestrationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (api *ResponseOrchestrationAPI) FinalizeRun(w http.ResponseWriter, r *http.Request) {
	principal, ok := responsePrincipal(w, r)
	if !ok {
		return
	}
	record, err := api.Store.FinalizeResponseRun(r.Context(), principal.TenantID, r.PathValue("response_run_id"))
	if err != nil {
		writeResponseOrchestrationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (api *ResponseOrchestrationAPI) CancelRun(w http.ResponseWriter, r *http.Request) {
	principal, ok := responsePrincipal(w, r)
	if !ok {
		return
	}
	record, err := api.Store.CancelResponseRun(r.Context(), principal.TenantID, r.PathValue("response_run_id"), principal.UserID)
	if err != nil {
		writeResponseOrchestrationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (api *ResponseOrchestrationAPI) ListApprovals(w http.ResponseWriter, r *http.Request) {
	principal, ok := responsePrincipal(w, r)
	if !ok {
		return
	}
	afterID, limit, err := responsePagination(r)
	if err != nil {
		writeResponseOrchestrationError(w, err)
		return
	}
	records, hasMore, err := api.Store.ListResponseApprovals(r.Context(), principal.TenantID, r.URL.Query().Get("status"), afterID, limit)
	if err != nil {
		writeResponseOrchestrationError(w, err)
		return
	}
	cursor := ""
	if hasMore && len(records) > 0 {
		cursor = strconv.FormatInt(records[len(records)-1].ID, 10)
	}
	writeResponsePage(w, records, hasMore, cursor)
}

func (api *ResponseOrchestrationAPI) GetApproval(w http.ResponseWriter, r *http.Request) {
	principal, ok := responsePrincipal(w, r)
	if !ok {
		return
	}
	record, err := api.Store.GetResponseApprovalByID(r.Context(), principal.TenantID, r.PathValue("approval_id"))
	if err != nil {
		writeResponseOrchestrationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (api *ResponseOrchestrationAPI) DecideApproval(w http.ResponseWriter, r *http.Request) {
	principal, ok := responsePrincipal(w, r)
	if !ok {
		return
	}
	var body struct {
		Decision     string  `json:"decision"`
		DecisionNote *string `json:"decision_note"`
	}
	if !decodeResponseJSON(w, r, &body) {
		return
	}
	decision := strings.ToLower(strings.TrimSpace(body.Decision))
	if decision != "approve" && decision != "reject" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "decision must be approve or reject"})
		return
	}
	approval, run, err := api.Store.DecideResponseApproval(r.Context(), principal.TenantID, r.PathValue("approval_id"), principal.UserID, decision == "approve", body.DecisionNote)
	if err != nil {
		writeResponseOrchestrationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"approval": approval, "response_run": run})
}

func (api *ResponseOrchestrationAPI) ListExecutions(w http.ResponseWriter, r *http.Request) {
	principal, ok := responsePrincipal(w, r)
	if !ok {
		return
	}
	records, err := api.Store.ListResponseActionExecutions(r.Context(), principal.TenantID, r.PathValue("response_run_id"))
	if err != nil {
		writeResponseOrchestrationError(w, err)
		return
	}
	if records == nil {
		records = []storage.ResponseActionExecutionRecord{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": records})
}

func (api *ResponseOrchestrationAPI) GetExecution(w http.ResponseWriter, r *http.Request) {
	principal, ok := responsePrincipal(w, r)
	if !ok {
		return
	}
	record, err := api.Store.GetResponseActionExecutionByID(r.Context(), principal.TenantID, r.PathValue("action_execution_id"))
	if err != nil {
		writeResponseOrchestrationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, record)
}
