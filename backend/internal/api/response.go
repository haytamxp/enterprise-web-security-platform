package api

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/database"
)

var responseIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

var responseActionTypes = map[string]bool{
	"notify":           true,
	"block_ip":         true,
	"isolate_host":     true,
	"disable_account":  true,
	"collect_evidence": true,
}

type ResponsePlaybook struct {
	ID          int64                    `json:"id"`
	PlaybookID  string                   `json:"playbook_id"`
	Name        string                   `json:"name"`
	Description *string                  `json:"description,omitempty"`
	IsActive    bool                     `json:"is_active"`
	CreatedBy   string                   `json:"created_by"`
	UpdatedBy   string                   `json:"updated_by"`
	CreatedAt   time.Time                `json:"created_at"`
	UpdatedAt   time.Time                `json:"updated_at"`
	Actions     []ResponsePlaybookAction `json:"actions,omitempty"`
}

type ResponsePlaybookAction struct {
	ID               int64          `json:"id"`
	ResponseActionID string         `json:"response_action_id"`
	PlaybookID       string         `json:"playbook_id"`
	ActionKey        string         `json:"action_key"`
	StepOrder        int            `json:"step_order"`
	ActionType       string         `json:"action_type"`
	RequiresApproval bool           `json:"requires_approval"`
	IsEnabled        bool           `json:"is_enabled"`
	Config           map[string]any `json:"config"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

type ResponseRun struct {
	ID               int64      `json:"id"`
	ResponseRunID    string     `json:"response_run_id"`
	IncidentID       string     `json:"incident_id"`
	PlaybookID       string     `json:"playbook_id"`
	RequestedBy      string     `json:"requested_by"`
	IdempotencyKey   string     `json:"idempotency_key"`
	RequestReason    *string    `json:"request_reason,omitempty"`
	RequiresApproval bool       `json:"requires_approval"`
	Status           string     `json:"status"`
	CreatedAt        time.Time  `json:"created_at"`
	StartedAt        *time.Time `json:"started_at,omitempty"`
	FinishedAt       *time.Time `json:"finished_at,omitempty"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type ResponseApproval struct {
	ID            int64      `json:"id"`
	ApprovalID    string     `json:"approval_id"`
	ResponseRunID string     `json:"response_run_id"`
	RequestedBy   string     `json:"requested_by"`
	DecidedBy     *string    `json:"decided_by,omitempty"`
	Status        string     `json:"status"`
	DecisionNote  *string    `json:"decision_note,omitempty"`
	RequestedAt   time.Time  `json:"requested_at"`
	DecidedAt     *time.Time `json:"decided_at,omitempty"`
}

type ResponseActionExecution struct {
	ID                int64          `json:"id"`
	ActionExecutionID string         `json:"action_execution_id"`
	ResponseRunID     string         `json:"response_run_id"`
	PlaybookID        string         `json:"playbook_id"`
	ResponseActionID  string         `json:"response_action_id"`
	StepOrder         int            `json:"step_order"`
	ActionType        string         `json:"action_type"`
	Status            string         `json:"status"`
	AttemptCount      int            `json:"attempt_count"`
	ConfigSnapshot    map[string]any `json:"config_snapshot"`
	ResultSummary     *string        `json:"result_summary,omitempty"`
	ErrorCode         *string        `json:"error_code,omitempty"`
	ExternalReference *string        `json:"external_reference,omitempty"`
	StartedAt         *time.Time     `json:"started_at,omitempty"`
	FinishedAt        *time.Time     `json:"finished_at,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}

type ResponsePlaybookCreateRequest struct {
	PlaybookID  string  `json:"playbook_id"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
}

type ResponsePlaybookUpdateRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	IsActive    *bool   `json:"is_active"`
}

type ResponseActionCreateRequest struct {
	ResponseActionID string         `json:"response_action_id"`
	ActionKey        string         `json:"action_key"`
	StepOrder        int            `json:"step_order"`
	ActionType       string         `json:"action_type"`
	RequiresApproval *bool          `json:"requires_approval"`
	IsEnabled        *bool          `json:"is_enabled"`
	Config           map[string]any `json:"config"`
}

type ResponseActionUpdateRequest struct {
	ActionKey        *string        `json:"action_key"`
	StepOrder        *int           `json:"step_order"`
	ActionType       *string        `json:"action_type"`
	RequiresApproval *bool          `json:"requires_approval"`
	IsEnabled        *bool          `json:"is_enabled"`
	Config           map[string]any `json:"config"`
}

type ResponseRunCreateRequest struct {
	ResponseRunID    string  `json:"response_run_id"`
	IncidentID       string  `json:"incident_id"`
	PlaybookID       string  `json:"playbook_id"`
	IdempotencyKey   string  `json:"idempotency_key"`
	RequestReason    *string `json:"request_reason"`
	RequiresApproval *bool   `json:"requires_approval"`
}

type ResponseApprovalDecisionRequest struct {
	DecisionNote *string `json:"decision_note"`
}

type ResponseActionResultRequest struct {
	Status            string  `json:"status"`
	ResultSummary     *string `json:"result_summary"`
	ErrorCode         *string `json:"error_code"`
	ExternalReference *string `json:"external_reference"`
}

type responseScanner interface {
	Scan(dest ...any) error
}

const responsePlaybookColumns = `
id, playbook_id, name, description, is_active,
created_by::text, updated_by::text, created_at, updated_at
`

const responseActionColumns = `
id, response_action_id, playbook_id, action_key, step_order,
action_type, requires_approval, is_enabled, config, created_at, updated_at
`

const responseRunSelect = `
SELECT rr.id, rr.response_run_id, i.incident_id, rr.playbook_id,
       rr.requested_by::text, rr.idempotency_key, rr.request_reason,
       rr.requires_approval, rr.status, rr.created_at, rr.started_at,
       rr.finished_at, rr.updated_at
FROM response_runs rr
JOIN incidents i
  ON i.tenant_id = rr.tenant_id AND i.id = rr.incident_db_id
`

const responseApprovalSelect = `
SELECT a.id, a.approval_id, rr.response_run_id,
       a.requested_by::text, a.decided_by::text, a.status,
       a.decision_note, a.requested_at, a.decided_at
FROM response_approvals a
JOIN response_runs rr
  ON rr.tenant_id = a.tenant_id AND rr.id = a.response_run_db_id
`

const responseExecutionSelect = `
SELECT e.id, e.action_execution_id, rr.response_run_id,
       e.playbook_id, e.response_action_id, e.step_order,
       e.action_type, e.status, e.attempt_count, e.config_snapshot,
       e.result_summary, e.error_code, e.external_reference,
       e.started_at, e.finished_at, e.created_at, e.updated_at
FROM response_action_executions e
JOIN response_runs rr
  ON rr.tenant_id = e.tenant_id AND rr.id = e.response_run_db_id
`

func writeResponseJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeResponseError(w http.ResponseWriter, status int, message string) {
	writeResponseJSON(w, status, map[string]string{"error": message})
}

func decodeResponseJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		return err
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("request must contain one JSON object")
		}
		return err
	}
	return nil
}

func responseIdentity(w http.ResponseWriter, r *http.Request) (AuthIdentity, bool) {
	identity, ok := AuthIdentityFromContext(r.Context())
	if !ok {
		writeResponseError(w, http.StatusUnauthorized, "Authentication required")
		return AuthIdentity{}, false
	}
	return identity, true
}

func responseHasRole(identity AuthIdentity, roles ...string) bool {
	for _, role := range roles {
		if identity.Role == role {
			return true
		}
	}
	return false
}

func responseRequireRole(w http.ResponseWriter, identity AuthIdentity, roles ...string) bool {
	if !responseHasRole(identity, roles...) {
		writeResponseError(w, http.StatusForbidden, "Your role is not allowed to perform this operation")
		return false
	}
	return true
}

func validResponseID(value string) bool {
	return responseIDPattern.MatchString(value)
}

func newResponseID(prefix string) (string, error) {
	data := make([]byte, 18)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(data), nil
}

func responseSQLState(err error) string {
	type stateError interface {
		SQLState() string
	}
	var state stateError
	if errors.As(err, &state) {
		return state.SQLState()
	}
	return ""
}

func responsePage(r *http.Request) (int, int, bool) {
	limit := 50
	offset := 0

	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 100 {
			return 0, 0, false
		}
		limit = value
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 0 {
			return 0, 0, false
		}
		offset = value
	}
	return limit, offset, true
}

func scanResponsePlaybook(scanner responseScanner) (ResponsePlaybook, error) {
	var item ResponsePlaybook
	var description sql.NullString

	err := scanner.Scan(
		&item.ID, &item.PlaybookID, &item.Name, &description,
		&item.IsActive, &item.CreatedBy, &item.UpdatedBy,
		&item.CreatedAt, &item.UpdatedAt,
	)
	if err != nil {
		return item, err
	}
	if description.Valid {
		item.Description = &description.String
	}
	return item, nil
}

func scanResponseAction(scanner responseScanner) (ResponsePlaybookAction, error) {
	var item ResponsePlaybookAction
	var configJSON []byte

	err := scanner.Scan(
		&item.ID, &item.ResponseActionID, &item.PlaybookID,
		&item.ActionKey, &item.StepOrder, &item.ActionType,
		&item.RequiresApproval, &item.IsEnabled, &configJSON,
		&item.CreatedAt, &item.UpdatedAt,
	)
	if err != nil {
		return item, err
	}
	item.Config = make(map[string]any)
	if len(configJSON) > 0 {
		if err := json.Unmarshal(configJSON, &item.Config); err != nil {
			return item, err
		}
	}
	if item.Config == nil {
		item.Config = make(map[string]any)
	}
	return item, nil
}

func scanResponseRun(scanner responseScanner) (ResponseRun, error) {
	var item ResponseRun
	var reason sql.NullString
	var started, finished sql.NullTime

	err := scanner.Scan(
		&item.ID, &item.ResponseRunID, &item.IncidentID, &item.PlaybookID,
		&item.RequestedBy, &item.IdempotencyKey, &reason,
		&item.RequiresApproval, &item.Status, &item.CreatedAt,
		&started, &finished, &item.UpdatedAt,
	)
	if err != nil {
		return item, err
	}
	if reason.Valid {
		item.RequestReason = &reason.String
	}
	if started.Valid {
		item.StartedAt = &started.Time
	}
	if finished.Valid {
		item.FinishedAt = &finished.Time
	}
	return item, nil
}

func scanResponseApproval(scanner responseScanner) (ResponseApproval, error) {
	var item ResponseApproval
	var decidedBy, note sql.NullString
	var decidedAt sql.NullTime

	err := scanner.Scan(
		&item.ID, &item.ApprovalID, &item.ResponseRunID,
		&item.RequestedBy, &decidedBy, &item.Status,
		&note, &item.RequestedAt, &decidedAt,
	)
	if err != nil {
		return item, err
	}
	if decidedBy.Valid {
		item.DecidedBy = &decidedBy.String
	}
	if note.Valid {
		item.DecisionNote = &note.String
	}
	if decidedAt.Valid {
		item.DecidedAt = &decidedAt.Time
	}
	return item, nil
}

func scanResponseExecution(scanner responseScanner) (ResponseActionExecution, error) {
	var item ResponseActionExecution
	var configJSON []byte
	var summary, errorCode, externalRef sql.NullString
	var started, finished sql.NullTime

	err := scanner.Scan(
		&item.ID, &item.ActionExecutionID, &item.ResponseRunID,
		&item.PlaybookID, &item.ResponseActionID, &item.StepOrder,
		&item.ActionType, &item.Status, &item.AttemptCount,
		&configJSON, &summary, &errorCode, &externalRef,
		&started, &finished, &item.CreatedAt, &item.UpdatedAt,
	)
	if err != nil {
		return item, err
	}

	item.ConfigSnapshot = make(map[string]any)
	if len(configJSON) > 0 {
		if err := json.Unmarshal(configJSON, &item.ConfigSnapshot); err != nil {
			return item, err
		}
	}
	if summary.Valid {
		item.ResultSummary = &summary.String
	}
	if errorCode.Valid {
		item.ErrorCode = &errorCode.String
	}
	if externalRef.Valid {
		item.ExternalReference = &externalRef.String
	}
	if started.Valid {
		item.StartedAt = &started.Time
	}
	if finished.Valid {
		item.FinishedAt = &finished.Time
	}
	return item, nil
}

func listResponsePlaybookActions(ctx context.Context, tenantID, playbookID string) ([]ResponsePlaybookAction, error) {
	rows, err := database.DB.QueryContext(
		ctx,
		`SELECT `+responseActionColumns+`
 FROM response_playbook_actions
 WHERE tenant_id = $1 AND playbook_id = $2
 ORDER BY step_order, id`,
		tenantID, playbookID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]ResponsePlaybookAction, 0)
	for rows.Next() {
		item, err := scanResponseAction(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// CreateResponsePlaybookHandler creates an inactive response playbook.
//
// @Summary Create response playbook
// @Tags Response Playbooks
// @Accept json
// @Produce json
// @Param body body ResponsePlaybookCreateRequest true "Playbook"
// @Success 201 {object} ResponsePlaybook
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Router /api/v1/response/playbooks [post]
func CreateResponsePlaybookHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := responseIdentity(w, r)
	if !ok {
		return
	}
	if !responseRequireRole(w, identity, "admin") {
		return
	}

	var request ResponsePlaybookCreateRequest
	if err := decodeResponseJSON(w, r, &request); err != nil {
		writeResponseError(w, http.StatusBadRequest, "Invalid JSON request body")
		return
	}

	request.PlaybookID = strings.TrimSpace(request.PlaybookID)
	request.Name = strings.TrimSpace(request.Name)
	if request.PlaybookID == "" {
		var err error
		request.PlaybookID, err = newResponseID("playbook")
		if err != nil {
			writeResponseError(w, http.StatusInternalServerError, "Could not generate playbook ID")
			return
		}
	}
	if !validResponseID(request.PlaybookID) || request.Name == "" || len(request.Name) > 200 {
		writeResponseError(w, http.StatusBadRequest, "playbook_id must be valid and name must contain 1-200 characters")
		return
	}
	if request.Description != nil && len(*request.Description) > 10000 {
		writeResponseError(w, http.StatusBadRequest, "description cannot exceed 10000 characters")
		return
	}

	item, err := scanResponsePlaybook(database.DB.QueryRowContext(
		r.Context(),
		`INSERT INTO response_playbooks
 (tenant_id, playbook_id, name, description, is_active, created_by, updated_by)
 VALUES ($1, $2, $3, NULLIF($4, ''), FALSE, $5, $5)
 RETURNING `+responsePlaybookColumns,
		identity.TenantID, request.PlaybookID, request.Name,
		responseStringValue(request.Description), identity.UserID,
	))
	if err != nil {
		if responseSQLState(err) == "23505" {
			writeResponseError(w, http.StatusConflict, "A playbook with this ID already exists")
			return
		}
		writeResponseError(w, http.StatusInternalServerError, "Could not create playbook")
		return
	}
	writeResponseJSON(w, http.StatusCreated, item)
}

// ListResponsePlaybooksHandler lists tenant playbooks.
//
// @Summary List response playbooks
// @Tags Response Playbooks
// @Produce json
// @Param is_active query bool false "Filter by active state"
// @Param limit query int false "Maximum results (1-100)"
// @Param offset query int false "Pagination offset"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Router /api/v1/response/playbooks [get]
func ListResponsePlaybooksHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := responseIdentity(w, r)
	if !ok {
		return
	}
	limit, offset, valid := responsePage(r)
	if !valid {
		writeResponseError(w, http.StatusBadRequest, "limit must be 1-100 and offset must be zero or greater")
		return
	}

	query := `SELECT ` + responsePlaybookColumns + ` FROM response_playbooks WHERE tenant_id = $1`
	args := []any{identity.TenantID}
	if raw := strings.TrimSpace(r.URL.Query().Get("is_active")); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			writeResponseError(w, http.StatusBadRequest, "is_active must be true or false")
			return
		}
		args = append(args, value)
		query += fmt.Sprintf(" AND is_active = $%d", len(args))
	}
	args = append(args, limit)
	limitPos := len(args)
	args = append(args, offset)
	offsetPos := len(args)
	query += fmt.Sprintf(" ORDER BY updated_at DESC, id DESC LIMIT $%d OFFSET $%d", limitPos, offsetPos)

	rows, err := database.DB.QueryContext(r.Context(), query, args...)
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not list playbooks")
		return
	}
	defer rows.Close()

	items := make([]ResponsePlaybook, 0)
	for rows.Next() {
		item, err := scanResponsePlaybook(rows)
		if err != nil {
			writeResponseError(w, http.StatusInternalServerError, "Could not read playbooks")
			return
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not read playbooks")
		return
	}
	writeResponseJSON(w, http.StatusOK, map[string]any{
		"items": items, "count": len(items), "limit": limit, "offset": offset,
	})
}

// GetResponsePlaybookHandler gets a playbook and its actions.
//
// @Summary Get response playbook
// @Tags Response Playbooks
// @Produce json
// @Param playbook_id path string true "Playbook ID"
// @Success 200 {object} ResponsePlaybook
// @Failure 404 {object} map[string]string
// @Router /api/v1/response/playbooks/{playbook_id} [get]
func GetResponsePlaybookHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := responseIdentity(w, r)
	if !ok {
		return
	}
	playbookID := strings.TrimSpace(r.PathValue("playbook_id"))
	if !validResponseID(playbookID) {
		writeResponseError(w, http.StatusBadRequest, "Invalid playbook_id")
		return
	}

	item, err := scanResponsePlaybook(database.DB.QueryRowContext(
		r.Context(),
		`SELECT `+responsePlaybookColumns+`
 FROM response_playbooks
 WHERE tenant_id = $1 AND playbook_id = $2`,
		identity.TenantID, playbookID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		writeResponseError(w, http.StatusNotFound, "Playbook not found")
		return
	}
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not retrieve playbook")
		return
	}
	item.Actions, err = listResponsePlaybookActions(r.Context(), identity.TenantID, playbookID)
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not retrieve playbook actions")
		return
	}
	writeResponseJSON(w, http.StatusOK, item)
}

// UpdateResponsePlaybookHandler updates playbook metadata and activation state.
//
// @Summary Update response playbook
// @Tags Response Playbooks
// @Accept json
// @Produce json
// @Param playbook_id path string true "Playbook ID"
// @Param body body ResponsePlaybookUpdateRequest true "Playbook changes"
// @Success 200 {object} ResponsePlaybook
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Router /api/v1/response/playbooks/{playbook_id} [patch]
func UpdateResponsePlaybookHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := responseIdentity(w, r)
	if !ok {
		return
	}
	if !responseRequireRole(w, identity, "admin") {
		return
	}

	playbookID := strings.TrimSpace(r.PathValue("playbook_id"))
	if !validResponseID(playbookID) {
		writeResponseError(w, http.StatusBadRequest, "Invalid playbook_id")
		return
	}

	var request ResponsePlaybookUpdateRequest
	if err := decodeResponseJSON(w, r, &request); err != nil {
		writeResponseError(w, http.StatusBadRequest, "Invalid JSON request body")
		return
	}
	if request.Name == nil && request.Description == nil && request.IsActive == nil {
		writeResponseError(w, http.StatusBadRequest, "At least one field must be provided")
		return
	}
	if request.Name != nil {
		*request.Name = strings.TrimSpace(*request.Name)
		if *request.Name == "" || len(*request.Name) > 200 {
			writeResponseError(w, http.StatusBadRequest, "name must contain 1-200 characters")
			return
		}
	}
	if request.Description != nil && len(*request.Description) > 10000 {
		writeResponseError(w, http.StatusBadRequest, "description cannot exceed 10000 characters")
		return
	}
	if request.IsActive != nil && *request.IsActive {
		var count int
		err := database.DB.QueryRowContext(
			r.Context(),
			`SELECT COUNT(*) FROM response_playbook_actions
 WHERE tenant_id = $1 AND playbook_id = $2 AND is_enabled = TRUE`,
			identity.TenantID, playbookID,
		).Scan(&count)
		if err != nil {
			writeResponseError(w, http.StatusInternalServerError, "Could not validate playbook actions")
			return
		}
		if count == 0 {
			writeResponseError(w, http.StatusConflict, "A playbook needs at least one enabled action before activation")
			return
		}
	}

	item, err := scanResponsePlaybook(database.DB.QueryRowContext(
		r.Context(),
		`UPDATE response_playbooks
 SET name = COALESCE($1, name),
     description = CASE WHEN $2 THEN NULLIF($3, '') ELSE description END,
     is_active = COALESCE($4, is_active),
     updated_by = $5,
     updated_at = NOW()
 WHERE tenant_id = $6 AND playbook_id = $7
 RETURNING `+responsePlaybookColumns,
		responseStringPointerValue(request.Name),
		request.Description != nil, responseStringValue(request.Description),
		request.IsActive, identity.UserID, identity.TenantID, playbookID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		writeResponseError(w, http.StatusNotFound, "Playbook not found")
		return
	}
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not update playbook")
		return
	}
	writeResponseJSON(w, http.StatusOK, item)
}

// CreateResponsePlaybookActionHandler adds an action to an inactive playbook.
//
// @Summary Add playbook action
// @Tags Response Playbooks
// @Accept json
// @Produce json
// @Param playbook_id path string true "Playbook ID"
// @Param body body ResponseActionCreateRequest true "Action definition"
// @Success 201 {object} ResponsePlaybookAction
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Router /api/v1/response/playbooks/{playbook_id}/actions [post]
func CreateResponsePlaybookActionHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := responseIdentity(w, r)
	if !ok {
		return
	}
	if !responseRequireRole(w, identity, "admin") {
		return
	}

	playbookID := strings.TrimSpace(r.PathValue("playbook_id"))
	if !validResponseID(playbookID) {
		writeResponseError(w, http.StatusBadRequest, "Invalid playbook_id")
		return
	}

	var request ResponseActionCreateRequest
	if err := decodeResponseJSON(w, r, &request); err != nil {
		writeResponseError(w, http.StatusBadRequest, "Invalid JSON request body")
		return
	}

	request.ResponseActionID = strings.TrimSpace(request.ResponseActionID)
	request.ActionKey = strings.TrimSpace(request.ActionKey)
	request.ActionType = strings.TrimSpace(request.ActionType)

	if request.ResponseActionID == "" {
		var err error
		request.ResponseActionID, err = newResponseID("action")
		if err != nil {
			writeResponseError(w, http.StatusInternalServerError, "Could not generate action ID")
			return
		}
	}
	if !validResponseID(request.ResponseActionID) ||
		!validResponseID(request.ActionKey) ||
		request.StepOrder < 1 || request.StepOrder > 1000 ||
		!responseActionTypes[request.ActionType] {
		writeResponseError(w, http.StatusBadRequest, "Invalid action ID, action_key, step_order, or action_type")
		return
	}

	requiresApproval := true
	if request.RequiresApproval != nil {
		requiresApproval = *request.RequiresApproval
	}
	enabled := true
	if request.IsEnabled != nil {
		enabled = *request.IsEnabled
	}
	config := request.Config
	if config == nil {
		config = make(map[string]any)
	}
	configJSON, err := json.Marshal(config)
	if err != nil {
		writeResponseError(w, http.StatusBadRequest, "config must be a valid JSON object")
		return
	}

	var active bool
	err = database.DB.QueryRowContext(
		r.Context(),
		`SELECT is_active FROM response_playbooks
 WHERE tenant_id = $1 AND playbook_id = $2`,
		identity.TenantID, playbookID,
	).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		writeResponseError(w, http.StatusNotFound, "Playbook not found")
		return
	}
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not verify playbook")
		return
	}
	if active {
		writeResponseError(w, http.StatusConflict, "Deactivate the playbook before changing its actions")
		return
	}

	item, err := scanResponseAction(database.DB.QueryRowContext(
		r.Context(),
		`INSERT INTO response_playbook_actions (
tenant_id, response_action_id, playbook_id, action_key,
step_order, action_type, requires_approval, is_enabled, config
)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)
RETURNING `+responseActionColumns,
		identity.TenantID, request.ResponseActionID, playbookID,
		request.ActionKey, request.StepOrder, request.ActionType,
		requiresApproval, enabled, string(configJSON),
	))
	if err != nil {
		if responseSQLState(err) == "23505" {
			writeResponseError(w, http.StatusConflict, "Action ID, action key, or step order already exists in this playbook")
			return
		}
		writeResponseError(w, http.StatusInternalServerError, "Could not create playbook action")
		return
	}
	writeResponseJSON(w, http.StatusCreated, item)
}

// ListResponsePlaybookActionsHandler lists a playbook's configured actions.
//
// @Summary List playbook actions
// @Tags Response Playbooks
// @Produce json
// @Param playbook_id path string true "Playbook ID"
// @Success 200 {object} map[string]interface{}
// @Failure 404 {object} map[string]string
// @Router /api/v1/response/playbooks/{playbook_id}/actions [get]
func ListResponsePlaybookActionsHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := responseIdentity(w, r)
	if !ok {
		return
	}
	playbookID := strings.TrimSpace(r.PathValue("playbook_id"))
	if !validResponseID(playbookID) {
		writeResponseError(w, http.StatusBadRequest, "Invalid playbook_id")
		return
	}
	var exists bool
	err := database.DB.QueryRowContext(
		r.Context(),
		`SELECT EXISTS(SELECT 1 FROM response_playbooks WHERE tenant_id=$1 AND playbook_id=$2)`,
		identity.TenantID, playbookID,
	).Scan(&exists)
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not verify playbook")
		return
	}
	if !exists {
		writeResponseError(w, http.StatusNotFound, "Playbook not found")
		return
	}
	items, err := listResponsePlaybookActions(r.Context(), identity.TenantID, playbookID)
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not list playbook actions")
		return
	}
	writeResponseJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}

// UpdateResponsePlaybookActionHandler updates an action on an inactive playbook.
//
// @Summary Update playbook action
// @Tags Response Playbooks
// @Accept json
// @Produce json
// @Param playbook_id path string true "Playbook ID"
// @Param response_action_id path string true "Response action ID"
// @Param body body ResponseActionUpdateRequest true "Action changes"
// @Success 200 {object} ResponsePlaybookAction
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Router /api/v1/response/playbooks/{playbook_id}/actions/{response_action_id} [patch]
func UpdateResponsePlaybookActionHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := responseIdentity(w, r)
	if !ok {
		return
	}
	if !responseRequireRole(w, identity, "admin") {
		return
	}

	playbookID := strings.TrimSpace(r.PathValue("playbook_id"))
	actionID := strings.TrimSpace(r.PathValue("response_action_id"))
	if !validResponseID(playbookID) || !validResponseID(actionID) {
		writeResponseError(w, http.StatusBadRequest, "Invalid playbook_id or response_action_id")
		return
	}

	var request ResponseActionUpdateRequest
	if err := decodeResponseJSON(w, r, &request); err != nil {
		writeResponseError(w, http.StatusBadRequest, "Invalid JSON request body")
		return
	}
	if request.ActionKey == nil && request.StepOrder == nil &&
		request.ActionType == nil && request.RequiresApproval == nil &&
		request.IsEnabled == nil && request.Config == nil {
		writeResponseError(w, http.StatusBadRequest, "At least one field must be provided")
		return
	}
	if request.ActionKey != nil {
		*request.ActionKey = strings.TrimSpace(*request.ActionKey)
		if !validResponseID(*request.ActionKey) {
			writeResponseError(w, http.StatusBadRequest, "Invalid action_key")
			return
		}
	}
	if request.StepOrder != nil && (*request.StepOrder < 1 || *request.StepOrder > 1000) {
		writeResponseError(w, http.StatusBadRequest, "step_order must be between 1 and 1000")
		return
	}
	if request.ActionType != nil && !responseActionTypes[strings.TrimSpace(*request.ActionType)] {
		writeResponseError(w, http.StatusBadRequest, "Invalid action_type")
		return
	}

	var active bool
	err := database.DB.QueryRowContext(
		r.Context(),
		`SELECT is_active FROM response_playbooks WHERE tenant_id=$1 AND playbook_id=$2`,
		identity.TenantID, playbookID,
	).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		writeResponseError(w, http.StatusNotFound, "Playbook not found")
		return
	}
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not verify playbook")
		return
	}
	if active {
		writeResponseError(w, http.StatusConflict, "Deactivate the playbook before changing its actions")
		return
	}

	var configValue any
	if request.Config != nil {
		data, err := json.Marshal(request.Config)
		if err != nil {
			writeResponseError(w, http.StatusBadRequest, "config must be a valid JSON object")
			return
		}
		configValue = string(data)
	}

	item, err := scanResponseAction(database.DB.QueryRowContext(
		r.Context(),
		`UPDATE response_playbook_actions
 SET action_key=COALESCE($1,action_key),
     step_order=COALESCE($2,step_order),
     action_type=COALESCE($3,action_type),
     requires_approval=COALESCE($4,requires_approval),
     is_enabled=COALESCE($5,is_enabled),
     config=COALESCE($6::jsonb,config),
     updated_at=NOW()
 WHERE tenant_id=$7 AND playbook_id=$8 AND response_action_id=$9
 RETURNING `+responseActionColumns,
		responseStringPointerValue(request.ActionKey), request.StepOrder,
		responseStringPointerValue(request.ActionType), request.RequiresApproval,
		request.IsEnabled, configValue, identity.TenantID, playbookID, actionID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		writeResponseError(w, http.StatusNotFound, "Playbook action not found")
		return
	}
	if err != nil {
		if responseSQLState(err) == "23505" {
			writeResponseError(w, http.StatusConflict, "Action key or step order already exists")
			return
		}
		writeResponseError(w, http.StatusInternalServerError, "Could not update playbook action")
		return
	}
	writeResponseJSON(w, http.StatusOK, item)
}

// CreateResponseRunHandler creates a run and snapshots all enabled playbook actions.
//
// @Summary Create response run
// @Tags Response Runs
// @Accept json
// @Produce json
// @Param body body ResponseRunCreateRequest true "Response run request"
// @Success 201 {object} ResponseRun
// @Success 200 {object} ResponseRun
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Router /api/v1/response/runs [post]
func CreateResponseRunHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := responseIdentity(w, r)
	if !ok {
		return
	}
	if !responseRequireRole(w, identity, "admin", "analyst", "responder") {
		return
	}

	var request ResponseRunCreateRequest
	if err := decodeResponseJSON(w, r, &request); err != nil {
		writeResponseError(w, http.StatusBadRequest, "Invalid JSON request body")
		return
	}
	request.IncidentID = strings.TrimSpace(request.IncidentID)
	request.PlaybookID = strings.TrimSpace(request.PlaybookID)
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	request.ResponseRunID = strings.TrimSpace(request.ResponseRunID)

	if request.ResponseRunID == "" {
		generatedRunID, generateErr := newResponseID("run")
		if generateErr != nil {
			writeResponseError(w, http.StatusInternalServerError, "Could not generate response run ID")
			return
		}
		request.ResponseRunID = generatedRunID
	}
	if !validResponseID(request.ResponseRunID) ||
		!validResponseID(request.IncidentID) ||
		!validResponseID(request.PlaybookID) ||
		!validResponseID(request.IdempotencyKey) {
		writeResponseError(w, http.StatusBadRequest, "response_run_id, incident_id, playbook_id, and idempotency_key must be valid identifiers")
		return
	}
	if request.RequestReason != nil && len(*request.RequestReason) > 2000 {
		writeResponseError(w, http.StatusBadRequest, "request_reason cannot exceed 2000 characters")
		return
	}

	tx, err := database.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not start response transaction")
		return
	}
	defer func() { _ = tx.Rollback() }()

	var playbookActive bool
	err = tx.QueryRowContext(
		r.Context(),
		`SELECT is_active FROM response_playbooks
 WHERE tenant_id=$1 AND playbook_id=$2 FOR SHARE`,
		identity.TenantID, request.PlaybookID,
	).Scan(&playbookActive)
	if errors.Is(err, sql.ErrNoRows) {
		writeResponseError(w, http.StatusNotFound, "Playbook not found")
		return
	}
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not verify playbook")
		return
	}
	if !playbookActive {
		writeResponseError(w, http.StatusConflict, "Only active playbooks can be executed")
		return
	}

	var incidentDBID int64
	err = tx.QueryRowContext(
		r.Context(),
		`SELECT id FROM incidents WHERE tenant_id=$1 AND incident_id=$2`,
		identity.TenantID, request.IncidentID,
	).Scan(&incidentDBID)
	if errors.Is(err, sql.ErrNoRows) {
		writeResponseError(w, http.StatusNotFound, "Incident not found in this tenant")
		return
	}
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not verify incident")
		return
	}

	rows, err := tx.QueryContext(
		r.Context(),
		`SELECT response_action_id, step_order, action_type,
        requires_approval, config
 FROM response_playbook_actions
 WHERE tenant_id=$1 AND playbook_id=$2 AND is_enabled=TRUE
 ORDER BY step_order
 FOR SHARE`,
		identity.TenantID, request.PlaybookID,
	)
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not load playbook actions")
		return
	}

	type actionSnapshot struct {
		ID               string
		StepOrder        int
		ActionType       string
		RequiresApproval bool
		Config           []byte
	}
	actions := make([]actionSnapshot, 0)
	approvalRequired := request.RequiresApproval != nil && *request.RequiresApproval

	for rows.Next() {
		var action actionSnapshot
		if err := rows.Scan(&action.ID, &action.StepOrder, &action.ActionType, &action.RequiresApproval, &action.Config); err != nil {
			rows.Close()
			writeResponseError(w, http.StatusInternalServerError, "Could not read playbook actions")
			return
		}
		if action.RequiresApproval {
			approvalRequired = true
		}
		actions = append(actions, action)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		writeResponseError(w, http.StatusInternalServerError, "Could not read playbook actions")
		return
	}
	rows.Close()

	if len(actions) == 0 {
		writeResponseError(w, http.StatusConflict, "The playbook has no enabled actions")
		return
	}

	initialStatus := "queued"
	if approvalRequired {
		initialStatus = "pending_approval"
	}

	var runDBID int64
	err = tx.QueryRowContext(
		r.Context(),
		`INSERT INTO response_runs (
tenant_id, response_run_id, incident_db_id, playbook_id,
requested_by, idempotency_key, request_reason,
requires_approval, status
)
VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''),$8,$9)
ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
RETURNING id`,
		identity.TenantID, request.ResponseRunID, incidentDBID,
		request.PlaybookID, identity.UserID, request.IdempotencyKey,
		responseStringValue(request.RequestReason), approvalRequired, initialStatus,
	).Scan(&runDBID)

	if errors.Is(err, sql.ErrNoRows) {
		existing, readErr := scanResponseRun(tx.QueryRowContext(
			r.Context(),
			responseRunSelect+` WHERE rr.tenant_id=$1 AND rr.idempotency_key=$2`,
			identity.TenantID, request.IdempotencyKey,
		))
		if readErr != nil {
			writeResponseError(w, http.StatusInternalServerError, "Could not retrieve existing idempotent run")
			return
		}
		if err := tx.Commit(); err != nil {
			writeResponseError(w, http.StatusInternalServerError, "Could not finish response transaction")
			return
		}
		writeResponseJSON(w, http.StatusOK, existing)
		return
	}
	if err != nil {
		if responseSQLState(err) == "23505" {
			writeResponseError(w, http.StatusConflict, "response_run_id already exists")
			return
		}
		writeResponseError(w, http.StatusInternalServerError, "Could not create response run")
		return
	}

	for _, action := range actions {
		executionID, idErr := newResponseID("execution")
		if idErr != nil {
			writeResponseError(w, http.StatusInternalServerError, "Could not generate action execution ID")
			return
		}
		_, err = tx.ExecContext(
			r.Context(),
			`INSERT INTO response_action_executions (
tenant_id, action_execution_id, response_run_db_id,
playbook_id, response_action_id, step_order,
action_type, status, config_snapshot
)
VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',$8::jsonb)`,
			identity.TenantID, executionID, runDBID, request.PlaybookID,
			action.ID, action.StepOrder, action.ActionType, string(action.Config),
		)
		if err != nil {
			writeResponseError(w, http.StatusInternalServerError, "Could not create action execution snapshots")
			return
		}
	}

	if approvalRequired {
		approvalID, idErr := newResponseID("approval")
		if idErr != nil {
			writeResponseError(w, http.StatusInternalServerError, "Could not generate approval ID")
			return
		}
		_, err = tx.ExecContext(
			r.Context(),
			`INSERT INTO response_approvals (
tenant_id, approval_id, response_run_db_id, requested_by, status
) VALUES ($1,$2,$3,$4,'pending')`,
			identity.TenantID, approvalID, runDBID, identity.UserID,
		)
		if err != nil {
			writeResponseError(w, http.StatusInternalServerError, "Could not create approval request")
			return
		}
	}

	item, err := scanResponseRun(tx.QueryRowContext(
		r.Context(),
		responseRunSelect+` WHERE rr.tenant_id=$1 AND rr.id=$2`,
		identity.TenantID, runDBID,
	))
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not retrieve created response run")
		return
	}

	if err := tx.Commit(); err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not commit response run")
		return
	}
	writeResponseJSON(w, http.StatusCreated, item)
}

// ListResponseRunsHandler lists runs within the authenticated tenant.
//
// @Summary List response runs
// @Tags Response Runs
// @Produce json
// @Param status query string false "Run status"
// @Param incident_id query string false "Incident ID"
// @Param limit query int false "Maximum results (1-100)"
// @Param offset query int false "Pagination offset"
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/response/runs [get]
func ListResponseRunsHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := responseIdentity(w, r)
	if !ok {
		return
	}
	limit, offset, valid := responsePage(r)
	if !valid {
		writeResponseError(w, http.StatusBadRequest, "Invalid limit or offset")
		return
	}

	status := strings.TrimSpace(r.URL.Query().Get("status"))
	incidentID := strings.TrimSpace(r.URL.Query().Get("incident_id"))
	allowedStatuses := map[string]bool{
		"pending_approval": true, "queued": true, "running": true,
		"succeeded": true, "partially_failed": true, "failed": true,
		"rejected": true, "cancelled": true, "timed_out": true,
	}
	if status != "" && !allowedStatuses[status] {
		writeResponseError(w, http.StatusBadRequest, "Invalid response run status")
		return
	}
	if incidentID != "" && !validResponseID(incidentID) {
		writeResponseError(w, http.StatusBadRequest, "Invalid incident_id")
		return
	}

	query := responseRunSelect + ` WHERE rr.tenant_id=$1`
	args := []any{identity.TenantID}
	if status != "" {
		args = append(args, status)
		query += fmt.Sprintf(" AND rr.status=$%d", len(args))
	}
	if incidentID != "" {
		args = append(args, incidentID)
		query += fmt.Sprintf(" AND i.incident_id=$%d", len(args))
	}
	args = append(args, limit)
	limitPos := len(args)
	args = append(args, offset)
	offsetPos := len(args)
	query += fmt.Sprintf(" ORDER BY rr.created_at DESC, rr.id DESC LIMIT $%d OFFSET $%d", limitPos, offsetPos)

	rows, err := database.DB.QueryContext(r.Context(), query, args...)
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not list response runs")
		return
	}
	defer rows.Close()

	items := make([]ResponseRun, 0)
	for rows.Next() {
		item, err := scanResponseRun(rows)
		if err != nil {
			writeResponseError(w, http.StatusInternalServerError, "Could not read response runs")
			return
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not read response runs")
		return
	}
	writeResponseJSON(w, http.StatusOK, map[string]any{
		"items": items, "count": len(items), "limit": limit, "offset": offset,
	})
}

// GetResponseRunHandler retrieves one response run.
//
// @Summary Get response run
// @Tags Response Runs
// @Produce json
// @Param response_run_id path string true "Response run ID"
// @Success 200 {object} ResponseRun
// @Failure 404 {object} map[string]string
// @Router /api/v1/response/runs/{response_run_id} [get]
func GetResponseRunHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := responseIdentity(w, r)
	if !ok {
		return
	}
	runID := strings.TrimSpace(r.PathValue("response_run_id"))
	if !validResponseID(runID) {
		writeResponseError(w, http.StatusBadRequest, "Invalid response_run_id")
		return
	}
	item, err := scanResponseRun(database.DB.QueryRowContext(
		r.Context(),
		responseRunSelect+` WHERE rr.tenant_id=$1 AND rr.response_run_id=$2`,
		identity.TenantID, runID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		writeResponseError(w, http.StatusNotFound, "Response run not found")
		return
	}
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not retrieve response run")
		return
	}
	writeResponseJSON(w, http.StatusOK, item)
}

// ListResponseRunActionsHandler lists action execution snapshots for a run.
//
// @Summary List response run actions
// @Tags Response Runs
// @Produce json
// @Param response_run_id path string true "Response run ID"
// @Success 200 {object} map[string]interface{}
// @Failure 404 {object} map[string]string
// @Router /api/v1/response/runs/{response_run_id}/actions [get]
func ListResponseRunActionsHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := responseIdentity(w, r)
	if !ok {
		return
	}
	runID := strings.TrimSpace(r.PathValue("response_run_id"))
	if !validResponseID(runID) {
		writeResponseError(w, http.StatusBadRequest, "Invalid response_run_id")
		return
	}

	var runDBID int64
	err := database.DB.QueryRowContext(
		r.Context(),
		`SELECT id FROM response_runs WHERE tenant_id=$1 AND response_run_id=$2`,
		identity.TenantID, runID,
	).Scan(&runDBID)
	if errors.Is(err, sql.ErrNoRows) {
		writeResponseError(w, http.StatusNotFound, "Response run not found")
		return
	}
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not verify response run")
		return
	}

	rows, err := database.DB.QueryContext(
		r.Context(),
		responseExecutionSelect+` WHERE e.tenant_id=$1 AND e.response_run_db_id=$2 ORDER BY e.step_order, e.id`,
		identity.TenantID, runDBID,
	)
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not list action executions")
		return
	}
	defer rows.Close()

	items := make([]ResponseActionExecution, 0)
	for rows.Next() {
		item, err := scanResponseExecution(rows)
		if err != nil {
			writeResponseError(w, http.StatusInternalServerError, "Could not read action executions")
			return
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not read action executions")
		return
	}
	writeResponseJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}

// ListResponseApprovalsHandler lists approval requests for the tenant.
//
// @Summary List response approvals
// @Tags Response Approvals
// @Produce json
// @Param status query string false "pending, approved, or rejected"
// @Param limit query int false "Maximum results (1-100)"
// @Param offset query int false "Pagination offset"
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/response/approvals [get]
func ListResponseApprovalsHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := responseIdentity(w, r)
	if !ok {
		return
	}
	limit, offset, valid := responsePage(r)
	if !valid {
		writeResponseError(w, http.StatusBadRequest, "Invalid limit or offset")
		return
	}

	status := strings.TrimSpace(r.URL.Query().Get("status"))
	if status != "" && status != "pending" && status != "approved" && status != "rejected" {
		writeResponseError(w, http.StatusBadRequest, "status must be pending, approved, or rejected")
		return
	}

	query := responseApprovalSelect + ` WHERE a.tenant_id=$1`
	args := []any{identity.TenantID}
	if status != "" {
		args = append(args, status)
		query += fmt.Sprintf(" AND a.status=$%d", len(args))
	}
	args = append(args, limit)
	limitPos := len(args)
	args = append(args, offset)
	offsetPos := len(args)
	query += fmt.Sprintf(" ORDER BY a.requested_at DESC, a.id DESC LIMIT $%d OFFSET $%d", limitPos, offsetPos)

	rows, err := database.DB.QueryContext(r.Context(), query, args...)
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not list approvals")
		return
	}
	defer rows.Close()

	items := make([]ResponseApproval, 0)
	for rows.Next() {
		item, err := scanResponseApproval(rows)
		if err != nil {
			writeResponseError(w, http.StatusInternalServerError, "Could not read approvals")
			return
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not read approvals")
		return
	}
	writeResponseJSON(w, http.StatusOK, map[string]any{
		"items": items, "count": len(items), "limit": limit, "offset": offset,
	})
}

// GetResponseApprovalHandler retrieves one approval request.
//
// @Summary Get response approval
// @Tags Response Approvals
// @Produce json
// @Param approval_id path string true "Approval ID"
// @Success 200 {object} ResponseApproval
// @Failure 404 {object} map[string]string
// @Router /api/v1/response/approvals/{approval_id} [get]
func GetResponseApprovalHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := responseIdentity(w, r)
	if !ok {
		return
	}
	approvalID := strings.TrimSpace(r.PathValue("approval_id"))
	if !validResponseID(approvalID) {
		writeResponseError(w, http.StatusBadRequest, "Invalid approval_id")
		return
	}
	item, err := scanResponseApproval(database.DB.QueryRowContext(
		r.Context(),
		responseApprovalSelect+` WHERE a.tenant_id=$1 AND a.approval_id=$2`,
		identity.TenantID, approvalID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		writeResponseError(w, http.StatusNotFound, "Approval not found")
		return
	}
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not retrieve approval")
		return
	}
	writeResponseJSON(w, http.StatusOK, item)
}

// ApproveResponseApprovalHandler approves a response run request.
//
// @Summary Approve response run
// @Tags Response Approvals
// @Accept json
// @Produce json
// @Param approval_id path string true "Approval ID"
// @Param body body ResponseApprovalDecisionRequest false "Decision note"
// @Success 200 {object} ResponseApproval
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Router /api/v1/response/approvals/{approval_id}/approve [post]
func ApproveResponseApprovalHandler(w http.ResponseWriter, r *http.Request) {
	decideResponseApproval(w, r, true)
}

// RejectResponseApprovalHandler rejects a response run request.
//
// @Summary Reject response run
// @Tags Response Approvals
// @Accept json
// @Produce json
// @Param approval_id path string true "Approval ID"
// @Param body body ResponseApprovalDecisionRequest false "Decision note"
// @Success 200 {object} ResponseApproval
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Router /api/v1/response/approvals/{approval_id}/reject [post]
func RejectResponseApprovalHandler(w http.ResponseWriter, r *http.Request) {
	decideResponseApproval(w, r, false)
}

func decideResponseApproval(w http.ResponseWriter, r *http.Request, approve bool) {
	identity, ok := responseIdentity(w, r)
	if !ok {
		return
	}
	if !responseRequireRole(w, identity, "admin") {
		return
	}

	approvalID := strings.TrimSpace(r.PathValue("approval_id"))
	if !validResponseID(approvalID) {
		writeResponseError(w, http.StatusBadRequest, "Invalid approval_id")
		return
	}

	var request ResponseApprovalDecisionRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := decodeResponseJSON(w, r, &request); err != nil {
			writeResponseError(w, http.StatusBadRequest, "Invalid JSON request body")
			return
		}
	}
	if request.DecisionNote != nil && len(*request.DecisionNote) > 2000 {
		writeResponseError(w, http.StatusBadRequest, "decision_note cannot exceed 2000 characters")
		return
	}

	tx, err := database.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not start approval transaction")
		return
	}
	defer func() { _ = tx.Rollback() }()

	var runDBID int64
	var requestedBy, currentStatus string
	err = tx.QueryRowContext(
		r.Context(),
		`SELECT response_run_db_id, requested_by::text, status
 FROM response_approvals
 WHERE tenant_id=$1 AND approval_id=$2
 FOR UPDATE`,
		identity.TenantID, approvalID,
	).Scan(&runDBID, &requestedBy, &currentStatus)
	if errors.Is(err, sql.ErrNoRows) {
		writeResponseError(w, http.StatusNotFound, "Approval not found")
		return
	}
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not load approval")
		return
	}
	if currentStatus != "pending" {
		writeResponseError(w, http.StatusConflict, "Approval has already been decided")
		return
	}
	if requestedBy == identity.UserID {
		writeResponseError(w, http.StatusForbidden, "The requester cannot approve or reject their own response run")
		return
	}

	var runStatus string
	err = tx.QueryRowContext(
		r.Context(),
		`SELECT status FROM response_runs
 WHERE tenant_id=$1 AND id=$2 FOR UPDATE`,
		identity.TenantID, runDBID,
	).Scan(&runStatus)
	if err != nil {
		writeResponseError(w, http.StatusConflict, "The related response run is not available")
		return
	}
	if runStatus != "pending_approval" {
		writeResponseError(w, http.StatusConflict, "The response run is not awaiting approval")
		return
	}

	decision := "rejected"
	if approve {
		decision = "approved"
	}
	_, err = tx.ExecContext(
		r.Context(),
		`UPDATE response_approvals
 SET status=$1, decided_by=$2, decided_at=NOW(), decision_note=NULLIF($3,'')
 WHERE tenant_id=$4 AND approval_id=$5`,
		decision, identity.UserID, responseStringValue(request.DecisionNote),
		identity.TenantID, approvalID,
	)
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not save approval decision")
		return
	}

	if approve {
		_, err = tx.ExecContext(
			r.Context(),
			`UPDATE response_runs
 SET status='queued', updated_at=NOW()
 WHERE tenant_id=$1 AND id=$2`,
			identity.TenantID, runDBID,
		)
	} else {
		_, err = tx.ExecContext(
			r.Context(),
			`UPDATE response_action_executions
 SET status='skipped', finished_at=NOW(), updated_at=NOW()
 WHERE tenant_id=$1 AND response_run_db_id=$2 AND status='pending'`,
			identity.TenantID, runDBID,
		)
		if err == nil {
			_, err = tx.ExecContext(
				r.Context(),
				`UPDATE response_runs
 SET status='rejected', finished_at=NOW(), updated_at=NOW()
 WHERE tenant_id=$1 AND id=$2`,
				identity.TenantID, runDBID,
			)
		}
	}
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not update response run after decision")
		return
	}

	item, err := scanResponseApproval(tx.QueryRowContext(
		r.Context(),
		responseApprovalSelect+` WHERE a.tenant_id=$1 AND a.approval_id=$2`,
		identity.TenantID, approvalID,
	))
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not retrieve approval decision")
		return
	}
	if err := tx.Commit(); err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not commit approval decision")
		return
	}
	writeResponseJSON(w, http.StatusOK, item)
}

// StartResponseRunHandler changes an approved/queued run to running.
// It does not execute external actions.
//
// @Summary Start response run
// @Tags Response Runs
// @Produce json
// @Param response_run_id path string true "Response run ID"
// @Success 200 {object} ResponseRun
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Router /api/v1/response/runs/{response_run_id}/start [post]
func StartResponseRunHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := responseIdentity(w, r)
	if !ok {
		return
	}
	if !responseRequireRole(w, identity, "admin", "responder") {
		return
	}
	runID := strings.TrimSpace(r.PathValue("response_run_id"))
	if !validResponseID(runID) {
		writeResponseError(w, http.StatusBadRequest, "Invalid response_run_id")
		return
	}

	result, err := database.DB.ExecContext(
		r.Context(),
		`UPDATE response_runs
 SET status='running', started_at=COALESCE(started_at,NOW()), updated_at=NOW()
 WHERE tenant_id=$1 AND response_run_id=$2 AND status='queued'`,
		identity.TenantID, runID,
	)
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not start response run")
		return
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		var current string
		err := database.DB.QueryRowContext(
			r.Context(),
			`SELECT status FROM response_runs WHERE tenant_id=$1 AND response_run_id=$2`,
			identity.TenantID, runID,
		).Scan(&current)
		if errors.Is(err, sql.ErrNoRows) {
			writeResponseError(w, http.StatusNotFound, "Response run not found")
			return
		}
		if err != nil {
			writeResponseError(w, http.StatusInternalServerError, "Could not retrieve response run status")
			return
		}
		writeResponseError(w, http.StatusConflict, "Response run must be queued before it can start; current status: "+current)
		return
	}

	item, err := scanResponseRun(database.DB.QueryRowContext(
		r.Context(),
		responseRunSelect+` WHERE rr.tenant_id=$1 AND rr.response_run_id=$2`,
		identity.TenantID, runID,
	))
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not retrieve started response run")
		return
	}
	writeResponseJSON(w, http.StatusOK, item)
}

// CancelResponseRunHandler cancels a run and skips any actions not yet started.
//
// @Summary Cancel response run
// @Tags Response Runs
// @Produce json
// @Param response_run_id path string true "Response run ID"
// @Success 200 {object} ResponseRun
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Router /api/v1/response/runs/{response_run_id}/cancel [post]
func CancelResponseRunHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := responseIdentity(w, r)
	if !ok {
		return
	}
	if !responseRequireRole(w, identity, "admin") {
		return
	}
	runID := strings.TrimSpace(r.PathValue("response_run_id"))
	if !validResponseID(runID) {
		writeResponseError(w, http.StatusBadRequest, "Invalid response_run_id")
		return
	}

	tx, err := database.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not start cancellation transaction")
		return
	}
	defer func() { _ = tx.Rollback() }()

	var runDBID int64
	var status string
	err = tx.QueryRowContext(
		r.Context(),
		`SELECT id,status FROM response_runs
 WHERE tenant_id=$1 AND response_run_id=$2 FOR UPDATE`,
		identity.TenantID, runID,
	).Scan(&runDBID, &status)
	if errors.Is(err, sql.ErrNoRows) {
		writeResponseError(w, http.StatusNotFound, "Response run not found")
		return
	}
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not load response run")
		return
	}
	if status != "pending_approval" && status != "queued" && status != "running" {
		writeResponseError(w, http.StatusConflict, "Only pending, queued, or running response runs can be cancelled")
		return
	}

	_, err = tx.ExecContext(
		r.Context(),
		`UPDATE response_action_executions
 SET status='cancelled', finished_at=NOW(), updated_at=NOW()
 WHERE tenant_id=$1 AND response_run_db_id=$2
   AND status IN ('pending','running')`,
		identity.TenantID, runDBID,
	)
	if err == nil {
		_, err = tx.ExecContext(
			r.Context(),
			`UPDATE response_approvals
 SET status='rejected', decided_by=$1, decided_at=NOW(),
     decision_note='Run cancelled by administrator'
 WHERE tenant_id=$2 AND response_run_db_id=$3 AND status='pending'`,
			identity.UserID, identity.TenantID, runDBID,
		)
	}
	if err == nil {
		_, err = tx.ExecContext(
			r.Context(),
			`UPDATE response_runs
 SET status='cancelled', finished_at=NOW(), updated_at=NOW()
 WHERE tenant_id=$1 AND id=$2`,
			identity.TenantID, runDBID,
		)
	}
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not cancel response run")
		return
	}

	item, err := scanResponseRun(tx.QueryRowContext(
		r.Context(),
		responseRunSelect+` WHERE rr.tenant_id=$1 AND rr.id=$2`,
		identity.TenantID, runDBID,
	))
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not retrieve cancelled response run")
		return
	}
	if err := tx.Commit(); err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not commit cancellation")
		return
	}
	writeResponseJSON(w, http.StatusOK, item)
}

// UpdateResponseActionExecutionHandler records an executor's action result.
// This endpoint records execution state; it does not perform the action itself.
//
// @Summary Record response action execution result
// @Tags Response Runs
// @Accept json
// @Produce json
// @Param response_run_id path string true "Response run ID"
// @Param action_execution_id path string true "Action execution ID"
// @Param body body ResponseActionResultRequest true "Execution result"
// @Success 200 {object} ResponseActionExecution
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Router /api/v1/response/runs/{response_run_id}/actions/{action_execution_id} [patch]
func UpdateResponseActionExecutionHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := responseIdentity(w, r)
	if !ok {
		return
	}
	if !responseRequireRole(w, identity, "admin", "responder") {
		return
	}

	runID := strings.TrimSpace(r.PathValue("response_run_id"))
	executionID := strings.TrimSpace(r.PathValue("action_execution_id"))
	if !validResponseID(runID) || !validResponseID(executionID) {
		writeResponseError(w, http.StatusBadRequest, "Invalid response_run_id or action_execution_id")
		return
	}

	var request ResponseActionResultRequest
	if err := decodeResponseJSON(w, r, &request); err != nil {
		writeResponseError(w, http.StatusBadRequest, "Invalid JSON request body")
		return
	}
	request.Status = strings.TrimSpace(request.Status)
	if request.Status != "running" && request.Status != "succeeded" &&
		request.Status != "failed" && request.Status != "skipped" &&
		request.Status != "timed_out" && request.Status != "cancelled" {
		writeResponseError(w, http.StatusBadRequest, "Invalid action execution status")
		return
	}
	if request.ResultSummary != nil && len(*request.ResultSummary) > 5000 {
		writeResponseError(w, http.StatusBadRequest, "result_summary cannot exceed 5000 characters")
		return
	}
	if request.ErrorCode != nil && len(*request.ErrorCode) > 64 {
		writeResponseError(w, http.StatusBadRequest, "error_code cannot exceed 64 characters")
		return
	}
	if request.ExternalReference != nil && len(*request.ExternalReference) > 255 {
		writeResponseError(w, http.StatusBadRequest, "external_reference cannot exceed 255 characters")
		return
	}

	tx, err := database.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not start action update transaction")
		return
	}
	defer func() { _ = tx.Rollback() }()

	var runDBID int64
	var runStatus string
	var currentStatus string
	var attempts int
	err = tx.QueryRowContext(
		r.Context(),
		`SELECT rr.id, rr.status, e.status, e.attempt_count
 FROM response_action_executions e
 JOIN response_runs rr
   ON rr.tenant_id=e.tenant_id AND rr.id=e.response_run_db_id
 WHERE e.tenant_id=$1 AND rr.response_run_id=$2
   AND e.action_execution_id=$3
 FOR UPDATE OF rr,e`,
		identity.TenantID, runID, executionID,
	).Scan(&runDBID, &runStatus, &currentStatus, &attempts)
	if errors.Is(err, sql.ErrNoRows) {
		writeResponseError(w, http.StatusNotFound, "Action execution not found")
		return
	}
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not load action execution")
		return
	}
	if runStatus != "running" {
		writeResponseError(w, http.StatusConflict, "Start the response run before updating action executions")
		return
	}

	allowed := false
	switch currentStatus {
	case "pending":
		allowed = request.Status == "running" || request.Status == "skipped" || request.Status == "cancelled"
	case "running":
		allowed = request.Status == "succeeded" || request.Status == "failed" ||
			request.Status == "skipped" || request.Status == "timed_out" || request.Status == "cancelled"
	case "failed", "timed_out":
		allowed = request.Status == "running" && attempts < 10
	}
	if !allowed {
		writeResponseError(w, http.StatusConflict, "Invalid action execution state transition")
		return
	}
	if request.Status == "running" && attempts >= 10 {
		writeResponseError(w, http.StatusConflict, "Action execution retry limit reached")
		return
	}

	item, err := scanResponseExecution(tx.QueryRowContext(
		r.Context(),
		`UPDATE response_action_executions
 SET status=$1,
     attempt_count=CASE WHEN $1='running' THEN attempt_count+1 ELSE attempt_count END,
     result_summary=CASE WHEN $2 THEN NULLIF($3,'') ELSE result_summary END,
     error_code=CASE WHEN $4 THEN NULLIF($5,'') ELSE error_code END,
     external_reference=CASE WHEN $6 THEN NULLIF($7,'') ELSE external_reference END,
     started_at=CASE WHEN $1='running' THEN NOW() ELSE started_at END,
     finished_at=CASE WHEN $1='running' THEN NULL ELSE NOW() END,
     updated_at=NOW()
 WHERE tenant_id=$8 AND response_run_db_id=$9 AND action_execution_id=$10
 RETURNING id, action_execution_id,
   (SELECT response_run_id FROM response_runs WHERE tenant_id=$8 AND id=$9),
   playbook_id, response_action_id, step_order, action_type, status,
   attempt_count, config_snapshot, result_summary, error_code,
   external_reference, started_at, finished_at, created_at, updated_at`,
		request.Status,
		request.ResultSummary != nil, responseStringValue(request.ResultSummary),
		request.ErrorCode != nil, responseStringValue(request.ErrorCode),
		request.ExternalReference != nil, responseStringValue(request.ExternalReference),
		identity.TenantID, runDBID, executionID,
	))
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not update action execution")
		return
	}

	var remaining, succeeded, failed, timedOut, cancelled, skipped int
	err = tx.QueryRowContext(
		r.Context(),
		`SELECT
   COUNT(*) FILTER (WHERE status IN ('pending','running')),
   COUNT(*) FILTER (WHERE status='succeeded'),
   COUNT(*) FILTER (WHERE status='failed'),
   COUNT(*) FILTER (WHERE status='timed_out'),
   COUNT(*) FILTER (WHERE status='cancelled'),
            COUNT(*) FILTER (WHERE status='skipped')
 FROM response_action_executions
 WHERE tenant_id=$1 AND response_run_db_id=$2`,
		identity.TenantID, runDBID,
	).Scan(&remaining, &succeeded, &failed, &timedOut, &cancelled, &skipped)
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not calculate response run result")
		return
	}

	if remaining == 0 {
		finalStatus := "succeeded"
		totalFailures := failed + timedOut
		if totalFailures > 0 && succeeded > 0 {
			finalStatus = "partially_failed"
		} else if totalFailures > 0 {
			finalStatus = "failed"
			if timedOut > 0 && failed == 0 {
				finalStatus = "timed_out"
			}
		} else if (cancelled+skipped) > 0 && succeeded == 0 {
			finalStatus = "cancelled"
		}
		_, err = tx.ExecContext(
			r.Context(),
			`UPDATE response_runs
 SET status=$1, finished_at=NOW(), updated_at=NOW()
 WHERE tenant_id=$2 AND id=$3`,
			finalStatus, identity.TenantID, runDBID,
		)
	} else {
		_, err = tx.ExecContext(
			r.Context(),
			`UPDATE response_runs
 SET started_at=COALESCE(started_at,NOW()), updated_at=NOW()
 WHERE tenant_id=$1 AND id=$2 AND status='running'`,
			identity.TenantID, runDBID,
		)
	}
	if err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not update response run status")
		return
	}

	if err := tx.Commit(); err != nil {
		writeResponseError(w, http.StatusInternalServerError, "Could not commit action execution result")
		return
	}
	writeResponseJSON(w, http.StatusOK, item)
}

func responseStringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func responseStringPointerValue(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}
