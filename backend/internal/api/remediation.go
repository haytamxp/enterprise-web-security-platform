package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/database"
)

var remediationUUIDPattern = regexp.MustCompile(
	`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`,
)

type remediationTaskResponse struct {
	ID            int64      `json:"id"`
	RemediationID string     `json:"remediation_id"`
	FindingID     string     `json:"finding_id"`
	Title         string     `json:"title"`
	Description   *string    `json:"description"`
	Priority      string     `json:"priority"`
	Status        string     `json:"status"`
	AssignedTo    *string    `json:"assigned_to"`
	DueAt         *time.Time `json:"due_at"`
	CreatedBy     string     `json:"created_by"`
	CompletedAt   *time.Time `json:"completed_at"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

const remediationSelectColumns = `
id,
remediation_id,
finding_id,
title,
description,
priority,
status,
assigned_to::text,
due_at,
created_by::text,
completed_at,
created_at,
updated_at
`

func scanRemediationTask(row interface {
	Scan(...any) error
}) (remediationTaskResponse, error) {
	var task remediationTaskResponse
	var description sql.NullString
	var assignedTo sql.NullString
	var dueAt sql.NullTime
	var completedAt sql.NullTime

	err := row.Scan(
		&task.ID,
		&task.RemediationID,
		&task.FindingID,
		&task.Title,
		&description,
		&task.Priority,
		&task.Status,
		&assignedTo,
		&dueAt,
		&task.CreatedBy,
		&completedAt,
		&task.CreatedAt,
		&task.UpdatedAt,
	)
	if err != nil {
		return task, err
	}

	if description.Valid {
		task.Description = &description.String
	}
	if assignedTo.Valid {
		task.AssignedTo = &assignedTo.String
	}
	if dueAt.Valid {
		task.DueAt = &dueAt.Time
	}
	if completedAt.Valid {
		task.CompletedAt = &completedAt.Time
	}

	return task, nil
}

func writeRemediationJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeRemediationError(w http.ResponseWriter, status int, message string) {
	writeRemediationJSON(w, status, map[string]string{"error": message})
}

func validRemediationPriority(value string) bool {
	switch value {
	case "critical", "high", "medium", "low":
		return true
	default:
		return false
	}
}

func validRemediationStatus(value string) bool {
	switch value {
	case "open", "in_progress", "blocked", "completed", "cancelled":
		return true
	default:
		return false
	}
}

func parseRemediationTime(value string) (*time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}

	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, err
	}

	parsed = parsed.UTC()
	return &parsed, nil
}

// CreateRemediationTaskHandler godoc
// @Summary Create a remediation task
// @Description Creates a remediation task linked to an existing finding.
// @Tags Remediation
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param remediation body object true "Remediation task"
// @Success 201 {object} remediationTaskResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Router /remediation-tasks [post]
func CreateRemediationTaskHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := AuthIdentityFromContext(r.Context())
	if !ok {
		writeRemediationError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	if identity.Role != "admin" {
		writeRemediationError(w, http.StatusForbidden, "Only administrators can create remediation tasks")
		return
	}

	var request struct {
		RemediationID string `json:"remediation_id"`
		FindingID     string `json:"finding_id"`
		Title         string `json:"title"`
		Description   string `json:"description"`
		Priority      string `json:"priority"`
		Status        string `json:"status"`
		AssignedTo    string `json:"assigned_to"`
		DueAt         string `json:"due_at"`
	}

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeRemediationError(w, http.StatusBadRequest, "Invalid JSON request")
		return
	}

	request.RemediationID = strings.TrimSpace(request.RemediationID)
	request.FindingID = strings.TrimSpace(request.FindingID)
	request.Title = strings.TrimSpace(request.Title)
	request.Description = strings.TrimSpace(request.Description)
	request.Priority = strings.ToLower(strings.TrimSpace(request.Priority))
	request.Status = strings.ToLower(strings.TrimSpace(request.Status))
	request.AssignedTo = strings.TrimSpace(request.AssignedTo)

	if request.RemediationID == "" || request.FindingID == "" || request.Title == "" {
		writeRemediationError(w, http.StatusBadRequest, "remediation_id, finding_id and title are required")
		return
	}
	if len(request.RemediationID) > 128 || len(request.FindingID) > 128 || len(request.Title) > 512 {
		writeRemediationError(w, http.StatusBadRequest, "A task identifier, finding identifier or title is too long")
		return
	}
	if len(request.Description) > 10000 {
		writeRemediationError(w, http.StatusBadRequest, "description must not exceed 10000 characters")
		return
	}
	if !validRemediationPriority(request.Priority) {
		writeRemediationError(w, http.StatusBadRequest, "priority must be critical, high, medium or low")
		return
	}

	if request.Status == "" {
		request.Status = "open"
	}
	if !validRemediationStatus(request.Status) {
		writeRemediationError(w, http.StatusBadRequest, "Invalid remediation status")
		return
	}
	if request.Status == "completed" {
		writeRemediationError(w, http.StatusBadRequest, "Create the task first; completion must be recorded through an update")
		return
	}

	var assignedTo any
	if request.AssignedTo != "" {
		if !remediationUUIDPattern.MatchString(request.AssignedTo) {
			writeRemediationError(w, http.StatusBadRequest, "assigned_to must be a valid user UUID")
			return
		}
		assignedTo = request.AssignedTo
	}

	dueAt, err := parseRemediationTime(request.DueAt)
	if err != nil {
		writeRemediationError(w, http.StatusBadRequest, "due_at must be an RFC3339 timestamp")
		return
	}

	query := `
INSERT INTO remediation_tasks (
tenant_id,
remediation_id,
finding_id,
title,
description,
priority,
status,
assigned_to,
due_at,
created_by
)
VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7, $8, $9, $10)
RETURNING ` + remediationSelectColumns

	task, err := scanRemediationTask(database.DB.QueryRowContext(
		r.Context(),
		query,
		identity.TenantID,
		request.RemediationID,
		request.FindingID,
		request.Title,
		request.Description,
		request.Priority,
		request.Status,
		assignedTo,
		dueAt,
		identity.UserID,
	))
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			writeRemediationError(w, http.StatusConflict, "A remediation task with this ID already exists")
			return
		}
		if strings.Contains(err.Error(), "foreign key") {
			writeRemediationError(w, http.StatusBadRequest, "The finding or assigned user does not exist in this organization")
			return
		}
		writeRemediationError(w, http.StatusInternalServerError, "Could not create remediation task")
		return
	}

	writeRemediationJSON(w, http.StatusCreated, task)
}

// ListRemediationTasksHandler godoc
// @Summary List remediation tasks
// @Description Lists remediation tasks belonging to the authenticated user's organization.
// @Tags Remediation
// @Produce json
// @Security BearerAuth
// @Param finding_id query string false "Filter by finding ID"
// @Param status query string false "Filter by status"
// @Param limit query int false "Maximum number of results (1-100)"
// @Success 200 {object} map[string]interface{}
// @Router /remediation-tasks [get]
func ListRemediationTasksHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := AuthIdentityFromContext(r.Context())
	if !ok {
		writeRemediationError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	limit := 50
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed < 1 || parsed > 100 {
			writeRemediationError(w, http.StatusBadRequest, "limit must be between 1 and 100")
			return
		}
		limit = parsed
	}

	findingID := strings.TrimSpace(r.URL.Query().Get("finding_id"))
	status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))

	if status != "" && !validRemediationStatus(status) {
		writeRemediationError(w, http.StatusBadRequest, "Invalid remediation status filter")
		return
	}

	query := `SELECT ` + remediationSelectColumns + `
FROM remediation_tasks
WHERE tenant_id = $1
AND ($2 = '' OR finding_id = $2)
AND ($3 = '' OR status = $3)
ORDER BY id DESC
LIMIT $4`

	rows, err := database.DB.QueryContext(
		r.Context(), query, identity.TenantID, findingID, status, limit,
	)
	if err != nil {
		writeRemediationError(w, http.StatusInternalServerError, "Could not list remediation tasks")
		return
	}
	defer rows.Close()

	items := make([]remediationTaskResponse, 0)
	for rows.Next() {
		task, err := scanRemediationTask(rows)
		if err != nil {
			writeRemediationError(w, http.StatusInternalServerError, "Could not read remediation tasks")
			return
		}
		items = append(items, task)
	}
	if err := rows.Err(); err != nil {
		writeRemediationError(w, http.StatusInternalServerError, "Could not read remediation tasks")
		return
	}

	writeRemediationJSON(w, http.StatusOK, map[string]any{
		"items": items,
		"count": len(items),
		"limit": limit,
	})
}

// GetRemediationTaskHandler godoc
// @Summary Get a remediation task
// @Tags Remediation
// @Produce json
// @Security BearerAuth
// @Param remediation_id path string true "Remediation ID"
// @Success 200 {object} remediationTaskResponse
// @Failure 404 {object} map[string]string
// @Router /remediation-tasks/{remediation_id} [get]
func GetRemediationTaskHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := AuthIdentityFromContext(r.Context())
	if !ok {
		writeRemediationError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	remediationID := strings.TrimSpace(r.PathValue("remediation_id"))
	if remediationID == "" {
		writeRemediationError(w, http.StatusBadRequest, "Invalid remediation ID")
		return
	}

	task, err := scanRemediationTask(database.DB.QueryRowContext(
		r.Context(),
		`SELECT `+remediationSelectColumns+`
 FROM remediation_tasks
 WHERE tenant_id = $1 AND remediation_id = $2`,
		identity.TenantID,
		remediationID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		writeRemediationError(w, http.StatusNotFound, "Remediation task not found")
		return
	}
	if err != nil {
		writeRemediationError(w, http.StatusInternalServerError, "Could not retrieve remediation task")
		return
	}

	writeRemediationJSON(w, http.StatusOK, task)
}

// UpdateRemediationTaskHandler godoc
// @Summary Update a remediation task
// @Description Administrators can update all fields. Responders can update description and status on tasks assigned to them.
// @Tags Remediation
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param remediation_id path string true "Remediation ID"
// @Param remediation body object true "Fields to update"
// @Success 200 {object} remediationTaskResponse
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /remediation-tasks/{remediation_id} [patch]
func UpdateRemediationTaskHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := AuthIdentityFromContext(r.Context())
	if !ok {
		writeRemediationError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	remediationID := strings.TrimSpace(r.PathValue("remediation_id"))
	if remediationID == "" {
		writeRemediationError(w, http.StatusBadRequest, "Invalid remediation ID")
		return
	}

	var request struct {
		Title       *string `json:"title"`
		Description *string `json:"description"`
		Priority    *string `json:"priority"`
		Status      *string `json:"status"`
		AssignedTo  *string `json:"assigned_to"`
		DueAt       *string `json:"due_at"`
	}

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeRemediationError(w, http.StatusBadRequest, "Invalid JSON request")
		return
	}

	if request.Title == nil && request.Description == nil &&
		request.Priority == nil && request.Status == nil &&
		request.AssignedTo == nil && request.DueAt == nil {
		writeRemediationError(w, http.StatusBadRequest, "Provide at least one field to update")
		return
	}

	isAdmin := identity.Role == "admin"
	if !isAdmin && identity.Role != "responder" {
		writeRemediationError(w, http.StatusForbidden, "You cannot update remediation tasks")
		return
	}

	if !isAdmin && (request.Title != nil || request.Priority != nil ||
		request.AssignedTo != nil || request.DueAt != nil) {
		writeRemediationError(w, http.StatusForbidden, "Responders can only update description and status")
		return
	}

	if request.Title != nil {
		value := strings.TrimSpace(*request.Title)
		if value == "" || len(value) > 512 {
			writeRemediationError(w, http.StatusBadRequest, "title must contain 1-512 characters")
			return
		}
		request.Title = &value
	}
	if request.Description != nil && len(*request.Description) > 10000 {
		writeRemediationError(w, http.StatusBadRequest, "description must not exceed 10000 characters")
		return
	}
	if request.Priority != nil {
		value := strings.ToLower(strings.TrimSpace(*request.Priority))
		if !validRemediationPriority(value) {
			writeRemediationError(w, http.StatusBadRequest, "Invalid priority")
			return
		}
		request.Priority = &value
	}
	if request.Status != nil {
		value := strings.ToLower(strings.TrimSpace(*request.Status))
		if !validRemediationStatus(value) {
			writeRemediationError(w, http.StatusBadRequest, "Invalid status")
			return
		}
		request.Status = &value
	}

	var assignedTo any
	if request.AssignedTo != nil {
		value := strings.TrimSpace(*request.AssignedTo)
		if value != "" && !remediationUUIDPattern.MatchString(value) {
			writeRemediationError(w, http.StatusBadRequest, "assigned_to must be a valid user UUID or an empty string")
			return
		}
		assignedTo = value
	}

	var dueAt any
	if request.DueAt != nil {
		parsed, err := parseRemediationTime(*request.DueAt)
		if err != nil {
			writeRemediationError(w, http.StatusBadRequest, "due_at must be an RFC3339 timestamp or an empty string")
			return
		}
		dueAt = parsed
	}

	descriptionValue := ""
	if request.Description != nil {
		descriptionValue = *request.Description
	}

	query := `
UPDATE remediation_tasks
SET
title = COALESCE($1, title),
description = CASE WHEN $2 THEN NULLIF($3, '') ELSE description END,
priority = COALESCE($4, priority),
status = COALESCE($5, status),
assigned_to = CASE WHEN $6 THEN NULLIF($7, '')::uuid ELSE assigned_to END,
due_at = CASE WHEN $8 THEN $9::timestamptz ELSE due_at END,
completed_at = CASE
WHEN COALESCE($5, status) = 'completed'
THEN COALESCE(completed_at, NOW())
ELSE NULL
END,
updated_at = NOW()
WHERE tenant_id = $10
  AND remediation_id = $11
  AND ($12 OR assigned_to = NULLIF($13, '')::uuid)
RETURNING ` + remediationSelectColumns

	var titleValue any
	var priorityValue any
	var statusValue any
	if request.Title != nil {
		titleValue = *request.Title
	}
	if request.Priority != nil {
		priorityValue = *request.Priority
	}
	if request.Status != nil {
		statusValue = *request.Status
	}

	task, err := scanRemediationTask(database.DB.QueryRowContext(
		r.Context(),
		query,
		titleValue,
		request.Description != nil,
		descriptionValue,
		priorityValue,
		statusValue,
		request.AssignedTo != nil,
		assignedTo,
		request.DueAt != nil,
		dueAt,
		identity.TenantID,
		remediationID,
		isAdmin,
		identity.UserID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		writeRemediationError(w, http.StatusNotFound, "Remediation task not found or not assigned to you")
		return
	}
	if err != nil {
		if strings.Contains(err.Error(), "foreign key") {
			writeRemediationError(w, http.StatusBadRequest, "The assigned user does not exist in this organization")
			return
		}
		writeRemediationError(w, http.StatusInternalServerError, "Could not update remediation task")
		return
	}

	writeRemediationJSON(w, http.StatusOK, task)
}
