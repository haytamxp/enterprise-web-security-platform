package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/database"
)

// incidentResponse represents the public incident data returned by the API.
type incidentResponse struct {
	IncidentID    string    `json:"incident_id"`
	SchemaVersion string    `json:"schema_version"`
	AssetID       string    `json:"asset_id"`
	OccurredAt    time.Time `json:"occurred_at"`
	Severity      string    `json:"severity"`
	Confidence    float64   `json:"confidence"`
	Title         string    `json:"title"`
	CorrelationID string    `json:"correlation_id"`
	Description   string    `json:"description"`
	PlaybookRef   *string   `json:"playbook_ref,omitempty"`
	Status        string    `json:"status"`
	ReceivedAt    time.Time `json:"received_at"`
}

// rowScanner allows the same scanning function to work with sql.Row and sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanIncident converts one database row into an API incident.
func scanIncident(row rowScanner) (incidentResponse, error) {
	var incident incidentResponse
	var playbookRef sql.NullString

	err := row.Scan(
		&incident.IncidentID,
		&incident.SchemaVersion,
		&incident.AssetID,
		&incident.OccurredAt,
		&incident.Severity,
		&incident.Confidence,
		&incident.Title,
		&incident.CorrelationID,
		&incident.Description,
		&playbookRef,
		&incident.Status,
		&incident.ReceivedAt,
	)

	if err != nil {
		return incident, err
	}

	if playbookRef.Valid {
		incident.PlaybookRef = &playbookRef.String
	}

	return incident, nil
}

// CreateIncidentHandler receives and stores an incident sent by P2.
//
// @Summary      Incident ingestion
// @Description  Receives an incident and stores it in the authenticated tenant
// @Tags         Incidents
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        incident body map[string]interface{} true "P2 incident"
// @Success      201 {object} map[string]string
// @Failure      400 {string} string "Invalid JSON or missing data"
// @Router       /incidents [post]
func CreateIncidentHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := AuthIdentityFromContext(r.Context())
	if !ok {
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	var payload struct {
		Title       string `json:"title"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON request", http.StatusBadRequest)
		return
	}

	payload.Title = strings.TrimSpace(payload.Title)
	payload.Severity = strings.TrimSpace(payload.Severity)
	payload.Description = strings.TrimSpace(payload.Description)

	if payload.Title == "" || payload.Severity == "" || payload.Description == "" {
		http.Error(w, "Title, severity and description are required", http.StatusBadRequest)
		return
	}

	occurredAt := time.Now().UTC()
	correlationID := fmt.Sprintf("corr-%d", occurredAt.UnixNano())

	query := `
		INSERT INTO incidents (
			incident_id,
			schema_version,
			asset_id,
			occurred_at,
			severity,
			confidence,
			title,
			correlation_id,
			description,
			tenant_id
		)
		VALUES (
			gen_random_uuid()::text,
			'1.0',
			'asset-default',
			$1,
			$2,
			0.85,
			$3,
			$4,
			$5,
			$6
		)
		RETURNING incident_id
	`

	var incidentID string

	err := database.DB.QueryRow(
		query,
		occurredAt,
		payload.Severity,
		payload.Title,
		correlationID,
		payload.Description,
		identity.TenantID,
	).Scan(&incidentID)

	if err != nil {
		http.Error(w, "Could not store incident", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	json.NewEncoder(w).Encode(map[string]string{
		"status":      "success",
		"incident_id": incidentID,
	})
}

// ListIncidentsHandler returns incidents belonging to the authenticated tenant.
//
// Supported query parameters:
// limit, offset, severity, status, asset_id
//
// @Summary      List incidents
// @Description  Returns paginated incidents belonging to the authenticated tenant
// @Tags         Incidents
// @Produce      json
// @Security     BearerAuth
// @Param        limit query int false "Number of results (1-100, default 20)"
// @Param        offset query int false "Number of results to skip"
// @Param        severity query string false "Filter by severity"
// @Param        status query string false "Filter by status"
// @Param        asset_id query string false "Filter by asset"
// @Success      200 {object} map[string]interface{}
// @Failure      400 {string} string "Invalid pagination parameters"
// @Failure      401 {string} string "Authentication required"
// @Router       /incidents [get]
func ListIncidentsHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := AuthIdentityFromContext(r.Context())
	if !ok {
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	queryParams := r.URL.Query()

	limit := 20
	if rawLimit := queryParams.Get("limit"); rawLimit != "" {
		value, err := strconv.Atoi(rawLimit)
		if err != nil || value < 1 || value > 100 {
			http.Error(w, "Limit must be between 1 and 100", http.StatusBadRequest)
			return
		}
		limit = value
	}

	offset := 0
	if rawOffset := queryParams.Get("offset"); rawOffset != "" {
		value, err := strconv.Atoi(rawOffset)
		if err != nil || value < 0 {
			http.Error(w, "Offset must be a non-negative integer", http.StatusBadRequest)
			return
		}
		offset = value
	}

	// Tenant ID always comes from the authenticated JWT, never from the URL.
	args := []any{identity.TenantID}
	where := "tenant_id = $1"

	filters := []struct {
		column string
		value  string
	}{
		{column: "severity", value: strings.TrimSpace(queryParams.Get("severity"))},
		{column: "status", value: strings.TrimSpace(queryParams.Get("status"))},
		{column: "asset_id", value: strings.TrimSpace(queryParams.Get("asset_id"))},
	}

	for _, filter := range filters {
		if filter.value == "" {
			continue
		}

		args = append(args, filter.value)
		where += fmt.Sprintf(" AND %s = $%d", filter.column, len(args))
	}

	// Count matching incidents for pagination metadata.
	var total int64

	countQuery := "SELECT COUNT(*) FROM incidents WHERE " + where

	err := database.DB.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		http.Error(w, "Could not count incidents", http.StatusInternalServerError)
		return
	}

	// Retrieve the current page.
	queryArgs := append([]any(nil), args...)
	queryArgs = append(queryArgs, limit, offset)

	listQuery := fmt.Sprintf(`
		SELECT
			incident_id,
			schema_version,
			asset_id,
			occurred_at,
			severity,
			confidence,
			title,
			correlation_id,
			description,
			playbook_ref,
			status,
			received_at
		FROM incidents
		WHERE %s
		ORDER BY occurred_at DESC, id DESC
		LIMIT $%d OFFSET $%d
	`, where, len(queryArgs)-1, len(queryArgs))

	rows, err := database.DB.Query(listQuery, queryArgs...)
	if err != nil {
		http.Error(w, "Could not retrieve incidents", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	incidents := make([]incidentResponse, 0)

	for rows.Next() {
		incident, err := scanIncident(rows)
		if err != nil {
			http.Error(w, "Could not read incident data", http.StatusInternalServerError)
			return
		}

		incidents = append(incidents, incident)
	}

	if err := rows.Err(); err != nil {
		http.Error(w, "Could not read incident data", http.StatusInternalServerError)
		return
	}

	response := struct {
		Data       []incidentResponse `json:"data"`
		Pagination struct {
			Limit  int   `json:"limit"`
			Offset int   `json:"offset"`
			Total  int64 `json:"total"`
		} `json:"pagination"`
	}{
		Data: incidents,
	}

	response.Pagination.Limit = limit
	response.Pagination.Offset = offset
	response.Pagination.Total = total

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetIncidentHandler returns one incident belonging to the authenticated tenant.
//
// @Summary      Get incident
// @Description  Returns an incident by its public incident ID
// @Tags         Incidents
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Public incident ID"
// @Success      200 {object} incidentResponse
// @Failure      401 {string} string "Authentication required"
// @Failure      404 {string} string "Incident not found"
// @Router       /incidents/{id} [get]
func GetIncidentHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := AuthIdentityFromContext(r.Context())
	if !ok {
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	incidentID := strings.TrimSpace(r.PathValue("id"))
	if incidentID == "" {
		http.Error(w, "Incident ID is required", http.StatusBadRequest)
		return
	}

	query := `
		SELECT
			incident_id,
			schema_version,
			asset_id,
			occurred_at,
			severity,
			confidence,
			title,
			correlation_id,
			description,
			playbook_ref,
			status,
			received_at
		FROM incidents
		WHERE incident_id = $1
		  AND tenant_id = $2
	`

	incident, err := scanIncident(
		database.DB.QueryRow(query, incidentID, identity.TenantID),
	)

	if err == sql.ErrNoRows {
		http.Error(w, "Incident not found", http.StatusNotFound)
		return
	}

	if err != nil {
		http.Error(w, "Could not retrieve incident", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(incident)
}
