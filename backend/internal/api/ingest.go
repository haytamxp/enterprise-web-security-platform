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

// eventResponse represents the event data returned by the API.
type eventResponse struct {
	EventID       string    `json:"event_id"`
	SchemaVersion string    `json:"schema_version"`
	SourceProduct string    `json:"source_product"`
	EventType     string    `json:"event_type"`
	AssetID       *string   `json:"asset_id,omitempty"`
	OccurredAt    time.Time `json:"occurred_at"`
	Severity      int       `json:"severity"`
	Confidence    float64   `json:"confidence"`
	CorrelationID *string   `json:"correlation_id,omitempty"`
	SrcIP         *string   `json:"src_ip,omitempty"`
	DestIP        *string   `json:"dest_ip,omitempty"`
	RuleID        *string   `json:"rule_id,omitempty"`
	Signature     *string   `json:"signature,omitempty"`
	Description   *string   `json:"description,omitempty"`
	RawRef        *string   `json:"raw_ref,omitempty"`
	ReceivedAt    time.Time `json:"received_at"`
}

type eventPagination struct {
	Limit  int   `json:"limit"`
	Offset int   `json:"offset"`
	Total  int64 `json:"total"`
}

type eventListResponse struct {
	Data       []eventResponse `json:"data"`
	Pagination eventPagination `json:"pagination"`
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
	var tenantID string

	if identity, ok := AuthIdentityFromContext(r.Context()); ok {
		tenantID = identity.TenantID
	} else if connectorIdentity, ok := ConnectorIdentityFromContext(r.Context()); ok {
		tenantID = connectorIdentity.TenantID
	}

	if tenantID == "" {
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
		tenantID,
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

// ListEventsHandler returns events belonging to the authenticated tenant.
//
// @Summary      List security events
// @Description  Returns paginated security events belonging to the authenticated user's tenant
// @Tags         Events
// @Produce      json
// @Security     BearerAuth
// @Param        limit query int false "Number of events (1-100)"
// @Param        offset query int false "Number of events to skip"
// @Param        severity query int false "Severity (1-5)"
// @Param        source_product query string false "Event source"
// @Param        event_type query string false "Event type"
// @Param        asset_id query string false "Asset identifier"
// @Success      200 {object} eventListResponse
// @Failure      400 {string} string "Invalid query parameters"
// @Failure      401 {string} string "Authentication required"
// @Failure      500 {string} string "Could not retrieve events"
// @Router       /events [get]
func ListEventsHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := AuthIdentityFromContext(r.Context())
	if !ok {
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	queryParams := r.URL.Query()

	// Pagination
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

	// Always restrict results to the authenticated user's tenant.
	args := []any{identity.TenantID}
	where := "tenant_id = $1"

	// Severity filter
	if rawSeverity := strings.TrimSpace(queryParams.Get("severity")); rawSeverity != "" {
		severity, err := strconv.Atoi(rawSeverity)
		if err != nil || severity < 1 || severity > 5 {
			http.Error(w, "Severity must be between 1 and 5", http.StatusBadRequest)
			return
		}

		args = append(args, severity)
		where += fmt.Sprintf(" AND severity = $%d", len(args))
	}

	// Source product filter
	if source := strings.TrimSpace(queryParams.Get("source_product")); source != "" {
		switch source {
		case "wazuh", "suricata", "application_log":
		default:
			http.Error(w, "Invalid source_product", http.StatusBadRequest)
			return
		}

		args = append(args, source)
		where += fmt.Sprintf(" AND source_product = $%d", len(args))
	}

	// Event type filter
	if eventType := strings.TrimSpace(queryParams.Get("event_type")); eventType != "" {
		switch eventType {
		case "alert", "flow", "http", "auth_failure", "anomaly":
		default:
			http.Error(w, "Invalid event_type", http.StatusBadRequest)
			return
		}

		args = append(args, eventType)
		where += fmt.Sprintf(" AND event_type = $%d", len(args))
	}

	// Asset filter
	if assetID := strings.TrimSpace(queryParams.Get("asset_id")); assetID != "" {
		args = append(args, assetID)
		where += fmt.Sprintf(" AND asset_id = $%d", len(args))
	}

	// Count matching events.
	var total int64

	countQuery := "SELECT COUNT(*) FROM events WHERE " + where

	if err := database.DB.QueryRow(countQuery, args...).Scan(&total); err != nil {
		http.Error(w, "Could not count events", http.StatusInternalServerError)
		return
	}

	// Retrieve the requested page.
	queryArgs := append([]any(nil), args...)
	queryArgs = append(queryArgs, limit, offset)

	listQuery := fmt.Sprintf(`
		SELECT
			event_id,
			schema_version,
			source_product,
			event_type,
			asset_id,
			occurred_at,
			severity,
			confidence,
			correlation_id,
			src_ip,
			dest_ip,
			rule_id,
			signature,
			description,
			raw_ref,
			received_at
		FROM events
		WHERE %s
		ORDER BY occurred_at DESC, id DESC
		LIMIT $%d OFFSET $%d
	`, where, len(queryArgs)-1, len(queryArgs))

	rows, err := database.DB.Query(listQuery, queryArgs...)
	if err != nil {
		http.Error(w, "Could not retrieve events", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	events := make([]eventResponse, 0)

	for rows.Next() {
		var event eventResponse

		err := rows.Scan(
			&event.EventID,
			&event.SchemaVersion,
			&event.SourceProduct,
			&event.EventType,
			&event.AssetID,
			&event.OccurredAt,
			&event.Severity,
			&event.Confidence,
			&event.CorrelationID,
			&event.SrcIP,
			&event.DestIP,
			&event.RuleID,
			&event.Signature,
			&event.Description,
			&event.RawRef,
			&event.ReceivedAt,
		)

		if err != nil {
			http.Error(w, "Could not read event data", http.StatusInternalServerError)
			return
		}

		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		http.Error(w, "Could not read event data", http.StatusInternalServerError)
		return
	}

	response := eventListResponse{
		Data: events,
		Pagination: eventPagination{
			Limit:  limit,
			Offset: offset,
			Total:  total,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetEventHandler returns one event belonging to the authenticated tenant.
//
// @Summary      Get security event
// @Description  Returns an event by its public event ID, restricted to the authenticated user's tenant
// @Tags         Events
// @Produce      json
// @Security     BearerAuth
// @Param        event_id path string true "Public event ID"
// @Success      200 {object} eventResponse
// @Failure      401 {string} string "Authentication required"
// @Failure      404 {string} string "Event not found"
// @Failure      500 {string} string "Could not retrieve event"
// @Router       /events/{event_id} [get]
func GetEventHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := AuthIdentityFromContext(r.Context())
	if !ok {
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	eventID := strings.TrimSpace(r.PathValue("event_id"))
	if eventID == "" {
		http.Error(w, "Event ID is required", http.StatusBadRequest)
		return
	}

	var event eventResponse

	err := database.DB.QueryRow(`
		SELECT
			event_id,
			schema_version,
			source_product,
			event_type,
			asset_id,
			occurred_at,
			severity,
			confidence,
			correlation_id,
			src_ip,
			dest_ip,
			rule_id,
			signature,
			description,
			raw_ref,
			received_at
		FROM events
		WHERE event_id = $1 AND tenant_id = $2
	`, eventID, identity.TenantID).Scan(
		&event.EventID,
		&event.SchemaVersion,
		&event.SourceProduct,
		&event.EventType,
		&event.AssetID,
		&event.OccurredAt,
		&event.Severity,
		&event.Confidence,
		&event.CorrelationID,
		&event.SrcIP,
		&event.DestIP,
		&event.RuleID,
		&event.Signature,
		&event.Description,
		&event.RawRef,
		&event.ReceivedAt,
	)

	if err == sql.ErrNoRows {
		http.Error(w, "Event not found", http.StatusNotFound)
		return
	}

	if err != nil {
		http.Error(w, "Could not retrieve event", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(event)
}

// CreateEventHandler receives and stores security events from P2.
//
// @Summary      Event ingestion
// @Description  Receives security events from an authenticated connector
// @Tags         Events
// @Accept       json
// @Produce      json
// @Param        Authorization header string true "Connector credentials: Connector <key_id>.<secret>"
// @Param        event body map[string]interface{} true "Security event"
// @Success      201 {object} map[string]string
// @Failure      400 {string} string "Invalid event"
// @Failure      401 {string} string "Invalid connector credentials"
// @Failure      403 {string} string "Missing connector scope"
// @Failure      409 {string} string "Duplicate event"
// @Router       /events [post]
func CreateEventHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := ConnectorIdentityFromContext(r.Context())
	if !ok {
		http.Error(w, "Connector authentication required", http.StatusUnauthorized)
		return
	}

	var payload struct {
		EventID       string    `json:"event_id"`
		SchemaVersion string    `json:"schema_version"`
		SourceProduct string    `json:"source_product"`
		EventType     string    `json:"event_type"`
		AssetID       *string   `json:"asset_id"`
		OccurredAt    time.Time `json:"occurred_at"`
		Severity      int       `json:"severity"`
		Confidence    float64   `json:"confidence"`
		CorrelationID *string   `json:"correlation_id"`
		SrcIP         *string   `json:"src_ip"`
		DestIP        *string   `json:"dest_ip"`
		RuleID        *string   `json:"rule_id"`
		Signature     *string   `json:"signature"`
		Description   *string   `json:"description"`
		RawRef        *string   `json:"raw_ref"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON request", http.StatusBadRequest)
		return
	}

	payload.EventID = strings.TrimSpace(payload.EventID)
	payload.SchemaVersion = strings.TrimSpace(payload.SchemaVersion)
	payload.SourceProduct = strings.TrimSpace(payload.SourceProduct)
	payload.EventType = strings.TrimSpace(payload.EventType)

	if payload.EventID == "" ||
		payload.SchemaVersion != "1.0" ||
		payload.OccurredAt.IsZero() ||
		payload.Severity < 1 || payload.Severity > 5 ||
		payload.Confidence < 0 || payload.Confidence > 1 {
		http.Error(w, "Missing or invalid required event fields", http.StatusBadRequest)
		return
	}

	switch payload.SourceProduct {
	case "wazuh", "suricata", "application_log":
	default:
		http.Error(w, "Invalid source_product", http.StatusBadRequest)
		return
	}

	switch payload.EventType {
	case "alert", "flow", "http", "auth_failure", "anomaly":
	default:
		http.Error(w, "Invalid event_type", http.StatusBadRequest)
		return
	}

	var eventID string

	err := database.DB.QueryRow(`
		INSERT INTO events (
			event_id, schema_version, source_product, event_type,
			asset_id, occurred_at, severity, confidence,
			correlation_id, src_ip, dest_ip, rule_id,
			signature, description, raw_ref, tenant_id
		)
		VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13, $14, $15, $16
		)
		RETURNING event_id
	`,
		payload.EventID,
		payload.SchemaVersion,
		payload.SourceProduct,
		payload.EventType,
		payload.AssetID,
		payload.OccurredAt,
		payload.Severity,
		payload.Confidence,
		payload.CorrelationID,
		payload.SrcIP,
		payload.DestIP,
		payload.RuleID,
		payload.Signature,
		payload.Description,
		payload.RawRef,
		identity.TenantID,
	).Scan(&eventID)

	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
			http.Error(w, "Event already exists", http.StatusConflict)
			return
		}

		http.Error(w, "Could not store event", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	json.NewEncoder(w).Encode(map[string]string{
		"status":   "success",
		"event_id": eventID,
	})
}
