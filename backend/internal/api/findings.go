
package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/database"
)

const findingSelectColumns = `
	id, schema_version, finding_id, asset_id, source, title,
	description, status, severity, confidence,
	cvss_version, cvss_score, cvss_vector,
	cwe_ids, references_json, evidence_refs,
	remediation_guidance, detected_at, last_observed_at,
	deduplication_key, references_to_incidents,
	created_at, updated_at
`

type findingResponse struct {
	ID                     int64           `json:"id"`
	SchemaVersion          string          `json:"schema_version"`
	FindingID              string          `json:"finding_id"`
	AssetID                string          `json:"asset_id"`
	Source                 string          `json:"source"`
	Title                  string          `json:"title"`
	Description            *string         `json:"description,omitempty"`
	Status                 string          `json:"status"`
	Severity               string          `json:"severity"`
	Confidence             float64         `json:"confidence"`
	CVSSVersion            *string         `json:"cvss_version,omitempty"`
	CVSSScore              *float64        `json:"cvss_score,omitempty"`
	CVSSVector             *string         `json:"cvss_vector,omitempty"`
	CWEIDs                 json.RawMessage `json:"cwe_ids" swaggertype:"array,string"`
	References             json.RawMessage `json:"references" swaggertype:"array,string"`
	EvidenceRefs           json.RawMessage `json:"evidence_refs" swaggertype:"array,string"`
	RemediationGuidance     *string         `json:"remediation_guidance,omitempty"`
	DetectedAt             time.Time       `json:"detected_at"`
	LastObservedAt         *time.Time      `json:"last_observed_at,omitempty"`
	DeduplicationKey       *string         `json:"deduplication_key,omitempty"`
	ReferencesToIncidents  json.RawMessage `json:"references_to_incidents" swaggertype:"array,string"`
	CreatedAt              time.Time       `json:"created_at"`
	UpdatedAt              time.Time       `json:"updated_at"`
}

type findingCreateRequest struct {
	SchemaVersion         string          `json:"schema_version"`
	FindingID             string          `json:"finding_id"`
	AssetID               string          `json:"asset_id"`
	Source                string          `json:"source"`
	Title                 string          `json:"title"`
	Description           *string         `json:"description"`
	Status                string          `json:"status"`
	Severity              string          `json:"severity"`
	Confidence            float64         `json:"confidence"`
	CVSSVersion           *string         `json:"cvss_version"`
	CVSSScore             *float64        `json:"cvss_score"`
	CVSSVector            *string         `json:"cvss_vector"`
	CWEIDs                json.RawMessage `json:"cwe_ids" swaggertype:"array,string"`
	References            json.RawMessage `json:"references" swaggertype:"array,string"`
	EvidenceRefs          json.RawMessage `json:"evidence_refs" swaggertype:"array,string"`
	RemediationGuidance    *string         `json:"remediation_guidance"`
	DetectedAt            *time.Time      `json:"detected_at"`
	LastObservedAt        *time.Time      `json:"last_observed_at"`
	DeduplicationKey      *string         `json:"deduplication_key"`
	ReferencesToIncidents json.RawMessage `json:"references_to_incidents" swaggertype:"array,string"`
}

type findingUpdateRequest struct {
	Status                *string          `json:"status"`
	Severity              *string          `json:"severity"`
	Confidence            *float64         `json:"confidence"`
	Description           *string          `json:"description"`
	RemediationGuidance    *string          `json:"remediation_guidance"`
	LastObservedAt        *time.Time       `json:"last_observed_at"`
	DeduplicationKey      *string          `json:"deduplication_key"`
	CWEIDs                *json.RawMessage `json:"cwe_ids" swaggertype:"array,string"`
	References            *json.RawMessage `json:"references" swaggertype:"array,string"`
	EvidenceRefs          *json.RawMessage `json:"evidence_refs" swaggertype:"array,string"`
	ReferencesToIncidents *json.RawMessage `json:"references_to_incidents" swaggertype:"array,string"`
}

type findingListResponse struct {
	Items        []findingResponse `json:"items"`
	HasMore      bool              `json:"has_more"`
	NextBeforeID string            `json:"next_before_id,omitempty"`
}

type findingScanner interface {
	Scan(dest ...any) error
}

func scanFinding(scanner findingScanner) (findingResponse, error) {
	var f findingResponse

	var description sql.NullString
	var cvssVersion sql.NullString
	var cvssScore sql.NullFloat64
	var cvssVector sql.NullString
	var remediation sql.NullString
	var lastObserved sql.NullTime
	var deduplicationKey sql.NullString

	var cweIDs []byte
	var references []byte
	var evidenceRefs []byte
	var incidentReferences []byte

	err := scanner.Scan(
		&f.ID,
		&f.SchemaVersion,
		&f.FindingID,
		&f.AssetID,
		&f.Source,
		&f.Title,
		&description,
		&f.Status,
		&f.Severity,
		&f.Confidence,
		&cvssVersion,
		&cvssScore,
		&cvssVector,
		&cweIDs,
		&references,
		&evidenceRefs,
		&remediation,
		&f.DetectedAt,
		&lastObserved,
		&deduplicationKey,
		&incidentReferences,
		&f.CreatedAt,
		&f.UpdatedAt,
	)
	if err != nil {
		return f, err
	}

	if description.Valid {
		f.Description = &description.String
	}
	if cvssVersion.Valid {
		f.CVSSVersion = &cvssVersion.String
	}
	if cvssScore.Valid {
		f.CVSSScore = &cvssScore.Float64
	}
	if cvssVector.Valid {
		f.CVSSVector = &cvssVector.String
	}
	if remediation.Valid {
		f.RemediationGuidance = &remediation.String
	}
	if lastObserved.Valid {
		f.LastObservedAt = &lastObserved.Time
	}
	if deduplicationKey.Valid {
		f.DeduplicationKey = &deduplicationKey.String
	}

	f.CWEIDs = json.RawMessage(cweIDs)
	f.References = json.RawMessage(references)
	f.EvidenceRefs = json.RawMessage(evidenceRefs)
	f.ReferencesToIncidents = json.RawMessage(incidentReferences)

	return f, nil
}

func writeFindingJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeFindingError(w http.ResponseWriter, status int, message string) {
	writeFindingJSON(w, status, map[string]string{
		"error": message,
	})
}

func findingTenantID(w http.ResponseWriter, r *http.Request) (string, bool) {
	identity, ok := AuthIdentityFromContext(r.Context())
	if !ok || strings.TrimSpace(identity.TenantID) == "" {
		writeFindingError(w, http.StatusUnauthorized, "authenticated tenant identity is missing")
		return "", false
	}

	return identity.TenantID, true
}

func decodeFindingJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(destination); err != nil {
		return err
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("request must contain only one JSON object")
		}
		return err
	}

	return nil
}

func validFindingValue(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func normalizeFindingArray(value json.RawMessage) (string, error) {
	if len(value) == 0 {
		return "[]", nil
	}

	trimmed := strings.TrimSpace(string(value))
	if !json.Valid(value) || !strings.HasPrefix(trimmed, "[") {
		return "", errors.New("value must be a valid JSON array")
	}

	return trimmed, nil
}

func validFindingCVSS(version *string, score *float64, vector *string) bool {
	if version == nil && score == nil && vector == nil {
		return true
	}

	if version == nil || score == nil {
		return false
	}

	if *version != "4.0" || *score < 0 || *score > 10 {
		return false
	}

	if vector != nil && len(*vector) > 512 {
		return false
	}

	return true
}

// CreateFindingHandler creates a finding for the authenticated tenant.
//
// @Summary Create a finding
// @Tags Findings
// @Accept json
// @Produce json
// @Param finding body findingCreateRequest true "Finding data"
// @Success 201 {object} findingResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Security BearerAuth
// @Router /findings [post]
func CreateFindingHandler(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := findingTenantID(w, r)
	if !ok {
		return
	}

	var request findingCreateRequest
	if err := decodeFindingJSON(w, r, &request); err != nil {
		writeFindingError(w, http.StatusBadRequest, "invalid JSON request body")
		return
	}

	request.SchemaVersion = strings.TrimSpace(request.SchemaVersion)
	if request.SchemaVersion == "" {
		request.SchemaVersion = "1.0"
	}
	if request.SchemaVersion != "1.0" {
		writeFindingError(w, http.StatusBadRequest, "schema_version must be 1.0")
		return
	}

	request.FindingID = strings.TrimSpace(request.FindingID)
	request.AssetID = strings.TrimSpace(request.AssetID)
	request.Source = strings.TrimSpace(request.Source)
	request.Title = strings.TrimSpace(request.Title)

	if request.FindingID == "" || len(request.FindingID) > 128 {
		writeFindingError(w, http.StatusBadRequest, "finding_id is required and must not exceed 128 characters")
		return
	}
	if request.AssetID == "" || len(request.AssetID) > 128 {
		writeFindingError(w, http.StatusBadRequest, "asset_id is required and must not exceed 128 characters")
		return
	}
	if !validFindingValue(request.Source, "p1_offensive", "p4_assurance", "manual", "scanner", "other") {
		writeFindingError(w, http.StatusBadRequest, "invalid source")
		return
	}
	if request.Title == "" || len(request.Title) > 512 {
		writeFindingError(w, http.StatusBadRequest, "title is required and must not exceed 512 characters")
		return
	}
	if request.Description != nil {
		value := strings.TrimSpace(*request.Description)
		if len(value) == 0 || len(value) > 10000 {
			writeFindingError(w, http.StatusBadRequest, "description must contain between 1 and 10000 characters")
			return
		}
		request.Description = &value
	}

	if request.Status == "" {
		request.Status = "detected"
	}
	if !validFindingValue(request.Status,
		"detected", "triaged", "confirmed", "false_positive",
		"remediating", "fixed_pending_retest", "retest_passed",
		"accepted_risk", "closed") {
		writeFindingError(w, http.StatusBadRequest, "invalid status")
		return
	}

	if request.Severity == "" {
		request.Severity = "unknown"
	}
	if !validFindingValue(request.Severity, "critical", "high", "medium", "low", "info", "unknown") {
		writeFindingError(w, http.StatusBadRequest, "invalid severity")
		return
	}

	if request.Confidence < 0 || request.Confidence > 1 {
		writeFindingError(w, http.StatusBadRequest, "confidence must be between 0 and 1")
		return
	}

	if !validFindingCVSS(request.CVSSVersion, request.CVSSScore, request.CVSSVector) {
		writeFindingError(w, http.StatusBadRequest, "CVSS must be absent or include version 4.0 and a score between 0 and 10")
		return
	}

	if request.RemediationGuidance != nil && len(*request.RemediationGuidance) > 10000 {
		writeFindingError(w, http.StatusBadRequest, "remediation_guidance is too long")
		return
	}
	if request.DeduplicationKey != nil && len(*request.DeduplicationKey) > 256 {
		writeFindingError(w, http.StatusBadRequest, "deduplication_key must not exceed 256 characters")
		return
	}

	cweIDs, err := normalizeFindingArray(request.CWEIDs)
	if err != nil {
		writeFindingError(w, http.StatusBadRequest, "cwe_ids must be a JSON array")
		return
	}
	references, err := normalizeFindingArray(request.References)
	if err != nil {
		writeFindingError(w, http.StatusBadRequest, "references must be a JSON array")
		return
	}
	evidenceRefs, err := normalizeFindingArray(request.EvidenceRefs)
	if err != nil {
		writeFindingError(w, http.StatusBadRequest, "evidence_refs must be a JSON array")
		return
	}
	incidentReferences, err := normalizeFindingArray(request.ReferencesToIncidents)
	if err != nil {
		writeFindingError(w, http.StatusBadRequest, "references_to_incidents must be a JSON array")
		return
	}

	detectedAt := time.Now().UTC()
	if request.DetectedAt != nil {
		detectedAt = request.DetectedAt.UTC()
	}

	query := `
		INSERT INTO findings (
			tenant_id, schema_version, finding_id, asset_id,
			source, title, description, status, severity, confidence,
			cvss_version, cvss_score, cvss_vector,
			cwe_ids, references_json, evidence_refs,
			remediation_guidance, detected_at, last_observed_at,
			deduplication_key, references_to_incidents
		)
		VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			$11, $12, $13, $14::jsonb, $15::jsonb, $16::jsonb,
			$17, $18, $19, $20, $21::jsonb
		)
		RETURNING ` + findingSelectColumns

	finding, err := scanFinding(database.DB.QueryRowContext(
		r.Context(),
		query,
		tenantID,
		request.SchemaVersion,
		request.FindingID,
		request.AssetID,
		request.Source,
		request.Title,
		request.Description,
		request.Status,
		request.Severity,
		request.Confidence,
		request.CVSSVersion,
		request.CVSSScore,
		request.CVSSVector,
		cweIDs,
		references,
		evidenceRefs,
		request.RemediationGuidance,
		detectedAt,
		request.LastObservedAt,
		request.DeduplicationKey,
		incidentReferences,
	))
	if err != nil {
		message := strings.ToLower(err.Error())

		if strings.Contains(message, "findings_tenant_finding_id_key") {
			writeFindingError(w, http.StatusConflict, "finding_id already exists in this tenant")
			return
		}
		if strings.Contains(message, "findings_tenant_asset_id_fkey") {
			writeFindingError(w, http.StatusBadRequest, "asset does not exist in this tenant")
			return
		}

		writeFindingError(w, http.StatusInternalServerError, "could not create finding")
		return
	}

	writeFindingJSON(w, http.StatusCreated, finding)
}

// ListFindingsHandler returns findings belonging to the authenticated tenant.
//
// @Summary List findings
// @Tags Findings
// @Produce json
// @Param status query string false "Filter by status"
// @Param severity query string false "Filter by severity"
// @Param asset_id query string false "Filter by asset"
// @Param limit query int false "Page size (1-100)"
// @Param before_id query int false "Return records with a smaller database ID"
// @Success 200 {object} findingListResponse
// @Failure 401 {object} map[string]string
// @Security BearerAuth
// @Router /findings [get]
func ListFindingsHandler(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := findingTenantID(w, r)
	if !ok {
		return
	}

	queryParams := r.URL.Query()

	limit := 50
	if rawLimit := queryParams.Get("limit"); rawLimit != "" {
		value, err := strconv.Atoi(rawLimit)
		if err != nil || value < 1 || value > 100 {
			writeFindingError(w, http.StatusBadRequest, "limit must be between 1 and 100")
			return
		}
		limit = value
	}

	var beforeID int64
	if rawBeforeID := queryParams.Get("before_id"); rawBeforeID != "" {
		value, err := strconv.ParseInt(rawBeforeID, 10, 64)
		if err != nil || value <= 0 {
			writeFindingError(w, http.StatusBadRequest, "before_id must be a positive integer")
			return
		}
		beforeID = value
	}

	status := strings.TrimSpace(queryParams.Get("status"))
	if status != "" && !validFindingValue(status,
		"detected", "triaged", "confirmed", "false_positive",
		"remediating", "fixed_pending_retest", "retest_passed",
		"accepted_risk", "closed") {
		writeFindingError(w, http.StatusBadRequest, "invalid status filter")
		return
	}

	severity := strings.TrimSpace(queryParams.Get("severity"))
	if severity != "" && !validFindingValue(severity, "critical", "high", "medium", "low", "info", "unknown") {
		writeFindingError(w, http.StatusBadRequest, "invalid severity filter")
		return
	}

	assetID := strings.TrimSpace(queryParams.Get("asset_id"))

	conditions := []string{"tenant_id = $1"}
	args := []any{tenantID}

	addFilter := func(condition string, value any) {
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf(condition, len(args)))
	}

	if beforeID > 0 {
		addFilter("id < $%d", beforeID)
	}
	if status != "" {
		addFilter("status = $%d", status)
	}
	if severity != "" {
		addFilter("severity = $%d", severity)
	}
	if assetID != "" {
		addFilter("asset_id = $%d", assetID)
	}

	args = append(args, limit+1)
	limitPlaceholder := len(args)

	query := fmt.Sprintf(
		"SELECT %s FROM findings WHERE %s ORDER BY id DESC LIMIT $%d",
		findingSelectColumns,
		strings.Join(conditions, " AND "),
		limitPlaceholder,
	)

	rows, err := database.DB.QueryContext(r.Context(), query, args...)
	if err != nil {
		writeFindingError(w, http.StatusInternalServerError, "could not list findings")
		return
	}
	defer rows.Close()

	items := make([]findingResponse, 0, limit+1)
	for rows.Next() {
		finding, err := scanFinding(rows)
		if err != nil {
			writeFindingError(w, http.StatusInternalServerError, "could not read findings")
			return
		}
		items = append(items, finding)
	}

	if err := rows.Err(); err != nil {
		writeFindingError(w, http.StatusInternalServerError, "could not read findings")
		return
	}

	response := findingListResponse{
		Items: items,
		HasMore: len(items) > limit,
	}

	if response.HasMore {
		items = items[:limit]
		response.Items = items
		response.NextBeforeID = strconv.FormatInt(items[len(items)-1].ID, 10)
	}

	writeFindingJSON(w, http.StatusOK, response)
}

// GetFindingHandler retrieves one finding belonging to the authenticated tenant.
//
// @Summary Get a finding
// @Tags Findings
// @Produce json
// @Param finding_id path string true "Finding ID"
// @Success 200 {object} findingResponse
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Security BearerAuth
// @Router /findings/{finding_id} [get]
func GetFindingHandler(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := findingTenantID(w, r)
	if !ok {
		return
	}

	findingID := strings.TrimSpace(r.PathValue("finding_id"))
	if findingID == "" {
		writeFindingError(w, http.StatusBadRequest, "finding_id is required")
		return
	}

	query := "SELECT " + findingSelectColumns + `
		FROM findings
		WHERE tenant_id = $1 AND finding_id = $2
	`

	finding, err := scanFinding(database.DB.QueryRowContext(r.Context(), query, tenantID, findingID))
	if errors.Is(err, sql.ErrNoRows) {
		writeFindingError(w, http.StatusNotFound, "finding not found")
		return
	}
	if err != nil {
		writeFindingError(w, http.StatusInternalServerError, "could not retrieve finding")
		return
	}

	writeFindingJSON(w, http.StatusOK, finding)
}

// UpdateFindingHandler updates mutable fields of a tenant-owned finding.
//
// @Summary Update a finding
// @Tags Findings
// @Accept json
// @Produce json
// @Param finding_id path string true "Finding ID"
// @Param finding body findingUpdateRequest true "Fields to update"
// @Success 200 {object} findingResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Security BearerAuth
// @Router /findings/{finding_id} [patch]
func UpdateFindingHandler(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := findingTenantID(w, r)
	if !ok {
		return
	}

	findingID := strings.TrimSpace(r.PathValue("finding_id"))
	if findingID == "" {
		writeFindingError(w, http.StatusBadRequest, "finding_id is required")
		return
	}

	var request findingUpdateRequest
	if err := decodeFindingJSON(w, r, &request); err != nil {
		writeFindingError(w, http.StatusBadRequest, "invalid JSON request body")
		return
	}

	hasUpdate := request.Status != nil ||
		request.Severity != nil ||
		request.Confidence != nil ||
		request.Description != nil ||
		request.RemediationGuidance != nil ||
		request.LastObservedAt != nil ||
		request.DeduplicationKey != nil ||
		request.CWEIDs != nil ||
		request.References != nil ||
		request.EvidenceRefs != nil ||
		request.ReferencesToIncidents != nil

	if !hasUpdate {
		writeFindingError(w, http.StatusBadRequest, "provide at least one field to update")
		return
	}

	if request.Status != nil && !validFindingValue(*request.Status,
		"detected", "triaged", "confirmed", "false_positive",
		"remediating", "fixed_pending_retest", "retest_passed",
		"accepted_risk", "closed") {
		writeFindingError(w, http.StatusBadRequest, "invalid status")
		return
	}

	if request.Severity != nil && !validFindingValue(*request.Severity, "critical", "high", "medium", "low", "info", "unknown") {
		writeFindingError(w, http.StatusBadRequest, "invalid severity")
		return
	}

	if request.Confidence != nil && (*request.Confidence < 0 || *request.Confidence > 1) {
		writeFindingError(w, http.StatusBadRequest, "confidence must be between 0 and 1")
		return
	}

	if request.Description != nil {
		value := strings.TrimSpace(*request.Description)
		if len(value) == 0 || len(value) > 10000 {
			writeFindingError(w, http.StatusBadRequest, "description must contain between 1 and 10000 characters")
			return
		}
		request.Description = &value
	}

	if request.DeduplicationKey != nil && len(*request.DeduplicationKey) > 256 {
		writeFindingError(w, http.StatusBadRequest, "deduplication_key must not exceed 256 characters")
		return
	}

	var cweIDs any
	var references any
	var evidenceRefs any
	var incidentReferences any

	if request.CWEIDs != nil {
		value, err := normalizeFindingArray(*request.CWEIDs)
		if err != nil {
			writeFindingError(w, http.StatusBadRequest, "cwe_ids must be a JSON array")
			return
		}
		cweIDs = value
	}

	if request.References != nil {
		value, err := normalizeFindingArray(*request.References)
		if err != nil {
			writeFindingError(w, http.StatusBadRequest, "references must be a JSON array")
			return
		}
		references = value
	}

	if request.EvidenceRefs != nil {
		value, err := normalizeFindingArray(*request.EvidenceRefs)
		if err != nil {
			writeFindingError(w, http.StatusBadRequest, "evidence_refs must be a JSON array")
			return
		}
		evidenceRefs = value
	}

	if request.ReferencesToIncidents != nil {
		value, err := normalizeFindingArray(*request.ReferencesToIncidents)
		if err != nil {
			writeFindingError(w, http.StatusBadRequest, "references_to_incidents must be a JSON array")
			return
		}
		incidentReferences = value
	}

	query := `
		UPDATE findings
		SET
			status = COALESCE($1, status),
			severity = COALESCE($2, severity),
			confidence = COALESCE($3, confidence),
			description = COALESCE($4, description),
			remediation_guidance = COALESCE($5, remediation_guidance),
			last_observed_at = COALESCE($6, last_observed_at),
			deduplication_key = COALESCE($7, deduplication_key),
			cwe_ids = COALESCE($8::jsonb, cwe_ids),
			references_json = COALESCE($9::jsonb, references_json),
			evidence_refs = COALESCE($10::jsonb, evidence_refs),
			references_to_incidents = COALESCE($11::jsonb, references_to_incidents),
			updated_at = NOW()
		WHERE tenant_id = $12 AND finding_id = $13
		RETURNING ` + findingSelectColumns

	finding, err := scanFinding(database.DB.QueryRowContext(
		r.Context(),
		query,
		request.Status,
		request.Severity,
		request.Confidence,
		request.Description,
		request.RemediationGuidance,
		request.LastObservedAt,
		request.DeduplicationKey,
		cweIDs,
		references,
		evidenceRefs,
		incidentReferences,
		tenantID,
		findingID,
	))

	if errors.Is(err, sql.ErrNoRows) {
		writeFindingError(w, http.StatusNotFound, "finding not found")
		return
	}
	if err != nil {
		writeFindingError(w, http.StatusInternalServerError, "could not update finding")
		return
	}

	writeFindingJSON(w, http.StatusOK, finding)
}

