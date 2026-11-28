package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/database"
)

var retestIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// RetestResultResponse is the API representation of a retest result.
type RetestResultResponse struct {
	ID            int64     `json:"id"`
	RetestID      string    `json:"retest_id"`
	RemediationID string    `json:"remediation_id"`
	FindingID     string    `json:"finding_id"`
	Status        string    `json:"status"`
	Summary       string    `json:"summary"`
	EvidenceRefs  []any     `json:"evidence_refs"`
	PerformedBy   string    `json:"performed_by"`
	TestedAt      time.Time `json:"tested_at"`
	CreatedAt     time.Time `json:"created_at"`
}

// RetestCreateRequest is the payload used to record a retest.
type RetestCreateRequest struct {
	RetestID      string `json:"retest_id"`
	RemediationID string `json:"remediation_id"`
	FindingID     string `json:"finding_id"`
	Status        string `json:"status"`
	Summary       string `json:"summary"`
	EvidenceRefs  []any  `json:"evidence_refs"`
	TestedAt      string `json:"tested_at"`
}

type retestScanner interface {
	Scan(dest ...any) error
}

const retestResultColumns = `
id,
retest_id,
remediation_id,
finding_id,
status,
summary,
evidence_refs,
performed_by::text,
tested_at,
created_at
`

func scanRetestResult(scanner retestScanner) (RetestResultResponse, error) {
	var result RetestResultResponse
	var evidenceJSON []byte

	err := scanner.Scan(
		&result.ID,
		&result.RetestID,
		&result.RemediationID,
		&result.FindingID,
		&result.Status,
		&result.Summary,
		&evidenceJSON,
		&result.PerformedBy,
		&result.TestedAt,
		&result.CreatedAt,
	)
	if err != nil {
		return result, err
	}

	result.EvidenceRefs = make([]any, 0)
	if len(evidenceJSON) > 0 {
		if err := json.Unmarshal(evidenceJSON, &result.EvidenceRefs); err != nil {
			return result, err
		}
	}
	if result.EvidenceRefs == nil {
		result.EvidenceRefs = make([]any, 0)
	}

	return result, nil
}

func writeRetestJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeRetestError(w http.ResponseWriter, status int, message string) {
	writeRetestJSON(w, status, map[string]string{"error": message})
}

func decodeRetestJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

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

func validRetestIdentifier(value string) bool {
	return retestIdentifierPattern.MatchString(value)
}

func validRetestStatus(value string) bool {
	switch value {
	case "fixed", "still_present", "inconclusive":
		return true
	default:
		return false
	}
}

func retestSQLState(err error) string {
	type sqlStateError interface {
		SQLState() string
	}

	var stateErr sqlStateError
	if errors.As(err, &stateErr) {
		return stateErr.SQLState()
	}

	return ""
}

func retestIdentity(w http.ResponseWriter, r *http.Request) (AuthIdentity, bool) {
	identity, ok := AuthIdentityFromContext(r.Context())
	if !ok {
		writeRetestError(w, http.StatusUnauthorized, "Authentication required")
		return AuthIdentity{}, false
	}
	return identity, true
}

// CreateRetestResultHandler records the result of a remediation retest.
//
// @Summary Record a retest result
// @Description Records whether a remediation was successful, unsuccessful, or inconclusive. The tenant and performer are derived from the authenticated identity.
// @Tags Retesting
// @Accept json
// @Produce json
// @Param retest body RetestCreateRequest true "Retest result"
// @Success 201 {object} RetestResultResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/retests [post]
func CreateRetestResultHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := retestIdentity(w, r)
	if !ok {
		return
	}

	switch identity.Role {
	case "admin", "analyst", "responder":
	// These roles may record retest results, subject to assignment checks below.
	default:
		writeRetestError(w, http.StatusForbidden, "Your role cannot record retest results")
		return
	}

	var request RetestCreateRequest
	if err := decodeRetestJSON(w, r, &request); err != nil {
		writeRetestError(w, http.StatusBadRequest, "Invalid JSON request body")
		return
	}

	request.RetestID = strings.TrimSpace(request.RetestID)
	request.RemediationID = strings.TrimSpace(request.RemediationID)
	request.FindingID = strings.TrimSpace(request.FindingID)
	request.Status = strings.TrimSpace(request.Status)
	request.Summary = strings.TrimSpace(request.Summary)

	if !validRetestIdentifier(request.RetestID) {
		writeRetestError(w, http.StatusBadRequest, "retest_id is required and must be a valid identifier")
		return
	}
	if !validRetestIdentifier(request.RemediationID) {
		writeRetestError(w, http.StatusBadRequest, "remediation_id is required and must be a valid identifier")
		return
	}
	if !validRetestIdentifier(request.FindingID) {
		writeRetestError(w, http.StatusBadRequest, "finding_id is required and must be a valid identifier")
		return
	}
	if !validRetestStatus(request.Status) {
		writeRetestError(w, http.StatusBadRequest, "status must be fixed, still_present, or inconclusive")
		return
	}
	if request.Summary == "" || utf8.RuneCountInString(request.Summary) > 10000 {
		writeRetestError(w, http.StatusBadRequest, "summary must contain between 1 and 10000 characters")
		return
	}

	evidenceRefs := request.EvidenceRefs
	if evidenceRefs == nil {
		evidenceRefs = make([]any, 0)
	}
	evidenceJSON, err := json.Marshal(evidenceRefs)
	if err != nil {
		writeRetestError(w, http.StatusBadRequest, "evidence_refs must be a valid JSON array")
		return
	}

	testedAt := time.Now().UTC()
	if strings.TrimSpace(request.TestedAt) != "" {
		testedAt, err = time.Parse(time.RFC3339Nano, strings.TrimSpace(request.TestedAt))
		if err != nil {
			writeRetestError(w, http.StatusBadRequest, "tested_at must use RFC3339 format")
			return
		}
	}

	tx, err := database.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeRetestError(w, http.StatusInternalServerError, "Could not start retest transaction")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// Lock the task while checking assignment and recording the result.
	var assignedTo sql.NullString
	err = tx.QueryRowContext(
		r.Context(),
		`SELECT assigned_to::text
 FROM remediation_tasks
 WHERE tenant_id = $1
   AND remediation_id = $2
   AND finding_id = $3
 FOR UPDATE`,
		identity.TenantID,
		request.RemediationID,
		request.FindingID,
	).Scan(&assignedTo)

	if errors.Is(err, sql.ErrNoRows) {
		writeRetestError(w, http.StatusNotFound, "Remediation task not found for this tenant and finding")
		return
	}
	if err != nil {
		writeRetestError(w, http.StatusInternalServerError, "Could not verify remediation task")
		return
	}

	if identity.Role == "responder" {
		if !assignedTo.Valid || assignedTo.String != identity.UserID {
			writeRetestError(w, http.StatusForbidden, "Responders may only retest tasks assigned to them")
			return
		}
	}

	result, err := scanRetestResult(tx.QueryRowContext(
		r.Context(),
		`INSERT INTO retest_results (
tenant_id,
retest_id,
remediation_id,
finding_id,
status,
summary,
evidence_refs,
performed_by,
tested_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)
RETURNING `+retestResultColumns,
		identity.TenantID,
		request.RetestID,
		request.RemediationID,
		request.FindingID,
		request.Status,
		request.Summary,
		string(evidenceJSON),
		identity.UserID,
		testedAt,
	))
	if err != nil {
		switch retestSQLState(err) {
		case "23505":
			writeRetestError(w, http.StatusConflict, "A retest with this retest_id already exists")
		case "23503", "23514":
			writeRetestError(w, http.StatusBadRequest, "Retest references or values violate a database constraint")
		default:
			writeRetestError(w, http.StatusInternalServerError, "Could not save retest result")
		}
		return
	}

	if err := tx.Commit(); err != nil {
		writeRetestError(w, http.StatusInternalServerError, "Could not commit retest result")
		return
	}

	writeRetestJSON(w, http.StatusCreated, result)
}

// ListRetestResultsHandler lists retest results for the authenticated tenant.
//
// @Summary List retest results
// @Description Lists retest results belonging to the authenticated tenant. Supports finding_id, remediation_id, and status filters.
// @Tags Retesting
// @Produce json
// @Param finding_id query string false "Filter by finding ID"
// @Param remediation_id query string false "Filter by remediation ID"
// @Param status query string false "Filter by result status"
// @Param limit query int false "Maximum results (1-100, default 50)"
// @Param offset query int false "Pagination offset"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/retests [get]
func ListRetestResultsHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := retestIdentity(w, r)
	if !ok {
		return
	}
	listRetestResults(w, r, identity, "")
}

// ListFindingRetestResultsHandler lists the retest history for one finding.
//
// @Summary List retests for a finding
// @Description Lists the retest history for a finding belonging to the authenticated tenant.
// @Tags Retesting
// @Produce json
// @Param finding_id path string true "Finding ID"
// @Param status query string false "Filter by result status"
// @Param limit query int false "Maximum results (1-100, default 50)"
// @Param offset query int false "Pagination offset"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/findings/{finding_id}/retests [get]
func ListFindingRetestResultsHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := retestIdentity(w, r)
	if !ok {
		return
	}

	findingID := strings.TrimSpace(r.PathValue("finding_id"))
	if !validRetestIdentifier(findingID) {
		writeRetestError(w, http.StatusBadRequest, "Invalid finding_id")
		return
	}

	var exists bool
	err := database.DB.QueryRowContext(
		r.Context(),
		`SELECT EXISTS (
SELECT 1 FROM findings
WHERE tenant_id = $1 AND finding_id = $2
)`,
		identity.TenantID,
		findingID,
	).Scan(&exists)
	if err != nil {
		writeRetestError(w, http.StatusInternalServerError, "Could not verify finding")
		return
	}
	if !exists {
		writeRetestError(w, http.StatusNotFound, "Finding not found")
		return
	}

	listRetestResults(w, r, identity, findingID)
}

func listRetestResults(w http.ResponseWriter, r *http.Request, identity AuthIdentity, fixedFindingID string) {
	query := r.URL.Query()

	findingID := fixedFindingID
	if findingID == "" {
		findingID = strings.TrimSpace(query.Get("finding_id"))
	}
	remediationID := strings.TrimSpace(query.Get("remediation_id"))
	status := strings.TrimSpace(query.Get("status"))

	if findingID != "" && !validRetestIdentifier(findingID) {
		writeRetestError(w, http.StatusBadRequest, "Invalid finding_id filter")
		return
	}
	if remediationID != "" && !validRetestIdentifier(remediationID) {
		writeRetestError(w, http.StatusBadRequest, "Invalid remediation_id filter")
		return
	}
	if status != "" && !validRetestStatus(status) {
		writeRetestError(w, http.StatusBadRequest, "Invalid status filter")
		return
	}

	limit := 50
	if rawLimit := strings.TrimSpace(query.Get("limit")); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed < 1 || parsed > 100 {
			writeRetestError(w, http.StatusBadRequest, "limit must be between 1 and 100")
			return
		}
		limit = parsed
	}

	offset := 0
	if rawOffset := strings.TrimSpace(query.Get("offset")); rawOffset != "" {
		parsed, err := strconv.Atoi(rawOffset)
		if err != nil || parsed < 0 {
			writeRetestError(w, http.StatusBadRequest, "offset must be zero or greater")
			return
		}
		offset = parsed
	}

	conditions := []string{"tenant_id = $1"}
	args := []any{identity.TenantID}

	addFilter := func(column, value string) {
		if value == "" {
			return
		}
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf("%s = $%d", column, len(args)))
	}

	addFilter("finding_id", findingID)
	addFilter("remediation_id", remediationID)
	addFilter("status", status)

	args = append(args, limit)
	limitPosition := len(args)
	args = append(args, offset)
	offsetPosition := len(args)

	sqlQuery := `SELECT ` + retestResultColumns + `
FROM retest_results
WHERE ` + strings.Join(conditions, " AND ") + `
ORDER BY tested_at DESC, id DESC
LIMIT $` + strconv.Itoa(limitPosition) + `
OFFSET $` + strconv.Itoa(offsetPosition)

	rows, err := database.DB.QueryContext(r.Context(), sqlQuery, args...)
	if err != nil {
		writeRetestError(w, http.StatusInternalServerError, "Could not list retest results")
		return
	}
	defer rows.Close()

	items := make([]RetestResultResponse, 0)
	for rows.Next() {
		item, err := scanRetestResult(rows)
		if err != nil {
			writeRetestError(w, http.StatusInternalServerError, "Could not read retest result")
			return
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		writeRetestError(w, http.StatusInternalServerError, "Could not read retest results")
		return
	}

	writeRetestJSON(w, http.StatusOK, map[string]any{
		"items":  items,
		"count":  len(items),
		"limit":  limit,
		"offset": offset,
	})
}

// GetRetestResultHandler retrieves one retest result by its identifier.
//
// @Summary Get a retest result
// @Description Retrieves a retest result belonging to the authenticated tenant.
// @Tags Retesting
// @Produce json
// @Param retest_id path string true "Retest ID"
// @Success 200 {object} RetestResultResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/retests/{retest_id} [get]
func GetRetestResultHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := retestIdentity(w, r)
	if !ok {
		return
	}

	retestID := strings.TrimSpace(r.PathValue("retest_id"))
	if !validRetestIdentifier(retestID) {
		writeRetestError(w, http.StatusBadRequest, "Invalid retest_id")
		return
	}

	result, err := scanRetestResult(database.DB.QueryRowContext(
		r.Context(),
		`SELECT `+retestResultColumns+`
 FROM retest_results
 WHERE tenant_id = $1 AND retest_id = $2`,
		identity.TenantID,
		retestID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		writeRetestError(w, http.StatusNotFound, "Retest result not found")
		return
	}
	if err != nil {
		writeRetestError(w, http.StatusInternalServerError, "Could not retrieve retest result")
		return
	}

	writeRetestJSON(w, http.StatusOK, result)
}
