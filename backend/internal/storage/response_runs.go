package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrResponseIncidentNotFound       = errors.New("incident not found in tenant")
	ErrResponseRunNotFound            = errors.New("response run not found")
	ErrInvalidResponseRun             = errors.New("invalid response run input")
	ErrDuplicateResponseRun           = errors.New("response run already exists")
	ErrResponseIdempotencyConflict    = errors.New("idempotency key was already used for a different request")
	ErrResponseApprovalNotFound       = errors.New("response approval not found")
	ErrResponseApprovalAlreadyDecided = errors.New("response approval has already been decided")
	ErrInvalidResponseApprover        = errors.New("approver is not an active user in this tenant")
	ErrResponseSelfApproval           = errors.New("requester cannot approve their own response run")
	ErrResponseRunNotQueued           = errors.New("response run is not queued")
	ErrResponseRunNotRunning          = errors.New("response run is not running")
	ErrResponseExecutionNotFound      = errors.New("response action execution not found")
	ErrInvalidResponseExecution       = errors.New("invalid response action execution input")
	ErrInvalidResponseExecutionState  = errors.New("invalid response action execution state")
	ErrResponseExecutionAttemptsLimit = errors.New("response action execution attempt limit reached")
	ErrResponseRunHasPendingActions   = errors.New("response run still has pending or running actions")
	ErrResponseRunAlreadyFinished     = errors.New("response run is already finished")
)

const maxResponseRunPageSize = 100
const maxResponseDecisionNote = 2000
const maxResponseExecutionSummary = 5000
const maxResponseExecutionAttempts = 10

const responseRunSelectColumns = `
r.id, r.tenant_id::text, r.response_run_id, i.incident_id, r.playbook_id,
r.requested_by::text, r.idempotency_key, r.request_reason, r.requires_approval,
r.status, r.created_at, r.started_at, r.finished_at, r.updated_at
`

const responseApprovalSelectColumns = `
a.id, a.tenant_id::text, a.approval_id, r.response_run_id,
a.requested_by::text, a.decided_by::text, a.status, a.decision_note,
a.requested_at, a.decided_at
`

const responseExecutionSelectColumns = `
e.id, e.tenant_id::text, e.action_execution_id, r.response_run_id,
e.response_action_id, e.step_order, e.action_type, e.status,
e.attempt_count, e.config_snapshot, e.result_summary, e.error_code,
e.external_reference, e.started_at, e.finished_at, e.created_at, e.updated_at
`

type ResponseRunRecord struct {
	ID               int64      `json:"-"`
	TenantID         string     `json:"tenant_id"`
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

type ResponseApprovalRecord struct {
	ID            int64      `json:"-"`
	TenantID      string     `json:"tenant_id"`
	ApprovalID    string     `json:"approval_id"`
	ResponseRunID string     `json:"response_run_id"`
	RequestedBy   string     `json:"requested_by"`
	DecidedBy     *string    `json:"decided_by,omitempty"`
	Status        string     `json:"status"`
	DecisionNote  *string    `json:"decision_note,omitempty"`
	RequestedAt   time.Time  `json:"requested_at"`
	DecidedAt     *time.Time `json:"decided_at,omitempty"`
}

type ResponseActionExecutionRecord struct {
	ID                int64           `json:"-"`
	TenantID          string          `json:"tenant_id"`
	ActionExecutionID string          `json:"action_execution_id"`
	ResponseRunID     string          `json:"response_run_id"`
	ResponseActionID  string          `json:"response_action_id"`
	StepOrder         int             `json:"step_order"`
	ActionType        string          `json:"action_type"`
	Status            string          `json:"status"`
	AttemptCount      int             `json:"attempt_count"`
	ConfigSnapshot    json.RawMessage `json:"config_snapshot"`
	ResultSummary     *string         `json:"result_summary,omitempty"`
	ErrorCode         *string         `json:"error_code,omitempty"`
	ExternalReference *string         `json:"external_reference,omitempty"`
	StartedAt         *time.Time      `json:"started_at,omitempty"`
	FinishedAt        *time.Time      `json:"finished_at,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

type CreateResponseRunParams struct {
	ResponseRunID  string
	IncidentID     string
	PlaybookID     string
	IdempotencyKey string
	RequestReason  *string
}

type FinishResponseActionExecutionParams struct {
	Status            string
	ResultSummary     *string
	ErrorCode         *string
	ExternalReference *string
}

type responseScanner interface {
	Scan(dest ...any) error
}

func scanResponseRun(row responseScanner) (ResponseRunRecord, error) {
	var record ResponseRunRecord
	var reason sql.NullString
	var startedAt, finishedAt sql.NullTime
	err := row.Scan(
		&record.ID, &record.TenantID, &record.ResponseRunID, &record.IncidentID,
		&record.PlaybookID, &record.RequestedBy, &record.IdempotencyKey,
		&reason, &record.RequiresApproval, &record.Status, &record.CreatedAt,
		&startedAt, &finishedAt, &record.UpdatedAt,
	)
	if err != nil {
		return ResponseRunRecord{}, err
	}
	if reason.Valid {
		value := reason.String
		record.RequestReason = &value
	}
	if startedAt.Valid {
		value := startedAt.Time
		record.StartedAt = &value
	}
	if finishedAt.Valid {
		value := finishedAt.Time
		record.FinishedAt = &value
	}
	return record, nil
}

func scanResponseApproval(row responseScanner) (ResponseApprovalRecord, error) {
	var record ResponseApprovalRecord
	var decidedBy, note sql.NullString
	var decidedAt sql.NullTime
	err := row.Scan(
		&record.ID, &record.TenantID, &record.ApprovalID, &record.ResponseRunID,
		&record.RequestedBy, &decidedBy, &record.Status, &note,
		&record.RequestedAt, &decidedAt,
	)
	if err != nil {
		return ResponseApprovalRecord{}, err
	}
	if decidedBy.Valid {
		value := decidedBy.String
		record.DecidedBy = &value
	}
	if note.Valid {
		value := note.String
		record.DecisionNote = &value
	}
	if decidedAt.Valid {
		value := decidedAt.Time
		record.DecidedAt = &value
	}
	return record, nil
}

func scanResponseActionExecution(row responseScanner) (ResponseActionExecutionRecord, error) {
	var record ResponseActionExecutionRecord
	var config []byte
	var summary, errorCode, externalReference sql.NullString
	var startedAt, finishedAt sql.NullTime
	err := row.Scan(
		&record.ID, &record.TenantID, &record.ActionExecutionID, &record.ResponseRunID,
		&record.ResponseActionID, &record.StepOrder, &record.ActionType,
		&record.Status, &record.AttemptCount, &config, &summary, &errorCode,
		&externalReference, &startedAt, &finishedAt, &record.CreatedAt, &record.UpdatedAt,
	)
	if err != nil {
		return ResponseActionExecutionRecord{}, err
	}
	if len(config) == 0 {
		record.ConfigSnapshot = json.RawMessage(`{}`)
	} else {
		record.ConfigSnapshot = append(json.RawMessage(nil), config...)
	}
	if summary.Valid {
		value := summary.String
		record.ResultSummary = &value
	}
	if errorCode.Valid {
		value := errorCode.String
		record.ErrorCode = &value
	}
	if externalReference.Valid {
		value := externalReference.String
		record.ExternalReference = &value
	}
	if startedAt.Valid {
		value := startedAt.Time
		record.StartedAt = &value
	}
	if finishedAt.Valid {
		value := finishedAt.Time
		record.FinishedAt = &value
	}
	return record, nil
}

func generateResponseRecordID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate response record ID: %w", err)
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}

func validateCreateResponseRun(p CreateResponseRunParams) error {
	if p.ResponseRunID == "" || len(p.ResponseRunID) > 128 ||
		p.IncidentID == "" || len(p.IncidentID) > 128 ||
		p.PlaybookID == "" || len(p.PlaybookID) > 128 ||
		p.IdempotencyKey == "" || len(p.IdempotencyKey) > 128 {
		return ErrInvalidResponseRun
	}
	if p.RequestReason != nil && len(*p.RequestReason) > 2000 {
		return ErrInvalidResponseRun
	}
	return nil
}

func (s *Store) CreateResponseRun(
	ctx context.Context,
	tenantID string,
	requestedBy string,
	p CreateResponseRunParams,
) (ResponseRunRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	requestedBy = strings.TrimSpace(requestedBy)
	p.ResponseRunID = strings.TrimSpace(p.ResponseRunID)
	p.IncidentID = strings.TrimSpace(p.IncidentID)
	p.PlaybookID = strings.TrimSpace(p.PlaybookID)
	p.IdempotencyKey = strings.TrimSpace(p.IdempotencyKey)
	if p.RequestReason != nil {
		reason := strings.TrimSpace(*p.RequestReason)
		p.RequestReason = &reason
	}
	if tenantID == "" {
		return ResponseRunRecord{}, ErrTenantRequired
	}
	if requestedBy == "" || validateCreateResponseRun(p) != nil {
		return ResponseRunRecord{}, ErrInvalidResponseRun
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ResponseRunRecord{}, fmt.Errorf("begin response run creation: %w", err)
	}
	defer tx.Rollback()

	active, err := activeTenantUser(ctx, tx, tenantID, requestedBy)
	if err != nil {
		return ResponseRunRecord{}, fmt.Errorf("validate response requester: %w", err)
	}
	if !active {
		return ResponseRunRecord{}, ErrInvalidResponseActor
	}

	// Resolve idempotent retries before checking mutable playbook state. A retry
	// must return the original run even if the playbook was later deactivated.
	existing, existingErr := scanResponseRun(tx.QueryRowContext(ctx, `
SELECT `+responseRunSelectColumns+`
FROM response_runs r
JOIN incidents i ON i.tenant_id = r.tenant_id AND i.id = r.incident_db_id
WHERE r.tenant_id = $1::uuid AND r.idempotency_key = $2`, tenantID, p.IdempotencyKey))
	if existingErr == nil {
		if existing.IncidentID != p.IncidentID || existing.PlaybookID != p.PlaybookID ||
			existing.RequestedBy != requestedBy || !sameOptionalString(existing.RequestReason, p.RequestReason) {
			return ResponseRunRecord{}, ErrResponseIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return ResponseRunRecord{}, fmt.Errorf("commit idempotent response run lookup: %w", err)
		}
		return existing, nil
	}
	if !errors.Is(existingErr, sql.ErrNoRows) {
		return ResponseRunRecord{}, fmt.Errorf("check response run idempotency key: %w", existingErr)
	}

	var incidentDBID int64
	err = tx.QueryRowContext(ctx, `
SELECT id FROM incidents
WHERE tenant_id = $1::uuid AND incident_id = $2`, tenantID, p.IncidentID).Scan(&incidentDBID)
	if errors.Is(err, sql.ErrNoRows) {
		return ResponseRunRecord{}, ErrResponseIncidentNotFound
	}
	if err != nil {
		return ResponseRunRecord{}, fmt.Errorf("resolve response incident: %w", err)
	}

	var playbookDBID int64
	err = tx.QueryRowContext(ctx, `
SELECT id FROM response_playbooks
WHERE tenant_id = $1::uuid AND playbook_id = $2 AND is_active = TRUE
FOR SHARE`, tenantID, p.PlaybookID).Scan(&playbookDBID)
	if errors.Is(err, sql.ErrNoRows) {
		return ResponseRunRecord{}, ErrResponsePlaybookNotFound
	}
	if err != nil {
		return ResponseRunRecord{}, fmt.Errorf("resolve active response playbook: %w", err)
	}
	_ = playbookDBID // The lock protects the enabled action snapshot below.

	type actionSnapshot struct {
		id         string
		step       int
		actionType string
		requires   bool
		config     []byte
	}
	rows, err := tx.QueryContext(ctx, `
SELECT response_action_id, step_order, action_type, requires_approval, config
FROM response_playbook_actions
WHERE tenant_id = $1::uuid AND playbook_id = $2 AND is_enabled = TRUE
ORDER BY step_order ASC, id ASC
FOR SHARE`, tenantID, p.PlaybookID)
	if err != nil {
		return ResponseRunRecord{}, fmt.Errorf("load enabled response playbook actions: %w", err)
	}
	actions := make([]actionSnapshot, 0)
	requiresApproval := false
	for rows.Next() {
		var action actionSnapshot
		if err := rows.Scan(&action.id, &action.step, &action.actionType, &action.requires, &action.config); err != nil {
			rows.Close()
			return ResponseRunRecord{}, fmt.Errorf("scan response playbook action snapshot: %w", err)
		}
		if action.requires {
			requiresApproval = true
		}
		actions = append(actions, action)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return ResponseRunRecord{}, fmt.Errorf("iterate response playbook action snapshots: %w", err)
	}
	if err := rows.Close(); err != nil {
		return ResponseRunRecord{}, fmt.Errorf("close response playbook action snapshots: %w", err)
	}
	if len(actions) == 0 {
		return ResponseRunRecord{}, ErrResponsePlaybookNoActions
	}

	initialStatus := "queued"
	if requiresApproval {
		initialStatus = "pending_approval"
	}

	var runDBID int64
	err = tx.QueryRowContext(ctx, `
INSERT INTO response_runs (
    tenant_id, response_run_id, incident_db_id, playbook_id, requested_by,
    idempotency_key, request_reason, requires_approval, status
) VALUES ($1::uuid, $2, $3, $4, $5::uuid, $6, $7, $8, $9)
ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
RETURNING id`,
		tenantID, p.ResponseRunID, incidentDBID, p.PlaybookID, requestedBy,
		p.IdempotencyKey, p.RequestReason, requiresApproval, initialStatus,
	).Scan(&runDBID)
	if errors.Is(err, sql.ErrNoRows) {
		existing, getErr := scanResponseRun(tx.QueryRowContext(ctx, `
SELECT `+responseRunSelectColumns+`
FROM response_runs r
JOIN incidents i ON i.tenant_id = r.tenant_id AND i.id = r.incident_db_id
WHERE r.tenant_id = $1::uuid AND r.idempotency_key = $2`, tenantID, p.IdempotencyKey))
		if getErr != nil {
			return ResponseRunRecord{}, fmt.Errorf("load existing idempotent response run: %w", getErr)
		}
		if existing.IncidentID != p.IncidentID || existing.PlaybookID != p.PlaybookID || existing.RequestedBy != requestedBy || !sameOptionalString(existing.RequestReason, p.RequestReason) {
			return ResponseRunRecord{}, ErrResponseIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return ResponseRunRecord{}, fmt.Errorf("commit idempotent response run lookup: %w", err)
		}
		return existing, nil
	}
	if err != nil {
		if pgState(err) == "23505" {
			return ResponseRunRecord{}, ErrDuplicateResponseRun
		}
		return ResponseRunRecord{}, fmt.Errorf("insert response run: %w", err)
	}

	for _, action := range actions {
		executionID, idErr := generateResponseRecordID("raex_")
		if idErr != nil {
			return ResponseRunRecord{}, idErr
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO response_action_executions (
    tenant_id, action_execution_id, response_run_db_id, playbook_id,
    response_action_id, step_order, action_type, status, config_snapshot
) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, 'pending', $8::jsonb)`,
			tenantID, executionID, runDBID, p.PlaybookID, action.id,
			action.step, action.actionType, string(action.config),
		); err != nil {
			return ResponseRunRecord{}, fmt.Errorf("create response action execution snapshot: %w", err)
		}
	}

	if requiresApproval {
		approvalID, idErr := generateResponseRecordID("rap_")
		if idErr != nil {
			return ResponseRunRecord{}, idErr
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO response_approvals (
    tenant_id, approval_id, response_run_db_id, requested_by, status
) VALUES ($1::uuid, $2, $3, $4::uuid, 'pending')`,
			tenantID, approvalID, runDBID, requestedBy,
		); err != nil {
			return ResponseRunRecord{}, fmt.Errorf("create response approval: %w", err)
		}
	}

	record, err := scanResponseRun(tx.QueryRowContext(ctx, `
SELECT `+responseRunSelectColumns+`
FROM response_runs r
JOIN incidents i ON i.tenant_id = r.tenant_id AND i.id = r.incident_db_id
WHERE r.tenant_id = $1::uuid AND r.id = $2`, tenantID, runDBID))
	if err != nil {
		return ResponseRunRecord{}, fmt.Errorf("read created response run: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ResponseRunRecord{}, fmt.Errorf("commit response run creation: %w", err)
	}
	return record, nil
}

func sameOptionalString(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func (s *Store) GetResponseRunByID(ctx context.Context, tenantID, responseRunID string) (ResponseRunRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	responseRunID = strings.TrimSpace(responseRunID)
	if tenantID == "" {
		return ResponseRunRecord{}, ErrTenantRequired
	}
	if responseRunID == "" {
		return ResponseRunRecord{}, ErrResponseRunNotFound
	}
	record, err := scanResponseRun(s.DB.QueryRowContext(ctx, `
SELECT `+responseRunSelectColumns+`
FROM response_runs r
JOIN incidents i ON i.tenant_id = r.tenant_id AND i.id = r.incident_db_id
WHERE r.tenant_id = $1::uuid AND r.response_run_id = $2`, tenantID, responseRunID))
	if errors.Is(err, sql.ErrNoRows) {
		return ResponseRunRecord{}, ErrResponseRunNotFound
	}
	if err != nil {
		return ResponseRunRecord{}, fmt.Errorf("get response run: %w", err)
	}
	return record, nil
}

func (s *Store) ListResponseRuns(ctx context.Context, tenantID string, afterID int64, limit int) ([]ResponseRunRecord, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, false, ErrTenantRequired
	}
	if afterID < 0 || limit < 1 || limit > maxResponseRunPageSize {
		return nil, false, ErrInvalidPagination
	}
	rows, err := s.DB.QueryContext(ctx, `
SELECT `+responseRunSelectColumns+`
FROM response_runs r
JOIN incidents i ON i.tenant_id = r.tenant_id AND i.id = r.incident_db_id
WHERE r.tenant_id = $1::uuid AND r.id > $2
ORDER BY r.id ASC LIMIT $3`, tenantID, afterID, limit+1)
	if err != nil {
		return nil, false, fmt.Errorf("list response runs: %w", err)
	}
	defer rows.Close()
	records := make([]ResponseRunRecord, 0, limit+1)
	for rows.Next() {
		record, scanErr := scanResponseRun(rows)
		if scanErr != nil {
			return nil, false, fmt.Errorf("scan response run: %w", scanErr)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate response runs: %w", err)
	}
	hasMore := len(records) > limit
	if hasMore {
		records = records[:limit]
	}
	return records, hasMore, nil
}

func (s *Store) GetResponseApprovalByID(ctx context.Context, tenantID, approvalID string) (ResponseApprovalRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	approvalID = strings.TrimSpace(approvalID)
	if tenantID == "" {
		return ResponseApprovalRecord{}, ErrTenantRequired
	}
	if approvalID == "" {
		return ResponseApprovalRecord{}, ErrResponseApprovalNotFound
	}
	record, err := scanResponseApproval(s.DB.QueryRowContext(ctx, `
SELECT `+responseApprovalSelectColumns+`
FROM response_approvals a
JOIN response_runs r ON r.tenant_id = a.tenant_id AND r.id = a.response_run_db_id
WHERE a.tenant_id = $1::uuid AND a.approval_id = $2`, tenantID, approvalID))
	if errors.Is(err, sql.ErrNoRows) {
		return ResponseApprovalRecord{}, ErrResponseApprovalNotFound
	}
	if err != nil {
		return ResponseApprovalRecord{}, fmt.Errorf("get response approval: %w", err)
	}
	return record, nil
}

func (s *Store) ListResponseApprovals(ctx context.Context, tenantID, status string, afterID int64, limit int) ([]ResponseApprovalRecord, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	status = strings.TrimSpace(status)
	if tenantID == "" {
		return nil, false, ErrTenantRequired
	}
	if afterID < 0 || limit < 1 || limit > maxResponseRunPageSize || (status != "" && status != "pending" && status != "approved" && status != "rejected") {
		return nil, false, ErrInvalidPagination
	}
	rows, err := s.DB.QueryContext(ctx, `
SELECT `+responseApprovalSelectColumns+`
FROM response_approvals a
JOIN response_runs r ON r.tenant_id = a.tenant_id AND r.id = a.response_run_db_id
WHERE a.tenant_id = $1::uuid AND a.id > $2
  AND ($3 = '' OR a.status = $3)
ORDER BY a.id ASC LIMIT $4`, tenantID, afterID, status, limit+1)
	if err != nil {
		return nil, false, fmt.Errorf("list response approvals: %w", err)
	}
	defer rows.Close()
	records := make([]ResponseApprovalRecord, 0, limit+1)
	for rows.Next() {
		record, scanErr := scanResponseApproval(rows)
		if scanErr != nil {
			return nil, false, fmt.Errorf("scan response approval: %w", scanErr)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate response approvals: %w", err)
	}
	hasMore := len(records) > limit
	if hasMore {
		records = records[:limit]
	}
	return records, hasMore, nil
}

func (s *Store) DecideResponseApproval(
	ctx context.Context,
	tenantID, approvalID, decidedBy string,
	approve bool,
	note *string,
) (ResponseApprovalRecord, ResponseRunRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	approvalID = strings.TrimSpace(approvalID)
	decidedBy = strings.TrimSpace(decidedBy)
	if note != nil {
		value := strings.TrimSpace(*note)
		note = &value
	}
	if tenantID == "" {
		return ResponseApprovalRecord{}, ResponseRunRecord{}, ErrTenantRequired
	}
	if approvalID == "" || decidedBy == "" || (note != nil && len(*note) > maxResponseDecisionNote) {
		return ResponseApprovalRecord{}, ResponseRunRecord{}, ErrInvalidResponseRun
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ResponseApprovalRecord{}, ResponseRunRecord{}, fmt.Errorf("begin response approval decision: %w", err)
	}
	defer tx.Rollback()

	var approvalStatus, requesterID, runID, runStatus string
	err = tx.QueryRowContext(ctx, `
SELECT a.status, a.requested_by::text, r.response_run_id, r.status
FROM response_approvals a
JOIN response_runs r ON r.tenant_id = a.tenant_id AND r.id = a.response_run_db_id
WHERE a.tenant_id = $1::uuid AND a.approval_id = $2
FOR UPDATE OF a, r`, tenantID, approvalID).Scan(&approvalStatus, &requesterID, &runID, &runStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return ResponseApprovalRecord{}, ResponseRunRecord{}, ErrResponseApprovalNotFound
	}
	if err != nil {
		return ResponseApprovalRecord{}, ResponseRunRecord{}, fmt.Errorf("lock response approval: %w", err)
	}
	if approvalStatus != "pending" || runStatus != "pending_approval" {
		return ResponseApprovalRecord{}, ResponseRunRecord{}, ErrResponseApprovalAlreadyDecided
	}
	if approve && requesterID == decidedBy {
		return ResponseApprovalRecord{}, ResponseRunRecord{}, ErrResponseSelfApproval
	}
	active, err := activeTenantUser(ctx, tx, tenantID, decidedBy)
	if err != nil {
		return ResponseApprovalRecord{}, ResponseRunRecord{}, fmt.Errorf("validate response approver: %w", err)
	}
	if !active {
		return ResponseApprovalRecord{}, ResponseRunRecord{}, ErrInvalidResponseApprover
	}

	nextApprovalStatus := "rejected"
	nextRunStatus := "rejected"
	if approve {
		nextApprovalStatus = "approved"
		nextRunStatus = "queued"
	}
	approval, err := scanResponseApproval(tx.QueryRowContext(ctx, `
UPDATE response_approvals a
SET status = $3, decided_by = $4::uuid, decision_note = $5, decided_at = NOW()
FROM response_runs r
WHERE a.tenant_id = $1::uuid AND a.approval_id = $2
  AND r.tenant_id = a.tenant_id AND r.id = a.response_run_db_id
RETURNING a.id, a.tenant_id::text, a.approval_id, r.response_run_id,
          a.requested_by::text, a.decided_by::text, a.status, a.decision_note,
          a.requested_at, a.decided_at`,
		tenantID, approvalID, nextApprovalStatus, decidedBy, note,
	))
	if err != nil {
		return ResponseApprovalRecord{}, ResponseRunRecord{}, fmt.Errorf("record response approval decision: %w", err)
	}
	if !approve {
		if _, err := tx.ExecContext(ctx, `
UPDATE response_action_executions
SET status = 'skipped', finished_at = NOW(), updated_at = NOW()
WHERE tenant_id = $1::uuid
  AND response_run_db_id = (SELECT id FROM response_runs WHERE tenant_id = $1::uuid AND response_run_id = $2)
  AND status = 'pending'`, tenantID, runID); err != nil {
			return ResponseApprovalRecord{}, ResponseRunRecord{}, fmt.Errorf("skip actions for rejected response run: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE response_runs
SET status = $3::varchar,
    finished_at = CASE WHEN $3::varchar = 'rejected' THEN NOW() ELSE NULL END,
    updated_at = NOW()
WHERE tenant_id = $1::uuid AND response_run_id = $2`, tenantID, runID, nextRunStatus); err != nil {
		return ResponseApprovalRecord{}, ResponseRunRecord{}, fmt.Errorf("update response run after approval decision: %w", err)
	}
	run, err := scanResponseRun(tx.QueryRowContext(ctx, `
SELECT `+responseRunSelectColumns+`
FROM response_runs r
JOIN incidents i ON i.tenant_id = r.tenant_id AND i.id = r.incident_db_id
WHERE r.tenant_id = $1::uuid AND r.response_run_id = $2`, tenantID, runID))
	if err != nil {
		return ResponseApprovalRecord{}, ResponseRunRecord{}, fmt.Errorf("read response run after approval decision: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ResponseApprovalRecord{}, ResponseRunRecord{}, fmt.Errorf("commit response approval decision: %w", err)
	}
	return approval, run, nil
}

func (s *Store) StartResponseRun(ctx context.Context, tenantID, responseRunID string) (ResponseRunRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	responseRunID = strings.TrimSpace(responseRunID)
	if tenantID == "" {
		return ResponseRunRecord{}, ErrTenantRequired
	}
	if responseRunID == "" {
		return ResponseRunRecord{}, ErrInvalidResponseRun
	}
	var current string
	err := s.DB.QueryRowContext(ctx, `
UPDATE response_runs
SET status = 'running', started_at = NOW(), updated_at = NOW()
WHERE tenant_id = $1::uuid AND response_run_id = $2 AND status = 'queued'
RETURNING status`, tenantID, responseRunID).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		_, getErr := s.GetResponseRunByID(ctx, tenantID, responseRunID)
		if errors.Is(getErr, ErrResponseRunNotFound) {
			return ResponseRunRecord{}, ErrResponseRunNotFound
		}
		if getErr != nil {
			return ResponseRunRecord{}, getErr
		}
		return ResponseRunRecord{}, ErrResponseRunNotQueued
	}
	if err != nil {
		return ResponseRunRecord{}, fmt.Errorf("start response run: %w", err)
	}
	return s.GetResponseRunByID(ctx, tenantID, responseRunID)
}

func (s *Store) ListResponseActionExecutions(ctx context.Context, tenantID, responseRunID string) ([]ResponseActionExecutionRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	responseRunID = strings.TrimSpace(responseRunID)
	if tenantID == "" {
		return nil, ErrTenantRequired
	}
	if responseRunID == "" {
		return nil, ErrResponseRunNotFound
	}
	var exists bool
	if err := s.DB.QueryRowContext(ctx, `
SELECT EXISTS (SELECT 1 FROM response_runs WHERE tenant_id = $1::uuid AND response_run_id = $2)`, tenantID, responseRunID).Scan(&exists); err != nil {
		return nil, fmt.Errorf("check response run before listing executions: %w", err)
	}
	if !exists {
		return nil, ErrResponseRunNotFound
	}
	rows, err := s.DB.QueryContext(ctx, `
SELECT `+responseExecutionSelectColumns+`
FROM response_action_executions e
JOIN response_runs r ON r.tenant_id = e.tenant_id AND r.id = e.response_run_db_id
WHERE e.tenant_id = $1::uuid AND r.response_run_id = $2
ORDER BY e.step_order ASC, e.id ASC`, tenantID, responseRunID)
	if err != nil {
		return nil, fmt.Errorf("list response action executions: %w", err)
	}
	defer rows.Close()
	records := make([]ResponseActionExecutionRecord, 0)
	for rows.Next() {
		record, scanErr := scanResponseActionExecution(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan response action execution: %w", scanErr)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate response action executions: %w", err)
	}
	return records, nil
}

func (s *Store) GetResponseActionExecutionByID(ctx context.Context, tenantID, actionExecutionID string) (ResponseActionExecutionRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	actionExecutionID = strings.TrimSpace(actionExecutionID)
	if tenantID == "" {
		return ResponseActionExecutionRecord{}, ErrTenantRequired
	}
	if actionExecutionID == "" {
		return ResponseActionExecutionRecord{}, ErrResponseExecutionNotFound
	}
	record, err := scanResponseActionExecution(s.DB.QueryRowContext(ctx, `
SELECT `+responseExecutionSelectColumns+`
FROM response_action_executions e
JOIN response_runs r ON r.tenant_id = e.tenant_id AND r.id = e.response_run_db_id
WHERE e.tenant_id = $1::uuid AND e.action_execution_id = $2`, tenantID, actionExecutionID))
	if errors.Is(err, sql.ErrNoRows) {
		return ResponseActionExecutionRecord{}, ErrResponseExecutionNotFound
	}
	if err != nil {
		return ResponseActionExecutionRecord{}, fmt.Errorf("get response action execution: %w", err)
	}
	return record, nil
}

func (s *Store) StartResponseActionExecution(ctx context.Context, tenantID, responseRunID, actionExecutionID string) (ResponseActionExecutionRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	responseRunID = strings.TrimSpace(responseRunID)
	actionExecutionID = strings.TrimSpace(actionExecutionID)
	if tenantID == "" {
		return ResponseActionExecutionRecord{}, ErrTenantRequired
	}
	if responseRunID == "" || actionExecutionID == "" {
		return ResponseActionExecutionRecord{}, ErrInvalidResponseExecution
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ResponseActionExecutionRecord{}, fmt.Errorf("begin response action start: %w", err)
	}
	defer tx.Rollback()

	var runStatus string
	err = tx.QueryRowContext(ctx, `
SELECT status FROM response_runs
WHERE tenant_id = $1::uuid AND response_run_id = $2
FOR UPDATE`, tenantID, responseRunID).Scan(&runStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return ResponseActionExecutionRecord{}, ErrResponseRunNotFound
	}
	if err != nil {
		return ResponseActionExecutionRecord{}, fmt.Errorf("lock response run before action start: %w", err)
	}
	if runStatus != "running" {
		return ResponseActionExecutionRecord{}, ErrResponseRunNotRunning
	}

	var record ResponseActionExecutionRecord
	var startedAt, finishedAt sql.NullTime
	var summary, errorCode, externalReference sql.NullString
	var config []byte
	err = tx.QueryRowContext(ctx, `
UPDATE response_action_executions e
SET status = 'running', attempt_count = attempt_count + 1,
    started_at = NOW(), finished_at = NULL,
    result_summary = NULL, error_code = NULL, external_reference = NULL,
    updated_at = NOW()
FROM response_runs r
WHERE e.tenant_id = $1::uuid AND r.tenant_id = e.tenant_id
  AND r.response_run_id = $2 AND e.response_run_db_id = r.id
  AND r.status = 'running'
  AND e.action_execution_id = $3
  AND e.status IN ('pending', 'failed', 'timed_out')
  AND e.attempt_count < $4
RETURNING e.id, e.tenant_id::text, e.action_execution_id, r.response_run_id,
          e.response_action_id, e.step_order, e.action_type, e.status,
          e.attempt_count, e.config_snapshot, e.result_summary, e.error_code,
          e.external_reference, e.started_at, e.finished_at, e.created_at, e.updated_at`,
		tenantID, responseRunID, actionExecutionID, maxResponseExecutionAttempts,
	).Scan(
		&record.ID, &record.TenantID, &record.ActionExecutionID, &record.ResponseRunID,
		&record.ResponseActionID, &record.StepOrder, &record.ActionType, &record.Status,
		&record.AttemptCount, &config, &summary, &errorCode, &externalReference,
		&startedAt, &finishedAt, &record.CreatedAt, &record.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ResponseActionExecutionRecord{}, s.responseExecutionStartError(ctx, tenantID, responseRunID, actionExecutionID)
	}
	if err != nil {
		return ResponseActionExecutionRecord{}, fmt.Errorf("start response action execution: %w", err)
	}
	record.ConfigSnapshot = append(json.RawMessage(nil), config...)
	if summary.Valid {
		value := summary.String
		record.ResultSummary = &value
	}
	if errorCode.Valid {
		value := errorCode.String
		record.ErrorCode = &value
	}
	if externalReference.Valid {
		value := externalReference.String
		record.ExternalReference = &value
	}
	if startedAt.Valid {
		value := startedAt.Time
		record.StartedAt = &value
	}
	if finishedAt.Valid {
		value := finishedAt.Time
		record.FinishedAt = &value
	}
	if err := tx.Commit(); err != nil {
		return ResponseActionExecutionRecord{}, fmt.Errorf("commit response action start: %w", err)
	}
	return record, nil
}

func (s *Store) responseExecutionStartError(ctx context.Context, tenantID, runID, executionID string) error {
	var status string
	var attempts int
	err := s.DB.QueryRowContext(ctx, `
SELECT e.status, e.attempt_count
FROM response_action_executions e
JOIN response_runs r ON r.tenant_id = e.tenant_id AND r.id = e.response_run_db_id
WHERE e.tenant_id = $1::uuid AND r.response_run_id = $2 AND e.action_execution_id = $3`, tenantID, runID, executionID).Scan(&status, &attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrResponseExecutionNotFound
	}
	if err != nil {
		return fmt.Errorf("inspect response action execution: %w", err)
	}
	if attempts >= maxResponseExecutionAttempts && (status == "pending" || status == "failed" || status == "timed_out") {
		return ErrResponseExecutionAttemptsLimit
	}
	return ErrInvalidResponseExecutionState
}

func validateResponseExecutionFinish(p FinishResponseActionExecutionParams) error {
	switch p.Status {
	case "succeeded", "failed", "skipped", "timed_out", "cancelled":
	default:
		return ErrInvalidResponseExecution
	}
	if p.ResultSummary != nil && len(*p.ResultSummary) > maxResponseExecutionSummary {
		return ErrInvalidResponseExecution
	}
	if p.ErrorCode != nil && (strings.TrimSpace(*p.ErrorCode) == "" || len(*p.ErrorCode) > 64) {
		return ErrInvalidResponseExecution
	}
	if p.ExternalReference != nil && (strings.TrimSpace(*p.ExternalReference) == "" || len(*p.ExternalReference) > 255) {
		return ErrInvalidResponseExecution
	}
	return nil
}

func (s *Store) FinishResponseActionExecution(ctx context.Context, tenantID, responseRunID, actionExecutionID string, p FinishResponseActionExecutionParams) (ResponseActionExecutionRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	responseRunID = strings.TrimSpace(responseRunID)
	actionExecutionID = strings.TrimSpace(actionExecutionID)
	if tenantID == "" {
		return ResponseActionExecutionRecord{}, ErrTenantRequired
	}
	if responseRunID == "" || actionExecutionID == "" || validateResponseExecutionFinish(p) != nil {
		return ResponseActionExecutionRecord{}, ErrInvalidResponseExecution
	}
	if p.ResultSummary != nil {
		value := strings.TrimSpace(*p.ResultSummary)
		p.ResultSummary = &value
	}
	if p.ErrorCode != nil {
		value := strings.TrimSpace(*p.ErrorCode)
		p.ErrorCode = &value
	}
	if p.ExternalReference != nil {
		value := strings.TrimSpace(*p.ExternalReference)
		p.ExternalReference = &value
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ResponseActionExecutionRecord{}, fmt.Errorf("begin response action finish: %w", err)
	}
	defer tx.Rollback()
	var runStatus string
	err = tx.QueryRowContext(ctx, `
SELECT status FROM response_runs
WHERE tenant_id = $1::uuid AND response_run_id = $2
FOR UPDATE`, tenantID, responseRunID).Scan(&runStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return ResponseActionExecutionRecord{}, ErrResponseRunNotFound
	}
	if err != nil {
		return ResponseActionExecutionRecord{}, fmt.Errorf("lock response run before action finish: %w", err)
	}
	if runStatus != "running" {
		return ResponseActionExecutionRecord{}, ErrResponseRunNotRunning
	}

	var record ResponseActionExecutionRecord
	var config []byte
	var summary, errorCode, externalReference sql.NullString
	var startedAt, finishedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
UPDATE response_action_executions e
SET status = $4,
    result_summary = $5,
    error_code = $6,
    external_reference = $7,
    finished_at = NOW(),
    updated_at = NOW()
FROM response_runs r
WHERE e.tenant_id = $1::uuid AND r.tenant_id = e.tenant_id
  AND r.response_run_id = $2 AND e.response_run_db_id = r.id
  AND r.status = 'running'
  AND e.action_execution_id = $3
  AND (e.status = 'running' OR (e.status = 'pending' AND $4 = 'skipped'))
RETURNING e.id, e.tenant_id::text, e.action_execution_id, r.response_run_id,
          e.response_action_id, e.step_order, e.action_type, e.status,
          e.attempt_count, e.config_snapshot, e.result_summary, e.error_code,
          e.external_reference, e.started_at, e.finished_at, e.created_at, e.updated_at`,
		tenantID, responseRunID, actionExecutionID, p.Status, p.ResultSummary,
		p.ErrorCode, p.ExternalReference,
	).Scan(
		&record.ID, &record.TenantID, &record.ActionExecutionID, &record.ResponseRunID,
		&record.ResponseActionID, &record.StepOrder, &record.ActionType, &record.Status,
		&record.AttemptCount, &config, &summary, &errorCode, &externalReference,
		&startedAt, &finishedAt, &record.CreatedAt, &record.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ResponseActionExecutionRecord{}, s.responseExecutionFinishError(ctx, tenantID, responseRunID, actionExecutionID)
	}
	if err != nil {
		return ResponseActionExecutionRecord{}, fmt.Errorf("finish response action execution: %w", err)
	}
	record.ConfigSnapshot = append(json.RawMessage(nil), config...)
	if summary.Valid {
		value := summary.String
		record.ResultSummary = &value
	}
	if errorCode.Valid {
		value := errorCode.String
		record.ErrorCode = &value
	}
	if externalReference.Valid {
		value := externalReference.String
		record.ExternalReference = &value
	}
	if startedAt.Valid {
		value := startedAt.Time
		record.StartedAt = &value
	}
	if finishedAt.Valid {
		value := finishedAt.Time
		record.FinishedAt = &value
	}
	if err := tx.Commit(); err != nil {
		return ResponseActionExecutionRecord{}, fmt.Errorf("commit response action finish: %w", err)
	}
	return record, nil
}

func (s *Store) responseExecutionFinishError(ctx context.Context, tenantID, runID, executionID string) error {
	var exists bool
	err := s.DB.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1 FROM response_action_executions e
    JOIN response_runs r ON r.tenant_id = e.tenant_id AND r.id = e.response_run_db_id
    WHERE e.tenant_id = $1::uuid AND r.response_run_id = $2 AND e.action_execution_id = $3
)`, tenantID, runID, executionID).Scan(&exists)
	if err != nil {
		return fmt.Errorf("inspect response action execution: %w", err)
	}
	if !exists {
		return ErrResponseExecutionNotFound
	}
	return ErrInvalidResponseExecutionState
}

func (s *Store) FinalizeResponseRun(ctx context.Context, tenantID, responseRunID string) (ResponseRunRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	responseRunID = strings.TrimSpace(responseRunID)
	if tenantID == "" {
		return ResponseRunRecord{}, ErrTenantRequired
	}
	if responseRunID == "" {
		return ResponseRunRecord{}, ErrInvalidResponseRun
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ResponseRunRecord{}, fmt.Errorf("begin response run finalization: %w", err)
	}
	defer tx.Rollback()
	var runStatus string
	err = tx.QueryRowContext(ctx, `
SELECT status FROM response_runs WHERE tenant_id = $1::uuid AND response_run_id = $2 FOR UPDATE`, tenantID, responseRunID).Scan(&runStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return ResponseRunRecord{}, ErrResponseRunNotFound
	}
	if err != nil {
		return ResponseRunRecord{}, fmt.Errorf("lock response run for finalization: %w", err)
	}
	if runStatus != "running" {
		return ResponseRunRecord{}, ErrResponseRunNotRunning
	}

	var pending, running, succeeded, failed, timedOut, cancelled int
	err = tx.QueryRowContext(ctx, `
SELECT
    COUNT(*) FILTER (WHERE e.status = 'pending'),
    COUNT(*) FILTER (WHERE e.status = 'running'),
    COUNT(*) FILTER (WHERE e.status = 'succeeded'),
    COUNT(*) FILTER (WHERE e.status = 'failed'),
    COUNT(*) FILTER (WHERE e.status = 'timed_out'),
    COUNT(*) FILTER (WHERE e.status = 'cancelled')
FROM response_action_executions e
JOIN response_runs r ON r.tenant_id = e.tenant_id AND r.id = e.response_run_db_id
WHERE e.tenant_id = $1::uuid AND r.response_run_id = $2`, tenantID, responseRunID).Scan(
		&pending, &running, &succeeded, &failed, &timedOut, &cancelled,
	)
	if err != nil {
		return ResponseRunRecord{}, fmt.Errorf("count response action execution states: %w", err)
	}
	if pending > 0 || running > 0 {
		return ResponseRunRecord{}, ErrResponseRunHasPendingActions
	}

	nextStatus := "succeeded"
	switch {
	case succeeded > 0 && failed+timedOut+cancelled > 0:
		nextStatus = "partially_failed"
	case failed > 0:
		nextStatus = "failed"
	case timedOut > 0:
		nextStatus = "timed_out"
	case cancelled > 0:
		nextStatus = "cancelled"
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE response_runs SET status = $3, finished_at = NOW(), updated_at = NOW()
WHERE tenant_id = $1::uuid AND response_run_id = $2`, tenantID, responseRunID, nextStatus); err != nil {
		return ResponseRunRecord{}, fmt.Errorf("update finalized response run: %w", err)
	}
	record, err := scanResponseRun(tx.QueryRowContext(ctx, `
SELECT `+responseRunSelectColumns+`
FROM response_runs r JOIN incidents i ON i.tenant_id = r.tenant_id AND i.id = r.incident_db_id
WHERE r.tenant_id = $1::uuid AND r.response_run_id = $2`, tenantID, responseRunID))
	if err != nil {
		return ResponseRunRecord{}, fmt.Errorf("read finalized response run: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ResponseRunRecord{}, fmt.Errorf("commit response run finalization: %w", err)
	}
	return record, nil
}

func (s *Store) CancelResponseRun(ctx context.Context, tenantID, responseRunID, cancelledBy string) (ResponseRunRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	responseRunID = strings.TrimSpace(responseRunID)
	cancelledBy = strings.TrimSpace(cancelledBy)
	if tenantID == "" {
		return ResponseRunRecord{}, ErrTenantRequired
	}
	if responseRunID == "" || cancelledBy == "" {
		return ResponseRunRecord{}, ErrInvalidResponseRun
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ResponseRunRecord{}, fmt.Errorf("begin response run cancellation: %w", err)
	}
	defer tx.Rollback()
	var current string
	err = tx.QueryRowContext(ctx, `
SELECT status FROM response_runs WHERE tenant_id = $1::uuid AND response_run_id = $2 FOR UPDATE`, tenantID, responseRunID).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return ResponseRunRecord{}, ErrResponseRunNotFound
	}
	if err != nil {
		return ResponseRunRecord{}, fmt.Errorf("lock response run for cancellation: %w", err)
	}
	if current != "pending_approval" && current != "queued" && current != "running" {
		return ResponseRunRecord{}, ErrResponseRunAlreadyFinished
	}
	active, err := activeTenantUser(ctx, tx, tenantID, cancelledBy)
	if err != nil {
		return ResponseRunRecord{}, fmt.Errorf("validate response run canceller: %w", err)
	}
	if !active {
		return ResponseRunRecord{}, ErrInvalidResponseActor
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE response_action_executions e
SET status = 'cancelled', finished_at = NOW(), updated_at = NOW()
FROM response_runs r
WHERE e.tenant_id = $1::uuid AND r.tenant_id = e.tenant_id
  AND r.response_run_id = $2 AND e.response_run_db_id = r.id
  AND e.status IN ('pending', 'running')`, tenantID, responseRunID); err != nil {
		return ResponseRunRecord{}, fmt.Errorf("cancel response action executions: %w", err)
	}
	if current == "pending_approval" {
		if _, err := tx.ExecContext(ctx, `
UPDATE response_approvals SET status = 'rejected', decision_note = 'Response run cancelled before approval',
    decided_at = NOW(), decided_by = $3::uuid
WHERE tenant_id = $1::uuid
  AND response_run_db_id = (SELECT id FROM response_runs WHERE tenant_id = $1::uuid AND response_run_id = $2)
  AND status = 'pending'`, tenantID, responseRunID, cancelledBy); err != nil {
			return ResponseRunRecord{}, fmt.Errorf("close pending response approval on cancellation: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE response_runs SET status = 'cancelled', finished_at = NOW(), updated_at = NOW()
WHERE tenant_id = $1::uuid AND response_run_id = $2`, tenantID, responseRunID); err != nil {
		return ResponseRunRecord{}, fmt.Errorf("cancel response run: %w", err)
	}
	record, err := scanResponseRun(tx.QueryRowContext(ctx, `
SELECT `+responseRunSelectColumns+`
FROM response_runs r JOIN incidents i ON i.tenant_id = r.tenant_id AND i.id = r.incident_db_id
WHERE r.tenant_id = $1::uuid AND r.response_run_id = $2`, tenantID, responseRunID))
	if err != nil {
		return ResponseRunRecord{}, fmt.Errorf("read cancelled response run: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ResponseRunRecord{}, fmt.Errorf("commit response run cancellation: %w", err)
	}
	return record, nil
}
