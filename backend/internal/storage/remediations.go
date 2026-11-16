package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrRemediationNotFound     = errors.New("remediation not found")
	ErrRetestNotFound          = errors.New("retest result not found")
	ErrFindingNotActionable    = errors.New("finding is not eligible for remediation")
	ErrInvalidRemediation      = errors.New("invalid remediation input")
	ErrInvalidRemediationState = errors.New("invalid remediation state transition")
	ErrInvalidAssignee         = errors.New("assignee is not an active user in this tenant")
	ErrInvalidRetest           = errors.New("invalid retest input")
	ErrDuplicateRetest         = errors.New("duplicate retest ID")
	ErrInvalidRemediationPage  = errors.New("invalid remediation pagination parameters")
)

const maxRemediationPageSize = 100

const remediationSelectColumns = `
id, tenant_id::text, remediation_id, finding_id, title, description,
priority, status, assigned_to::text, due_at, created_by::text,
completed_at, created_at, updated_at
`

type RemediationRecord struct {
	ID            int64      `json:"-"`
	TenantID      string     `json:"tenant_id"`
	RemediationID string     `json:"remediation_id"`
	FindingID     string     `json:"finding_id"`
	Title         string     `json:"title"`
	Description   *string    `json:"description,omitempty"`
	Priority      string     `json:"priority"`
	Status        string     `json:"status"`
	AssignedTo    *string    `json:"assigned_to,omitempty"`
	DueAt         *time.Time `json:"due_at,omitempty"`
	CreatedBy     string     `json:"created_by"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type RetestRecord struct {
	ID            int64     `json:"-"`
	TenantID      string    `json:"tenant_id"`
	RetestID      string    `json:"retest_id"`
	RemediationID string    `json:"remediation_id"`
	FindingID     string    `json:"finding_id"`
	Status        string    `json:"status"`
	Summary       string    `json:"summary"`
	EvidenceRefs  []string  `json:"evidence_refs"`
	PerformedBy   string    `json:"performed_by"`
	TestedAt      time.Time `json:"tested_at"`
	CreatedAt     time.Time `json:"created_at"`
}

type CreateRemediationParams struct {
	RemediationID string
	FindingID     string
	Title         string
	Description   *string
	Priority      string
	AssignedTo    *string
	DueAt         *time.Time
}

type UpdateRemediationParams struct {
	Status     *string
	AssignedTo *string
	DueAt      *time.Time
}

type CreateRetestParams struct {
	RetestID     string
	Status       string
	Summary      string
	EvidenceRefs []string
	TestedAt     time.Time
}

type remediationScanner interface{ Scan(dest ...any) error }

func scanRemediation(row remediationScanner) (RemediationRecord, error) {
	var r RemediationRecord
	var description, assignedTo sql.NullString
	var dueAt, completedAt sql.NullTime
	err := row.Scan(
		&r.ID, &r.TenantID, &r.RemediationID, &r.FindingID, &r.Title,
		&description, &r.Priority, &r.Status, &assignedTo, &dueAt,
		&r.CreatedBy, &completedAt, &r.CreatedAt, &r.UpdatedAt,
	)
	if err != nil {
		return RemediationRecord{}, err
	}
	if description.Valid {
		v := description.String
		r.Description = &v
	}
	if assignedTo.Valid {
		v := assignedTo.String
		r.AssignedTo = &v
	}
	if dueAt.Valid {
		v := dueAt.Time
		r.DueAt = &v
	}
	if completedAt.Valid {
		v := completedAt.Time
		r.CompletedAt = &v
	}
	return r, nil
}

func validateRemediationPriority(v string) bool {
	switch v {
	case "critical", "high", "medium", "low":
		return true
	}
	return false
}

func validateRemediationStatus(v string) bool {
	switch v {
	case "open", "in_progress", "blocked", "completed", "cancelled":
		return true
	}
	return false
}

func validateRetestStatus(v string) bool {
	switch v {
	case "fixed", "still_present", "inconclusive":
		return true
	}
	return false
}

func validRemediationTransition(from, to string) bool {
	if from == to {
		return from == "open" || from == "in_progress" || from == "blocked"
	}
	switch from {
	case "open":
		return to == "in_progress" || to == "blocked" || to == "cancelled"
	case "in_progress":
		return to == "blocked" || to == "cancelled"
	case "blocked":
		return to == "in_progress" || to == "cancelled"
	}
	return false // completion is exclusively driven by a successful retest
}

func activeTenantUser(ctx context.Context, tx *sql.Tx, tenantID, userID string) (bool, error) {
	var active bool
	err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1 FROM users
    WHERE tenant_id = $1::uuid AND user_id = $2::uuid AND is_active = TRUE
)`, tenantID, userID).Scan(&active)
	return active, err
}

func (s *Store) CreateRemediation(ctx context.Context, tenantID, createdBy string, p CreateRemediationParams) (RemediationRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	createdBy = strings.TrimSpace(createdBy)
	p.RemediationID = strings.TrimSpace(p.RemediationID)
	p.FindingID = strings.TrimSpace(p.FindingID)
	p.Title = strings.TrimSpace(p.Title)
	if tenantID == "" {
		return RemediationRecord{}, ErrTenantRequired
	}
	if createdBy == "" || p.RemediationID == "" || len(p.RemediationID) > 128 || p.FindingID == "" || len(p.FindingID) > 128 || p.Title == "" || len(p.Title) > 512 || !validateRemediationPriority(p.Priority) {
		return RemediationRecord{}, ErrInvalidRemediation
	}
	if p.Description != nil && len(*p.Description) > 10000 {
		return RemediationRecord{}, ErrInvalidRemediation
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return RemediationRecord{}, fmt.Errorf("begin remediation transaction: %w", err)
	}
	defer tx.Rollback()

	var findingStatus string
	err = tx.QueryRowContext(ctx, `
SELECT status FROM findings
WHERE tenant_id = $1::uuid AND finding_id = $2
FOR UPDATE`, tenantID, p.FindingID).Scan(&findingStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return RemediationRecord{}, ErrFindingNotFound
	}
	if err != nil {
		return RemediationRecord{}, fmt.Errorf("lock finding for remediation: %w", err)
	}
	switch findingStatus {
	case "detected", "triaged", "confirmed", "remediating", "fixed_pending_retest", "retest_passed":
	default:
		return RemediationRecord{}, ErrFindingNotActionable
	}

	creatorActive, err := activeTenantUser(ctx, tx, tenantID, createdBy)
	if err != nil {
		return RemediationRecord{}, fmt.Errorf("validate remediation creator: %w", err)
	}
	if !creatorActive {
		return RemediationRecord{}, ErrInvalidAssignee
	}
	if p.AssignedTo != nil {
		assigned := strings.TrimSpace(*p.AssignedTo)
		if assigned == "" {
			return RemediationRecord{}, ErrInvalidAssignee
		}
		active, checkErr := activeTenantUser(ctx, tx, tenantID, assigned)
		if checkErr != nil {
			return RemediationRecord{}, fmt.Errorf("validate remediation assignee: %w", checkErr)
		}
		if !active {
			return RemediationRecord{}, ErrInvalidAssignee
		}
		p.AssignedTo = &assigned
	}

	_, err = tx.ExecContext(ctx, `
UPDATE findings SET status = 'remediating', updated_at = NOW()
WHERE tenant_id = $1::uuid AND finding_id = $2`, tenantID, p.FindingID)
	if err != nil {
		return RemediationRecord{}, fmt.Errorf("set finding remediation status: %w", err)
	}

	var record RemediationRecord
	record, err = scanRemediation(tx.QueryRowContext(ctx, `
INSERT INTO remediation_tasks (
    tenant_id, remediation_id, finding_id, title, description, priority,
    status, assigned_to, due_at, created_by
) VALUES ($1::uuid, $2, $3, $4, $5, $6, 'open', $7::uuid, $8, $9::uuid)
RETURNING `+remediationSelectColumns,
		tenantID, p.RemediationID, p.FindingID, p.Title, p.Description,
		p.Priority, p.AssignedTo, p.DueAt, createdBy))
	if err != nil {
		if pgState(err) == "23505" {
			return RemediationRecord{}, ErrDuplicate
		}
		if pgState(err) == "23503" {
			return RemediationRecord{}, ErrInvalidAssignee
		}
		return RemediationRecord{}, fmt.Errorf("insert remediation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return RemediationRecord{}, fmt.Errorf("commit remediation: %w", err)
	}
	return record, nil
}

func pgState(err error) string {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState()
	}
	return ""
}

func (s *Store) GetRemediationByID(ctx context.Context, tenantID, remediationID string) (RemediationRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	remediationID = strings.TrimSpace(remediationID)
	if tenantID == "" {
		return RemediationRecord{}, ErrTenantRequired
	}
	if remediationID == "" {
		return RemediationRecord{}, ErrRemediationNotFound
	}
	r, err := scanRemediation(s.DB.QueryRowContext(ctx, `
SELECT `+remediationSelectColumns+`
FROM remediation_tasks WHERE tenant_id = $1::uuid AND remediation_id = $2`, tenantID, remediationID))
	if errors.Is(err, sql.ErrNoRows) {
		return RemediationRecord{}, ErrRemediationNotFound
	}
	if err != nil {
		return RemediationRecord{}, fmt.Errorf("get remediation: %w", err)
	}
	return r, nil
}

func (s *Store) ListRemediations(ctx context.Context, tenantID string, afterID int64, limit int) ([]RemediationRecord, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, false, ErrTenantRequired
	}
	if afterID < 0 || limit < 1 || limit > maxRemediationPageSize {
		return nil, false, ErrInvalidRemediationPage
	}
	rows, err := s.DB.QueryContext(ctx, `
SELECT `+remediationSelectColumns+`
FROM remediation_tasks
WHERE tenant_id = $1::uuid AND id > $2
ORDER BY id ASC LIMIT $3`, tenantID, afterID, limit+1)
	if err != nil {
		return nil, false, fmt.Errorf("list remediations: %w", err)
	}
	defer rows.Close()
	records := make([]RemediationRecord, 0, limit+1)
	for rows.Next() {
		record, scanErr := scanRemediation(rows)
		if scanErr != nil {
			return nil, false, fmt.Errorf("scan remediation: %w", scanErr)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate remediations: %w", err)
	}
	hasMore := len(records) > limit
	if hasMore {
		records = records[:limit]
	}
	return records, hasMore, nil
}

func (s *Store) UpdateRemediation(ctx context.Context, tenantID, remediationID string, p UpdateRemediationParams) (RemediationRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	remediationID = strings.TrimSpace(remediationID)
	if tenantID == "" {
		return RemediationRecord{}, ErrTenantRequired
	}
	if remediationID == "" || (p.Status == nil && p.AssignedTo == nil && p.DueAt == nil) {
		return RemediationRecord{}, ErrInvalidRemediation
	}
	if p.Status != nil && !validateRemediationStatus(*p.Status) {
		return RemediationRecord{}, ErrInvalidRemediation
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return RemediationRecord{}, fmt.Errorf("begin remediation update: %w", err)
	}
	defer tx.Rollback()
	var current string
	err = tx.QueryRowContext(ctx, `SELECT status FROM remediation_tasks WHERE tenant_id = $1::uuid AND remediation_id = $2 FOR UPDATE`, tenantID, remediationID).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return RemediationRecord{}, ErrRemediationNotFound
	}
	if err != nil {
		return RemediationRecord{}, fmt.Errorf("lock remediation: %w", err)
	}
	next := current
	if p.Status != nil {
		next = *p.Status
	}
	if !validRemediationTransition(current, next) {
		return RemediationRecord{}, ErrInvalidRemediationState
	}
	if p.AssignedTo != nil {
		assigned := strings.TrimSpace(*p.AssignedTo)
		if assigned == "" {
			return RemediationRecord{}, ErrInvalidAssignee
		}
		active, checkErr := activeTenantUser(ctx, tx, tenantID, assigned)
		if checkErr != nil {
			return RemediationRecord{}, fmt.Errorf("validate assignee: %w", checkErr)
		}
		if !active {
			return RemediationRecord{}, ErrInvalidAssignee
		}
		p.AssignedTo = &assigned
	}
	var assignedArg any
	if p.AssignedTo != nil {
		assignedArg = *p.AssignedTo
	}
	var dueArg any
	if p.DueAt != nil {
		dueArg = *p.DueAt
	}
	record, err := scanRemediation(tx.QueryRowContext(ctx, `
UPDATE remediation_tasks
SET status = $3,
    assigned_to = COALESCE($4::uuid, assigned_to),
    due_at = COALESCE($5::timestamptz, due_at),
    updated_at = NOW()
WHERE tenant_id = $1::uuid AND remediation_id = $2
RETURNING `+remediationSelectColumns,
		tenantID, remediationID, next, assignedArg, dueArg))
	if err != nil {
		return RemediationRecord{}, fmt.Errorf("update remediation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return RemediationRecord{}, fmt.Errorf("commit remediation update: %w", err)
	}
	return record, nil
}

func (s *Store) CreateRetest(ctx context.Context, tenantID, performedBy, remediationID string, p CreateRetestParams) (RetestRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	performedBy = strings.TrimSpace(performedBy)
	remediationID = strings.TrimSpace(remediationID)
	p.RetestID = strings.TrimSpace(p.RetestID)
	p.Status = strings.TrimSpace(p.Status)
	p.Summary = strings.TrimSpace(p.Summary)
	if tenantID == "" {
		return RetestRecord{}, ErrTenantRequired
	}
	if performedBy == "" || remediationID == "" || p.RetestID == "" || len(p.RetestID) > 128 || !validateRetestStatus(p.Status) || p.Summary == "" || len(p.Summary) > 10000 || p.TestedAt.IsZero() || len(p.EvidenceRefs) > 100 {
		return RetestRecord{}, ErrInvalidRetest
	}
	for _, ref := range p.EvidenceRefs {
		if strings.TrimSpace(ref) == "" || len(ref) > 1024 {
			return RetestRecord{}, ErrInvalidRetest
		}
	}
	if p.EvidenceRefs == nil {
		p.EvidenceRefs = []string{}
	}
	evidenceJSON, err := json.Marshal(p.EvidenceRefs)
	if err != nil {
		return RetestRecord{}, fmt.Errorf("encode retest evidence references: %w", err)
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return RetestRecord{}, fmt.Errorf("begin retest transaction: %w", err)
	}
	defer tx.Rollback()
	var findingID, taskStatus string
	err = tx.QueryRowContext(ctx, `
SELECT finding_id, status FROM remediation_tasks
WHERE tenant_id = $1::uuid AND remediation_id = $2 FOR UPDATE`, tenantID, remediationID).Scan(&findingID, &taskStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return RetestRecord{}, ErrRemediationNotFound
	}
	if err != nil {
		return RetestRecord{}, fmt.Errorf("lock remediation for retest: %w", err)
	}
	if taskStatus == "cancelled" || taskStatus == "completed" {
		return RetestRecord{}, ErrInvalidRemediationState
	}
	active, err := activeTenantUser(ctx, tx, tenantID, performedBy)
	if err != nil {
		return RetestRecord{}, fmt.Errorf("validate retest performer: %w", err)
	}
	if !active {
		return RetestRecord{}, ErrInvalidAssignee
	}

	var record RetestRecord
	var returnedEvidenceJSON []byte
	err = tx.QueryRowContext(ctx, `
INSERT INTO retest_results (
    tenant_id, retest_id, remediation_id, finding_id, status,
    summary, evidence_refs, performed_by, tested_at
) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::jsonb, $8::uuid, $9)
RETURNING id, tenant_id::text, retest_id, remediation_id, finding_id,
          status, summary, evidence_refs, performed_by::text, tested_at, created_at`,
		tenantID, p.RetestID, remediationID, findingID, p.Status,
		p.Summary, string(evidenceJSON), performedBy, p.TestedAt.UTC()).Scan(
		&record.ID, &record.TenantID, &record.RetestID, &record.RemediationID,
		&record.FindingID, &record.Status, &record.Summary, &returnedEvidenceJSON,
		&record.PerformedBy, &record.TestedAt, &record.CreatedAt)
	if err != nil {
		if pgState(err) == "23505" {
			return RetestRecord{}, ErrDuplicateRetest
		}
		return RetestRecord{}, fmt.Errorf("insert retest result: %w", err)
	}
	if err := json.Unmarshal(returnedEvidenceJSON, &record.EvidenceRefs); err != nil {
		return RetestRecord{}, fmt.Errorf("decode returned retest evidence references: %w", err)
	}

	if p.Status == "fixed" || p.Status == "still_present" {
		findingStatus := "retest_passed"
		taskNext := "completed"
		if p.Status == "still_present" {
			findingStatus = "remediating"
			taskNext = "in_progress"
		}
		result, updateErr := tx.ExecContext(ctx, `
UPDATE findings SET status = $3, updated_at = NOW()
WHERE tenant_id = $1::uuid AND finding_id = $2
  AND status IN ('detected', 'triaged', 'confirmed', 'remediating', 'fixed_pending_retest', 'retest_passed')`,
			tenantID, findingID, findingStatus)
		if updateErr != nil {
			return RetestRecord{}, fmt.Errorf("update finding after retest: %w", updateErr)
		}
		affected, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return RetestRecord{}, fmt.Errorf("check finding retest update: %w", rowsErr)
		}
		if affected != 1 {
			return RetestRecord{}, ErrFindingNotActionable
		}
		_, updateErr = tx.ExecContext(ctx, `
UPDATE remediation_tasks
SET status = $3::varchar,
    completed_at = CASE WHEN $3::varchar = 'completed' THEN NOW() ELSE NULL END,
    updated_at = NOW()
WHERE tenant_id = $1::uuid AND remediation_id = $2`, tenantID, remediationID, taskNext)
		if updateErr != nil {
			return RetestRecord{}, fmt.Errorf("update remediation after retest: %w", updateErr)
		}
	}
	if err := tx.Commit(); err != nil {
		return RetestRecord{}, fmt.Errorf("commit retest: %w", err)
	}
	return record, nil
}

func (s *Store) ListRetests(ctx context.Context, tenantID, remediationID string) ([]RetestRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	remediationID = strings.TrimSpace(remediationID)
	if tenantID == "" {
		return nil, ErrTenantRequired
	}
	if remediationID == "" {
		return nil, ErrRemediationNotFound
	}
	var exists bool
	if err := s.DB.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM remediation_tasks WHERE tenant_id = $1::uuid AND remediation_id = $2)`, tenantID, remediationID).Scan(&exists); err != nil {
		return nil, fmt.Errorf("check remediation for retest list: %w", err)
	}
	if !exists {
		return nil, ErrRemediationNotFound
	}
	rows, err := s.DB.QueryContext(ctx, `
SELECT id, tenant_id::text, retest_id, remediation_id, finding_id,
       status, summary, evidence_refs, performed_by::text, tested_at, created_at
FROM retest_results
WHERE tenant_id = $1::uuid AND remediation_id = $2
ORDER BY tested_at DESC, id DESC LIMIT 500`, tenantID, remediationID)
	if err != nil {
		return nil, fmt.Errorf("list retests: %w", err)
	}
	defer rows.Close()
	records := make([]RetestRecord, 0)
	for rows.Next() {
		var r RetestRecord
		var refsJSON []byte
		if err := rows.Scan(&r.ID, &r.TenantID, &r.RetestID, &r.RemediationID,
			&r.FindingID, &r.Status, &r.Summary, &refsJSON, &r.PerformedBy,
			&r.TestedAt, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan retest: %w", err)
		}
		if err := json.Unmarshal(refsJSON, &r.EvidenceRefs); err != nil {
			return nil, fmt.Errorf("decode retest evidence references: %w", err)
		}
		if r.EvidenceRefs == nil {
			r.EvidenceRefs = []string{}
		}
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate retests: %w", err)
	}
	return records, nil
}
