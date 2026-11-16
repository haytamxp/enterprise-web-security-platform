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
	ErrResponsePlaybookNotFound  = errors.New("response playbook not found")
	ErrInvalidResponsePlaybook   = errors.New("invalid response playbook")
	ErrDuplicateResponsePlaybook = errors.New("response playbook already exists")
	ErrResponsePlaybookActive    = errors.New("deactivate response playbook before changing its actions")
	ErrResponsePlaybookNoActions = errors.New("response playbook must contain an enabled action before activation")
	ErrResponseActionNotFound    = errors.New("response playbook action not found")
	ErrInvalidResponseAction     = errors.New("invalid response playbook action")
	ErrDuplicateResponseAction   = errors.New("response playbook action already exists")
	ErrInvalidResponseActor      = errors.New("response actor is not an active user in this tenant")
)

const (
	maxResponsePlaybookPageSize = 100
	maxResponseActionConfigSize = 16 * 1024
)

const responsePlaybookSelectColumns = `
id, tenant_id::text, playbook_id, name, description, is_active,
created_by::text, updated_by::text, created_at, updated_at
`

const responsePlaybookActionSelectColumns = `
id, tenant_id::text, response_action_id, playbook_id, action_key,
step_order, action_type, requires_approval, is_enabled, config,
created_at, updated_at
`

type ResponsePlaybookRecord struct {
	ID          int64     `json:"-"`
	TenantID    string    `json:"tenant_id"`
	PlaybookID  string    `json:"playbook_id"`
	Name        string    `json:"name"`
	Description *string   `json:"description,omitempty"`
	IsActive    bool      `json:"is_active"`
	CreatedBy   string    `json:"created_by"`
	UpdatedBy   string    `json:"updated_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type ResponsePlaybookActionRecord struct {
	ID               int64           `json:"-"`
	TenantID         string          `json:"tenant_id"`
	ResponseActionID string          `json:"response_action_id"`
	PlaybookID       string          `json:"playbook_id"`
	ActionKey        string          `json:"action_key"`
	StepOrder        int             `json:"step_order"`
	ActionType       string          `json:"action_type"`
	RequiresApproval bool            `json:"requires_approval"`
	IsEnabled        bool            `json:"is_enabled"`
	Config           json.RawMessage `json:"config"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

type CreateResponsePlaybookParams struct {
	PlaybookID  string
	Name        string
	Description *string
}

type UpdateResponsePlaybookParams struct {
	Name           *string
	Description    *string
	DescriptionSet bool // true allows explicitly clearing the description with a nil Description
	IsActive       *bool
}

type CreateResponsePlaybookActionParams struct {
	ResponseActionID string
	PlaybookID       string
	ActionKey        string
	StepOrder        int
	ActionType       string
	RequiresApproval bool
	IsEnabled        bool
	Config           json.RawMessage
}

type UpdateResponsePlaybookActionParams struct {
	ActionKey        *string
	StepOrder        *int
	ActionType       *string
	RequiresApproval *bool
	IsEnabled        *bool
	Config           json.RawMessage
	ConfigSet        bool
}

type responsePlaybookScanner interface {
	Scan(dest ...any) error
}

func scanResponsePlaybook(row responsePlaybookScanner) (ResponsePlaybookRecord, error) {
	var record ResponsePlaybookRecord
	var description sql.NullString

	err := row.Scan(
		&record.ID,
		&record.TenantID,
		&record.PlaybookID,
		&record.Name,
		&description,
		&record.IsActive,
		&record.CreatedBy,
		&record.UpdatedBy,
		&record.CreatedAt,
		&record.UpdatedAt,
	)
	if err != nil {
		return ResponsePlaybookRecord{}, err
	}
	if description.Valid {
		value := description.String
		record.Description = &value
	}
	return record, nil
}

func scanResponsePlaybookAction(row responsePlaybookScanner) (ResponsePlaybookActionRecord, error) {
	var record ResponsePlaybookActionRecord
	var config []byte

	err := row.Scan(
		&record.ID,
		&record.TenantID,
		&record.ResponseActionID,
		&record.PlaybookID,
		&record.ActionKey,
		&record.StepOrder,
		&record.ActionType,
		&record.RequiresApproval,
		&record.IsEnabled,
		&config,
		&record.CreatedAt,
		&record.UpdatedAt,
	)
	if err != nil {
		return ResponsePlaybookActionRecord{}, err
	}
	if len(config) == 0 {
		record.Config = json.RawMessage(`{}`)
	} else {
		record.Config = append(json.RawMessage(nil), config...)
	}
	return record, nil
}

func validateResponseActionType(value string) bool {
	switch value {
	case "notify", "block_ip", "isolate_host", "disable_account", "collect_evidence":
		return true
	default:
		return false
	}
}

func normalizeResponseActionConfig(value json.RawMessage) (json.RawMessage, error) {
	if len(value) == 0 {
		return json.RawMessage(`{}`), nil
	}
	if len(value) > maxResponseActionConfigSize {
		return nil, ErrInvalidResponseAction
	}

	var object map[string]json.RawMessage
	if err := json.Unmarshal(value, &object); err != nil || object == nil {
		return nil, ErrInvalidResponseAction
	}

	encoded, err := json.Marshal(object)
	if err != nil {
		return nil, fmt.Errorf("normalize response action config: %w", err)
	}
	if len(encoded) > maxResponseActionConfigSize {
		return nil, ErrInvalidResponseAction
	}
	return json.RawMessage(encoded), nil
}

func validateCreateResponsePlaybook(p CreateResponsePlaybookParams) error {
	if p.PlaybookID == "" || len(p.PlaybookID) > 128 || p.Name == "" || len(p.Name) > 200 {
		return ErrInvalidResponsePlaybook
	}
	if p.Description != nil && len(*p.Description) > 10000 {
		return ErrInvalidResponsePlaybook
	}
	return nil
}

func (s *Store) CreateResponsePlaybook(
	ctx context.Context,
	tenantID string,
	createdBy string,
	p CreateResponsePlaybookParams,
) (ResponsePlaybookRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	createdBy = strings.TrimSpace(createdBy)
	p.PlaybookID = strings.TrimSpace(p.PlaybookID)
	p.Name = strings.TrimSpace(p.Name)
	if p.Description != nil {
		description := strings.TrimSpace(*p.Description)
		p.Description = &description
	}

	if tenantID == "" {
		return ResponsePlaybookRecord{}, ErrTenantRequired
	}
	if createdBy == "" || validateCreateResponsePlaybook(p) != nil {
		return ResponsePlaybookRecord{}, ErrInvalidResponsePlaybook
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ResponsePlaybookRecord{}, fmt.Errorf("begin response playbook creation: %w", err)
	}
	defer tx.Rollback()

	active, err := activeTenantUser(ctx, tx, tenantID, createdBy)
	if err != nil {
		return ResponsePlaybookRecord{}, fmt.Errorf("validate response playbook creator: %w", err)
	}
	if !active {
		return ResponsePlaybookRecord{}, ErrInvalidResponseActor
	}

	record, err := scanResponsePlaybook(tx.QueryRowContext(ctx, `
INSERT INTO response_playbooks (
    tenant_id, playbook_id, name, description, is_active, created_by, updated_by
) VALUES ($1::uuid, $2, $3, $4, FALSE, $5::uuid, $5::uuid)
RETURNING `+responsePlaybookSelectColumns,
		tenantID, p.PlaybookID, p.Name, p.Description, createdBy,
	))
	if err != nil {
		if pgState(err) == "23505" {
			return ResponsePlaybookRecord{}, ErrDuplicateResponsePlaybook
		}
		if pgState(err) == "23503" {
			return ResponsePlaybookRecord{}, ErrInvalidResponseActor
		}
		return ResponsePlaybookRecord{}, fmt.Errorf("insert response playbook: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return ResponsePlaybookRecord{}, fmt.Errorf("commit response playbook creation: %w", err)
	}
	return record, nil
}

func (s *Store) GetResponsePlaybookByID(
	ctx context.Context,
	tenantID string,
	playbookID string,
) (ResponsePlaybookRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	playbookID = strings.TrimSpace(playbookID)
	if tenantID == "" {
		return ResponsePlaybookRecord{}, ErrTenantRequired
	}
	if playbookID == "" {
		return ResponsePlaybookRecord{}, ErrResponsePlaybookNotFound
	}

	record, err := scanResponsePlaybook(s.DB.QueryRowContext(ctx, `
SELECT `+responsePlaybookSelectColumns+`
FROM response_playbooks
WHERE tenant_id = $1::uuid AND playbook_id = $2`, tenantID, playbookID))
	if errors.Is(err, sql.ErrNoRows) {
		return ResponsePlaybookRecord{}, ErrResponsePlaybookNotFound
	}
	if err != nil {
		return ResponsePlaybookRecord{}, fmt.Errorf("get response playbook: %w", err)
	}
	return record, nil
}

func (s *Store) ListResponsePlaybooks(
	ctx context.Context,
	tenantID string,
	afterID int64,
	limit int,
) ([]ResponsePlaybookRecord, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, false, ErrTenantRequired
	}
	if afterID < 0 || limit < 1 || limit > maxResponsePlaybookPageSize {
		return nil, false, ErrInvalidPagination
	}

	rows, err := s.DB.QueryContext(ctx, `
SELECT `+responsePlaybookSelectColumns+`
FROM response_playbooks
WHERE tenant_id = $1::uuid AND id > $2
ORDER BY id ASC
LIMIT $3`, tenantID, afterID, limit+1)
	if err != nil {
		return nil, false, fmt.Errorf("list response playbooks: %w", err)
	}
	defer rows.Close()

	records := make([]ResponsePlaybookRecord, 0, limit+1)
	for rows.Next() {
		record, scanErr := scanResponsePlaybook(rows)
		if scanErr != nil {
			return nil, false, fmt.Errorf("scan response playbook: %w", scanErr)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate response playbooks: %w", err)
	}

	hasMore := len(records) > limit
	if hasMore {
		records = records[:limit]
	}
	return records, hasMore, nil
}

func (s *Store) UpdateResponsePlaybook(
	ctx context.Context,
	tenantID string,
	playbookID string,
	updatedBy string,
	p UpdateResponsePlaybookParams,
) (ResponsePlaybookRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	playbookID = strings.TrimSpace(playbookID)
	updatedBy = strings.TrimSpace(updatedBy)
	if tenantID == "" {
		return ResponsePlaybookRecord{}, ErrTenantRequired
	}
	if playbookID == "" || updatedBy == "" ||
		(p.Name == nil && !p.DescriptionSet && p.IsActive == nil) {
		return ResponsePlaybookRecord{}, ErrInvalidResponsePlaybook
	}
	if p.Name != nil {
		name := strings.TrimSpace(*p.Name)
		if name == "" || len(name) > 200 {
			return ResponsePlaybookRecord{}, ErrInvalidResponsePlaybook
		}
		p.Name = &name
	}
	if p.Description != nil {
		description := strings.TrimSpace(*p.Description)
		if len(description) > 10000 {
			return ResponsePlaybookRecord{}, ErrInvalidResponsePlaybook
		}
		p.Description = &description
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ResponsePlaybookRecord{}, fmt.Errorf("begin response playbook update: %w", err)
	}
	defer tx.Rollback()

	var currentActive bool
	err = tx.QueryRowContext(ctx, `
SELECT is_active FROM response_playbooks
WHERE tenant_id = $1::uuid AND playbook_id = $2
FOR UPDATE`, tenantID, playbookID).Scan(&currentActive)
	if errors.Is(err, sql.ErrNoRows) {
		return ResponsePlaybookRecord{}, ErrResponsePlaybookNotFound
	}
	if err != nil {
		return ResponsePlaybookRecord{}, fmt.Errorf("lock response playbook: %w", err)
	}

	actorActive, err := activeTenantUser(ctx, tx, tenantID, updatedBy)
	if err != nil {
		return ResponsePlaybookRecord{}, fmt.Errorf("validate response playbook updater: %w", err)
	}
	if !actorActive {
		return ResponsePlaybookRecord{}, ErrInvalidResponseActor
	}

	nextActive := currentActive
	if p.IsActive != nil {
		nextActive = *p.IsActive
	}
	if nextActive {
		var hasEnabledAction bool
		err = tx.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1 FROM response_playbook_actions
    WHERE tenant_id = $1::uuid AND playbook_id = $2 AND is_enabled = TRUE
)`, tenantID, playbookID).Scan(&hasEnabledAction)
		if err != nil {
			return ResponsePlaybookRecord{}, fmt.Errorf("check enabled response actions: %w", err)
		}
		if !hasEnabledAction {
			return ResponsePlaybookRecord{}, ErrResponsePlaybookNoActions
		}
	}

	record, err := scanResponsePlaybook(tx.QueryRowContext(ctx, `
UPDATE response_playbooks
SET name = COALESCE($3, name),
    description = CASE WHEN $4::boolean THEN $5::text ELSE description END,
    is_active = $6,
    updated_by = $7::uuid,
    updated_at = NOW()
WHERE tenant_id = $1::uuid AND playbook_id = $2
RETURNING `+responsePlaybookSelectColumns,
		tenantID, playbookID, p.Name, p.DescriptionSet, p.Description, nextActive, updatedBy,
	))
	if err != nil {
		if pgState(err) == "23503" {
			return ResponsePlaybookRecord{}, ErrInvalidResponseActor
		}
		return ResponsePlaybookRecord{}, fmt.Errorf("update response playbook: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ResponsePlaybookRecord{}, fmt.Errorf("commit response playbook update: %w", err)
	}
	return record, nil
}

func (s *Store) CreateResponsePlaybookAction(
	ctx context.Context,
	tenantID string,
	p CreateResponsePlaybookActionParams,
) (ResponsePlaybookActionRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	p.ResponseActionID = strings.TrimSpace(p.ResponseActionID)
	p.PlaybookID = strings.TrimSpace(p.PlaybookID)
	p.ActionKey = strings.TrimSpace(p.ActionKey)
	p.ActionType = strings.TrimSpace(p.ActionType)

	if tenantID == "" {
		return ResponsePlaybookActionRecord{}, ErrTenantRequired
	}
	if p.ResponseActionID == "" || len(p.ResponseActionID) > 128 ||
		p.PlaybookID == "" || len(p.PlaybookID) > 128 ||
		p.ActionKey == "" || len(p.ActionKey) > 128 ||
		p.StepOrder < 1 || p.StepOrder > 1000 ||
		!validateResponseActionType(p.ActionType) {
		return ResponsePlaybookActionRecord{}, ErrInvalidResponseAction
	}
	config, err := normalizeResponseActionConfig(p.Config)
	if err != nil {
		return ResponsePlaybookActionRecord{}, err
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ResponsePlaybookActionRecord{}, fmt.Errorf("begin response action creation: %w", err)
	}
	defer tx.Rollback()

	var playbookActive bool
	err = tx.QueryRowContext(ctx, `
SELECT is_active FROM response_playbooks
WHERE tenant_id = $1::uuid AND playbook_id = $2
FOR UPDATE`, tenantID, p.PlaybookID).Scan(&playbookActive)
	if errors.Is(err, sql.ErrNoRows) {
		return ResponsePlaybookActionRecord{}, ErrResponsePlaybookNotFound
	}
	if err != nil {
		return ResponsePlaybookActionRecord{}, fmt.Errorf("lock response playbook for action creation: %w", err)
	}
	if playbookActive {
		return ResponsePlaybookActionRecord{}, ErrResponsePlaybookActive
	}

	record, err := scanResponsePlaybookAction(tx.QueryRowContext(ctx, `
INSERT INTO response_playbook_actions (
    tenant_id, response_action_id, playbook_id, action_key, step_order,
    action_type, requires_approval, is_enabled, config
) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
RETURNING `+responsePlaybookActionSelectColumns,
		tenantID, p.ResponseActionID, p.PlaybookID, p.ActionKey, p.StepOrder,
		p.ActionType, p.RequiresApproval, p.IsEnabled, string(config),
	))
	if err != nil {
		if pgState(err) == "23505" {
			return ResponsePlaybookActionRecord{}, ErrDuplicateResponseAction
		}
		return ResponsePlaybookActionRecord{}, fmt.Errorf("insert response playbook action: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ResponsePlaybookActionRecord{}, fmt.Errorf("commit response action creation: %w", err)
	}
	return record, nil
}

func (s *Store) ListResponsePlaybookActions(
	ctx context.Context,
	tenantID string,
	playbookID string,
) ([]ResponsePlaybookActionRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	playbookID = strings.TrimSpace(playbookID)
	if tenantID == "" {
		return nil, ErrTenantRequired
	}
	if playbookID == "" {
		return nil, ErrResponsePlaybookNotFound
	}

	var exists bool
	if err := s.DB.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1 FROM response_playbooks
    WHERE tenant_id = $1::uuid AND playbook_id = $2
)`, tenantID, playbookID).Scan(&exists); err != nil {
		return nil, fmt.Errorf("check response playbook before listing actions: %w", err)
	}
	if !exists {
		return nil, ErrResponsePlaybookNotFound
	}

	rows, err := s.DB.QueryContext(ctx, `
SELECT `+responsePlaybookActionSelectColumns+`
FROM response_playbook_actions
WHERE tenant_id = $1::uuid AND playbook_id = $2
ORDER BY step_order ASC, id ASC`, tenantID, playbookID)
	if err != nil {
		return nil, fmt.Errorf("list response playbook actions: %w", err)
	}
	defer rows.Close()

	records := make([]ResponsePlaybookActionRecord, 0)
	for rows.Next() {
		record, scanErr := scanResponsePlaybookAction(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan response playbook action: %w", scanErr)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate response playbook actions: %w", err)
	}
	return records, nil
}

func (s *Store) UpdateResponsePlaybookAction(
	ctx context.Context,
	tenantID string,
	responseActionID string,
	p UpdateResponsePlaybookActionParams,
) (ResponsePlaybookActionRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	responseActionID = strings.TrimSpace(responseActionID)
	if tenantID == "" {
		return ResponsePlaybookActionRecord{}, ErrTenantRequired
	}
	if responseActionID == "" ||
		(p.ActionKey == nil && p.StepOrder == nil && p.ActionType == nil &&
			p.RequiresApproval == nil && p.IsEnabled == nil && !p.ConfigSet) {
		return ResponsePlaybookActionRecord{}, ErrInvalidResponseAction
	}
	if p.ActionKey != nil {
		value := strings.TrimSpace(*p.ActionKey)
		if value == "" || len(value) > 128 {
			return ResponsePlaybookActionRecord{}, ErrInvalidResponseAction
		}
		p.ActionKey = &value
	}
	if p.StepOrder != nil && (*p.StepOrder < 1 || *p.StepOrder > 1000) {
		return ResponsePlaybookActionRecord{}, ErrInvalidResponseAction
	}
	if p.ActionType != nil {
		value := strings.TrimSpace(*p.ActionType)
		if !validateResponseActionType(value) {
			return ResponsePlaybookActionRecord{}, ErrInvalidResponseAction
		}
		p.ActionType = &value
	}
	var config json.RawMessage
	var err error
	if p.ConfigSet {
		config, err = normalizeResponseActionConfig(p.Config)
		if err != nil {
			return ResponsePlaybookActionRecord{}, err
		}
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ResponsePlaybookActionRecord{}, fmt.Errorf("begin response action update: %w", err)
	}
	defer tx.Rollback()

	var playbookID string
	var playbookActive bool
	err = tx.QueryRowContext(ctx, `
SELECT a.playbook_id, p.is_active
FROM response_playbook_actions a
JOIN response_playbooks p
  ON p.tenant_id = a.tenant_id AND p.playbook_id = a.playbook_id
WHERE a.tenant_id = $1::uuid AND a.response_action_id = $2
FOR UPDATE OF p`, tenantID, responseActionID).Scan(&playbookID, &playbookActive)
	if errors.Is(err, sql.ErrNoRows) {
		return ResponsePlaybookActionRecord{}, ErrResponseActionNotFound
	}
	if err != nil {
		return ResponsePlaybookActionRecord{}, fmt.Errorf("lock response action and playbook: %w", err)
	}
	if playbookActive {
		return ResponsePlaybookActionRecord{}, ErrResponsePlaybookActive
	}

	var configArg any
	if p.ConfigSet {
		configArg = string(config)
	}

	record, err := scanResponsePlaybookAction(tx.QueryRowContext(ctx, `
UPDATE response_playbook_actions
SET action_key = COALESCE($3, action_key),
    step_order = COALESCE($4, step_order),
    action_type = COALESCE($5, action_type),
    requires_approval = COALESCE($6, requires_approval),
    is_enabled = COALESCE($7, is_enabled),
    config = CASE WHEN $8::boolean THEN $9::jsonb ELSE config END,
    updated_at = NOW()
WHERE tenant_id = $1::uuid AND response_action_id = $2
RETURNING `+responsePlaybookActionSelectColumns,
		tenantID, responseActionID, p.ActionKey, p.StepOrder, p.ActionType,
		p.RequiresApproval, p.IsEnabled, p.ConfigSet, configArg,
	))
	if err != nil {
		if pgState(err) == "23505" {
			return ResponsePlaybookActionRecord{}, ErrDuplicateResponseAction
		}
		return ResponsePlaybookActionRecord{}, fmt.Errorf("update response playbook action: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ResponsePlaybookActionRecord{}, fmt.Errorf("commit response action update: %w", err)
	}
	_ = playbookID // retained above to establish the tenant-scoped parent lock
	return record, nil
}
