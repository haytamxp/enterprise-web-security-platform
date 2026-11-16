package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

func openResponsePlaybookIntegrationStore(t *testing.T) (*Store, context.Context) {
	t.Helper()

	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping PostgreSQL integration test")
	}

	ctx := context.Background()
	store, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}

	var databaseName string
	if err := store.DB.QueryRowContext(ctx, `SELECT current_database()`).Scan(&databaseName); err != nil {
		_ = store.DB.Close()
		t.Fatalf("identify test database: %v", err)
	}
	if databaseName != "ewstrp_test" {
		_ = store.DB.Close()
		t.Fatalf("refusing to run integration test against database %q; expected ewstrp_test", databaseName)
	}

	t.Cleanup(func() {
		_ = store.DB.Close()
	})

	return store, ctx
}

func createResponsePlaybookTestTenant(t *testing.T, ctx context.Context, store *Store, suffix, label string) string {
	t.Helper()

	var tenantID string
	err := store.DB.QueryRowContext(ctx, `
INSERT INTO tenants (name, slug)
VALUES ($1, $2)
RETURNING tenant_id::text`,
		"M7 response test "+label,
		"m7-response-"+label+"-"+suffix,
	).Scan(&tenantID)
	if err != nil {
		t.Fatalf("create tenant %s: %v", label, err)
	}
	return tenantID
}

func createResponsePlaybookTestUser(t *testing.T, ctx context.Context, store *Store, tenantID, suffix, label string) string {
	t.Helper()

	var userID string
	err := store.DB.QueryRowContext(ctx, `
INSERT INTO users (tenant_id, email, password_hash, role, is_active)
VALUES ($1::uuid, $2, 'integration-test-password-hash', 'admin', TRUE)
RETURNING user_id::text`,
		tenantID,
		fmt.Sprintf("m7-response-%s-%s@example.test", label, suffix),
	).Scan(&userID)
	if err != nil {
		t.Fatalf("create test user %s: %v", label, err)
	}
	return userID
}

func cleanupResponsePlaybookTestTenant(t *testing.T, store *Store, tenantID string) {
	t.Helper()
	if tenantID == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Delete children before parents. These IDs belong only to this test tenant.
	statements := []string{
		`DELETE FROM response_playbook_actions WHERE tenant_id = $1::uuid`,
		`DELETE FROM response_playbooks WHERE tenant_id = $1::uuid`,
		`DELETE FROM users WHERE tenant_id = $1::uuid`,
		`DELETE FROM tenants WHERE tenant_id = $1::uuid`,
	}
	for _, statement := range statements {
		if _, err := store.DB.ExecContext(ctx, statement, tenantID); err != nil {
			t.Logf("cleanup tenant %s: %v", tenantID, err)
			return
		}
	}
}

func TestResponsePlaybookStorageIntegration(t *testing.T) {
	store, ctx := openResponsePlaybookIntegrationStore(t)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	var tenantA, tenantB string
	t.Cleanup(func() {
		cleanupResponsePlaybookTestTenant(t, store, tenantB)
		cleanupResponsePlaybookTestTenant(t, store, tenantA)
	})

	tenantA = createResponsePlaybookTestTenant(t, ctx, store, suffix, "a")
	tenantB = createResponsePlaybookTestTenant(t, ctx, store, suffix, "b")
	userA := createResponsePlaybookTestUser(t, ctx, store, tenantA, suffix, "a")
	userB := createResponsePlaybookTestUser(t, ctx, store, tenantB, suffix, "b")

	created, err := store.CreateResponsePlaybook(ctx, tenantA, userA, CreateResponsePlaybookParams{
		PlaybookID: "pb-a-" + suffix,
		Name:       "Contain suspicious host",
	})
	if err != nil {
		t.Fatalf("create tenant A playbook: %v", err)
	}
	if created.TenantID != tenantA || created.IsActive {
		t.Fatalf("unexpected created playbook: %+v", created)
	}

	if _, err := store.CreateResponsePlaybook(ctx, tenantA, userA, CreateResponsePlaybookParams{
		PlaybookID: created.PlaybookID,
		Name:       "Duplicate playbook",
	}); !errors.Is(err, ErrDuplicateResponsePlaybook) {
		t.Fatalf("expected duplicate playbook error, got %v", err)
	}

	if _, err := store.GetResponsePlaybookByID(ctx, tenantB, created.PlaybookID); !errors.Is(err, ErrResponsePlaybookNotFound) {
		t.Fatalf("expected cross-tenant get to return not found, got %v", err)
	}

	listedB, hasMore, err := store.ListResponsePlaybooks(ctx, tenantB, 0, 10)
	if err != nil {
		t.Fatalf("list tenant B playbooks: %v", err)
	}
	if len(listedB) != 0 || hasMore {
		t.Fatalf("tenant B received tenant A playbooks: records=%+v hasMore=%v", listedB, hasMore)
	}

	// Activation must be blocked until at least one enabled action exists.
	activate := true
	if _, err := store.UpdateResponsePlaybook(ctx, tenantA, created.PlaybookID, userA, UpdateResponsePlaybookParams{
		IsActive: &activate,
	}); !errors.Is(err, ErrResponsePlaybookNoActions) {
		t.Fatalf("expected activation without actions to fail, got %v", err)
	}

	action, err := store.CreateResponsePlaybookAction(ctx, tenantA, CreateResponsePlaybookActionParams{
		ResponseActionID: "act-a-" + suffix,
		PlaybookID:       created.PlaybookID,
		ActionKey:        "notify-security-team",
		StepOrder:        1,
		ActionType:       "notify",
		RequiresApproval: false,
		IsEnabled:        true,
		Config:           json.RawMessage(`{"message":"integration test notification"}`),
	})
	if err != nil {
		t.Fatalf("create response action: %v", err)
	}
	if action.TenantID != tenantA || action.ActionType != "notify" {
		t.Fatalf("unexpected response action: %+v", action)
	}

	if _, err := store.CreateResponsePlaybookAction(ctx, tenantB, CreateResponsePlaybookActionParams{
		ResponseActionID: "act-cross-" + suffix,
		PlaybookID:       created.PlaybookID,
		ActionKey:        "cross-tenant-action",
		StepOrder:        1,
		ActionType:       "notify",
		IsEnabled:        true,
	}); !errors.Is(err, ErrResponsePlaybookNotFound) {
		t.Fatalf("expected cross-tenant action creation to return not found, got %v", err)
	}

	actions, err := store.ListResponsePlaybookActions(ctx, tenantA, created.PlaybookID)
	if err != nil {
		t.Fatalf("list response actions: %v", err)
	}
	if len(actions) != 1 || actions[0].ResponseActionID != action.ResponseActionID {
		t.Fatalf("unexpected response actions: %+v", actions)
	}

	if _, err := store.UpdateResponsePlaybook(ctx, tenantA, created.PlaybookID, userB, UpdateResponsePlaybookParams{
		Name: responsePlaybookStringPointer("Cross-tenant update"),
	}); !errors.Is(err, ErrInvalidResponseActor) {
		t.Fatalf("expected cross-tenant updater to be rejected, got %v", err)
	}

	activated, err := store.UpdateResponsePlaybook(ctx, tenantA, created.PlaybookID, userA, UpdateResponsePlaybookParams{
		IsActive: &activate,
	})
	if err != nil {
		t.Fatalf("activate playbook with enabled action: %v", err)
	}
	if !activated.IsActive {
		t.Fatal("playbook should be active")
	}

	if _, err := store.UpdateResponsePlaybookAction(ctx, tenantA, action.ResponseActionID, UpdateResponsePlaybookActionParams{
		IsEnabled: responsePlaybookBoolPointer(false),
	}); !errors.Is(err, ErrResponsePlaybookActive) {
		t.Fatalf("expected action update on active playbook to be rejected, got %v", err)
	}

	newName := "Contain suspicious endpoint"
	updated, err := store.UpdateResponsePlaybook(ctx, tenantA, created.PlaybookID, userA, UpdateResponsePlaybookParams{
		Name: &newName,
	})
	if err != nil {
		t.Fatalf("update playbook name: %v", err)
	}
	if updated.Name != newName || !updated.IsActive {
		t.Fatalf("unexpected updated playbook: %+v", updated)
	}

	deactivate := false
	if _, err := store.UpdateResponsePlaybook(ctx, tenantA, created.PlaybookID, userA, UpdateResponsePlaybookParams{
		IsActive: &deactivate,
	}); err != nil {
		t.Fatalf("deactivate playbook: %v", err)
	}

	newActionKey := "notify-on-call"
	updatedAction, err := store.UpdateResponsePlaybookAction(ctx, tenantA, action.ResponseActionID, UpdateResponsePlaybookActionParams{
		ActionKey: &newActionKey,
	})
	if err != nil {
		t.Fatalf("update inactive playbook action: %v", err)
	}
	if updatedAction.ActionKey != newActionKey {
		t.Fatalf("action key = %q, want %q", updatedAction.ActionKey, newActionKey)
	}

	if _, err := store.CreateResponsePlaybookAction(ctx, tenantA, CreateResponsePlaybookActionParams{
		ResponseActionID: "act-shell-" + suffix,
		PlaybookID:       created.PlaybookID,
		ActionKey:        "unsafe-shell",
		StepOrder:        2,
		ActionType:       "shell",
		IsEnabled:        true,
	}); !errors.Is(err, ErrInvalidResponseAction) {
		t.Fatalf("expected arbitrary shell action to be rejected, got %v", err)
	}

	readBack, err := store.GetResponsePlaybookByID(ctx, tenantA, created.PlaybookID)
	if err != nil {
		t.Fatalf("get response playbook: %v", err)
	}
	if readBack.Name != newName || readBack.IsActive {
		t.Fatalf("unexpected persisted playbook: %+v", readBack)
	}
}

func responsePlaybookStringPointer(value string) *string { return &value }
func responsePlaybookBoolPointer(value bool) *bool       { return &value }
