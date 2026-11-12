package storage

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/contract"
)

func openTenantIngestTestStore(t *testing.T) (*Store, context.Context) {
	t.Helper()

	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not configured; PostgreSQL integration test skipped")
	}

	parsedURL, err := url.Parse(databaseURL)
	if err != nil || strings.Trim(parsedURL.Path, "/") != "ewstrp_test" {
		t.Fatal("TEST_DATABASE_URL must point to the isolated ewstrp_test database")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	store, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal("could not connect to the isolated test database")
	}

	t.Cleanup(func() {
		_ = store.DB.Close()
	})

	var databaseName string
	if err := store.DB.QueryRowContext(
		ctx,
		`SELECT current_database()`,
	).Scan(&databaseName); err != nil {
		t.Fatal("could not verify test database")
	}

	if databaseName != "ewstrp_test" {
		t.Fatal("integration test connected to an unexpected database")
	}

	return store, ctx
}

func getDefaultTenantID(t *testing.T, ctx context.Context, store *Store) string {
	t.Helper()

	var tenantID string

	err := store.DB.QueryRowContext(ctx, `
SELECT tenant_id::text
FROM tenants
WHERE slug = 'default'
  AND is_active = TRUE
`).Scan(&tenantID)

	if err != nil {
		t.Fatal("could not resolve default test tenant")
	}

	return tenantID
}

func TestInsertEventRequiresTenant(t *testing.T) {
	store := &Store{}

	err := store.InsertEvent(
		context.Background(),
		"",
		contract.Event{},
	)

	if !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("expected ErrTenantRequired, got %v", err)
	}
}

func TestInsertIncidentRequiresTenant(t *testing.T) {
	store := &Store{}

	err := store.InsertIncident(
		context.Background(),
		"",
		contract.Incident{},
	)

	if !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("expected ErrTenantRequired, got %v", err)
	}
}

func TestInsertIncidentRollsBackWhenEventLinkInsertFails(t *testing.T) {
	store, ctx := openTenantIngestTestStore(t)
	tenantID := getDefaultTenantID(t, ctx, store)

	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	eventID := "evt-rollback-" + suffix
	incidentID := "inc-rollback-" + suffix

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, _ = store.DB.ExecContext(
			cleanupCtx,
			`DELETE FROM incidents WHERE tenant_id = $1::uuid AND incident_id = $2`,
			tenantID,
			incidentID,
		)

		_, _ = store.DB.ExecContext(
			cleanupCtx,
			`DELETE FROM events WHERE tenant_id = $1::uuid AND event_id = $2`,
			tenantID,
			eventID,
		)
	})

	now := time.Now().UTC()

	event := contract.Event{
		EventID:       eventID,
		SchemaVersion: contract.SchemaVersion,
		SourceProduct: "suricata",
		EventType:     "alert",
		OccurredAt:    now,
		Severity:      3,
		Confidence:    0.9,
	}

	if err := store.InsertEvent(ctx, tenantID, event); err != nil {
		t.Fatalf("insert prerequisite event: %v", err)
	}

	incident := contract.Incident{
		IncidentID:    incidentID,
		SchemaVersion: contract.SchemaVersion,
		AssetID:       "asset-test-rollback",
		OccurredAt:    now,
		Severity:      "high",
		Confidence:    0.8,
		Title:         "Rollback integration test",
		CorrelationID: "corr-rollback-" + suffix,
		EventIDs:      []string{eventID, eventID},
		Description:   "Synthetic test of transaction rollback",
		Status:        "open",
	}

	err := store.InsertIncident(ctx, tenantID, incident)
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("expected ErrDuplicate from duplicate event link, got %v", err)
	}

	var incidentExists bool
	err = store.DB.QueryRowContext(ctx, `
SELECT EXISTS (
SELECT 1
FROM incidents
WHERE tenant_id = $1::uuid
  AND incident_id = $2
)
`, tenantID, incidentID).Scan(&incidentExists)

	if err != nil {
		t.Fatalf("check incident after rollback: %v", err)
	}

	if incidentExists {
		t.Fatal("incident remains in database after failed transaction")
	}

	var linkCount int
	err = store.DB.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM incident_events
WHERE tenant_id = $1::uuid
  AND event_id = (
SELECT id
FROM events
WHERE tenant_id = $1::uuid
  AND event_id = $2
  )
`, tenantID, eventID).Scan(&linkCount)

	if err != nil {
		t.Fatalf("check event links after rollback: %v", err)
	}

	if linkCount != 0 {
		t.Fatalf("expected zero event links after rollback, got %d", linkCount)
	}
}

func TestInsertIncidentCannotReferenceAnotherTenantEvent(t *testing.T) {
	store, ctx := openTenantIngestTestStore(t)
	tenantA := getDefaultTenantID(t, ctx, store)

	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	tenantSlug := "tenant-b-" + suffix
	eventID := "evt-cross-tenant-" + suffix
	incidentID := "inc-cross-tenant-" + suffix

	var tenantB string
	err := store.DB.QueryRowContext(ctx, `
INSERT INTO tenants (name, slug)
VALUES ($1, $2)
RETURNING tenant_id::text
`, "Cross Tenant Test", tenantSlug).Scan(&tenantB)

	if err != nil {
		t.Fatalf("create second test tenant: %v", err)
	}

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, _ = store.DB.ExecContext(
			cleanupCtx,
			`DELETE FROM incidents WHERE tenant_id = $1::uuid AND incident_id = $2`,
			tenantB,
			incidentID,
		)

		_, _ = store.DB.ExecContext(
			cleanupCtx,
			`DELETE FROM events WHERE tenant_id = $1::uuid AND event_id = $2`,
			tenantA,
			eventID,
		)

		_, _ = store.DB.ExecContext(
			cleanupCtx,
			`DELETE FROM tenants WHERE tenant_id = $1::uuid`,
			tenantB,
		)
	})

	event := contract.Event{
		EventID:       eventID,
		SchemaVersion: contract.SchemaVersion,
		SourceProduct: "suricata",
		EventType:     "alert",
		OccurredAt:    time.Now().UTC(),
		Severity:      3,
		Confidence:    0.9,
	}

	if err := store.InsertEvent(ctx, tenantA, event); err != nil {
		t.Fatalf("insert event into tenant A: %v", err)
	}

	incident := contract.Incident{
		IncidentID:    incidentID,
		SchemaVersion: contract.SchemaVersion,
		AssetID:       "asset-cross-tenant",
		OccurredAt:    time.Now().UTC(),
		Severity:      "high",
		Confidence:    0.8,
		Title:         "Cross tenant isolation test",
		CorrelationID: "corr-cross-tenant-" + suffix,
		EventIDs:      []string{eventID},
		Description:   "Tenant B must not reference Tenant A event",
		Status:        "open",
	}

	err = store.InsertIncident(ctx, tenantB, incident)
	if !errors.Is(err, ErrUnknownEvent) {
		t.Fatalf("expected ErrUnknownEvent for cross-tenant reference, got %v", err)
	}

	var incidentExists bool
	err = store.DB.QueryRowContext(ctx, `
SELECT EXISTS (
SELECT 1
FROM incidents
WHERE tenant_id = $1::uuid
  AND incident_id = $2
)
`, tenantB, incidentID).Scan(&incidentExists)

	if err != nil {
		t.Fatalf("check cross-tenant incident: %v", err)
	}

	if incidentExists {
		t.Fatal("cross-tenant incident was persisted")
	}
}
