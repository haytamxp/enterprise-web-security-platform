package storage

import (
	"context"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/contract"
)

func TestInsertIncidentRollsBackWhenEventLinkInsertFails(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set TEST_DATABASE_URL to the isolated ewstrp_test database")
	}

	parsedURL, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatalf("parse TEST_DATABASE_URL: %v", err)
	}
	if strings.TrimPrefix(parsedURL.Path, "/") != "ewstrp_test" {
		t.Fatal("TEST_DATABASE_URL must point to ewstrp_test, not the working database")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	store, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() {
		_ = store.DB.Close()
	})

	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	eventID := "evt-rollback-" + suffix
	incidentID := "inc-rollback-" + suffix

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()

		_, _ = store.DB.ExecContext(cleanupCtx,
			`DELETE FROM incident_events WHERE incident_id = $1 OR event_id = $2`,
			incidentID, eventID)
		_, _ = store.DB.ExecContext(cleanupCtx,
			`DELETE FROM incidents WHERE incident_id = $1`, incidentID)
		_, _ = store.DB.ExecContext(cleanupCtx,
			`DELETE FROM events WHERE event_id = $1`, eventID)
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

	if err := store.InsertEvent(ctx, event); err != nil {
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

	// The duplicate link should fail after the incident and first link
	// have been attempted inside the transaction.
	err = store.InsertIncident(ctx, incident)
	if err == nil {
		t.Fatal("expected duplicate event link to fail, got nil")
	}

	var incidentExists bool
	err = store.DB.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM incidents WHERE incident_id = $1)`,
		incidentID,
	).Scan(&incidentExists)
	if err != nil {
		t.Fatalf("check incident after rollback: %v", err)
	}
	if incidentExists {
		t.Fatal("incident remains in database after failed transaction")
	}

	var linkCount int
	err = store.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM incident_events WHERE incident_id = $1`,
		incidentID,
	).Scan(&linkCount)
	if err != nil {
		t.Fatalf("check event links after rollback: %v", err)
	}
	if linkCount != 0 {
		t.Fatalf("expected zero event links after rollback, got %d", linkCount)
	}

	t.Log("transaction rollback verified: no incident or event links remain")
}
