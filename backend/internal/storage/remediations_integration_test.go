package storage

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"
)

func TestRemediationStorageIntegration(t *testing.T) {
	store, ctx := openTenantIngestTestStore(t)
	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)

	tenantA := createFindingStorageTestTenant(t, ctx, store, "M6 Remediation Tenant A", "m6-rem-a-"+suffix)
	tenantB := createFindingStorageTestTenant(t, ctx, store, "M6 Remediation Tenant B", "m6-rem-b-"+suffix)

	// Register cleanup immediately so setup failures do not leave test rows behind.
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, tenantID := range []string{tenantA, tenantB} {
			for _, statement := range []string{
				`DELETE FROM retest_results WHERE tenant_id = $1::uuid`,
				`DELETE FROM remediation_tasks WHERE tenant_id = $1::uuid`,
				`DELETE FROM findings WHERE tenant_id = $1::uuid`,
				`DELETE FROM assets WHERE tenant_id = $1::uuid`,
				`DELETE FROM users WHERE tenant_id = $1::uuid`,
				`DELETE FROM tenants WHERE tenant_id = $1::uuid`,
			} {
				if _, cleanupErr := store.DB.ExecContext(cleanupCtx, statement, tenantID); cleanupErr != nil {
					t.Errorf("cleanup Tenant %s: %v", tenantID, cleanupErr)
				}
			}
		}
	})

	userA, err := store.CreateUser(ctx, tenantA, "m6-admin-"+suffix+"@example.test", "integration-test-hash", "admin")
	if err != nil {
		t.Fatalf("create Tenant A admin: %v", err)
	}
	assigneeA, err := store.CreateUser(ctx, tenantA, "m6-assignee-"+suffix+"@example.test", "integration-test-hash", "responder")
	if err != nil {
		t.Fatalf("create Tenant A assignee: %v", err)
	}
	userB, err := store.CreateUser(ctx, tenantB, "m6-user-"+suffix+"@example.test", "integration-test-hash", "admin")
	if err != nil {
		t.Fatalf("create Tenant B admin: %v", err)
	}

	tenantAAssetID := "m6-asset-a-" + suffix
	tenantBAssetID := "m6-asset-b-" + suffix
	if _, err := store.InsertAsset(ctx, tenantA, makeAssetStorageTestAsset(t, tenantA, tenantAAssetID)); err != nil {
		t.Fatalf("insert Tenant A asset: %v", err)
	}
	if _, err := store.InsertAsset(ctx, tenantB, makeAssetStorageTestAsset(t, tenantB, tenantBAssetID)); err != nil {
		t.Fatalf("insert Tenant B asset: %v", err)
	}

	findingAID := "m6-finding-a-" + suffix
	findingA2ID := "m6-finding-a2-" + suffix
	findingBID := "m6-finding-b-" + suffix
	for _, item := range []struct{ tenantID, findingID, assetID string }{
		{tenantA, findingAID, tenantAAssetID},
		{tenantA, findingA2ID, tenantAAssetID},
		{tenantB, findingBID, tenantBAssetID},
	} {
		if _, err := store.InsertFinding(ctx, item.tenantID, makeFindingStorageTestFinding(t, item.tenantID, item.findingID, item.assetID)); err != nil {
			t.Fatalf("insert finding %s: %v", item.findingID, err)
		}
	}

	assignedTo := assigneeA.ID
	remediationID := "m6-remediation-" + suffix
	created, err := store.CreateRemediation(ctx, tenantA, userA.ID, CreateRemediationParams{
		RemediationID: remediationID,
		FindingID:     findingAID,
		Title:         "Resolve integration-test finding",
		Priority:      "high",
		AssignedTo:    &assignedTo,
	})
	if err != nil {
		t.Fatalf("create remediation: %v", err)
	}
	if created.Status != "open" || created.AssignedTo == nil || *created.AssignedTo != assigneeA.ID {
		t.Fatalf("unexpected created remediation: %+v", created)
	}

	if _, err := store.GetRemediationByID(ctx, tenantB, remediationID); !errors.Is(err, ErrRemediationNotFound) {
		t.Fatalf("expected tenant-isolated remediation lookup, got %v", err)
	}
	if _, _, err := store.ListRemediations(ctx, tenantB, 0, 10); err != nil {
		t.Fatalf("list Tenant B remediations: %v", err)
	} else if records, _, listErr := store.ListRemediations(ctx, tenantB, 0, 10); listErr != nil || len(records) != 0 {
		t.Fatalf("Tenant B should not see Tenant A remediation; records=%d err=%v", len(records), listErr)
	}

	// A user from another tenant must not be assignable.
	crossTenantAssignee := userB.ID
	_, err = store.CreateRemediation(ctx, tenantA, userA.ID, CreateRemediationParams{
		RemediationID: "m6-cross-assignee-" + suffix,
		FindingID:     findingA2ID,
		Title:         "Must reject cross-tenant assignee",
		Priority:      "medium",
		AssignedTo:    &crossTenantAssignee,
	})
	if !errors.Is(err, ErrInvalidAssignee) {
		t.Fatalf("expected ErrInvalidAssignee for cross-tenant assignee, got %v", err)
	}

	// A tenant cannot create a remediation against another tenant's finding.
	_, err = store.CreateRemediation(ctx, tenantA, userA.ID, CreateRemediationParams{
		RemediationID: "m6-cross-finding-" + suffix,
		FindingID:     findingBID,
		Title:         "Must reject cross-tenant finding",
		Priority:      "low",
	})
	if !errors.Is(err, ErrFindingNotFound) {
		t.Fatalf("expected ErrFindingNotFound for cross-tenant finding, got %v", err)
	}

	testedAt := time.Now().UTC().Add(-2 * time.Minute)
	_, err = store.CreateRetest(ctx, tenantA, assigneeA.ID, remediationID, CreateRetestParams{
		RetestID:     "m6-retest-inconclusive-" + suffix,
		Status:       "inconclusive",
		Summary:      "The result needs additional evidence.",
		EvidenceRefs: []string{"evidence-ref://m6/inconclusive"},
		TestedAt:     testedAt,
	})
	if err != nil {
		t.Fatalf("create inconclusive retest: %v", err)
	}
	current, err := store.GetRemediationByID(ctx, tenantA, remediationID)
	if err != nil || current.Status != "open" {
		t.Fatalf("inconclusive retest must leave task open; status=%q err=%v", current.Status, err)
	}

	_, err = store.CreateRetest(ctx, tenantA, assigneeA.ID, remediationID, CreateRetestParams{
		RetestID: "m6-retest-still-present-" + suffix,
		Status:   "still_present",
		Summary:  "The vulnerability is still reproducible.",
		TestedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("create still_present retest: %v", err)
	}
	current, err = store.GetRemediationByID(ctx, tenantA, remediationID)
	if err != nil || current.Status != "in_progress" {
		t.Fatalf("still_present retest must return task to in_progress; status=%q err=%v", current.Status, err)
	}

	_, err = store.CreateRetest(ctx, tenantA, assigneeA.ID, remediationID, CreateRetestParams{
		RetestID: "m6-retest-fixed-" + suffix,
		Status:   "fixed",
		Summary:  "The vulnerability is no longer reproducible.",
		TestedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("create fixed retest: %v", err)
	}
	current, err = store.GetRemediationByID(ctx, tenantA, remediationID)
	if err != nil || current.Status != "completed" || current.CompletedAt == nil {
		t.Fatalf("fixed retest must complete task; task=%+v err=%v", current, err)
	}

	// Completed tasks are terminal: a later failing retest must be rejected.
	_, err = store.CreateRetest(ctx, tenantA, assigneeA.ID, remediationID, CreateRetestParams{
		RetestID: "m6-retest-after-completion-" + suffix,
		Status:   "still_present",
		Summary:  "This result must not reopen a completed task.",
		TestedAt: time.Now().UTC(),
	})
	if !errors.Is(err, ErrInvalidRemediationState) {
		t.Fatalf("expected ErrInvalidRemediationState after completion, got %v", err)
	}

	retests, err := store.ListRetests(ctx, tenantA, remediationID)
	if err != nil {
		t.Fatalf("list Tenant A retests: %v", err)
	}
	if len(retests) != 3 {
		t.Fatalf("expected exactly 3 persisted retests (rejected retest must roll back), got %d", len(retests))
	}
	if _, err := store.ListRetests(ctx, tenantB, remediationID); !errors.Is(err, ErrRemediationNotFound) {
		t.Fatalf("expected cross-tenant retest list to be hidden, got %v", err)
	}

	var findingStatus string
	if err := store.DB.QueryRowContext(ctx, `SELECT status FROM findings WHERE tenant_id = $1::uuid AND finding_id = $2`, tenantA, findingAID).Scan(&findingStatus); err != nil {
		t.Fatalf("read final finding status: %v", err)
	}
	if findingStatus != "retest_passed" {
		t.Fatalf("expected finding status retest_passed, got %q", findingStatus)
	}

	t.Log(fmt.Sprintf("M6 integration passed for remediation %s", remediationID))
}
