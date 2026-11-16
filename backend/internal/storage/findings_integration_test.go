package storage

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/contract"
)

func makeFindingStorageTestFinding(
	t *testing.T,
	tenantID string,
	findingID string,
	assetID string,
) contract.Finding {
	t.Helper()

	timestamp := time.Now().UTC().Format(time.RFC3339Nano)

	payload := map[string]any{
		"schema_version": contract.SchemaVersion,
		"finding_id":     findingID,
		"asset_id":       assetID,
		"tenant_id":      tenantID,
		"source":         "p1_offensive",
		"title":          "M4 Integration Test Finding " + findingID,
		"description":    "",
		"status":         "detected",
		"severity":       "high",
		"confidence":     0.95,
		"cvss": map[string]any{
			"version": "4.0",
			"score":   8.1,
			"vector":  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
		},
		"cwe_ids": []string{
			"CWE-89",
			"CWE-79",
		},
		"references": []string{
			"https://example.test/security/" + findingID,
		},
		"evidence_refs": []any{
			map[string]any{
				"evidence_id":    "evidence-" + findingID,
				"classification": "restricted",
				"redacted":       true,
				"sha256":         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"storage_ref":    "evidence://vault/" + findingID,
				"media_type":     "text/plain",
			},
		},
		"remediation_guidance":    "",
		"detected_at":             timestamp,
		"last_observed_at":        timestamp,
		"deduplication_key":       "dedupe-" + findingID,
		"references_to_incidents": []string{"incident-" + findingID},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal finding fixture: %v", err)
	}

	var request contract.FindingRequest

	if err := json.Unmarshal(body, &request); err != nil {
		t.Fatalf("decode finding fixture: %v", err)
	}

	finding, fieldErrors := request.Validate()

	if len(fieldErrors) > 0 {
		t.Fatalf("finding fixture failed contract validation: %+v", fieldErrors)
	}

	return finding
}

func createFindingStorageTestTenant(
	t *testing.T,
	ctx context.Context,
	store *Store,
	name string,
	slug string,
) string {
	t.Helper()

	var tenantID string

	err := store.DB.QueryRowContext(ctx, `
INSERT INTO tenants (name, slug)
VALUES ($1, $2)
RETURNING tenant_id::text
`,
		name,
		slug,
	).Scan(&tenantID)

	if err != nil {
		t.Fatalf("create finding test tenant: %v", err)
	}

	return tenantID
}

func TestInsertFindingRequiresTenant(t *testing.T) {
	store := &Store{}

	_, err := store.InsertFinding(
		context.Background(),
		"",
		contract.Finding{},
	)

	if !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("expected ErrTenantRequired, got %v", err)
	}
}

func TestInsertFindingRejectsTenantMismatch(t *testing.T) {
	store := &Store{}

	bodyTenant := "body-tenant"

	finding := contract.Finding{
		TenantID: &bodyTenant,
	}

	_, err := store.InsertFinding(
		context.Background(),
		"authenticated-tenant",
		finding,
	)

	if !errors.Is(err, ErrFindingTenantMismatch) {
		t.Fatalf("expected ErrFindingTenantMismatch, got %v", err)
	}
}

func TestGetFindingByIDRequiresTenant(t *testing.T) {
	store := &Store{}

	_, err := store.GetFindingByID(
		context.Background(),
		"",
		"finding-test",
	)

	if !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("expected ErrTenantRequired, got %v", err)
	}
}

func TestGetFindingByIDRejectsEmptyFindingID(t *testing.T) {
	store := &Store{}

	_, err := store.GetFindingByID(
		context.Background(),
		"tenant-placeholder",
		" ",
	)

	if !errors.Is(err, ErrFindingNotFound) {
		t.Fatalf("expected ErrFindingNotFound, got %v", err)
	}
}

func TestListFindingsRequiresTenant(t *testing.T) {
	store := &Store{}

	_, _, err := store.ListFindings(
		context.Background(),
		"",
		0,
		10,
	)

	if !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("expected ErrTenantRequired, got %v", err)
	}
}

func TestListFindingsRejectsInvalidPagination(t *testing.T) {
	tests := []struct {
		name    string
		afterID int64
		limit   int
	}{
		{
			name:    "negative cursor",
			afterID: -1,
			limit:   10,
		},
		{
			name:    "zero limit",
			afterID: 0,
			limit:   0,
		},
		{
			name:    "limit above maximum",
			afterID: 0,
			limit:   maxFindingPageSize + 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &Store{}

			_, _, err := store.ListFindings(
				context.Background(),
				"tenant-placeholder",
				test.afterID,
				test.limit,
			)

			if !errors.Is(err, ErrInvalidFindingPagination) {
				t.Fatalf(
					"expected ErrInvalidFindingPagination, got %v",
					err,
				)
			}
		})
	}
}

func TestFindingStorageIntegration(t *testing.T) {
	store, ctx := openTenantIngestTestStore(t)

	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	prefix := "m4-findings-" + suffix

	tenantA := createFindingStorageTestTenant(
		t,
		ctx,
		store,
		"M4 Finding Integration Tenant A",
		"m4-findings-a-"+suffix,
	)

	tenantB := createFindingStorageTestTenant(
		t,
		ctx,
		store,
		"M4 Finding Integration Tenant B",
		"m4-findings-b-"+suffix,
	)

	// Each test tenant is isolated and contains only records created here.
	// Delete dependent Findings before Assets and Tenants.
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		defer cancel()

		for _, tenantID := range []string{tenantA, tenantB} {
			_, err := store.DB.ExecContext(
				cleanupCtx,
				`DELETE FROM findings WHERE tenant_id = $1::uuid`,
				tenantID,
			)
			if err != nil {
				t.Errorf("cleanup test findings: %v", err)
			}

			_, err = store.DB.ExecContext(
				cleanupCtx,
				`DELETE FROM assets WHERE tenant_id = $1::uuid`,
				tenantID,
			)
			if err != nil {
				t.Errorf("cleanup test assets: %v", err)
			}

			_, err = store.DB.ExecContext(
				cleanupCtx,
				`DELETE FROM tenants WHERE tenant_id = $1::uuid`,
				tenantID,
			)
			if err != nil {
				t.Errorf("cleanup test tenant: %v", err)
			}
		}
	})

	// ---------------------------------------------------------
	// 1. Create one Asset for each tenant.
	// ---------------------------------------------------------

	assetAID := prefix + "-asset-a"
	assetBID := prefix + "-asset-b"

	assetA := makeAssetStorageTestAsset(t, tenantA, assetAID)
	assetB := makeAssetStorageTestAsset(t, tenantB, assetBID)

	_, err := store.InsertAsset(ctx, tenantA, assetA)
	if err != nil {
		t.Fatalf("insert Tenant A asset: %v", err)
	}

	_, err = store.InsertAsset(ctx, tenantB, assetB)
	if err != nil {
		t.Fatalf("insert Tenant B asset: %v", err)
	}

	// ---------------------------------------------------------
	// 2. Insert three Findings into Tenant A.
	// ---------------------------------------------------------

	findingIDs := []string{
		prefix + "-finding-a1",
		prefix + "-finding-a2",
		prefix + "-finding-a3",
	}

	inserted := make([]FindingRecord, 0, len(findingIDs))

	for _, findingID := range findingIDs {
		finding := makeFindingStorageTestFinding(
			t,
			tenantA,
			findingID,
			assetAID,
		)

		record, err := store.InsertFinding(ctx, tenantA, finding)
		if err != nil {
			t.Fatalf("insert finding %s: %v", findingID, err)
		}

		if record.ID <= 0 {
			t.Fatalf("expected positive database ID, got %d", record.ID)
		}

		if record.Finding.FindingID != findingID {
			t.Fatalf(
				"expected finding ID %q, got %q",
				findingID,
				record.Finding.FindingID,
			)
		}

		if record.CreatedAt.IsZero() || record.UpdatedAt.IsZero() {
			t.Fatal("expected database timestamps to be returned")
		}

		inserted = append(inserted, record)
	}

	// ---------------------------------------------------------
	// 3. Duplicate Finding ID must be rejected in the same tenant.
	// ---------------------------------------------------------

	duplicate := makeFindingStorageTestFinding(
		t,
		tenantA,
		findingIDs[0],
		assetAID,
	)

	_, err = store.InsertFinding(ctx, tenantA, duplicate)

	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("expected ErrDuplicate, got %v", err)
	}

	// ---------------------------------------------------------
	// 4. The same external Finding ID is allowed in another tenant.
	// ---------------------------------------------------------

	sameIDInTenantB := makeFindingStorageTestFinding(
		t,
		tenantB,
		findingIDs[0],
		assetBID,
	)

	tenantBRecord, err := store.InsertFinding(
		ctx,
		tenantB,
		sameIDInTenantB,
	)
	if err != nil {
		t.Fatalf("same finding ID in Tenant B should be allowed: %v", err)
	}

	if tenantBRecord.Finding.TenantID == nil ||
		*tenantBRecord.Finding.TenantID != tenantB {
		t.Fatal("Tenant B Finding has an unexpected tenant ID")
	}

	// ---------------------------------------------------------
	// 5. A reference to an unknown Asset must be rejected.
	// ---------------------------------------------------------

	unknownAssetFinding := makeFindingStorageTestFinding(
		t,
		tenantA,
		prefix+"-unknown-asset",
		prefix+"-asset-does-not-exist",
	)

	_, err = store.InsertFinding(ctx, tenantA, unknownAssetFinding)

	if !errors.Is(err, ErrUnknownAsset) {
		t.Fatalf("expected ErrUnknownAsset, got %v", err)
	}

	// ---------------------------------------------------------
	// 6. Cross-tenant Asset reference must be rejected by PostgreSQL.
	// ---------------------------------------------------------

	crossTenantFinding := makeFindingStorageTestFinding(
		t,
		tenantA,
		prefix+"-cross-tenant-asset",
		assetBID,
	)

	_, err = store.InsertFinding(ctx, tenantA, crossTenantFinding)

	if !errors.Is(err, ErrUnknownAsset) {
		t.Fatalf(
			"expected ErrUnknownAsset for cross-tenant Asset reference, got %v",
			err,
		)
	}

	// ---------------------------------------------------------
	// 7. Retrieve a Finding and verify metadata round-trip.
	// ---------------------------------------------------------

	retrieved, err := store.GetFindingByID(
		ctx,
		tenantA,
		findingIDs[0],
	)
	if err != nil {
		t.Fatalf("get finding belonging to Tenant A: %v", err)
	}

	if retrieved.Finding.FindingID != findingIDs[0] {
		t.Fatalf("unexpected retrieved finding ID: %q", retrieved.Finding.FindingID)
	}

	if retrieved.Finding.TenantID == nil ||
		*retrieved.Finding.TenantID != tenantA {
		t.Fatal("retrieved Finding has an unexpected tenant ID")
	}

	if retrieved.Finding.CVSS == nil {
		t.Fatal("expected CVSS metadata to be returned")
	}

	if retrieved.Finding.CVSS.Version != "4.0" ||
		retrieved.Finding.CVSS.Score != 8.1 {
		t.Fatalf("unexpected CVSS metadata: %+v", retrieved.Finding.CVSS)
	}

	if retrieved.Finding.Description == nil ||
		*retrieved.Finding.Description != "" {
		t.Fatal("expected empty description to round-trip correctly")
	}

	if retrieved.Finding.RemediationGuidance == nil ||
		*retrieved.Finding.RemediationGuidance != "" {
		t.Fatal("expected empty remediation guidance to round-trip correctly")
	}

	if len(retrieved.Finding.CWEIDs) != 2 ||
		retrieved.Finding.CWEIDs[0] != "CWE-89" {
		t.Fatalf("unexpected CWE IDs: %+v", retrieved.Finding.CWEIDs)
	}

	if len(retrieved.Finding.References) != 1 {
		t.Fatalf("expected one reference, got %d", len(retrieved.Finding.References))
	}

	if len(retrieved.Finding.EvidenceRefs) != 1 {
		t.Fatalf(
			"expected one evidence reference, got %d",
			len(retrieved.Finding.EvidenceRefs),
		)
	}

	evidence := retrieved.Finding.EvidenceRefs[0]

	if evidence.EvidenceID != "evidence-"+findingIDs[0] {
		t.Fatalf("unexpected evidence ID: %q", evidence.EvidenceID)
	}

	if evidence.Classification != "restricted" || !evidence.Redacted {
		t.Fatalf("unexpected evidence metadata: %+v", evidence)
	}

	if evidence.SHA256 == nil || evidence.StorageRef == nil ||
		evidence.MediaType == nil {
		t.Fatal("expected optional evidence metadata to be preserved")
	}

	if len(retrieved.Finding.ReferencesToIncidents) != 1 {
		t.Fatal("expected incident references to be preserved")
	}

	// ---------------------------------------------------------
	// 8. Tenant B cannot retrieve Tenant A's other Findings.
	// ---------------------------------------------------------

	_, err = store.GetFindingByID(ctx, tenantB, findingIDs[1])

	if !errors.Is(err, ErrFindingNotFound) {
		t.Fatalf(
			"expected ErrFindingNotFound for cross-tenant read, got %v",
			err,
		)
	}

	// ---------------------------------------------------------
	// 9. Keyset pagination for Tenant A.
	// ---------------------------------------------------------

	firstPage, hasMore, err := store.ListFindings(
		ctx,
		tenantA,
		0,
		2,
	)
	if err != nil {
		t.Fatalf("get first Finding page: %v", err)
	}

	if len(firstPage) != 2 {
		t.Fatalf("expected 2 Findings on first page, got %d", len(firstPage))
	}

	if !hasMore {
		t.Fatal("expected hasMore=true after first Finding page")
	}

	if firstPage[0].Finding.FindingID != findingIDs[0] ||
		firstPage[1].Finding.FindingID != findingIDs[1] {
		t.Fatalf("unexpected first Finding page: %+v", firstPage)
	}

	lastID := firstPage[len(firstPage)-1].ID

	secondPage, hasMore, err := store.ListFindings(
		ctx,
		tenantA,
		lastID,
		2,
	)
	if err != nil {
		t.Fatalf("get second Finding page: %v", err)
	}

	if len(secondPage) != 1 {
		t.Fatalf("expected 1 Finding on second page, got %d", len(secondPage))
	}

	if hasMore {
		t.Fatal("expected hasMore=false after second Finding page")
	}

	if secondPage[0].Finding.FindingID != findingIDs[2] {
		t.Fatalf(
			"expected %q on second page, got %q",
			findingIDs[2],
			secondPage[0].Finding.FindingID,
		)
	}

	// ---------------------------------------------------------
	// 10. Tenant B must see only its own Finding.
	// ---------------------------------------------------------

	tenantBFindings, tenantBHasMore, err := store.ListFindings(
		ctx,
		tenantB,
		0,
		10,
	)
	if err != nil {
		t.Fatalf("list Tenant B Findings: %v", err)
	}

	if len(tenantBFindings) != 1 {
		t.Fatalf(
			"expected Tenant B to see exactly 1 Finding, got %d",
			len(tenantBFindings),
		)
	}

	if tenantBHasMore {
		t.Fatal("expected Tenant B hasMore=false")
	}

	if tenantBFindings[0].Finding.FindingID != findingIDs[0] {
		t.Fatalf(
			"Tenant B returned unexpected Finding: %q",
			tenantBFindings[0].Finding.FindingID,
		)
	}

	// Keep the inserted slice referenced to make the insertion assertions explicit.
	if len(inserted) != len(findingIDs) {
		t.Fatalf("expected %d inserted records, got %d", len(findingIDs), len(inserted))
	}
}
