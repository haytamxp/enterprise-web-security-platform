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

// makeAssetStorageTestAsset creates a valid Asset through the contract validator.
func makeAssetStorageTestAsset(
	t *testing.T,
	tenantID string,
	assetID string,
) contract.Asset {
	t.Helper()

	payload := map[string]any{
		"schema_version": contract.SchemaVersion,
		"asset_id":       assetID,
		"tenant_id":      tenantID,
		"name":           "M4 Integration Test Asset " + assetID,
		"asset_type":     "web_application",
		"environment":    "test",
		"owner_team":     "p3-integration-tests",
		"criticality":    "medium",
		"authorization": map[string]any{
			"status":           "pending",
			"allowed_targets":  []string{"https://example.test"},
			"excluded_targets": []string{},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal asset fixture: %v", err)
	}

	var request contract.AssetRequest

	if err := json.Unmarshal(body, &request); err != nil {
		t.Fatalf("decode asset fixture: %v", err)
	}

	asset, fieldErrors := request.Validate()

	if len(fieldErrors) > 0 {
		t.Fatalf("asset fixture failed contract validation: %+v", fieldErrors)
	}

	return asset
}

func TestInsertAssetRequiresTenant(t *testing.T) {
	store := &Store{}

	_, err := store.InsertAsset(
		context.Background(),
		"",
		contract.Asset{},
	)

	if !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("expected ErrTenantRequired, got %v", err)
	}
}

func TestInsertAssetRejectsTenantMismatch(t *testing.T) {
	store := &Store{}

	asset := contract.Asset{
		TenantID: "body-tenant",
	}

	_, err := store.InsertAsset(
		context.Background(),
		"authenticated-tenant",
		asset,
	)

	if !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("expected ErrTenantMismatch, got %v", err)
	}
}

func TestGetAssetByIDRequiresTenant(t *testing.T) {
	store := &Store{}

	_, err := store.GetAssetByID(
		context.Background(),
		"",
		"asset-test",
	)

	if !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("expected ErrTenantRequired, got %v", err)
	}
}

func TestGetAssetByIDRejectsEmptyAssetID(t *testing.T) {
	store := &Store{}

	_, err := store.GetAssetByID(
		context.Background(),
		"tenant-placeholder",
		" ",
	)

	if !errors.Is(err, ErrAssetNotFound) {
		t.Fatalf("expected ErrAssetNotFound, got %v", err)
	}
}

func TestListAssetsRequiresTenant(t *testing.T) {
	store := &Store{}

	_, _, err := store.ListAssets(
		context.Background(),
		"",
		0,
		10,
	)

	if !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("expected ErrTenantRequired, got %v", err)
	}
}

func TestListAssetsRejectsInvalidPagination(t *testing.T) {
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
			limit:   maxAssetPageSize + 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &Store{}

			_, _, err := store.ListAssets(
				context.Background(),
				"tenant-placeholder",
				test.afterID,
				test.limit,
			)

			if !errors.Is(err, ErrInvalidPagination) {
				t.Fatalf("expected ErrInvalidPagination, got %v", err)
			}
		})
	}
}

func TestAssetStorageIntegration(t *testing.T) {
	store, ctx := openTenantIngestTestStore(t)

	var tenantA string

	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	prefix := "m4-assets-" + suffix

	tenantSlug := "m4-assets-tenant-" + suffix

	if err := store.DB.QueryRowContext(ctx, `
INSERT INTO tenants (name, slug)
VALUES ($1, $2)
RETURNING tenant_id::text
`,
		"M4 Asset Integration Test A",
		tenantSlug+"-a",
	).Scan(&tenantA); err != nil {
		t.Fatalf("create first test tenant: %v", err)
	}

	var tenantB string

	err := store.DB.QueryRowContext(ctx, `
INSERT INTO tenants (name, slug)
VALUES ($1, $2)
RETURNING tenant_id::text
`,
		"M4 Asset Integration Test B",
		tenantSlug+"-b",
	).Scan(&tenantB)

	if err != nil {
		t.Fatalf("create second test tenant: %v", err)
	}

	// Remove only records created by this integration test.
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		defer cancel()

		_, err := store.DB.ExecContext(
			cleanupCtx,
			`DELETE FROM assets WHERE asset_id LIKE $1`,
			prefix+"%",
		)
		if err != nil {
			t.Errorf("cleanup test assets: %v", err)
		}

		_, err = store.DB.ExecContext(
			cleanupCtx,
			`DELETE FROM tenants WHERE tenant_id IN ($1::uuid, $2::uuid)`,
			tenantA,
			tenantB,
		)
		if err != nil {
			t.Errorf("cleanup test tenants: %v", err)
		}
	})

	// ---------------------------------------------------------
	// 1. Insert three assets into Tenant A.
	// ---------------------------------------------------------

	assetIDs := []string{
		prefix + "-a1",
		prefix + "-a2",
		prefix + "-a3",
	}

	inserted := make([]AssetRecord, 0, len(assetIDs))

	for _, assetID := range assetIDs {
		asset := makeAssetStorageTestAsset(t, tenantA, assetID)

		record, err := store.InsertAsset(ctx, tenantA, asset)
		if err != nil {
			t.Fatalf("insert asset %s: %v", assetID, err)
		}

		if record.ID <= 0 {
			t.Fatalf("expected a positive database ID, got %d", record.ID)
		}

		if record.Asset.AssetID != assetID {
			t.Fatalf(
				"expected asset ID %q, got %q",
				assetID,
				record.Asset.AssetID,
			)
		}

		if record.Asset.CreatedAt == nil || record.Asset.UpdatedAt == nil {
			t.Fatal("expected database timestamps to be returned")
		}

		inserted = append(inserted, record)
	}

	// ---------------------------------------------------------
	// 2. Duplicate asset IDs must be rejected.
	// ---------------------------------------------------------

	duplicate := makeAssetStorageTestAsset(t, tenantA, assetIDs[0])

	err = func() error {
		_, insertErr := store.InsertAsset(ctx, tenantA, duplicate)
		return insertErr
	}()

	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("expected ErrDuplicate, got %v", err)
	}

	// ---------------------------------------------------------
	// 3. Retrieve an asset belonging to Tenant A.
	// ---------------------------------------------------------

	retrieved, err := store.GetAssetByID(ctx, tenantA, assetIDs[0])
	if err != nil {
		t.Fatalf("get asset belonging to Tenant A: %v", err)
	}

	if retrieved.Asset.AssetID != assetIDs[0] {
		t.Fatalf(
			"expected asset %q, got %q",
			assetIDs[0],
			retrieved.Asset.AssetID,
		)
	}

	// ---------------------------------------------------------
	// 4. Insert one separate asset into Tenant B.
	// ---------------------------------------------------------

	tenantBAssetID := prefix + "-b1"
	tenantBAsset := makeAssetStorageTestAsset(t, tenantB, tenantBAssetID)

	_, err = store.InsertAsset(ctx, tenantB, tenantBAsset)
	if err != nil {
		t.Fatalf("insert asset into Tenant B: %v", err)
	}

	// Tenant B must not be able to retrieve Tenant A's asset.
	_, err = store.GetAssetByID(ctx, tenantB, assetIDs[0])

	if !errors.Is(err, ErrAssetNotFound) {
		t.Fatalf(
			"expected ErrAssetNotFound for cross-tenant read, got %v",
			err,
		)
	}

	// ---------------------------------------------------------
	// 5. Test keyset pagination for Tenant A.
	// ---------------------------------------------------------

	firstPage, hasMore, err := store.ListAssets(ctx, tenantA, 0, 2)
	if err != nil {
		t.Fatalf("get first asset page: %v", err)
	}

	if len(firstPage) != 2 {
		t.Fatalf("expected 2 assets on first page, got %d", len(firstPage))
	}

	if !hasMore {
		t.Fatal("expected hasMore=true after the first page")
	}

	if firstPage[0].Asset.AssetID != assetIDs[0] ||
		firstPage[1].Asset.AssetID != assetIDs[1] {
		t.Fatalf("unexpected first page order: %+v", firstPage)
	}

	lastID := firstPage[len(firstPage)-1].ID

	secondPage, hasMore, err := store.ListAssets(ctx, tenantA, lastID, 2)
	if err != nil {
		t.Fatalf("get second asset page: %v", err)
	}

	if len(secondPage) != 1 {
		t.Fatalf("expected 1 asset on second page, got %d", len(secondPage))
	}

	if hasMore {
		t.Fatal("expected hasMore=false after the second page")
	}

	if secondPage[0].Asset.AssetID != assetIDs[2] {
		t.Fatalf(
			"expected %q on second page, got %q",
			assetIDs[2],
			secondPage[0].Asset.AssetID,
		)
	}

	// ---------------------------------------------------------
	// 6. Verify Tenant B sees only its own asset.
	// ---------------------------------------------------------

	tenantBRecords, tenantBHasMore, err := store.ListAssets(
		ctx,
		tenantB,
		0,
		10,
	)
	if err != nil {
		t.Fatalf("list Tenant B assets: %v", err)
	}

	if len(tenantBRecords) != 1 {
		t.Fatalf(
			"expected Tenant B to see exactly 1 asset, got %d",
			len(tenantBRecords),
		)
	}

	if tenantBHasMore {
		t.Fatal("expected Tenant B hasMore=false")
	}

	if tenantBRecords[0].Asset.AssetID != tenantBAssetID {
		t.Fatalf(
			"Tenant B returned an unexpected asset: %q",
			tenantBRecords[0].Asset.AssetID,
		)
	}
}
