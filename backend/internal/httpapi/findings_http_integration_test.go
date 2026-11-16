package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/auth"
)

func performFindingIntegrationRequest(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
	payload any,
	token string,
) *httptest.ResponseRecorder {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal Finding HTTP request: %v", err)
	}

	request := httptest.NewRequest(
		method,
		path,
		bytes.NewReader(body),
	)

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	return response
}

func createFindingIntegrationPayload(
	tenantID string,
	assetID string,
	findingID string,
) map[string]any {
	return map[string]any{
		"schema_version": "1.0",
		"finding_id":     findingID,
		"asset_id":       assetID,
		"tenant_id":      tenantID,
		"source":         "manual",
		"title":          "M4 HTTP Integration Finding " + findingID,
		"status":         "detected",
		"severity":       "high",
		"confidence":     0.95,
		"detected_at":    time.Now().UTC().Format(time.RFC3339Nano),
		"cwe_ids":        []string{"CWE-79"},
		"references": []string{
			"https://owasp.org/Top10/A03_2021-Injection/",
		},
		"evidence_refs": []map[string]any{
			{
				"evidence_id":    "evidence-" + findingID,
				"classification": "restricted",
				"redacted":       true,
				"storage_ref":    "evidence://private/" + findingID,
				"media_type":     "text/plain",
			},
		},
		"references_to_incidents": []string{},
	}
}

func createFindingIntegrationTenant(
	t *testing.T,
	ctx context.Context,
	storeDB interface {
		QueryRowContext(
			context.Context,
			string,
			...any,
		) *sql.Row
	},
	name string,
	slug string,
) string {
	t.Helper()

	var tenantID string

	err := storeDB.QueryRowContext(
		ctx,
		`
INSERT INTO tenants (name, slug)
VALUES ($1, $2)
RETURNING tenant_id::text
`,
		name,
		slug,
	).Scan(&tenantID)

	if err != nil {
		t.Fatalf("create Finding integration tenant: %v", err)
	}

	return tenantID
}

func TestFindingsHTTPPostgresTenantIsolationCRUDAndPagination(t *testing.T) {
	store, ctx, _ := openHTTPConnectorTestStore(t)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	prefix := "m4-http-findings-" + suffix

	tenantA := createFindingIntegrationTenant(
		t,
		ctx,
		store.DB,
		"M4 Finding HTTP Integration Tenant A",
		prefix+"-tenant-a",
	)

	tenantB := createFindingIntegrationTenant(
		t,
		ctx,
		store.DB,
		"M4 Finding HTTP Integration Tenant B",
		prefix+"-tenant-b",
	)

	// Remove only the rows created by this test.
	// Findings must be deleted before their referenced assets.
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		defer cancel()

		_, err := store.DB.ExecContext(
			cleanupCtx,
			`DELETE FROM findings WHERE finding_id LIKE $1`,
			prefix+"-finding-%",
		)
		if err != nil {
			t.Errorf("cleanup integration findings: %v", err)
		}

		_, err = store.DB.ExecContext(
			cleanupCtx,
			`DELETE FROM assets WHERE asset_id LIKE $1`,
			prefix+"-asset-%",
		)
		if err != nil {
			t.Errorf("cleanup integration assets: %v", err)
		}

		_, err = store.DB.ExecContext(
			cleanupCtx,
			`
DELETE FROM tenants
WHERE tenant_id IN ($1::uuid, $2::uuid)
`,
			tenantA,
			tenantB,
		)
		if err != nil {
			t.Errorf("cleanup integration tenants: %v", err)
		}
	})

	// Use the real JWT middleware and production HTTP router.
	tokens, err := auth.NewTokenManager(
		strings.Repeat("findings-http-integration-secret-", 2),
		"findings-http-integration",
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("create Finding integration token manager: %v", err)
	}

	handler := NewWithAuth(store, tokens)

	tokenA := createAssetIntegrationToken(
		t,
		tokens,
		"m4-findings-user-a",
		tenantA,
	)

	tokenB := createAssetIntegrationToken(
		t,
		tokens,
		"m4-findings-user-b",
		tenantB,
	)

	assetA := prefix + "-asset-a"
	assetB := prefix + "-asset-b"

	findingA1 := prefix + "-finding-a1"
	findingA2 := prefix + "-finding-a2"
	findingA3 := prefix + "-finding-a3"

	// ---------------------------------------------------------
	// 1. Create one Asset for each tenant through the HTTP API.
	// ---------------------------------------------------------

	createAssetAResponse := performAssetIntegrationRequest(
		t,
		handler,
		http.MethodPost,
		"/api/v1/assets",
		createAssetIntegrationPayload(tenantA, assetA),
		tokenA,
	)

	if createAssetAResponse.Code != http.StatusCreated {
		t.Fatalf(
			"expected 201 when Tenant A creates its asset, got %d: %s",
			createAssetAResponse.Code,
			createAssetAResponse.Body.String(),
		)
	}

	createAssetBResponse := performAssetIntegrationRequest(
		t,
		handler,
		http.MethodPost,
		"/api/v1/assets",
		createAssetIntegrationPayload(tenantB, assetB),
		tokenB,
	)

	if createAssetBResponse.Code != http.StatusCreated {
		t.Fatalf(
			"expected 201 when Tenant B creates its asset, got %d: %s",
			createAssetBResponse.Code,
			createAssetBResponse.Body.String(),
		)
	}

	// ---------------------------------------------------------
	// 2. Reject a Finding whose tenant_id differs from the JWT.
	// ---------------------------------------------------------

	tenantMismatchResponse := performFindingIntegrationRequest(
		t,
		handler,
		http.MethodPost,
		"/api/v1/findings",
		createFindingIntegrationPayload(
			tenantB,
			assetA,
			prefix+"-finding-tenant-mismatch",
		),
		tokenA,
	)

	if tenantMismatchResponse.Code != http.StatusForbidden {
		t.Fatalf(
			"expected 403 for Finding tenant mismatch, got %d: %s",
			tenantMismatchResponse.Code,
			tenantMismatchResponse.Body.String(),
		)
	}

	// ---------------------------------------------------------
	// 3. Reject a reference to an unknown Asset.
	// ---------------------------------------------------------

	unknownAssetResponse := performFindingIntegrationRequest(
		t,
		handler,
		http.MethodPost,
		"/api/v1/findings",
		createFindingIntegrationPayload(
			tenantA,
			prefix+"-asset-does-not-exist",
			prefix+"-finding-unknown-asset",
		),
		tokenA,
	)

	if unknownAssetResponse.Code != http.StatusNotFound {
		t.Fatalf(
			"expected 404 for unknown Asset, got %d: %s",
			unknownAssetResponse.Code,
			unknownAssetResponse.Body.String(),
		)
	}

	// ---------------------------------------------------------
	// 4. Reject Tenant A referencing Tenant B's Asset.
	// ---------------------------------------------------------

	crossTenantAssetResponse := performFindingIntegrationRequest(
		t,
		handler,
		http.MethodPost,
		"/api/v1/findings",
		createFindingIntegrationPayload(
			tenantA,
			assetB,
			prefix+"-finding-cross-tenant-asset",
		),
		tokenA,
	)

	if crossTenantAssetResponse.Code != http.StatusNotFound {
		t.Fatalf(
			"expected 404 for cross-tenant Asset reference, got %d: %s",
			crossTenantAssetResponse.Code,
			crossTenantAssetResponse.Body.String(),
		)
	}

	// ---------------------------------------------------------
	// 5. Tenant A creates its first Finding.
	// ---------------------------------------------------------

	createA1Response := performFindingIntegrationRequest(
		t,
		handler,
		http.MethodPost,
		"/api/v1/findings",
		createFindingIntegrationPayload(tenantA, assetA, findingA1),
		tokenA,
	)

	if createA1Response.Code != http.StatusCreated {
		t.Fatalf(
			"expected 201 when Tenant A creates Finding A1, got %d: %s",
			createA1Response.Code,
			createA1Response.Body.String(),
		)
	}

	// The API must return safe evidence metadata without storage_ref.
	if strings.Contains(createA1Response.Body.String(), "storage_ref") {
		t.Fatal("Finding creation response exposed storage_ref")
	}

	if strings.Contains(
		createA1Response.Body.String(),
		"evidence://private/",
	) {
		t.Fatal("Finding creation response exposed the private evidence location")
	}

	var createResult struct {
		Stored  bool `json:"stored"`
		Finding struct {
			FindingID    string `json:"finding_id"`
			TenantID     string `json:"tenant_id"`
			EvidenceRefs []struct {
				EvidenceID string `json:"evidence_id"`
			} `json:"evidence_refs"`
		} `json:"finding"`
	}

	if err := json.Unmarshal(
		createA1Response.Body.Bytes(),
		&createResult,
	); err != nil {
		t.Fatalf("decode Finding creation response: %v", err)
	}

	if !createResult.Stored {
		t.Fatal("expected stored=true in Finding creation response")
	}

	if createResult.Finding.FindingID != findingA1 {
		t.Fatalf(
			"expected Finding ID %q, got %q",
			findingA1,
			createResult.Finding.FindingID,
		)
	}

	if createResult.Finding.TenantID != tenantA {
		t.Fatalf(
			"expected Tenant A ID %q, got %q",
			tenantA,
			createResult.Finding.TenantID,
		)
	}

	if len(createResult.Finding.EvidenceRefs) != 1 {
		t.Fatalf(
			"expected one safe evidence reference, got %d",
			len(createResult.Finding.EvidenceRefs),
		)
	}

	// ---------------------------------------------------------
	// 6. Duplicate Finding ID in the same tenant must return 409.
	// ---------------------------------------------------------

	duplicateResponse := performFindingIntegrationRequest(
		t,
		handler,
		http.MethodPost,
		"/api/v1/findings",
		createFindingIntegrationPayload(tenantA, assetA, findingA1),
		tokenA,
	)

	if duplicateResponse.Code != http.StatusConflict {
		t.Fatalf(
			"expected 409 for duplicate Finding, got %d: %s",
			duplicateResponse.Code,
			duplicateResponse.Body.String(),
		)
	}

	// ---------------------------------------------------------
	// 7. Tenant A creates two more Findings for pagination.
	// ---------------------------------------------------------

	createA2Response := performFindingIntegrationRequest(
		t,
		handler,
		http.MethodPost,
		"/api/v1/findings",
		createFindingIntegrationPayload(tenantA, assetA, findingA2),
		tokenA,
	)

	if createA2Response.Code != http.StatusCreated {
		t.Fatalf(
			"expected 201 for Finding A2, got %d: %s",
			createA2Response.Code,
			createA2Response.Body.String(),
		)
	}

	createA3Response := performFindingIntegrationRequest(
		t,
		handler,
		http.MethodPost,
		"/api/v1/findings",
		createFindingIntegrationPayload(tenantA, assetA, findingA3),
		tokenA,
	)

	if createA3Response.Code != http.StatusCreated {
		t.Fatalf(
			"expected 201 for Finding A3, got %d: %s",
			createA3Response.Code,
			createA3Response.Body.String(),
		)
	}

	// ---------------------------------------------------------
	// 8. The same external Finding ID is allowed in Tenant B.
	// ---------------------------------------------------------

	createBResponse := performFindingIntegrationRequest(
		t,
		handler,
		http.MethodPost,
		"/api/v1/findings",
		createFindingIntegrationPayload(tenantB, assetB, findingA1),
		tokenB,
	)

	if createBResponse.Code != http.StatusCreated {
		t.Fatalf(
			"expected 201 when Tenant B reuses Tenant A's Finding ID, got %d: %s",
			createBResponse.Code,
			createBResponse.Body.String(),
		)
	}

	// ---------------------------------------------------------
	// 9. Tenant A retrieves its Finding.
	// ---------------------------------------------------------

	getA1Response := performFindingIntegrationRequest(
		t,
		handler,
		http.MethodGet,
		"/api/v1/findings/"+findingA1,
		nil,
		tokenA,
	)

	if getA1Response.Code != http.StatusOK {
		t.Fatalf(
			"expected 200 when Tenant A retrieves its Finding, got %d: %s",
			getA1Response.Code,
			getA1Response.Body.String(),
		)
	}

	if strings.Contains(getA1Response.Body.String(), "storage_ref") {
		t.Fatal("Finding GET response exposed storage_ref")
	}

	if strings.Contains(
		getA1Response.Body.String(),
		"evidence://private/",
	) {
		t.Fatal("Finding GET response exposed the private evidence location")
	}

	var getA1Result struct {
		Finding struct {
			FindingID string `json:"finding_id"`
			TenantID  string `json:"tenant_id"`
			AssetID   string `json:"asset_id"`
		} `json:"finding"`
	}

	if err := json.Unmarshal(
		getA1Response.Body.Bytes(),
		&getA1Result,
	); err != nil {
		t.Fatalf("decode retrieved Finding: %v", err)
	}

	if getA1Result.Finding.FindingID != findingA1 {
		t.Fatalf(
			"expected Finding ID %q, got %q",
			findingA1,
			getA1Result.Finding.FindingID,
		)
	}

	if getA1Result.Finding.TenantID != tenantA {
		t.Fatalf(
			"expected Tenant A ID %q, got %q",
			tenantA,
			getA1Result.Finding.TenantID,
		)
	}

	if getA1Result.Finding.AssetID != assetA {
		t.Fatalf(
			"expected Asset ID %q, got %q",
			assetA,
			getA1Result.Finding.AssetID,
		)
	}

	// ---------------------------------------------------------
	// 10. Tenant B cannot retrieve a Finding existing only in A.
	// ---------------------------------------------------------

	crossTenantGetResponse := performFindingIntegrationRequest(
		t,
		handler,
		http.MethodGet,
		"/api/v1/findings/"+findingA2,
		nil,
		tokenB,
	)

	if crossTenantGetResponse.Code != http.StatusNotFound {
		t.Fatalf(
			"expected 404 for cross-tenant Finding retrieval, got %d: %s",
			crossTenantGetResponse.Code,
			crossTenantGetResponse.Body.String(),
		)
	}

	// Tenant B can retrieve its own Finding with the same external ID.
	getBResponse := performFindingIntegrationRequest(
		t,
		handler,
		http.MethodGet,
		"/api/v1/findings/"+findingA1,
		nil,
		tokenB,
	)

	if getBResponse.Code != http.StatusOK {
		t.Fatalf(
			"expected 200 when Tenant B retrieves its own Finding, got %d: %s",
			getBResponse.Code,
			getBResponse.Body.String(),
		)
	}

	var getBResult struct {
		Finding struct {
			TenantID string `json:"tenant_id"`
			AssetID  string `json:"asset_id"`
		} `json:"finding"`
	}

	if err := json.Unmarshal(
		getBResponse.Body.Bytes(),
		&getBResult,
	); err != nil {
		t.Fatalf("decode Tenant B Finding: %v", err)
	}

	if getBResult.Finding.TenantID != tenantB {
		t.Fatalf(
			"expected Tenant B ID %q, got %q",
			tenantB,
			getBResult.Finding.TenantID,
		)
	}

	if getBResult.Finding.AssetID != assetB {
		t.Fatalf(
			"expected Tenant B Asset ID %q, got %q",
			assetB,
			getBResult.Finding.AssetID,
		)
	}

	// ---------------------------------------------------------
	// 11. Tenant A lists Findings using keyset pagination.
	// ---------------------------------------------------------

	type listedFinding struct {
		FindingID string `json:"finding_id"`
		TenantID  string `json:"tenant_id"`
	}

	type findingPage struct {
		Items       []listedFinding `json:"items"`
		HasMore     bool            `json:"has_more"`
		NextAfterID *int64          `json:"next_after_id"`
	}

	page1Response := performFindingIntegrationRequest(
		t,
		handler,
		http.MethodGet,
		"/api/v1/findings?limit=2",
		nil,
		tokenA,
	)

	if page1Response.Code != http.StatusOK {
		t.Fatalf(
			"expected 200 for first Finding page, got %d: %s",
			page1Response.Code,
			page1Response.Body.String(),
		)
	}

	if strings.Contains(page1Response.Body.String(), "storage_ref") {
		t.Fatal("Finding list response exposed storage_ref")
	}

	var page1 findingPage

	if err := json.Unmarshal(
		page1Response.Body.Bytes(),
		&page1,
	); err != nil {
		t.Fatalf("decode first Finding page: %v", err)
	}

	if len(page1.Items) != 2 {
		t.Fatalf(
			"expected 2 Findings in first page, got %d",
			len(page1.Items),
		)
	}

	if !page1.HasMore {
		t.Fatal("expected has_more=true for first Finding page")
	}

	if page1.NextAfterID == nil {
		t.Fatal("expected next_after_id for first Finding page")
	}

	// ---------------------------------------------------------
	// 12. Retrieve the next page using next_after_id.
	// ---------------------------------------------------------

	page2Path := fmt.Sprintf(
		"/api/v1/findings?limit=2&after_id=%d",
		*page1.NextAfterID,
	)

	page2Response := performFindingIntegrationRequest(
		t,
		handler,
		http.MethodGet,
		page2Path,
		nil,
		tokenA,
	)

	if page2Response.Code != http.StatusOK {
		t.Fatalf(
			"expected 200 for second Finding page, got %d: %s",
			page2Response.Code,
			page2Response.Body.String(),
		)
	}

	var page2 findingPage

	if err := json.Unmarshal(
		page2Response.Body.Bytes(),
		&page2,
	); err != nil {
		t.Fatalf("decode second Finding page: %v", err)
	}

	if len(page2.Items) != 1 {
		t.Fatalf(
			"expected 1 Finding in second page, got %d",
			len(page2.Items),
		)
	}

	if page2.HasMore {
		t.Fatal("expected has_more=false for second Finding page")
	}

	if page2.NextAfterID != nil {
		t.Fatal("expected next_after_id=null for final Finding page")
	}

	// Verify that pagination returned exactly Tenant A's three Findings.
	foundIDs := make(map[string]bool)

	for _, item := range page1.Items {
		if item.TenantID != tenantA {
			t.Fatalf(
				"Tenant A page returned Finding %q belonging to tenant %q",
				item.FindingID,
				item.TenantID,
			)
		}

		foundIDs[item.FindingID] = true
	}

	for _, item := range page2.Items {
		if item.TenantID != tenantA {
			t.Fatalf(
				"Tenant A page returned Finding %q belonging to tenant %q",
				item.FindingID,
				item.TenantID,
			)
		}

		foundIDs[item.FindingID] = true
	}

	for _, expectedID := range []string{
		findingA1,
		findingA2,
		findingA3,
	} {
		if !foundIDs[expectedID] {
			t.Errorf(
				"paginated results did not contain Finding %q",
				expectedID,
			)
		}
	}

	if len(foundIDs) != 3 {
		t.Fatalf(
			"expected exactly 3 unique Tenant A Findings, got %d",
			len(foundIDs),
		)
	}

	// ---------------------------------------------------------
	// 13. Tenant B's list must contain only its own Finding.
	// ---------------------------------------------------------

	listBResponse := performFindingIntegrationRequest(
		t,
		handler,
		http.MethodGet,
		"/api/v1/findings?limit=100",
		nil,
		tokenB,
	)

	if listBResponse.Code != http.StatusOK {
		t.Fatalf(
			"expected 200 when Tenant B lists Findings, got %d: %s",
			listBResponse.Code,
			listBResponse.Body.String(),
		)
	}

	var listB findingPage

	if err := json.Unmarshal(
		listBResponse.Body.Bytes(),
		&listB,
	); err != nil {
		t.Fatalf("decode Tenant B Finding list: %v", err)
	}

	if len(listB.Items) != 1 {
		t.Fatalf(
			"expected Tenant B to see exactly one Finding, got %d",
			len(listB.Items),
		)
	}

	if listB.Items[0].FindingID != findingA1 {
		t.Fatalf(
			"expected Tenant B Finding ID %q, got %q",
			findingA1,
			listB.Items[0].FindingID,
		)
	}

	if listB.Items[0].TenantID != tenantB {
		t.Fatalf(
			"expected Tenant B ID %q, got %q",
			tenantB,
			listB.Items[0].TenantID,
		)
	}
}
