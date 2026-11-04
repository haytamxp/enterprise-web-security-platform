package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/auth"
)

func performAssetIntegrationRequest(
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
		t.Fatalf("marshal HTTP request: %v", err)
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

func createAssetIntegrationPayload(
	tenantID string,
	assetID string,
) map[string]any {
	return map[string]any{
		"schema_version": "1.0",
		"asset_id":       assetID,
		"tenant_id":      tenantID,
		"name":           "M4 HTTP Integration Asset " + assetID,
		"asset_type":     "web_application",
		"environment":    "test",
		"owner_team":     "p3-http-integration",
		"criticality":    "medium",
		"authorization": map[string]any{
			"status":           "pending",
			"allowed_targets":  []string{"https://example.test"},
			"excluded_targets": []string{},
		},
	}
}

func createAssetIntegrationToken(
	t *testing.T,
	tokens *auth.TokenManager,
	userID string,
	tenantID string,
) string {
	t.Helper()

	token, _, err := tokens.Issue(
		userID,
		tenantID,
		auth.RoleAdmin,
	)
	if err != nil {
		t.Fatalf("issue integration JWT: %v", err)
	}

	return token
}

func TestAssetsHTTPPostgresTenantIsolationAndCRUD(t *testing.T) {
	store, ctx, tenantA := openHTTPConnectorTestStore(t)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	prefix := "m4-http-assets-" + suffix

	// Create a second isolated tenant.
	var tenantB string

	err := store.DB.QueryRowContext(ctx, `
INSERT INTO tenants (name, slug)
VALUES ($1, $2)
RETURNING tenant_id::text
`,
		"M4 HTTP Asset Integration Tenant",
		"m4-http-assets-tenant-"+suffix,
	).Scan(&tenantB)

	if err != nil {
		t.Fatalf("create second integration tenant: %v", err)
	}

	// Cleanup only the rows created by this test.
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
			t.Errorf("cleanup integration assets: %v", err)
		}

		_, err = store.DB.ExecContext(
			cleanupCtx,
			`DELETE FROM tenants WHERE tenant_id = $1::uuid`,
			tenantB,
		)
		if err != nil {
			t.Errorf("cleanup integration tenant: %v", err)
		}
	})

	// Configure real signed JWTs for both tenants.
	tokens, err := auth.NewTokenManager(
		strings.Repeat("assets-http-integration-secret-", 2),
		"assets-http-integration",
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("create token manager: %v", err)
	}

	handler := NewWithAuth(store, tokens)

	tokenA := createAssetIntegrationToken(
		t,
		tokens,
		"m4-http-user-a",
		tenantA,
	)

	tokenB := createAssetIntegrationToken(
		t,
		tokens,
		"m4-http-user-b",
		tenantB,
	)

	assetA1 := prefix + "-a1"
	assetA2 := prefix + "-a2"
	assetB1 := prefix + "-b1"

	// ---------------------------------------------------------
	// 1. Tenant A cannot create an asset for Tenant B.
	// ---------------------------------------------------------

	mismatchResponse := performAssetIntegrationRequest(
		t,
		handler,
		http.MethodPost,
		"/api/v1/assets",
		createAssetIntegrationPayload(tenantB, prefix+"-mismatch"),
		tokenA,
	)

	if mismatchResponse.Code != http.StatusForbidden {
		t.Fatalf(
			"expected 403 for tenant mismatch, got %d: %s",
			mismatchResponse.Code,
			mismatchResponse.Body.String(),
		)
	}

	// ---------------------------------------------------------
	// 2. Tenant A creates its first asset.
	// ---------------------------------------------------------

	createA1Response := performAssetIntegrationRequest(
		t,
		handler,
		http.MethodPost,
		"/api/v1/assets",
		createAssetIntegrationPayload(tenantA, assetA1),
		tokenA,
	)

	if createA1Response.Code != http.StatusCreated {
		t.Fatalf(
			"expected 201 when Tenant A creates asset, got %d: %s",
			createA1Response.Code,
			createA1Response.Body.String(),
		)
	}

	// ---------------------------------------------------------
	// 3. Creating the same asset again must return 409.
	// ---------------------------------------------------------

	duplicateResponse := performAssetIntegrationRequest(
		t,
		handler,
		http.MethodPost,
		"/api/v1/assets",
		createAssetIntegrationPayload(tenantA, assetA1),
		tokenA,
	)

	if duplicateResponse.Code != http.StatusConflict {
		t.Fatalf(
			"expected 409 for duplicate asset, got %d: %s",
			duplicateResponse.Code,
			duplicateResponse.Body.String(),
		)
	}

	// ---------------------------------------------------------
	// 4. Tenant A creates a second asset.
	// ---------------------------------------------------------

	createA2Response := performAssetIntegrationRequest(
		t,
		handler,
		http.MethodPost,
		"/api/v1/assets",
		createAssetIntegrationPayload(tenantA, assetA2),
		tokenA,
	)

	if createA2Response.Code != http.StatusCreated {
		t.Fatalf(
			"expected 201 for second Tenant A asset, got %d: %s",
			createA2Response.Code,
			createA2Response.Body.String(),
		)
	}

	// ---------------------------------------------------------
	// 5. Tenant A retrieves its asset.
	// ---------------------------------------------------------

	getA1Response := performAssetIntegrationRequest(
		t,
		handler,
		http.MethodGet,
		"/api/v1/assets/"+assetA1,
		nil,
		tokenA,
	)

	if getA1Response.Code != http.StatusOK {
		t.Fatalf(
			"expected 200 when Tenant A retrieves its asset, got %d: %s",
			getA1Response.Code,
			getA1Response.Body.String(),
		)
	}

	var getResult struct {
		Asset struct {
			AssetID  string `json:"asset_id"`
			TenantID string `json:"tenant_id"`
		} `json:"asset"`
	}

	if err := json.Unmarshal(getA1Response.Body.Bytes(), &getResult); err != nil {
		t.Fatalf("decode retrieved asset response: %v", err)
	}

	if getResult.Asset.AssetID != assetA1 {
		t.Fatalf(
			"expected retrieved asset %q, got %q",
			assetA1,
			getResult.Asset.AssetID,
		)
	}

	if getResult.Asset.TenantID != tenantA {
		t.Fatalf(
			"expected tenant %q in response, got %q",
			tenantA,
			getResult.Asset.TenantID,
		)
	}

	// ---------------------------------------------------------
	// 6. Tenant B creates its own asset.
	// ---------------------------------------------------------

	createB1Response := performAssetIntegrationRequest(
		t,
		handler,
		http.MethodPost,
		"/api/v1/assets",
		createAssetIntegrationPayload(tenantB, assetB1),
		tokenB,
	)

	if createB1Response.Code != http.StatusCreated {
		t.Fatalf(
			"expected 201 when Tenant B creates asset, got %d: %s",
			createB1Response.Code,
			createB1Response.Body.String(),
		)
	}

	// ---------------------------------------------------------
	// 7. Tenant B cannot retrieve Tenant A's asset.
	// ---------------------------------------------------------

	crossTenantGetResponse := performAssetIntegrationRequest(
		t,
		handler,
		http.MethodGet,
		"/api/v1/assets/"+assetA1,
		nil,
		tokenB,
	)

	if crossTenantGetResponse.Code != http.StatusNotFound {
		t.Fatalf(
			"expected 404 for cross-tenant asset retrieval, got %d: %s",
			crossTenantGetResponse.Code,
			crossTenantGetResponse.Body.String(),
		)
	}

	// Tenant A must not retrieve Tenant B's asset either.
	reverseCrossTenantResponse := performAssetIntegrationRequest(
		t,
		handler,
		http.MethodGet,
		"/api/v1/assets/"+assetB1,
		nil,
		tokenA,
	)

	if reverseCrossTenantResponse.Code != http.StatusNotFound {
		t.Fatalf(
			"expected 404 for reverse cross-tenant retrieval, got %d: %s",
			reverseCrossTenantResponse.Code,
			reverseCrossTenantResponse.Body.String(),
		)
	}

	// ---------------------------------------------------------
	// 8. Tenant A list must not contain Tenant B's asset.
	// ---------------------------------------------------------

	listAResponse := performAssetIntegrationRequest(
		t,
		handler,
		http.MethodGet,
		"/api/v1/assets?limit=100",
		nil,
		tokenA,
	)

	if listAResponse.Code != http.StatusOK {
		t.Fatalf(
			"expected 200 when Tenant A lists assets, got %d: %s",
			listAResponse.Code,
			listAResponse.Body.String(),
		)
	}

	var listAResult struct {
		Items []struct {
			AssetID  string `json:"asset_id"`
			TenantID string `json:"tenant_id"`
		} `json:"items"`
		HasMore bool `json:"has_more"`
	}

	if err := json.Unmarshal(listAResponse.Body.Bytes(), &listAResult); err != nil {
		t.Fatalf("decode Tenant A asset list: %v", err)
	}

	foundA1 := false
	foundA2 := false

	for _, item := range listAResult.Items {
		if item.AssetID == assetA1 {
			foundA1 = true
		}

		if item.AssetID == assetA2 {
			foundA2 = true
		}

		if item.AssetID == assetB1 {
			t.Fatal("Tenant A list exposed an asset belonging to Tenant B")
		}

		if strings.HasPrefix(item.AssetID, prefix) && item.TenantID != tenantA {
			t.Fatalf(
				"Tenant A list returned asset %q belonging to tenant %q",
				item.AssetID,
				item.TenantID,
			)
		}
	}

	if !foundA1 || !foundA2 {
		t.Fatalf(
			"Tenant A list did not contain both created assets: A1=%v A2=%v",
			foundA1,
			foundA2,
		)
	}

	// ---------------------------------------------------------
	// 9. Tenant B list must contain only its own test asset.
	// ---------------------------------------------------------

	listBResponse := performAssetIntegrationRequest(
		t,
		handler,
		http.MethodGet,
		"/api/v1/assets?limit=100",
		nil,
		tokenB,
	)

	if listBResponse.Code != http.StatusOK {
		t.Fatalf(
			"expected 200 when Tenant B lists assets, got %d: %s",
			listBResponse.Code,
			listBResponse.Body.String(),
		)
	}

	var listBResult struct {
		Items []struct {
			AssetID  string `json:"asset_id"`
			TenantID string `json:"tenant_id"`
		} `json:"items"`
	}

	if err := json.Unmarshal(listBResponse.Body.Bytes(), &listBResult); err != nil {
		t.Fatalf("decode Tenant B asset list: %v", err)
	}

	if len(listBResult.Items) != 1 {
		t.Fatalf(
			"expected Tenant B to see exactly one asset, got %d",
			len(listBResult.Items),
		)
	}

	if listBResult.Items[0].AssetID != assetB1 {
		t.Fatalf(
			"expected Tenant B asset %q, got %q",
			assetB1,
			listBResult.Items[0].AssetID,
		)
	}

	if listBResult.Items[0].TenantID != tenantB {
		t.Fatalf(
			"expected Tenant B ID %q, got %q",
			tenantB,
			listBResult.Items[0].TenantID,
		)
	}
}
