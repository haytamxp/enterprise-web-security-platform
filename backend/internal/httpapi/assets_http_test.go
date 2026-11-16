package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/auth"
	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/storage"
)

const (
	assetsTestTenantA = "00000000-0000-4000-8000-000000000001"
	assetsTestTenantB = "00000000-0000-4000-8000-000000000002"
)

func newAssetsHTTPTestSetup(
	t *testing.T,
) (http.Handler, *auth.TokenManager) {
	t.Helper()

	tokens, err := auth.NewTokenManager(
		strings.Repeat("assets-http-test-secret-", 2),
		"assets-http-test",
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("create token manager: %v", err)
	}

	mux := http.NewServeMux()

	// The Store has no DB connection intentionally.
	// These tests must stop before any database operation.
	RegisterAssets(mux, &storage.Store{}, tokens)

	return mux, tokens
}

func issueAssetsHTTPTestToken(
	t *testing.T,
	tokens *auth.TokenManager,
	role string,
	tenantID string,
) string {
	t.Helper()

	token, _, err := tokens.Issue(
		"assets-http-test-user",
		tenantID,
		role,
	)
	if err != nil {
		t.Fatalf("issue JWT for role %q: %v", role, err)
	}

	return token
}

func performAssetsHTTPRequest(
	handler http.Handler,
	method string,
	target string,
	body string,
	token string,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(
		method,
		target,
		strings.NewReader(body),
	)

	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	return response
}

func validAssetsHTTPPayload(tenantID string) string {
	return fmt.Sprintf(`{
"schema_version": "1.0",
"asset_id": "http-test-asset",
"tenant_id": %q,
"name": "HTTP Integration Test Asset",
"asset_type": "web_application",
"environment": "test",
"owner_team": "p3-http-tests",
"criticality": "medium",
"authorization": {
"status": "pending",
"allowed_targets": ["https://example.test"],
"excluded_targets": []
}
}`, tenantID)
}

func TestAssetsHTTPRequiresAuthentication(t *testing.T) {
	handler, _ := newAssetsHTTPTestSetup(t)

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{
			name:   "create asset",
			method: http.MethodPost,
			path:   "/api/v1/assets",
		},
		{
			name:   "list assets",
			method: http.MethodGet,
			path:   "/api/v1/assets",
		},
		{
			name:   "get asset",
			method: http.MethodGet,
			path:   "/api/v1/assets/http-test-asset",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := performAssetsHTTPRequest(
				handler,
				test.method,
				test.path,
				"",
				"",
			)

			if response.Code != http.StatusUnauthorized {
				t.Fatalf(
					"expected 401 Unauthorized, got %d: %s",
					response.Code,
					response.Body.String(),
				)
			}

			if response.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatal("expected WWW-Authenticate: Bearer")
			}
		})
	}
}

func TestAssetsHTTPCreateRequiresManagePermission(t *testing.T) {
	handler, tokens := newAssetsHTTPTestSetup(t)

	roles := []string{
		auth.RoleViewer,
		auth.RoleAnalyst,
		auth.RoleResponder,
	}

	for _, role := range roles {
		t.Run(role, func(t *testing.T) {
			token := issueAssetsHTTPTestToken(
				t,
				tokens,
				role,
				assetsTestTenantA,
			)

			response := performAssetsHTTPRequest(
				handler,
				http.MethodPost,
				"/api/v1/assets",
				"{}",
				token,
			)

			if response.Code != http.StatusForbidden {
				t.Fatalf(
					"expected 403 Forbidden for role %q, got %d: %s",
					role,
					response.Code,
					response.Body.String(),
				)
			}
		})
	}
}

func TestAssetsHTTPReadPermissionAllowsAuthorizedRoles(t *testing.T) {
	handler, tokens := newAssetsHTTPTestSetup(t)

	roles := []string{
		auth.RoleAdmin,
		auth.RoleAnalyst,
		auth.RoleResponder,
		auth.RoleViewer,
	}

	for _, role := range roles {
		t.Run(role, func(t *testing.T) {
			token := issueAssetsHTTPTestToken(
				t,
				tokens,
				role,
				assetsTestTenantA,
			)

			// limit=0 is deliberately invalid.
			// Reaching the 400 response proves authentication and
			// assets:read authorization passed before storage validation.
			response := performAssetsHTTPRequest(
				handler,
				http.MethodGet,
				"/api/v1/assets?limit=0",
				"",
				token,
			)

			if response.Code != http.StatusBadRequest {
				t.Fatalf(
					"expected 400 after successful read authorization for role %q, got %d: %s",
					role,
					response.Code,
					response.Body.String(),
				)
			}
		})
	}
}

func TestAssetsHTTPCreateRejectsInvalidPayload(t *testing.T) {
	handler, tokens := newAssetsHTTPTestSetup(t)

	token := issueAssetsHTTPTestToken(
		t,
		tokens,
		auth.RoleAdmin,
		assetsTestTenantA,
	)

	response := performAssetsHTTPRequest(
		handler,
		http.MethodPost,
		"/api/v1/assets",
		`{}`,
		token,
	)

	if response.Code != http.StatusBadRequest {
		t.Fatalf(
			"expected 400 for invalid asset payload, got %d: %s",
			response.Code,
			response.Body.String(),
		)
	}
}

func TestAssetsHTTPCreateRejectsInvalidTenantUUID(t *testing.T) {
	handler, tokens := newAssetsHTTPTestSetup(t)

	token := issueAssetsHTTPTestToken(
		t,
		tokens,
		auth.RoleAdmin,
		assetsTestTenantA,
	)

	response := performAssetsHTTPRequest(
		handler,
		http.MethodPost,
		"/api/v1/assets",
		validAssetsHTTPPayload("not-a-uuid"),
		token,
	)

	if response.Code != http.StatusBadRequest {
		t.Fatalf(
			"expected 400 for invalid tenant UUID, got %d: %s",
			response.Code,
			response.Body.String(),
		)
	}
}

func TestAssetsHTTPCreateRejectsTenantMismatch(t *testing.T) {
	handler, tokens := newAssetsHTTPTestSetup(t)

	token := issueAssetsHTTPTestToken(
		t,
		tokens,
		auth.RoleAdmin,
		assetsTestTenantA,
	)

	response := performAssetsHTTPRequest(
		handler,
		http.MethodPost,
		"/api/v1/assets",
		validAssetsHTTPPayload(assetsTestTenantB),
		token,
	)

	if response.Code != http.StatusForbidden {
		t.Fatalf(
			"expected 403 for tenant mismatch, got %d: %s",
			response.Code,
			response.Body.String(),
		)
	}
}

func TestAssetsHTTPListRejectsMalformedPagination(t *testing.T) {
	handler, tokens := newAssetsHTTPTestSetup(t)

	token := issueAssetsHTTPTestToken(
		t,
		tokens,
		auth.RoleViewer,
		assetsTestTenantA,
	)

	response := performAssetsHTTPRequest(
		handler,
		http.MethodGet,
		"/api/v1/assets?after_id=not-an-integer",
		"",
		token,
	)

	if response.Code != http.StatusBadRequest {
		t.Fatalf(
			"expected 400 for malformed after_id, got %d: %s",
			response.Code,
			response.Body.String(),
		)
	}
}

func TestCanonicalUUID(t *testing.T) {
	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{
			name:  "valid lowercase UUID",
			value: assetsTestTenantA,
			valid: true,
		},
		{
			name:  "valid uppercase UUID",
			value: strings.ToUpper(assetsTestTenantA),
			valid: true,
		},
		{
			name:  "missing hyphens",
			value: strings.ReplaceAll(assetsTestTenantA, "-", ""),
			valid: false,
		},
		{
			name:  "invalid hexadecimal character",
			value: "00000000-0000-4000-8000-00000000000z",
			valid: false,
		},
		{
			name:  "empty UUID",
			value: "",
			valid: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, valid := canonicalUUID(test.value)

			if valid != test.valid {
				t.Fatalf(
					"expected valid=%v, got valid=%v",
					test.valid,
					valid,
				)
			}
		})
	}
}
