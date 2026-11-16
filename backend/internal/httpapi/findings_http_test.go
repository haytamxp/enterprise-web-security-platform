package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/auth"
	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/contract"
	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/storage"
)

func newFindingsHTTPTestSetup(
	t *testing.T,
) (http.Handler, *auth.TokenManager) {
	t.Helper()

	tokens, err := auth.NewTokenManager(
		strings.Repeat("findings-http-test-secret-", 2),
		"findings-http-test",
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("create token manager: %v", err)
	}

	mux := http.NewServeMux()

	// A database-less Store is intentional. Unit tests must stop
	// at authentication, authorization, or validation.
	RegisterFindings(mux, &storage.Store{}, tokens)

	return mux, tokens
}

func issueFindingsHTTPTestToken(
	t *testing.T,
	tokens *auth.TokenManager,
	role string,
	tenantID string,
) string {
	t.Helper()

	token, _, err := tokens.Issue(
		"findings-http-test-user",
		tenantID,
		role,
	)
	if err != nil {
		t.Fatalf("issue JWT for role %q: %v", role, err)
	}

	return token
}

func performFindingsHTTPRequest(
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

func validFindingsHTTPPayload(tenantID string) string {
	return fmt.Sprintf(`{
"schema_version": "1.0",
"finding_id": "http-test-finding",
"asset_id": "http-test-asset",
"tenant_id": %q,
"source": "p1_offensive",
"title": "HTTP Test Finding",
"description": "Synthetic test finding",
"status": "detected",
"severity": "high",
"confidence": 0.95,
"cvss": {
"version": "4.0",
"score": 8.1
},
"cwe_ids": ["CWE-89"],
"references": ["https://example.test/advisory"],
"evidence_refs": [
{
"evidence_id": "http-test-evidence",
"classification": "restricted",
"redacted": true,
"storage_ref": "evidence://private/internal-object"
}
],
"detected_at": "2026-11-04T10:00:00Z"
}`, tenantID)
}

func TestFindingsHTTPRequiresAuthentication(t *testing.T) {
	handler, _ := newFindingsHTTPTestSetup(t)

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{
			name:   "create finding",
			method: http.MethodPost,
			path:   "/api/v1/findings",
		},
		{
			name:   "list findings",
			method: http.MethodGet,
			path:   "/api/v1/findings",
		},
		{
			name:   "get finding",
			method: http.MethodGet,
			path:   "/api/v1/findings/http-test-finding",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := performFindingsHTTPRequest(
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

func TestFindingsHTTPCreateRequiresReviewPermission(t *testing.T) {
	handler, tokens := newFindingsHTTPTestSetup(t)

	// These roles can read findings but cannot create them.
	deniedRoles := []string{
		auth.RoleViewer,
		auth.RoleResponder,
	}

	for _, role := range deniedRoles {
		t.Run("denied_"+role, func(t *testing.T) {
			token := issueFindingsHTTPTestToken(
				t,
				tokens,
				role,
				assetsTestTenantA,
			)

			response := performFindingsHTTPRequest(
				handler,
				http.MethodPost,
				"/api/v1/findings",
				"{}",
				token,
			)

			if response.Code != http.StatusForbidden {
				t.Fatalf(
					"expected 403 for role %q, got %d: %s",
					role,
					response.Code,
					response.Body.String(),
				)
			}
		})
	}

	// Admin and Analyst have findings:review.
	// An invalid payload should reach validation and return 400,
	// proving that authorization was successful without using the DB.
	allowedRoles := []string{
		auth.RoleAdmin,
		auth.RoleAnalyst,
	}

	for _, role := range allowedRoles {
		t.Run("allowed_"+role, func(t *testing.T) {
			token := issueFindingsHTTPTestToken(
				t,
				tokens,
				role,
				assetsTestTenantA,
			)

			response := performFindingsHTTPRequest(
				handler,
				http.MethodPost,
				"/api/v1/findings",
				"{}",
				token,
			)

			if response.Code != http.StatusBadRequest {
				t.Fatalf(
					"expected 400 after successful authorization for role %q, got %d: %s",
					role,
					response.Code,
					response.Body.String(),
				)
			}
		})
	}
}

func TestFindingsHTTPReadPermissionAllowsAuthorizedRoles(t *testing.T) {
	handler, tokens := newFindingsHTTPTestSetup(t)

	roles := []string{
		auth.RoleAdmin,
		auth.RoleAnalyst,
		auth.RoleResponder,
		auth.RoleViewer,
	}

	for _, role := range roles {
		t.Run(role, func(t *testing.T) {
			token := issueFindingsHTTPTestToken(
				t,
				tokens,
				role,
				assetsTestTenantA,
			)

			// Invalid limit returns 400 only after read authorization succeeds.
			response := performFindingsHTTPRequest(
				handler,
				http.MethodGet,
				"/api/v1/findings?limit=0",
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

func TestFindingsHTTPCreateRejectsInvalidPayload(t *testing.T) {
	handler, tokens := newFindingsHTTPTestSetup(t)

	token := issueFindingsHTTPTestToken(
		t,
		tokens,
		auth.RoleAdmin,
		assetsTestTenantA,
	)

	response := performFindingsHTTPRequest(
		handler,
		http.MethodPost,
		"/api/v1/findings",
		"{}",
		token,
	)

	if response.Code != http.StatusBadRequest {
		t.Fatalf(
			"expected 400 for invalid Finding payload, got %d: %s",
			response.Code,
			response.Body.String(),
		)
	}
}

func TestFindingsHTTPCreateRejectsInvalidTenantUUID(t *testing.T) {
	handler, tokens := newFindingsHTTPTestSetup(t)

	token := issueFindingsHTTPTestToken(
		t,
		tokens,
		auth.RoleAdmin,
		assetsTestTenantA,
	)

	response := performFindingsHTTPRequest(
		handler,
		http.MethodPost,
		"/api/v1/findings",
		validFindingsHTTPPayload("not-a-uuid"),
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

func TestFindingsHTTPCreateRejectsTenantMismatch(t *testing.T) {
	handler, tokens := newFindingsHTTPTestSetup(t)

	token := issueFindingsHTTPTestToken(
		t,
		tokens,
		auth.RoleAdmin,
		assetsTestTenantA,
	)

	response := performFindingsHTTPRequest(
		handler,
		http.MethodPost,
		"/api/v1/findings",
		validFindingsHTTPPayload(assetsTestTenantB),
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

func TestFindingsHTTPListRejectsMalformedPagination(t *testing.T) {
	handler, tokens := newFindingsHTTPTestSetup(t)

	token := issueFindingsHTTPTestToken(
		t,
		tokens,
		auth.RoleViewer,
		assetsTestTenantA,
	)

	response := performFindingsHTTPRequest(
		handler,
		http.MethodGet,
		"/api/v1/findings?after_id=not-an-integer",
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

func TestFindingResponseDoesNotExposeStorageRef(t *testing.T) {
	storageRef := "evidence://private/internal-object"

	record := storage.FindingRecord{
		Finding: contract.Finding{
			SchemaVersion: "1.0",
			FindingID:     "response-test",
			AssetID:       "asset-response-test",
			Source:        "manual",
			Title:         "Response test",
			Status:        "detected",
			Severity:      "low",
			Confidence:    0.5,
			EvidenceRefs: []contract.FindingEvidenceReference{
				{
					EvidenceID:     "evidence-response-test",
					Classification: "restricted",
					Redacted:       true,
					StorageRef:     &storageRef,
				},
			},
			CWEIDs:                []string{},
			References:            []string{},
			ReferencesToIncidents: []string{},
		},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	response := findingToResponse(record)

	body, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal Finding response: %v", err)
	}

	if strings.Contains(string(body), "storage_ref") {
		t.Fatal("Finding response must not expose storage_ref")
	}

	if strings.Contains(string(body), storageRef) {
		t.Fatal("Finding response exposed the internal evidence storage reference")
	}

	if !strings.Contains(string(body), "evidence_id") {
		t.Fatal("expected safe evidence metadata to remain in the response")
	}
}
