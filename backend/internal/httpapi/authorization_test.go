package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/auth"
	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/authz"
)

func newAuthorizationTestTokenManager(t *testing.T) *auth.TokenManager {
	t.Helper()

	manager, err := auth.NewTokenManager(
		strings.Repeat("test-secret-", 4),
		"authorization-test",
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("create token manager: %v", err)
	}

	return manager
}

func issueAuthorizationTestToken(
	t *testing.T,
	manager *auth.TokenManager,
	role string,
) string {
	t.Helper()

	token, _, err := manager.Issue("test-user-id", "00000000-0000-4000-8000-000000000001", role)
	if err != nil {
		t.Fatalf("issue token for role %q: %v", role, err)
	}

	return token
}

func TestAuthorizationMiddlewareEnforcesRolePermissions(t *testing.T) {
	tokens := newAuthorizationTestTokenManager(t)

	tests := []struct {
		name       string
		role       string
		permission authz.Permission
		wantStatus int
	}{
		{
			name:       "admin can manage users",
			role:       auth.RoleAdmin,
			permission: authz.PermissionUsersManage,
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "analyst can triage incidents",
			role:       auth.RoleAnalyst,
			permission: authz.PermissionIncidentsTriage,
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "responder can execute remediation",
			role:       auth.RoleResponder,
			permission: authz.PermissionRemediationExecute,
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "viewer can read assets",
			role:       auth.RoleViewer,
			permission: authz.PermissionAssetsRead,
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "viewer cannot manage users",
			role:       auth.RoleViewer,
			permission: authz.PermissionUsersManage,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "analyst cannot respond to incidents",
			role:       auth.RoleAnalyst,
			permission: authz.PermissionIncidentsRespond,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "responder cannot triage incidents",
			role:       auth.RoleResponder,
			permission: authz.PermissionIncidentsTriage,
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := issueAuthorizationTestToken(t, tokens, tt.role)

			nextCalled := false

			protectedHandler := http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					nextCalled = true
					w.WriteHeader(http.StatusNoContent)
				},
			)

			handler := AuthMiddleware(
				tokens,
				AuthorizationMiddleware(tt.permission, protectedHandler),
			)

			request := httptest.NewRequest(http.MethodGet, "/protected", nil)
			request.Header.Set("Authorization", "Bearer "+token)

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf(
					"expected status %d, got %d; body=%s",
					tt.wantStatus,
					response.Code,
					response.Body.String(),
				)
			}

			wantNextCalled := tt.wantStatus == http.StatusNoContent

			if nextCalled != wantNextCalled {
				t.Fatalf(
					"next handler called = %v; want %v",
					nextCalled,
					wantNextCalled,
				)
			}
		})
	}
}

func TestAuthorizationMiddlewareRequiresAuthentication(t *testing.T) {
	nextCalled := false

	protectedHandler := http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusNoContent)
		},
	)

	handler := AuthorizationMiddleware(
		authz.PermissionUsersManage,
		protectedHandler,
	)

	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf(
			"expected status 401, got %d",
			response.Code,
		)
	}

	if response.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatal("expected WWW-Authenticate: Bearer")
	}

	if nextCalled {
		t.Fatal("protected handler must not run without authentication")
	}
}

func TestAuthorizationMiddlewareRejectsInvalidBearerToken(t *testing.T) {
	tokens := newAuthorizationTestTokenManager(t)

	handler := AuthMiddleware(
		tokens,
		AuthorizationMiddleware(
			authz.PermissionUsersManage,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fatal("protected handler must not run with an invalid token")
			}),
		),
	)

	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer invalid-token")

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", response.Code)
	}

	if response.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatal("expected WWW-Authenticate: Bearer")
	}
}

func TestAuthorizationMiddlewareIgnoresClientSuppliedRole(t *testing.T) {
	tokens := newAuthorizationTestTokenManager(t)

	// The signed token identifies this principal as a viewer.
	token := issueAuthorizationTestToken(t, tokens, auth.RoleViewer)

	handler := AuthMiddleware(
		tokens,
		AuthorizationMiddleware(
			authz.PermissionUsersManage,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fatal("viewer must not manage users")
			}),
		),
	)

	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+token)

	// A client-controlled role header must never grant privileges.
	request.Header.Set("X-Role", "admin")

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf(
			"expected status 403 despite forged X-Role header, got %d",
			response.Code,
		)
	}
}
