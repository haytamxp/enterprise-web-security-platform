package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/auth"
)

func newHTTPTestTokenManager(t *testing.T) *auth.TokenManager {
	t.Helper()

	manager, err := auth.NewTokenManager(
		strings.Repeat("test-secret-", 4),
		"ewstrp-api",
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("create token manager: %v", err)
	}

	return manager
}

func TestAuthMiddlewareRejectsMissingToken(t *testing.T) {
	manager := newHTTPTestTokenManager(t)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("protected handler should not be called")
	})

	handler := AuthMiddleware(manager, next)

	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", response.Code)
	}

	if response.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatal("expected WWW-Authenticate Bearer header")
	}
}

func TestAuthMiddlewareRejectsInvalidScheme(t *testing.T) {
	manager := newHTTPTestTokenManager(t)

	handler := AuthMiddleware(
		manager,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("protected handler should not be called")
		}),
	)

	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Basic sometoken")

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", response.Code)
	}
}

func TestAuthMiddlewareAcceptsValidToken(t *testing.T) {
	manager := newHTTPTestTokenManager(t)

	signed, _, err := manager.Issue("test-user-123", "00000000-0000-4000-8000-000000000001", auth.RoleAnalyst)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := PrincipalFromContext(r.Context())

		if !ok {
			t.Fatal("expected principal in request context")
		}

		if principal.UserID != "test-user-123" {
			t.Fatalf("unexpected user ID: %s", principal.UserID)
		}

		if principal.Role != auth.RoleAnalyst {
			t.Fatalf("unexpected role: %s", principal.Role)
		}

		w.WriteHeader(http.StatusNoContent)
	})

	handler := AuthMiddleware(manager, next)

	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+signed)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", response.Code)
	}
}
