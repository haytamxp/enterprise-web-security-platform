package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/auth"
	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/storage"
)

func TestResponseOrchestrationRoutesEnforceAuthenticationAndApprovalRBAC(t *testing.T) {
	tokens := newAuthorizationTestTokenManager(t)

	mux := http.NewServeMux()
	RegisterResponseOrchestration(mux, &storage.Store{}, tokens)

	tests := []struct {
		name       string
		role       string
		wantStatus int
	}{
		{
			name:       "missing bearer token",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "viewer cannot approve",
			role:       auth.RoleViewer,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "responder cannot approve",
			role:       auth.RoleResponder,
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(
				http.MethodPost,
				"/api/v1/response-approvals/approval-1/decision",
				strings.NewReader(`{}`),
			)

			if tt.role != "" {
				token := issueAuthorizationTestToken(t, tokens, tt.role)
				req.Header.Set("Authorization", "Bearer "+token)
			}

			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, req)

			if recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s",
					recorder.Code, tt.wantStatus, recorder.Body.String())
			}
		})
	}
}
