package httpapi

import (
	"context"
	"net/http"
	"strings"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/auth"
)

type principalContextKey struct{}

type Principal struct {
	UserID   string
	TenantID string
	Role     string
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok
}

// AuthMiddleware validates the Bearer token before calling the handler.
func AuthMiddleware(tokens *auth.TokenManager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tokens == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "authentication is unavailable",
			})
			return
		}

		header := strings.TrimSpace(r.Header.Get("Authorization"))
		scheme, rawToken, found := strings.Cut(header, " ")

		if !found || scheme != "Bearer" ||
			rawToken == "" ||
			strings.ContainsAny(rawToken, " \t\r\n") {

			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "authentication required",
			})
			return
		}

		claims, err := tokens.Verify(rawToken)
		if err != nil {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "invalid or expired token",
			})
			return
		}

		principal := Principal{
			UserID:   claims.Subject,
			TenantID: claims.TenantID,
			Role:     claims.Role,
		}

		ctx := context.WithValue(r.Context(), principalContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
