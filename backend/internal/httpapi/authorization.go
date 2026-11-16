package httpapi

import (
	"net/http"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/authz"
)

// AuthorizationMiddleware requires an authenticated principal with the
// requested permission. AuthMiddleware must run before this middleware.
func AuthorizationMiddleware(
	permission authz.Permission,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := PrincipalFromContext(r.Context())

		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "authentication required",
			})
			return
		}

		if !authz.HasPermission(principal.Role, permission) {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "insufficient permissions",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}
