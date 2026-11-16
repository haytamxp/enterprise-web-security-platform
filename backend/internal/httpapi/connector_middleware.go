package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/storage"
)

const ConnectorKeyHeader = "X-Connector-Key"

type connectorPrincipalContextKey struct{}

type ConnectorPrincipal struct {
	ConnectorID string
	TenantID    string
	Name        string
	Scopes      []string
}

func ConnectorPrincipalFromContext(
	ctx context.Context,
) (ConnectorPrincipal, bool) {
	principal, ok := ctx.Value(connectorPrincipalContextKey{}).(ConnectorPrincipal)
	return principal, ok
}

func hasConnectorScope(scopes []string, required string) bool {
	for _, scope := range scopes {
		if scope == required {
			return true
		}
	}
	return false
}

// ConnectorAuthMiddleware authenticates machine identities independently
// from human JWT authentication.
func ConnectorAuthMiddleware(
	store *storage.Store,
	requiredScope string,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if store == nil || store.DB == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "connector authentication is unavailable",
			})
			return
		}

		apiKey := r.Header.Get(ConnectorKeyHeader)
		if apiKey == "" {
			w.Header().Set("WWW-Authenticate", "Connector")
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "connector credentials required",
			})
			return
		}

		connector, err := store.AuthenticateConnector(r.Context(), apiKey)
		if errors.Is(err, storage.ErrInvalidConnectorKey) {
			w.Header().Set("WWW-Authenticate", "Connector")
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "invalid or expired connector credentials",
			})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "connector authentication failed",
			})
			return
		}

		if !hasConnectorScope(connector.Scopes, requiredScope) {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "connector scope is insufficient",
			})
			return
		}

		principal := ConnectorPrincipal{
			ConnectorID: connector.ID,
			TenantID:    connector.TenantID,
			Name:        connector.Name,
			Scopes:      append([]string(nil), connector.Scopes...),
		}

		ctx := context.WithValue(r.Context(), connectorPrincipalContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
