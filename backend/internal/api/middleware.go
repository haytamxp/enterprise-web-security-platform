package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/database"
)

// AuthClaims contains the identity information stored in a JWT.
type AuthClaims struct {
	UserID   string `json:"user_id"`
	TenantID string `json:"tenant_id"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// AuthIdentity represents the verified identity of a request.
type AuthIdentity struct {
	UserID   string
	TenantID string
	Role     string
	Email    string
}

type authIdentityContextKey struct{}

// AuthIdentityFromContext retrieves the verified identity from a request.
func AuthIdentityFromContext(ctx context.Context) (AuthIdentity, bool) {
	identity, ok := ctx.Value(authIdentityContextKey{}).(AuthIdentity)
	return identity, ok
}

// AuthMiddleware validates a JWT and makes its identity available to the handler.
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secret := os.Getenv("JWT_SECRET")

		if secret == "" {
			http.Error(w, "Authentication unavailable", http.StatusInternalServerError)
			return
		}

		parts := strings.Fields(r.Header.Get("Authorization"))

		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			http.Error(w, "Token manquant ou invalide", http.StatusUnauthorized)
			return
		}

		claims := &AuthClaims{}

		token, err := jwt.ParseWithClaims(
			parts[1],
			claims,
			func(token *jwt.Token) (interface{}, error) {
				if token.Method != jwt.SigningMethodHS256 {
					return nil, errors.New("unexpected signing method")
				}

				return []byte(secret), nil
			},
		)

		if err != nil || token == nil || !token.Valid {
			http.Error(w, "Token invalide ou expirÃ©", http.StatusUnauthorized)
			return
		}

		if claims.UserID == "" ||
			claims.TenantID == "" ||
			claims.Subject == "" ||
			claims.Role == "" ||
			claims.ExpiresAt == nil {
			http.Error(w, "Token invalide", http.StatusUnauthorized)
			return
		}

		switch claims.Role {
		case "admin", "analyst", "responder", "viewer":
		default:
			http.Error(w, "Token invalide", http.StatusUnauthorized)
			return
		}

		identity := AuthIdentity{
			UserID:   claims.UserID,
			TenantID: claims.TenantID,
			Role:     claims.Role,
			Email:    claims.Subject,
		}

		ctx := context.WithValue(
			r.Context(),
			authIdentityContextKey{},
			identity,
		)

		next(w, r.WithContext(ctx))
	}
}

// CorsMiddleware preserves the existing CORS behavior.
func CorsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ConnectorIdentity represents an authenticated machine connector.
type ConnectorIdentity struct {
	ConnectorID string
	TenantID    string
	Scopes      []string
}

type connectorIdentityContextKey struct{}

// ConnectorIdentityFromContext retrieves the verified connector identity.
func ConnectorIdentityFromContext(ctx context.Context) (ConnectorIdentity, bool) {
	identity, ok := ctx.Value(connectorIdentityContextKey{}).(ConnectorIdentity)
	return identity, ok
}

// ConnectorAuthMiddleware authenticates machine connectors using API keys.
func ConnectorAuthMiddleware(requiredScope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requiredScope == "" {
			http.Error(w, "Connector scope is not configured", http.StatusInternalServerError)
			return
		}
		parts := strings.Fields(r.Header.Get("Authorization"))

		if len(parts) != 2 || !strings.EqualFold(parts[0], "Connector") {
			http.Error(w, "Invalid connector credentials", http.StatusUnauthorized)
			return
		}

		credential := parts[1]
		separator := strings.IndexByte(credential, '.')

		if separator <= 0 || separator == len(credential)-1 {
			http.Error(w, "Invalid connector credentials", http.StatusUnauthorized)
			return
		}

		keyID := credential[:separator]
		secret := credential[separator+1:]

		if len(keyID) > 32 {
			http.Error(w, "Invalid connector credentials", http.StatusUnauthorized)
			return
		}

		var (
			connectorID string
			tenantID    string
			keyHash     []byte
			scopesJSON  []byte
			isActive    bool
			expiresAt   sql.NullTime
			revokedAt   sql.NullTime
		)

		err := database.DB.QueryRow(`
			SELECT connector_id::text, tenant_id::text, key_hash,
			       scopes, is_active, expires_at, revoked_at
			FROM connectors
			WHERE key_id = $1
		`, keyID).Scan(
			&connectorID,
			&tenantID,
			&keyHash,
			&scopesJSON,
			&isActive,
			&expiresAt,
			&revokedAt,
		)

		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "Invalid connector credentials", http.StatusUnauthorized)
				return
			}

			http.Error(w, "Connector authentication unavailable", http.StatusInternalServerError)
			return
		}

		expectedHash := sha256.Sum256([]byte(secret))

		if len(keyHash) != sha256.Size ||
			subtle.ConstantTimeCompare(keyHash, expectedHash[:]) != 1 {
			http.Error(w, "Invalid connector credentials", http.StatusUnauthorized)
			return
		}

		if !isActive || revokedAt.Valid ||
			(expiresAt.Valid && !expiresAt.Time.After(time.Now())) {
			http.Error(w, "Connector is inactive or expired", http.StatusUnauthorized)
			return
		}

		var scopes []string

		if err := json.Unmarshal(scopesJSON, &scopes); err != nil {
			http.Error(w, "Invalid connector configuration", http.StatusInternalServerError)
			return
		}

		hasRequiredScope := false

		for _, scope := range scopes {
			if scope == requiredScope {
				hasRequiredScope = true
				break
			}
		}

		if !hasRequiredScope {
			http.Error(w, "Connector lacks required permission", http.StatusForbidden)
			return
		}

		_, err = database.DB.Exec(`
			UPDATE connectors
			SET last_used_at = NOW()
			WHERE connector_id = $1
		`, connectorID)

		if err != nil {
			http.Error(w, "Connector authentication unavailable", http.StatusInternalServerError)
			return
		}

		identity := ConnectorIdentity{
			ConnectorID: connectorID,
			TenantID:    tenantID,
			Scopes:      scopes,
		}

		ctx := context.WithValue(
			r.Context(),
			connectorIdentityContextKey{},
			identity,
		)

		next(w, r.WithContext(ctx))
	}
}

// IncidentAuthMiddleware accepts either a human JWT or a connector key.
// Connectors must have the incidents:create scope.
func IncidentAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Fields(r.Header.Get("Authorization"))

		if len(parts) == 2 && strings.EqualFold(parts[0], "Connector") {
			ConnectorAuthMiddleware("incidents:create", next)(w, r)
			return
		}

		AuthMiddleware(next)(w, r)
	}
}
