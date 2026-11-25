package api

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
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
			http.Error(w, "Token invalide ou expiré", http.StatusUnauthorized)
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
