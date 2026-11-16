package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/auth"
	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/storage"
)

type AuthenticationAPI struct {
	Store  *storage.Store
	Tokens *auth.TokenManager
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func decodeLoginBody(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(target); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid login request",
		})
		return false
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "request must contain one JSON object",
		})
		return false
	}

	return true
}

func (a *AuthenticationAPI) Login(w http.ResponseWriter, r *http.Request) {
	if a.Store == nil || a.Tokens == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "authentication is unavailable",
		})
		return
	}

	var req LoginRequest

	if !decodeLoginBody(w, r, &req) {
		return
	}

	email := strings.TrimSpace(req.Email)

	if email == "" || len(email) > 254 || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "email and password are required",
		})
		return
	}

	user, err := a.Store.GetUserByEmail(r.Context(), email)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "invalid email or password",
			})
			return
		}

		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "login failed",
		})
		return
	}

	// Do not reveal whether an account is inactive or its password is incorrect.
	if !user.IsActive || !auth.VerifyPassword(req.Password, user.PasswordHash) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "invalid email or password",
		})
		return
	}

	if err := a.Store.UpdateLastLogin(r.Context(), user.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "login failed",
		})
		return
	}

	token, expiresAt, err := a.Tokens.Issue(user.ID, user.TenantID, user.Role)

	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "could not issue access token",
		})
		return
	}

	w.Header().Set("Cache-Control", "no-store")

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_at":   expiresAt,
		"user": map[string]string{
			"id":    user.ID,
			"email": user.Email,
			"role":  user.Role,
		},
	})
}

func (a *AuthenticationAPI) Me(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())

	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "authentication required",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"user_id":   principal.UserID,
		"tenant_id": principal.TenantID,
		"role":      principal.Role,
	})
}

func RegisterAuthentication(
	mux *http.ServeMux,
	store *storage.Store,
	tokens *auth.TokenManager,
) {
	api := &AuthenticationAPI{
		Store:  store,
		Tokens: tokens,
	}

	// Public endpoint: login.
	mux.HandleFunc("POST /api/v1/auth/login", api.Login)

	// Protected endpoint: current authenticated identity.
	mux.Handle(
		"GET /api/v1/auth/me",
		AuthMiddleware(tokens, http.HandlerFunc(api.Me)),
	)
}

// RegisterProtectedIngestion protects P2 ingestion using connector credentials.
// Human JWTs are deliberately not accepted by these machine-to-machine routes.
func RegisterProtectedIngestion(
	mux *http.ServeMux,
	store *storage.Store,
) {
	api := &IngestAPI{Store: store}

	mux.Handle(
		"POST /api/v1/events",
		ConnectorAuthMiddleware(
			store,
			storage.ConnectorScopeEventsIngest,
			http.HandlerFunc(api.CreateEvent),
		),
	)

	mux.Handle(
		"POST /api/v1/incidents",
		ConnectorAuthMiddleware(
			store,
			storage.ConnectorScopeIncidentsCreate,
			http.HandlerFunc(api.CreateIncident),
		),
	)
}
