package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/auth"
	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/storage"
)

func newMux() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "ok",
		})
	})

	return mux
}

func New() http.Handler {
	return NewWithStore(nil)
}

// NewWithStore is retained for existing tests and local compatibility.
// Production must use NewWithAuth.
func NewWithStore(store *storage.Store) http.Handler {
	mux := newMux()

	if store != nil {
		RegisterIngestion(mux, store)
	}

	return mux
}

// NewWithAuth registers authentication, ingestion, and human-user APIs.
func NewWithAuth(store *storage.Store, tokens *auth.TokenManager) http.Handler {
	mux := newMux()

	// Fail closed: do not expose application routes without authentication.
	if store == nil || tokens == nil {
		return mux
	}

	RegisterAuthentication(mux, store, tokens)
	RegisterProtectedIngestion(mux, store)
	RegisterAssets(mux, store, tokens)
	RegisterFindings(mux, store, tokens)
	RegisterRemediations(mux, store, tokens)
	RegisterResponseOrchestration(mux, store, tokens)

	return mux
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
