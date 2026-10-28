package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/storage"
)

func New() http.Handler {
	return NewWithStore(nil)
}

func NewWithStore(store *storage.Store) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	if store != nil {
		RegisterIngestion(mux, store)
	}
	return mux
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
