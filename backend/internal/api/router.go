package api

import (
	"net/http"

	_ "github.com/haytamxp/enterprise-web-security-platform/backend/docs"
	httpSwagger "github.com/swaggo/http-swagger"
)

// NewRouter configure toutes les routes de l'API
func NewRouter() http.Handler {
	mux := http.NewServeMux()

	// 1. Route de santé (Healthcheck)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	})

	// 2. Documentation Swagger UI
	mux.Handle("/swagger/", httpSwagger.WrapHandler)

	// 3. Authentification (Publique)
	mux.HandleFunc("POST /api/v1/auth/login", LoginHandler)
    mux.HandleFunc("POST /api/v1/auth/register", RegisterHandler)
	// 4. Ingestion P2 (Protégée par Token JWT)
	// On enveloppe le handler avec AuthMiddleware
	mux.HandleFunc("POST /api/v1/incidents", AuthMiddleware(CreateIncidentHandler))

	return CorsMiddleware(mux)
}