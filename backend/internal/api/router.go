package api

import (
	"net/http"

	_ "github.com/haytamxp/enterprise-web-security-platform/backend/docs"
	httpSwagger "github.com/swaggo/http-swagger"
)

// NewRouter configures all API routes.
func NewRouter() http.Handler {
	mux := http.NewServeMux()

	// Healthcheck
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Swagger documentation
	mux.Handle("/swagger/", httpSwagger.WrapHandler)

	// Authentication
	mux.HandleFunc("POST /api/v1/auth/login", LoginHandler)
	mux.HandleFunc("POST /api/v1/auth/register", AuthMiddleware(RegisterHandler))

	// Events and incidents
	mux.HandleFunc(
		"POST /api/v1/incidents",
		IncidentAuthMiddleware(CreateIncidentHandler),
	)
	mux.HandleFunc(
		"POST /api/v1/events",
		ConnectorAuthMiddleware("events:ingest", CreateEventHandler),
	)
	mux.HandleFunc("GET /api/v1/events", AuthMiddleware(ListEventsHandler))
	mux.HandleFunc("GET /api/v1/events/{event_id}", AuthMiddleware(GetEventHandler))
	mux.HandleFunc("GET /api/v1/incidents", AuthMiddleware(ListIncidentsHandler))
	mux.HandleFunc("GET /api/v1/incidents/{id}", AuthMiddleware(GetIncidentHandler))

	// Assets
	mux.HandleFunc("POST /api/v1/assets", AuthMiddleware(CreateAssetHandler))
	mux.HandleFunc("GET /api/v1/assets", AuthMiddleware(ListAssetsHandler))
	mux.HandleFunc("GET /api/v1/assets/{id}", AuthMiddleware(GetAssetHandler))
	mux.HandleFunc("PUT /api/v1/assets/{id}", AuthMiddleware(UpdateAssetHandler))
	mux.HandleFunc("DELETE /api/v1/assets/{id}", AuthMiddleware(DeleteAssetHandler))

	// Findings
	mux.HandleFunc("POST /api/v1/findings", AuthMiddleware(CreateFindingHandler))
	mux.HandleFunc("GET /api/v1/findings", AuthMiddleware(ListFindingsHandler))
	mux.HandleFunc("GET /api/v1/findings/{finding_id}", AuthMiddleware(GetFindingHandler))
	mux.HandleFunc("PATCH /api/v1/findings/{finding_id}", AuthMiddleware(UpdateFindingHandler))

	// Remediation Tasks: protected by human JWT authentication.
	mux.HandleFunc("POST /api/v1/remediation-tasks", AuthMiddleware(CreateRemediationTaskHandler))
	mux.HandleFunc("GET /api/v1/remediation-tasks", AuthMiddleware(ListRemediationTasksHandler))
	mux.HandleFunc("GET /api/v1/remediation-tasks/{remediation_id}", AuthMiddleware(GetRemediationTaskHandler))
	mux.HandleFunc("PATCH /api/v1/remediation-tasks/{remediation_id}", AuthMiddleware(UpdateRemediationTaskHandler))
	return CorsMiddleware(mux)
}
