package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIngestionRequiresAuthenticatedTenant(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{
			name: "event ingestion",
			path: "/api/v1/events",
		},
		{
			name: "incident ingestion",
			path: "/api/v1/incidents",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := &IngestAPI{}

			var handler http.Handler
			if strings.Contains(tt.path, "/events") {
				handler = http.HandlerFunc(api.CreateEvent)
			} else {
				handler = http.HandlerFunc(api.CreateIncident)
			}

			request := httptest.NewRequest(
				http.MethodPost,
				tt.path,
				strings.NewReader(`{}`),
			)

			// Even a client-supplied tenant header must not establish identity.
			request.Header.Set("X-Tenant-ID", "00000000-0000-4000-8000-000000000001")

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if response.Code != http.StatusUnauthorized {
				t.Fatalf(
					"expected 401 without authenticated tenant, got %d; body=%s",
					response.Code,
					response.Body.String(),
				)
			}

			if response.Header().Get("WWW-Authenticate") != "Connector" {
				t.Fatal("expected WWW-Authenticate: Bearer")
			}
		})
	}
}
