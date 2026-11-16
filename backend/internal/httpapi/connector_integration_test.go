package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/auth"
	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/storage"
)

func openHTTPConnectorTestStore(t *testing.T) (*storage.Store, context.Context, string) {
	t.Helper()

	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not configured; PostgreSQL HTTP integration test skipped")
	}

	parsedURL, err := url.Parse(databaseURL)
	if err != nil || strings.Trim(parsedURL.Path, "/") != "ewstrp_test" {
		t.Fatal("TEST_DATABASE_URL must point to the isolated ewstrp_test database")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	store, err := storage.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal("could not connect to the isolated test database")
	}

	t.Cleanup(func() {
		_ = store.DB.Close()
	})

	var databaseName string
	if err := store.DB.QueryRowContext(ctx, `SELECT current_database()`).Scan(&databaseName); err != nil {
		t.Fatal("could not verify test database")
	}

	if databaseName != "ewstrp_test" {
		t.Fatal("integration test connected to an unexpected database")
	}

	var tenantID string
	err = store.DB.QueryRowContext(ctx, `
SELECT tenant_id::text
FROM tenants
WHERE slug = 'default'
  AND is_active = TRUE
`).Scan(&tenantID)

	if err != nil {
		t.Fatal("could not resolve active default test tenant")
	}

	return store, ctx, tenantID
}

func createHTTPTestConnector(
	t *testing.T,
	ctx context.Context,
	store *storage.Store,
	tenantID string,
	name string,
	scopes []string,
) *storage.Connector {
	t.Helper()

	connector, err := store.CreateConnector(
		ctx,
		tenantID,
		name,
		scopes,
		nil,
	)
	if err != nil {
		t.Fatalf("create test connector: %v", err)
	}

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, _ = store.DB.ExecContext(
			cleanupCtx,
			`DELETE FROM connectors WHERE connector_id = $1::uuid`,
			connector.ID,
		)
	})

	return connector
}

func performConnectorJSONRequest(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
	payload any,
	headers map[string]string,
) *httptest.ResponseRecorder {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("encode HTTP test payload: %v", err)
	}

	request := httptest.NewRequest(
		method,
		path,
		bytes.NewReader(body),
	)
	request.Header.Set("Content-Type", "application/json")

	for name, value := range headers {
		request.Header.Set(name, value)
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	return response
}

func TestConnectorHTTPAuthorizationAndTenantScopedIngestion(t *testing.T) {
	store, ctx, tenantID := openHTTPConnectorTestStore(t)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	eventsConnector := createHTTPTestConnector(
		t,
		ctx,
		store,
		tenantID,
		"events-http-test-"+suffix,
		[]string{storage.ConnectorScopeEventsIngest},
	)

	incidentsConnector := createHTTPTestConnector(
		t,
		ctx,
		store,
		tenantID,
		"incidents-http-test-"+suffix,
		[]string{storage.ConnectorScopeIncidentsCreate},
	)

	tokens, err := auth.NewTokenManager(
		strings.Repeat("http-integration-secret-", 3),
		"connector-http-test",
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("create token manager: %v", err)
	}

	handler := NewWithAuth(store, tokens)

	eventID := "evt-http-" + suffix
	incidentID := "inc-http-" + suffix
	timestamp := time.Now().UTC().Format(time.RFC3339)

	eventPayload := map[string]any{
		"event_id":       eventID,
		"schema_version": "1.0",
		"source_product": "suricata",
		"event_type":     "alert",
		"asset_id":       "asset-http-test",
		"timestamp":      timestamp,
		"severity":       4,
		"confidence":     0.95,
		"correlation_id": "corr-http-" + suffix,
		"src_ip":         "192.168.1.50",
		"dest_ip":        "192.168.1.100",
		"rule_id":        "10001",
		"signature":      "HTTP connector integration test",
		"description":    "Testing authenticated event ingestion.",
		"raw_ref":        nil,
	}

	incidentPayload := map[string]any{
		"incident_id":    incidentID,
		"schema_version": "1.0",
		"asset_id":       "asset-http-test",
		"timestamp":      timestamp,
		"severity":       "high",
		"confidence":     0.95,
		"title":          "HTTP connector integration test",
		"correlation_id": "corr-http-" + suffix,
		"event_ids":      []string{eventID},
		"description":    "Testing authenticated incident creation.",
		"playbook_ref":   nil,
		"status":         "open",
	}

	t.Run("events scope can create an event", func(t *testing.T) {
		response := performConnectorJSONRequest(
			t,
			handler,
			http.MethodPost,
			"/api/v1/events",
			eventPayload,
			map[string]string{
				ConnectorKeyHeader: eventsConnector.APIKey,
			},
		)

		if response.Code != http.StatusCreated {
			t.Fatalf(
				"expected event creation status 201, got %d; body=%s",
				response.Code,
				response.Body.String(),
			)
		}
	})

	t.Run("events scope cannot create an incident", func(t *testing.T) {
		response := performConnectorJSONRequest(
			t,
			handler,
			http.MethodPost,
			"/api/v1/incidents",
			incidentPayload,
			map[string]string{
				ConnectorKeyHeader: eventsConnector.APIKey,
			},
		)

		if response.Code != http.StatusForbidden {
			t.Fatalf(
				"expected insufficient-scope status 403, got %d; body=%s",
				response.Code,
				response.Body.String(),
			)
		}
	})

	t.Run("incidents scope can create an incident", func(t *testing.T) {
		response := performConnectorJSONRequest(
			t,
			handler,
			http.MethodPost,
			"/api/v1/incidents",
			incidentPayload,
			map[string]string{
				ConnectorKeyHeader: incidentsConnector.APIKey,
			},
		)

		if response.Code != http.StatusCreated {
			t.Fatalf(
				"expected incident creation status 201, got %d; body=%s",
				response.Code,
				response.Body.String(),
			)
		}
	})

	t.Run("incidents scope cannot create an event", func(t *testing.T) {
		response := performConnectorJSONRequest(
			t,
			handler,
			http.MethodPost,
			"/api/v1/events",
			eventPayload,
			map[string]string{
				ConnectorKeyHeader: incidentsConnector.APIKey,
			},
		)

		if response.Code != http.StatusForbidden {
			t.Fatalf(
				"expected insufficient-scope status 403, got %d; body=%s",
				response.Code,
				response.Body.String(),
			)
		}
	})

	t.Run("human JWT cannot authenticate connector ingestion", func(t *testing.T) {
		token, _, err := tokens.Issue(
			"http-integration-user",
			tenantID,
			auth.RoleViewer,
		)
		if err != nil {
			t.Fatalf("issue human JWT: %v", err)
		}

		response := performConnectorJSONRequest(
			t,
			handler,
			http.MethodPost,
			"/api/v1/events",
			eventPayload,
			map[string]string{
				"Authorization": "Bearer " + token,
			},
		)

		if response.Code != http.StatusUnauthorized {
			t.Fatalf(
				"expected human JWT to be rejected with 401, got %d; body=%s",
				response.Code,
				response.Body.String(),
			)
		}

		if response.Header().Get("WWW-Authenticate") != "Connector" {
			t.Fatal("expected WWW-Authenticate: Connector")
		}
	})

	t.Run("missing connector key is rejected", func(t *testing.T) {
		response := performConnectorJSONRequest(
			t,
			handler,
			http.MethodPost,
			"/api/v1/events",
			eventPayload,
			nil,
		)

		if response.Code != http.StatusUnauthorized {
			t.Fatalf(
				"expected missing connector key status 401, got %d",
				response.Code,
			)
		}
	})

	t.Run("revoked connector key is rejected", func(t *testing.T) {
		if err := store.RevokeConnector(
			ctx,
			tenantID,
			eventsConnector.ID,
		); err != nil {
			t.Fatalf("revoke events connector: %v", err)
		}

		response := performConnectorJSONRequest(
			t,
			handler,
			http.MethodPost,
			"/api/v1/events",
			eventPayload,
			map[string]string{
				ConnectorKeyHeader: eventsConnector.APIKey,
			},
		)

		if response.Code != http.StatusUnauthorized {
			t.Fatalf(
				"expected revoked connector status 401, got %d; body=%s",
				response.Code,
				response.Body.String(),
			)
		}
	})
}
