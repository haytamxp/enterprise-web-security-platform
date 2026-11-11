package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/storage"
)

func TestResponsePaginationDefaultsAndCursor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/response-runs", nil)
	afterID, limit, err := responsePagination(req)
	if err != nil || afterID != 0 || limit != responseOrchestrationDefaultLimit {
		t.Fatalf("default pagination = (%d, %d, %v), want (0, %d, nil)", afterID, limit, err, responseOrchestrationDefaultLimit)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/response-runs?cursor=42&limit=25", nil)
	afterID, limit, err = responsePagination(req)
	if err != nil || afterID != 42 || limit != 25 {
		t.Fatalf("custom pagination = (%d, %d, %v), want (42, 25, nil)", afterID, limit, err)
	}
}

func TestResponsePaginationRejectsInvalidValues(t *testing.T) {
	for _, target := range []string{
		"/api/v1/response-runs?cursor=-1",
		"/api/v1/response-runs?cursor=not-a-number",
		"/api/v1/response-runs?limit=0",
		"/api/v1/response-runs?limit=101",
		"/api/v1/response-runs?limit=nope",
	} {
		t.Run(target, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, target, nil)
			if _, _, err := responsePagination(req); err == nil {
				t.Fatal("expected invalid pagination error")
			}
		})
	}
}

func TestDecodeResponseJSONRejectsUnknownAndTrailingValues(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
	}

	for _, body := range []string{
		`{"name":"safe","unexpected":true}`,
		`{"name":"safe"} {"second":true}`,
	} {
		t.Run(body, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
			recorder := httptest.NewRecorder()
			var decoded payload
			if decodeResponseJSON(recorder, req, &decoded) {
				t.Fatal("expected request body to be rejected")
			}
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestResponseOrchestrationErrorMapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "not found", err: storage.ErrResponseRunNotFound, want: http.StatusNotFound},
		{name: "invalid input", err: storage.ErrInvalidResponseRun, want: http.StatusBadRequest},
		{name: "state conflict", err: storage.ErrResponseRunNotQueued, want: http.StatusConflict},
		{name: "forbidden actor", err: storage.ErrInvalidResponseActor, want: http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			writeResponseOrchestrationError(recorder, tt.err)
			if recorder.Code != tt.want {
				t.Fatalf("status = %d, want %d", recorder.Code, tt.want)
			}
		})
	}
}

func TestResponseOrchestrationRoutesDoNotExposeExecutionFinish(t *testing.T) {
	mux := http.NewServeMux()
	RegisterResponseOrchestration(mux, &storage.Store{}, nil)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/response-runs/run-1/executions/execution-1/finish", nil)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("finish endpoint status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
}
