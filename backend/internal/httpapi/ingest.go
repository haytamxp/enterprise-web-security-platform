package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/contract"
	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/storage"
)

type IngestAPI struct {
	Store *storage.Store
}

func authenticatedTenantID(
	w http.ResponseWriter,
	r *http.Request,
) (string, bool) {
	principal, ok := ConnectorPrincipalFromContext(r.Context())

	if !ok || principal.ConnectorID == "" || principal.TenantID == "" {
		w.Header().Set("WWW-Authenticate", "Connector")
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "authenticated connector identity required",
		})
		return "", false
	}

	return principal.TenantID, true
}

func decodeBody(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(target); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid JSON payload",
		})
		return false
	}

	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "request must contain one JSON object",
		})
		return false
	}

	return true
}

func (a *IngestAPI) CreateEvent(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := authenticatedTenantID(w, r)
	if !ok {
		return
	}

	var req contract.EventRequest
	if !decodeBody(w, r, &req) {
		return
	}

	event, validationErrors := req.Validate()
	if len(validationErrors) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":   "invalid event payload",
			"details": validationErrors,
		})
		return
	}

	if err := a.Store.InsertEvent(r.Context(), tenantID, event); err != nil {
		if errors.Is(err, storage.ErrDuplicate) {
			writeJSON(w, http.StatusConflict, map[string]string{
				"error": "duplicate event_id",
			})
			return
		}

		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to store event",
		})
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"event_id": event.EventID,
		"stored":   true,
	})
}

func (a *IngestAPI) CreateIncident(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := authenticatedTenantID(w, r)
	if !ok {
		return
	}

	var req contract.IncidentRequest
	if !decodeBody(w, r, &req) {
		return
	}

	incident, validationErrors := req.Validate()
	if len(validationErrors) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":   "invalid incident payload",
			"details": validationErrors,
		})
		return
	}

	if err := a.Store.InsertIncident(r.Context(), tenantID, incident); err != nil {
		switch {
		case errors.Is(err, storage.ErrDuplicate):
			writeJSON(w, http.StatusConflict, map[string]string{
				"error": "duplicate incident_id",
			})
		case errors.Is(err, storage.ErrUnknownEvent):
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{
				"error": "incident references an unknown event",
			})
		case errors.Is(err, storage.ErrTenantRequired):
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "authenticated tenant identity required",
			})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "failed to store incident",
			})
		}
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"incident_id": incident.IncidentID,
		"stored":      true,
	})
}

func RegisterIngestion(mux *http.ServeMux, store *storage.Store) {
	api := &IngestAPI{Store: store}
	mux.HandleFunc("POST /api/v1/events", api.CreateEvent)
	mux.HandleFunc("POST /api/v1/incidents", api.CreateIncident)
}
