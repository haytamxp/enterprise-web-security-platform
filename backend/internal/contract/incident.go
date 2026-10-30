package contract

import (
	"fmt"
	"strings"
	"time"
)

// IncidentRequest is the raw JSON body of POST /api/v1/incidents.
type IncidentRequest struct {
	IncidentID    Field[string]   `json:"incident_id"`
	SchemaVersion Field[string]   `json:"schema_version"`
	AssetID       Field[string]   `json:"asset_id"`
	Timestamp     Field[string]   `json:"timestamp"`
	Severity      Field[string]   `json:"severity"`
	Confidence    Field[float64]  `json:"confidence"`
	Title         Field[string]   `json:"title"`
	CorrelationID Field[string]   `json:"correlation_id"`
	EventIDs      Field[[]string] `json:"event_ids"`
	Description   Field[string]   `json:"description"`
	PlaybookRef   Field[string]   `json:"playbook_ref"`
	Status        Field[string]   `json:"status"`
}

// Incident is a validated incident, ready for the database layer.
type Incident struct {
	IncidentID    string
	SchemaVersion string
	AssetID       string
	OccurredAt    time.Time
	Severity      string
	Confidence    float64
	Title         string
	CorrelationID string
	EventIDs      []string
	Description   string
	PlaybookRef   *string
	Status        string
}

// Validate checks the request against the P2 contract.
func (r IncidentRequest) Validate() (Incident, []FieldError) {
	var v validator
	var i Incident

	i.IncidentID = v.requiredString("incident_id", r.IncidentID, maxIDLen)
	i.SchemaVersion = SchemaVersion
	v.schemaVersion(r.SchemaVersion)
	i.AssetID = v.requiredString("asset_id", r.AssetID, maxIDLen) // null is rejected
	i.OccurredAt = v.timestamp(r.Timestamp)
	i.Severity = v.enum("severity", r.Severity, "critical", "high", "medium", "low")
	i.Confidence = v.confidence(r.Confidence)
	i.Title = v.requiredString("title", r.Title, maxShortLen)
	i.CorrelationID = v.requiredString("correlation_id", r.CorrelationID, maxIDLen)
	i.Description = v.requiredString("description", r.Description, maxTextLen)
	i.PlaybookRef = v.optionalNullableString("playbook_ref", r.PlaybookRef, maxShortLen)

	if status := v.requiredString("status", r.Status, maxIDLen); status != "" {
		if status != "open" {
			v.add("status", `must be "open" at creation`)
		} else {
			i.Status = status
		}
	}

	switch {
	case !r.EventIDs.Present:
		v.add("event_ids", "is required")
	case r.EventIDs.Null:
		v.add("event_ids", "must not be null")
	case len(r.EventIDs.Value) == 0:
		v.add("event_ids", "must contain at least one event id")
	case len(r.EventIDs.Value) > maxEventIDs:
		v.add("event_ids", fmt.Sprintf("must contain at most %d event ids", maxEventIDs))
	default:
		seen := make(map[string]struct{}, len(r.EventIDs.Value))
		ok := true
		for idx, id := range r.EventIDs.Value {
			name := fmt.Sprintf("event_ids[%d]", idx)
			if strings.TrimSpace(id) == "" || len(id) > maxIDLen {
				v.add(name, "must be a non-empty string of at most 128 characters")
				ok = false
				continue
			}
			if _, dup := seen[id]; dup {
				v.add(name, "duplicate event id")
				ok = false
				continue
			}
			seen[id] = struct{}{}
		}
		if ok {
			i.EventIDs = r.EventIDs.Value
		}
	}

	return i, v.errs
}
