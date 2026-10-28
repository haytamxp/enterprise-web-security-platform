package contract

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func intPointer(v int) *int {
	return &v
}

func floatPointer(v float64) *float64 {
	return &v
}

func stringPointer(v string) *string {
	return &v
}

func validEventRequest() EventRequest {
	return EventRequest{
		EventID:       "evt-test-001",
		SchemaVersion: SchemaVersion,
		SourceProduct: "suricata",
		EventType:     "alert",
		AssetID:       json.RawMessage(`"asset-web-01"`),
		Timestamp:     "2026-10-21T10:00:00Z",
		Severity:      intPointer(3),
		Confidence:    floatPointer(0.92),
		CorrelationID: json.RawMessage(`null`),
	}
}

func validIncidentRequest() IncidentRequest {
	return IncidentRequest{
		IncidentID:    "inc-test-001",
		SchemaVersion: SchemaVersion,
		AssetID:       "asset-web-01",
		Timestamp:     "2026-10-21T10:05:00Z",
		Severity:      "high",
		Confidence:    floatPointer(0.85),
		Title:         "Brute-force activity detected",
		CorrelationID: "corr-test-001",
		EventIDs:      []string{"evt-test-001"},
		Description:   "Multiple authentication failures were detected.",
		Status:        "open",
	}
}

func TestValidateEventAcceptsValidRequest(t *testing.T) {
	event, err := ValidateEvent(validEventRequest())
	if err != nil {
		t.Fatalf("expected valid event, got error: %v", err)
	}
	if event.EventID != "evt-test-001" {
		t.Fatalf("unexpected event ID: %q", event.EventID)
	}
	if event.Severity != 3 {
		t.Fatalf("expected severity 3, got %d", event.Severity)
	}
	if event.AssetID == nil || *event.AssetID != "asset-web-01" {
		t.Fatalf("unexpected asset ID: %#v", event.AssetID)
	}
	if event.CorrelationID != nil {
		t.Fatalf("expected null correlation ID, got %#v", event.CorrelationID)
	}
}

func TestValidateEventAllowsUnknownAssetAsNull(t *testing.T) {
	req := validEventRequest()
	req.AssetID = json.RawMessage(`null`)

	event, err := ValidateEvent(req)
	if err != nil {
		t.Fatalf("expected null asset_id to be accepted, got: %v", err)
	}
	if event.AssetID != nil {
		t.Fatalf("expected a nil asset ID, got %#v", event.AssetID)
	}
}

func TestValidateEventRejectsInvalidSeverity(t *testing.T) {
	req := validEventRequest()
	req.Severity = intPointer(6)

	if _, err := ValidateEvent(req); err == nil {
		t.Fatal("expected invalid severity to be rejected")
	}
}

func TestValidateEventRejectsNonFiniteConfidence(t *testing.T) {
	for _, test := range []struct {
		name       string
		confidence float64
	}{
		{name: "NaN", confidence: math.NaN()},
		{name: "positive_infinity", confidence: math.Inf(1)},
		{name: "negative_infinity", confidence: math.Inf(-1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := validEventRequest()
			req.Confidence = floatPointer(test.confidence)

			if _, err := ValidateEvent(req); err == nil {
				t.Fatal("expected non-finite confidence to be rejected")
			}
		})
	}
}

func TestValidateEventRequiresNullableFieldsToBePresent(t *testing.T) {
	req := validEventRequest()
	req.AssetID = nil

	if _, err := ValidateEvent(req); err == nil {
		t.Fatal("expected missing asset_id to be rejected")
	}
}

func TestValidateEventRejectsBlankNullableString(t *testing.T) {
	req := validEventRequest()
	req.AssetID = json.RawMessage(`""`)

	if _, err := ValidateEvent(req); err == nil {
		t.Fatal("expected blank asset_id to be rejected")
	}
}

func TestValidateEventRequiresUTCZuluTimestamp(t *testing.T) {
	req := validEventRequest()
	req.Timestamp = "2026-10-21T10:00:00+00:00"

	if _, err := ValidateEvent(req); err == nil {
		t.Fatal("expected timestamp not ending in Z to be rejected")
	}
}

func TestValidateEventRejectsOversizedRuleID(t *testing.T) {
	req := validEventRequest()
	req.RuleID = stringPointer(strings.Repeat("r", 257))

	if _, err := ValidateEvent(req); err == nil {
		t.Fatal("expected oversized rule_id to be rejected")
	}
}

func TestValidateIncidentAcceptsValidRequest(t *testing.T) {
	incident, err := ValidateIncident(validIncidentRequest())
	if err != nil {
		t.Fatalf("expected valid incident, got error: %v", err)
	}
	if incident.IncidentID != "inc-test-001" {
		t.Fatalf("unexpected incident ID: %q", incident.IncidentID)
	}
	if incident.Status != "open" {
		t.Fatalf("expected status open, got %q", incident.Status)
	}
	if len(incident.EventIDs) != 1 {
		t.Fatalf("expected one event ID, got %d", len(incident.EventIDs))
	}
}

func TestValidateIncidentRejectsNonFiniteConfidence(t *testing.T) {
	for _, confidence := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		req := validIncidentRequest()
		req.Confidence = floatPointer(confidence)

		if _, err := ValidateIncident(req); err == nil {
			t.Fatalf("expected non-finite confidence %v to be rejected", confidence)
		}
	}
}

func TestValidateIncidentRejectsDuplicateEventIDs(t *testing.T) {
	req := validIncidentRequest()
	req.EventIDs = []string{"evt-test-001", "evt-test-001"}

	if _, err := ValidateIncident(req); err == nil {
		t.Fatal("expected duplicate event IDs to be rejected")
	}
}

func TestValidateIncidentRejectsNonOpenInitialStatus(t *testing.T) {
	req := validIncidentRequest()
	req.Status = "closed"

	if _, err := ValidateIncident(req); err == nil {
		t.Fatal("expected non-open initial status to be rejected")
	}
}

func TestValidateIncidentRejectsOversizedPlaybookRef(t *testing.T) {
	req := validIncidentRequest()
	req.PlaybookRef = stringPointer(strings.Repeat("p", 129))

	if _, err := ValidateIncident(req); err == nil {
		t.Fatal("expected oversized playbook_ref to be rejected")
	}
}
