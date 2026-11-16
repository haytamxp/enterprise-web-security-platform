package contract

import (
	"encoding/json"
	"testing"
)

const validEvent = `{
  "event_id": "evt-001", "schema_version": "1.0", "source_product": "suricata",
  "event_type": "alert", "asset_id": "asset-001", "timestamp": "2026-10-26T14:30:00Z",
  "severity": 4, "confidence": 0.95, "correlation_id": "corr-001",
  "src_ip": "192.168.1.50", "dest_ip": "192.168.1.100", "rule_id": "10001",
  "signature": "Suspicious HTTP activity", "description": "An alert was detected by Suricata.",
  "raw_ref": null
}`

const validIncident = `{
  "incident_id": "inc-001", "schema_version": "1.0", "asset_id": "asset-001",
  "timestamp": "2026-10-26T14:35:00Z", "severity": "high", "confidence": 0.95,
  "title": "Suspicious web activity", "correlation_id": "corr-001",
  "event_ids": ["evt-001", "evt-002"], "description": "Two related security events were correlated.",
  "playbook_ref": null, "status": "open"
}`

// mutate decodes base into a map, applies fn, and re-encodes it, so each test
// case only states what differs from the valid payload.
func mutate(t *testing.T, base string, fn func(m map[string]any)) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(base), &m); err != nil {
		t.Fatal(err)
	}
	fn(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func hasField(errs []FieldError, field string) bool {
	for _, e := range errs {
		if e.Field == field {
			return true
		}
	}
	return false
}

func TestValidEvent(t *testing.T) {
	var req EventRequest
	if err := json.Unmarshal([]byte(validEvent), &req); err != nil {
		t.Fatal(err)
	}
	e, errs := req.Validate()
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if e.EventID != "evt-001" || e.Severity != 4 || e.AssetID == nil || *e.AssetID != "asset-001" {
		t.Fatalf("unexpected event: %+v", e)
	}
	if e.RawRef != nil {
		t.Fatal("raw_ref null should map to nil")
	}
}

func TestEventValidation(t *testing.T) {
	cases := []struct {
		name  string
		fn    func(m map[string]any)
		field string // field expected in the errors; "" means valid
	}{
		{"asset_id null is accepted", func(m map[string]any) { m["asset_id"] = nil }, ""},
		{"correlation_id null is accepted", func(m map[string]any) { m["correlation_id"] = nil }, ""},
		{"optional fields omitted", func(m map[string]any) {
			for _, k := range []string{"src_ip", "dest_ip", "rule_id", "signature", "description", "raw_ref"} {
				delete(m, k)
			}
		}, ""},
		{"asset_id omitted", func(m map[string]any) { delete(m, "asset_id") }, "asset_id"},
		{"correlation_id omitted", func(m map[string]any) { delete(m, "correlation_id") }, "correlation_id"},
		{"event_id omitted", func(m map[string]any) { delete(m, "event_id") }, "event_id"},
		{"event_id null", func(m map[string]any) { m["event_id"] = nil }, "event_id"},
		{"event_id blank", func(m map[string]any) { m["event_id"] = "  " }, "event_id"},
		{"schema version 2.0", func(m map[string]any) { m["schema_version"] = "2.0" }, "schema_version"},
		{"bad source_product", func(m map[string]any) { m["source_product"] = "snort" }, "source_product"},
		{"bad event_type", func(m map[string]any) { m["event_type"] = "login" }, "event_type"},
		{"severity 0", func(m map[string]any) { m["severity"] = 0 }, "severity"},
		{"severity 6", func(m map[string]any) { m["severity"] = 6 }, "severity"},
		{"severity omitted", func(m map[string]any) { delete(m, "severity") }, "severity"},
		{"confidence -0.1", func(m map[string]any) { m["confidence"] = -0.1 }, "confidence"},
		{"confidence 1.1", func(m map[string]any) { m["confidence"] = 1.1 }, "confidence"},
		{"timestamp not iso", func(m map[string]any) { m["timestamp"] = "yesterday" }, "timestamp"},
		{"timestamp not utc", func(m map[string]any) { m["timestamp"] = "2026-10-26T14:30:00+02:00" }, "timestamp"},
		{"timestamp omitted", func(m map[string]any) { delete(m, "timestamp") }, "timestamp"},
		{"bad src_ip", func(m map[string]any) { m["src_ip"] = "999.1.1.1" }, "src_ip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var req EventRequest
			if err := json.Unmarshal([]byte(mutate(t, validEvent, tc.fn)), &req); err != nil {
				t.Fatal(err)
			}
			_, errs := req.Validate()
			if tc.field == "" && len(errs) != 0 {
				t.Fatalf("expected valid, got %v", errs)
			}
			if tc.field != "" && !hasField(errs, tc.field) {
				t.Fatalf("expected error on %q, got %v", tc.field, errs)
			}
		})
	}
}

// Wrong JSON types must fail at decode time (the HTTP layer maps that to 400).
func TestEventWrongTypesFailToDecode(t *testing.T) {
	for name, fn := range map[string]func(m map[string]any){
		"severity as string":   func(m map[string]any) { m["severity"] = "4" },
		"severity as float":    func(m map[string]any) { m["severity"] = 4.5 },
		"confidence as string": func(m map[string]any) { m["confidence"] = "0.9" },
		"event_id as number":   func(m map[string]any) { m["event_id"] = 7 },
	} {
		t.Run(name, func(t *testing.T) {
			var req EventRequest
			if err := json.Unmarshal([]byte(mutate(t, validEvent, fn)), &req); err == nil {
				t.Fatal("expected a decode error")
			}
		})
	}
}

func TestValidIncident(t *testing.T) {
	var req IncidentRequest
	if err := json.Unmarshal([]byte(validIncident), &req); err != nil {
		t.Fatal(err)
	}
	i, errs := req.Validate()
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if i.IncidentID != "inc-001" || len(i.EventIDs) != 2 || i.Status != "open" || i.PlaybookRef != nil {
		t.Fatalf("unexpected incident: %+v", i)
	}
}

func TestIncidentValidation(t *testing.T) {
	cases := []struct {
		name  string
		fn    func(m map[string]any)
		field string
	}{
		{"asset_id null rejected", func(m map[string]any) { m["asset_id"] = nil }, "asset_id"},
		{"asset_id omitted", func(m map[string]any) { delete(m, "asset_id") }, "asset_id"},
		{"playbook_ref omitted ok", func(m map[string]any) { delete(m, "playbook_ref") }, ""},
		{"empty event_ids", func(m map[string]any) { m["event_ids"] = []string{} }, "event_ids"},
		{"event_ids null", func(m map[string]any) { m["event_ids"] = nil }, "event_ids"},
		{"event_ids omitted", func(m map[string]any) { delete(m, "event_ids") }, "event_ids"},
		{"duplicate event ids", func(m map[string]any) { m["event_ids"] = []string{"a", "a"} }, "event_ids[1]"},
		{"blank event id", func(m map[string]any) { m["event_ids"] = []string{"a", ""} }, "event_ids[1]"},
		{"status closed", func(m map[string]any) { m["status"] = "closed" }, "status"},
		{"status omitted", func(m map[string]any) { delete(m, "status") }, "status"},
		{"bad severity (event style)", func(m map[string]any) { m["severity"] = "urgent" }, "severity"},
		{"schema version", func(m map[string]any) { m["schema_version"] = "0.9" }, "schema_version"},
		{"confidence 2", func(m map[string]any) { m["confidence"] = 2 }, "confidence"},
		{"bad timestamp", func(m map[string]any) { m["timestamp"] = "2026-13-45T99:00:00Z" }, "timestamp"},
		{"title omitted", func(m map[string]any) { delete(m, "title") }, "title"},
		{"correlation_id omitted", func(m map[string]any) { delete(m, "correlation_id") }, "correlation_id"},
		{"description blank", func(m map[string]any) { m["description"] = "" }, "description"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var req IncidentRequest
			if err := json.Unmarshal([]byte(mutate(t, validIncident, tc.fn)), &req); err != nil {
				t.Fatal(err)
			}
			_, errs := req.Validate()
			if tc.field == "" && len(errs) != 0 {
				t.Fatalf("expected valid, got %v", errs)
			}
			if tc.field != "" && !hasField(errs, tc.field) {
				t.Fatalf("expected error on %q, got %v", tc.field, errs)
			}
		})
	}
}
