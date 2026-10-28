package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

const SchemaVersion = "1.0"

type EventRequest struct {
	EventID       string          `json:"event_id"`
	SchemaVersion string          `json:"schema_version"`
	SourceProduct string          `json:"source_product"`
	EventType     string          `json:"event_type"`
	AssetID       json.RawMessage `json:"asset_id"`
	Timestamp     string          `json:"timestamp"`
	Severity      *int            `json:"severity"`
	Confidence    *float64        `json:"confidence"`
	CorrelationID json.RawMessage `json:"correlation_id"`
	SrcIP         *string         `json:"src_ip"`
	DestIP        *string         `json:"dest_ip"`
	RuleID        *string         `json:"rule_id"`
	Signature     *string         `json:"signature"`
	Description   *string         `json:"description"`
	RawRef        *string         `json:"raw_ref"`
}

type Event struct {
	EventID       string
	SchemaVersion string
	SourceProduct string
	EventType     string
	AssetID       *string
	OccurredAt    time.Time
	Severity      int
	Confidence    float64
	CorrelationID *string
	SrcIP         *string
	DestIP        *string
	RuleID        *string
	Signature     *string
	Description   *string
	RawRef        *string
}

type IncidentRequest struct {
	IncidentID    string   `json:"incident_id"`
	SchemaVersion string   `json:"schema_version"`
	AssetID       string   `json:"asset_id"`
	Timestamp     string   `json:"timestamp"`
	Severity      string   `json:"severity"`
	Confidence    *float64 `json:"confidence"`
	Title         string   `json:"title"`
	CorrelationID string   `json:"correlation_id"`
	EventIDs      []string `json:"event_ids"`
	Description   string   `json:"description"`
	PlaybookRef   *string  `json:"playbook_ref"`
	Status        string   `json:"status"`
}

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

func checkString(name, value string, max int) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", name)
	}
	if len([]rune(value)) > max {
		return fmt.Errorf("%s exceeds %d characters", name, max)
	}
	return nil
}

func checkOptionalLength(name string, value *string, max int) error {
	if value == nil {
		return nil
	}
	if len([]rune(*value)) > max {
		return fmt.Errorf("%s exceeds %d characters", name, max)
	}
	return nil
}

func checkTimestamp(value string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil || !strings.HasSuffix(value, "Z") {
		return time.Time{}, fmt.Errorf("timestamp must be RFC3339 UTC ending in Z")
	}
	return t.UTC(), nil
}

func checkNullableString(name string, raw json.RawMessage) (*string, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%s is required (it may be null)", name)
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}

	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("%s must be a string or null", name)
	}
	if strings.TrimSpace(s) == "" {
		return nil, fmt.Errorf("%s must not be empty", name)
	}
	if len([]rune(s)) > 128 {
		return nil, fmt.Errorf("%s exceeds 128 characters", name)
	}
	return &s, nil
}

func checkIP(name string, value *string) error {
	if value == nil {
		return nil
	}
	if _, err := netip.ParseAddr(*value); err != nil {
		return fmt.Errorf("%s must be a valid IP address", name)
	}
	return nil
}

func ValidateEvent(r EventRequest) (Event, error) {
	var e Event

	if err := checkString("event_id", r.EventID, 128); err != nil {
		return e, err
	}
	if r.SchemaVersion != SchemaVersion {
		return e, fmt.Errorf("schema_version must be %q", SchemaVersion)
	}

	switch r.SourceProduct {
	case "wazuh", "suricata", "application_log":
	default:
		return e, fmt.Errorf("unsupported source_product")
	}
	switch r.EventType {
	case "alert", "flow", "http", "auth_failure", "anomaly":
	default:
		return e, fmt.Errorf("unsupported event_type")
	}
	if r.Severity == nil || *r.Severity < 1 || *r.Severity > 5 {
		return e, fmt.Errorf("severity must be an integer from 1 to 5")
	}
	if r.Confidence == nil || *r.Confidence < 0 || *r.Confidence > 1 {
		return e, fmt.Errorf("confidence must be between 0 and 1")
	}

	assetID, err := checkNullableString("asset_id", r.AssetID)
	if err != nil {
		return e, err
	}
	correlationID, err := checkNullableString("correlation_id", r.CorrelationID)
	if err != nil {
		return e, err
	}

	occurredAt, err := checkTimestamp(r.Timestamp)
	if err != nil {
		return e, err
	}
	if err = checkIP("src_ip", r.SrcIP); err != nil {
		return e, err
	}
	if err = checkIP("dest_ip", r.DestIP); err != nil {
		return e, err
	}

	for _, field := range []struct {
		name  string
		value *string
		max   int
	}{
		{"rule_id", r.RuleID, 256},
		{"signature", r.Signature, 512},
		{"raw_ref", r.RawRef, 1024},
	} {
		if err = checkOptionalLength(field.name, field.value, field.max); err != nil {
			return e, err
		}
	}

	e = Event{
		EventID:       r.EventID,
		SchemaVersion: r.SchemaVersion,
		SourceProduct: r.SourceProduct,
		EventType:     r.EventType,
		AssetID:       assetID,
		OccurredAt:    occurredAt,
		Severity:      *r.Severity,
		Confidence:    *r.Confidence,
		CorrelationID: correlationID,
		SrcIP:         r.SrcIP,
		DestIP:        r.DestIP,
		RuleID:        r.RuleID,
		Signature:     r.Signature,
		Description:   r.Description,
		RawRef:        r.RawRef,
	}
	return e, nil
}

func ValidateIncident(r IncidentRequest) (Incident, error) {
	var i Incident

	for _, item := range []struct {
		name  string
		value string
		max   int
	}{
		{"incident_id", r.IncidentID, 128},
		{"asset_id", r.AssetID, 128},
		{"title", r.Title, 1024},
		{"correlation_id", r.CorrelationID, 128},
		{"description", r.Description, 8192},
	} {
		if err := checkString(item.name, item.value, item.max); err != nil {
			return i, err
		}
	}
	if r.SchemaVersion != SchemaVersion {
		return i, fmt.Errorf("schema_version must be %q", SchemaVersion)
	}
	if r.Confidence == nil || *r.Confidence < 0 || *r.Confidence > 1 {
		return i, fmt.Errorf("confidence must be between 0 and 1")
	}
	switch r.Severity {
	case "critical", "high", "medium", "low":
	default:
		return i, fmt.Errorf("unsupported incident severity")
	}
	if r.Status != "open" {
		return i, fmt.Errorf("status must be open when creating an incident")
	}
	if err := checkOptionalLength("playbook_ref", r.PlaybookRef, 128); err != nil {
		return i, err
	}
	if len(r.EventIDs) == 0 || len(r.EventIDs) > 1000 {
		return i, fmt.Errorf("event_ids must contain between 1 and 1000 IDs")
	}

	seen := make(map[string]bool, len(r.EventIDs))
	for _, id := range r.EventIDs {
		if err := checkString("event_ids entry", id, 128); err != nil {
			return i, err
		}
		if seen[id] {
			return i, fmt.Errorf("event_ids contains duplicate ID %q", id)
		}
		seen[id] = true
	}

	t, err := checkTimestamp(r.Timestamp)
	if err != nil {
		return i, err
	}

	i = Incident{
		IncidentID:    r.IncidentID,
		SchemaVersion: r.SchemaVersion,
		AssetID:       r.AssetID,
		OccurredAt:    t,
		Severity:      r.Severity,
		Confidence:    *r.Confidence,
		Title:         r.Title,
		CorrelationID: r.CorrelationID,
		EventIDs:      r.EventIDs,
		Description:   r.Description,
		PlaybookRef:   r.PlaybookRef,
		Status:        r.Status,
	}
	return i, nil
}
