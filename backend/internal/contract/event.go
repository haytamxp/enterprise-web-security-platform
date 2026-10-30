package contract

import "time"

// EventRequest is the raw JSON body of POST /api/v1/events.
type EventRequest struct {
	EventID       Field[string]  `json:"event_id"`
	SchemaVersion Field[string]  `json:"schema_version"`
	SourceProduct Field[string]  `json:"source_product"`
	EventType     Field[string]  `json:"event_type"`
	AssetID       Field[string]  `json:"asset_id"`
	Timestamp     Field[string]  `json:"timestamp"`
	Severity      Field[int]     `json:"severity"`
	Confidence    Field[float64] `json:"confidence"`
	CorrelationID Field[string]  `json:"correlation_id"`
	SrcIP         Field[string]  `json:"src_ip"`
	DestIP        Field[string]  `json:"dest_ip"`
	RuleID        Field[string]  `json:"rule_id"`
	Signature     Field[string]  `json:"signature"`
	Description   Field[string]  `json:"description"`
	RawRef        Field[string]  `json:"raw_ref"`
}

// Event is a validated event, ready for the database layer. Nil pointers
// mean SQL NULL.
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

// Validate checks the request against the P2 contract. When it returns a
// non-empty error list, the Event must not be used.
func (r EventRequest) Validate() (Event, []FieldError) {
	var v validator
	var e Event

	e.EventID = v.requiredString("event_id", r.EventID, maxIDLen)
	e.SchemaVersion = SchemaVersion
	v.schemaVersion(r.SchemaVersion)
	e.SourceProduct = v.enum("source_product", r.SourceProduct, "wazuh", "suricata", "application_log")
	e.EventType = v.enum("event_type", r.EventType, "alert", "flow", "http", "auth_failure", "anomaly")
	e.AssetID = v.requiredNullableString("asset_id", r.AssetID, maxIDLen)
	e.OccurredAt = v.timestamp(r.Timestamp)

	switch {
	case !r.Severity.Present:
		v.add("severity", "is required")
	case r.Severity.Null:
		v.add("severity", "must not be null")
	case r.Severity.Value < 1 || r.Severity.Value > 5:
		v.add("severity", "must be an integer from 1 to 5")
	default:
		e.Severity = r.Severity.Value
	}

	e.Confidence = v.confidence(r.Confidence)
	e.CorrelationID = v.requiredNullableString("correlation_id", r.CorrelationID, maxIDLen)
	e.SrcIP = v.optionalIP("src_ip", r.SrcIP)
	e.DestIP = v.optionalIP("dest_ip", r.DestIP)
	e.RuleID = v.optionalNullableString("rule_id", r.RuleID, maxShortLen)
	e.Signature = v.optionalNullableString("signature", r.Signature, maxShortLen)
	e.Description = v.optionalNullableString("description", r.Description, maxTextLen)
	e.RawRef = v.optionalNullableString("raw_ref", r.RawRef, maxShortLen)

	return e, v.errs
}
