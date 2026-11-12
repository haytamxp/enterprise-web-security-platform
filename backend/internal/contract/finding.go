package contract

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// FindingCVSSRequest is the CVSS v4.0 object received in a Finding payload.
type FindingCVSSRequest struct {
	Version Field[string]  `json:"version"`
	Score   Field[float64] `json:"score"`
	Vector  Field[string]  `json:"vector"`
}

// UnmarshalJSON rejects unknown CVSS properties.
func (r *FindingCVSSRequest) UnmarshalJSON(data []byte) error {
	type wire FindingCVSSRequest

	var decoded wire

	if err := decodeStrictFindingObject(data, &decoded); err != nil {
		return err
	}

	*r = FindingCVSSRequest(decoded)
	return nil
}

// EvidenceReferenceRequest is one evidence reference in a Finding payload.
type EvidenceReferenceRequest struct {
	EvidenceID     Field[string] `json:"evidence_id"`
	Classification Field[string] `json:"classification"`
	Redacted       Field[bool]   `json:"redacted"`
	SHA256         Field[string] `json:"sha256"`
	StorageRef     Field[string] `json:"storage_ref"`
	MediaType      Field[string] `json:"media_type"`
}

// EvidenceReferenceArray strictly decodes evidence objects.
// JSON null elements and unknown nested properties are rejected.
type EvidenceReferenceArray []EvidenceReferenceRequest

func (a *EvidenceReferenceArray) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)

	if len(trimmed) == 0 || trimmed[0] != '[' {
		return errors.New("evidence_refs must be an array")
	}

	var rawItems []json.RawMessage

	if err := json.Unmarshal(trimmed, &rawItems); err != nil {
		return fmt.Errorf("decode evidence_refs: %w", err)
	}

	items := make(EvidenceReferenceArray, len(rawItems))

	for i, raw := range rawItems {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("evidence_refs[%d] must be an object, not null", i)
		}

		if err := decodeStrictFindingObject(raw, &items[i]); err != nil {
			return fmt.Errorf("decode evidence_refs[%d]: %w", i, err)
		}
	}

	*a = items
	return nil
}

// decodeStrictFindingObject decodes an object while rejecting unknown fields.
// It is used because Field[T].UnmarshalJSON performs its own nested decoding.
func decodeStrictFindingObject(data []byte, target any) error {
	trimmed := bytes.TrimSpace(data)

	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("must be a JSON object")
	}

	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(target); err != nil {
		return err
	}

	var extra any

	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("unexpected additional JSON value")
		}
		return err
	}

	return nil
}

// FindingRequest is the raw JSON body of a Finding request.
type FindingRequest struct {
	SchemaVersion         Field[string]                 `json:"schema_version"`
	FindingID             Field[string]                 `json:"finding_id"`
	AssetID               Field[string]                 `json:"asset_id"`
	TenantID              Field[string]                 `json:"tenant_id"`
	Source                Field[string]                 `json:"source"`
	Title                 Field[string]                 `json:"title"`
	Description           Field[string]                 `json:"description"`
	Status                Field[string]                 `json:"status"`
	Severity              Field[string]                 `json:"severity"`
	Confidence            Field[float64]                `json:"confidence"`
	CVSS                  Field[FindingCVSSRequest]     `json:"cvss"`
	CWEIDs                Field[StringArray]            `json:"cwe_ids"`
	References            Field[StringArray]            `json:"references"`
	EvidenceRefs          Field[EvidenceReferenceArray] `json:"evidence_refs"`
	RemediationGuidance   Field[string]                 `json:"remediation_guidance"`
	DetectedAt            Field[string]                 `json:"detected_at"`
	LastObservedAt        Field[string]                 `json:"last_observed_at"`
	DeduplicationKey      Field[string]                 `json:"deduplication_key"`
	ReferencesToIncidents Field[StringArray]            `json:"references_to_incidents"`
}

// UnmarshalJSON enforces additionalProperties: false at the root level.
func (r *FindingRequest) UnmarshalJSON(data []byte) error {
	type wire FindingRequest

	var decoded wire

	if err := decodeStrictFindingObject(data, &decoded); err != nil {
		return err
	}

	*r = FindingRequest(decoded)
	return nil
}

// FindingCVSS is validated CVSS metadata.
type FindingCVSS struct {
	Version string
	Score   float64
	Vector  *string
}

// FindingEvidenceReference is validated evidence metadata.
// It contains references and classifications, not the raw evidence itself.
type FindingEvidenceReference struct {
	EvidenceID     string
	Classification string
	Redacted       bool
	SHA256         *string
	StorageRef     *string
	MediaType      *string
}

// Finding is a validated Finding ready for the storage layer.
type Finding struct {
	SchemaVersion         string
	FindingID             string
	AssetID               string
	TenantID              *string
	Source                string
	Title                 string
	Description           *string
	Status                string
	Severity              string
	Confidence            float64
	CVSS                  *FindingCVSS
	CWEIDs                []string
	References            []string
	EvidenceRefs          []FindingEvidenceReference
	RemediationGuidance   *string
	DetectedAt            time.Time
	LastObservedAt        *time.Time
	DeduplicationKey      *string
	ReferencesToIncidents []string
}

// optionalUniqueFindingStringArray validates an optional unique string array.
func (v *validator) optionalUniqueFindingStringArray(
	name string,
	f Field[StringArray],
) []string {
	if !f.Present {
		return nil
	}

	if f.Null {
		v.add(name, "must be an array and must not be null")
		return nil
	}

	values := []string(f.Value)
	seen := make(map[string]struct{}, len(values))

	for i, value := range values {
		if _, exists := seen[value]; exists {
			v.add(
				fmt.Sprintf("%s[%d]", name, i),
				"must be unique",
			)
		}

		seen[value] = struct{}{}
	}

	return values
}

func isCWEIdentifier(value string) bool {
	if !strings.HasPrefix(value, "CWE-") || len(value) <= len("CWE-") {
		return false
	}

	for _, character := range value[len("CWE-"):] {
		if character < '0' || character > '9' {
			return false
		}
	}

	return true
}

func requiredFindingDateTime(
	v *validator,
	name string,
	f Field[string],
) time.Time {
	switch {
	case !f.Present:
		v.add(name, "is required")
		return time.Time{}

	case f.Null:
		v.add(name, "must not be null")
		return time.Time{}
	}

	parsed := v.optionalDateTime(name, f, false)
	if parsed == nil {
		return time.Time{}
	}

	return *parsed
}

func (v *validator) validateFindingCVSS(
	f Field[FindingCVSSRequest],
) *FindingCVSS {
	if !f.Present || f.Null {
		// CVSS is optional and explicit null is allowed by the schema.
		return nil
	}

	request := f.Value
	var result FindingCVSS

	result.Version = v.enum(
		"cvss.version",
		request.Version,
		"4.0",
	)

	switch {
	case !request.Score.Present:
		v.add("cvss.score", "is required")

	case request.Score.Null:
		v.add("cvss.score", "must not be null")

	case request.Score.Value < 0 || request.Score.Value > 10:
		v.add("cvss.score", "must be a number between 0 and 10")

	default:
		result.Score = request.Score.Value
	}

	result.Vector = v.optionalContractString(
		"cvss.vector",
		request.Vector,
		512,
		true,
	)

	return &result
}

func (v *validator) validateFindingEvidence(
	f Field[EvidenceReferenceArray],
) []FindingEvidenceReference {
	switch {
	case !f.Present:
		v.add("evidence_refs", "is required")
		return nil

	case f.Null:
		v.add("evidence_refs", "must be an array and must not be null")
		return nil
	}

	result := make(
		[]FindingEvidenceReference,
		0,
		len(f.Value),
	)

	for i, item := range f.Value {
		prefix := fmt.Sprintf("evidence_refs[%d].", i)

		var evidence FindingEvidenceReference

		evidence.EvidenceID = v.requiredString(
			prefix+"evidence_id",
			item.EvidenceID,
			128,
		)

		evidence.Classification = v.enum(
			prefix+"classification",
			item.Classification,
			"public",
			"internal",
			"confidential",
			"restricted",
		)

		switch {
		case !item.Redacted.Present:
			v.add(prefix+"redacted", "is required")

		case item.Redacted.Null:
			v.add(prefix+"redacted", "must not be null")

		default:
			evidence.Redacted = item.Redacted.Value
		}

		evidence.SHA256 = v.optionalContractString(
			prefix+"sha256",
			item.SHA256,
			64,
			false,
		)

		if evidence.SHA256 != nil {
			if len(*evidence.SHA256) != 64 {
				v.add(prefix+"sha256", "must contain exactly 64 hexadecimal characters")
			} else if _, err := hex.DecodeString(*evidence.SHA256); err != nil {
				v.add(prefix+"sha256", "must contain exactly 64 hexadecimal characters")
			}
		}

		evidence.StorageRef = v.optionalContractString(
			prefix+"storage_ref",
			item.StorageRef,
			512,
			false,
		)

		evidence.MediaType = v.optionalContractString(
			prefix+"media_type",
			item.MediaType,
			128,
			false,
		)

		result = append(result, evidence)
	}

	return result
}

// Validate checks the Finding request against finding.schema.json.
// The returned Finding must not be used when validation errors are present.
func (r FindingRequest) Validate() (Finding, []FieldError) {
	var v validator
	var finding Finding

	finding.SchemaVersion = SchemaVersion
	v.schemaVersion(r.SchemaVersion)

	finding.FindingID = v.requiredString(
		"finding_id",
		r.FindingID,
		128,
	)

	finding.AssetID = v.requiredString(
		"asset_id",
		r.AssetID,
		128,
	)

	finding.TenantID = v.optionalContractString(
		"tenant_id",
		r.TenantID,
		128,
		false,
	)

	if finding.TenantID != nil && strings.TrimSpace(*finding.TenantID) == "" {
		v.add("tenant_id", "must contain at least one non-whitespace character")
		finding.TenantID = nil
	}

	finding.Source = v.enum(
		"source",
		r.Source,
		"p1_offensive",
		"p4_assurance",
		"manual",
		"scanner",
		"other",
	)

	finding.Title = v.requiredString(
		"title",
		r.Title,
		512,
	)

	finding.Description = v.optionalContractString(
		"description",
		r.Description,
		10000,
		false,
	)

	finding.Status = v.enum(
		"status",
		r.Status,
		"detected",
		"triaged",
		"confirmed",
		"false_positive",
		"remediating",
		"fixed_pending_retest",
		"retest_passed",
		"accepted_risk",
		"closed",
	)

	finding.Severity = v.enum(
		"severity",
		r.Severity,
		"critical",
		"high",
		"medium",
		"low",
		"info",
		"unknown",
	)

	finding.Confidence = v.confidence(r.Confidence)

	finding.CVSS = v.validateFindingCVSS(r.CVSS)

	finding.CWEIDs = v.optionalUniqueFindingStringArray(
		"cwe_ids",
		r.CWEIDs,
	)

	for i, cweID := range finding.CWEIDs {
		if !isCWEIdentifier(cweID) {
			v.add(
				fmt.Sprintf("cwe_ids[%d]", i),
				"must match the format CWE- followed by one or more digits",
			)
		}
	}

	finding.References = v.optionalUniqueFindingStringArray(
		"references",
		r.References,
	)

	for i, reference := range finding.References {
		if !isAbsoluteURI(reference) {
			v.add(
				fmt.Sprintf("references[%d]", i),
				"must be a valid absolute URI",
			)
		}
	}

	finding.EvidenceRefs = v.validateFindingEvidence(r.EvidenceRefs)

	finding.RemediationGuidance = v.optionalContractString(
		"remediation_guidance",
		r.RemediationGuidance,
		10000,
		false,
	)

	finding.DetectedAt = requiredFindingDateTime(
		&v,
		"detected_at",
		r.DetectedAt,
	)

	finding.LastObservedAt = v.optionalDateTime(
		"last_observed_at",
		r.LastObservedAt,
		false,
	)

	finding.DeduplicationKey = v.optionalContractString(
		"deduplication_key",
		r.DeduplicationKey,
		256,
		false,
	)

	finding.ReferencesToIncidents = v.optionalUniqueFindingStringArray(
		"references_to_incidents",
		r.ReferencesToIncidents,
	)

	return finding, v.errs
}
