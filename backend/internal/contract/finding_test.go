package contract

import (
	"encoding/json"
	"strings"
	"testing"
)

func validFindingTestPayload() map[string]any {
	return map[string]any{
		"schema_version": "1.0",
		"finding_id":     "finding-test-001",
		"asset_id":       "asset-test-001",
		"tenant_id":      "00000000-0000-4000-8000-000000000001",
		"source":         "p1_offensive",
		"title":          "SQL Injection",
		"description":    "A synthetic SQL injection finding for contract tests.",
		"status":         "detected",
		"severity":       "high",
		"confidence":     0.95,
		"cvss": map[string]any{
			"version": "4.0",
			"score":   8.1,
			"vector":  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
		},
		"cwe_ids": []any{
			"CWE-89",
			"CWE-79",
		},
		"references": []any{
			"https://example.test/security/advisory",
		},
		"evidence_refs": []any{
			map[string]any{
				"evidence_id":    "evidence-test-001",
				"classification": "restricted",
				"redacted":       true,
				"sha256":         strings.Repeat("a", 64),
				"storage_ref":    "evidence://vault/test-001",
				"media_type":     "text/plain",
			},
		},
		"remediation_guidance": "Use parameterized SQL queries.",
		"detected_at":          "2026-11-04T10:00:00Z",
		"last_observed_at":     "2026-11-04T10:30:00Z",
		"deduplication_key":    "sql-injection-asset-test-001",
		"references_to_incidents": []any{
			"incident-test-001",
		},
	}
}

func validateFindingTestPayload(
	t *testing.T,
	payload map[string]any,
) (Finding, []FieldError) {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal test payload: %v", err)
	}

	var request FindingRequest

	if err := json.Unmarshal(body, &request); err != nil {
		t.Fatalf("decode test payload: %v", err)
	}

	return request.Validate()
}

func hasFindingFieldError(errs []FieldError, field string) bool {
	for _, fieldError := range errs {
		if fieldError.Field == field {
			return true
		}
	}

	return false
}

func TestFindingRequestValidateValidPayload(t *testing.T) {
	finding, errs := validateFindingTestPayload(
		t,
		validFindingTestPayload(),
	)

	if len(errs) > 0 {
		t.Fatalf("expected valid Finding payload, got errors: %+v", errs)
	}

	if finding.FindingID != "finding-test-001" {
		t.Fatalf("unexpected finding_id: %q", finding.FindingID)
	}

	if finding.AssetID != "asset-test-001" {
		t.Fatalf("unexpected asset_id: %q", finding.AssetID)
	}

	if finding.Source != "p1_offensive" {
		t.Fatalf("unexpected source: %q", finding.Source)
	}

	if finding.Status != "detected" {
		t.Fatalf("unexpected status: %q", finding.Status)
	}

	if finding.Severity != "high" {
		t.Fatalf("unexpected severity: %q", finding.Severity)
	}

	if finding.CVSS == nil {
		t.Fatal("expected CVSS metadata")
	}

	if finding.CVSS.Version != "4.0" || finding.CVSS.Score != 8.1 {
		t.Fatalf("unexpected CVSS metadata: %+v", finding.CVSS)
	}

	if len(finding.EvidenceRefs) != 1 {
		t.Fatalf("expected one evidence reference, got %d", len(finding.EvidenceRefs))
	}

	if finding.EvidenceRefs[0].EvidenceID != "evidence-test-001" {
		t.Fatalf("unexpected evidence ID: %q", finding.EvidenceRefs[0].EvidenceID)
	}

	if !finding.EvidenceRefs[0].Redacted {
		t.Fatal("expected evidence redacted=true")
	}

	if finding.DetectedAt.IsZero() {
		t.Fatal("expected a parsed detected_at timestamp")
	}
}

func TestFindingRequestAllowsOptionalFieldsAndNullCVSS(t *testing.T) {
	payload := validFindingTestPayload()

	delete(payload, "tenant_id")
	delete(payload, "description")
	delete(payload, "cwe_ids")
	delete(payload, "references")
	delete(payload, "remediation_guidance")
	delete(payload, "last_observed_at")
	delete(payload, "deduplication_key")
	delete(payload, "references_to_incidents")

	payload["cvss"] = nil
	payload["evidence_refs"] = []any{}

	finding, errs := validateFindingTestPayload(t, payload)

	if len(errs) > 0 {
		t.Fatalf("expected optional fields and null CVSS to be accepted: %+v", errs)
	}

	if finding.TenantID != nil {
		t.Fatalf("expected omitted tenant_id to remain nil, got %v", *finding.TenantID)
	}

	if finding.CVSS != nil {
		t.Fatal("expected null CVSS to produce a nil CVSS value")
	}

	if len(finding.EvidenceRefs) != 0 {
		t.Fatalf("expected empty evidence_refs, got %d items", len(finding.EvidenceRefs))
	}
}

func TestFindingRequestRejectsInvalidFields(t *testing.T) {
	tests := []struct {
		name      string
		wantField string
		mutate    func(map[string]any)
	}{
		{
			name:      "unsupported schema version",
			wantField: "schema_version",
			mutate: func(p map[string]any) {
				p["schema_version"] = "2.0"
			},
		},
		{
			name:      "missing finding ID",
			wantField: "finding_id",
			mutate: func(p map[string]any) {
				delete(p, "finding_id")
			},
		},
		{
			name:      "empty finding ID",
			wantField: "finding_id",
			mutate: func(p map[string]any) {
				p["finding_id"] = ""
			},
		},
		{
			name:      "null asset ID",
			wantField: "asset_id",
			mutate: func(p map[string]any) {
				p["asset_id"] = nil
			},
		},
		{
			name:      "null tenant ID",
			wantField: "tenant_id",
			mutate: func(p map[string]any) {
				p["tenant_id"] = nil
			},
		},
		{
			name:      "invalid source",
			wantField: "source",
			mutate: func(p map[string]any) {
				p["source"] = "wazuh"
			},
		},
		{
			name:      "title too long",
			wantField: "title",
			mutate: func(p map[string]any) {
				p["title"] = strings.Repeat("x", 513)
			},
		},
		{
			name:      "invalid status",
			wantField: "status",
			mutate: func(p map[string]any) {
				p["status"] = "open"
			},
		},
		{
			name:      "invalid severity",
			wantField: "severity",
			mutate: func(p map[string]any) {
				p["severity"] = "urgent"
			},
		},
		{
			name:      "confidence above maximum",
			wantField: "confidence",
			mutate: func(p map[string]any) {
				p["confidence"] = 1.01
			},
		},
		{
			name:      "missing detected timestamp",
			wantField: "detected_at",
			mutate: func(p map[string]any) {
				delete(p, "detected_at")
			},
		},
		{
			name:      "invalid detected timestamp",
			wantField: "detected_at",
			mutate: func(p map[string]any) {
				p["detected_at"] = "not-a-date"
			},
		},
		{
			name:      "invalid last observed timestamp",
			wantField: "last_observed_at",
			mutate: func(p map[string]any) {
				p["last_observed_at"] = "not-a-date"
			},
		},
		{
			name:      "missing evidence references",
			wantField: "evidence_refs",
			mutate: func(p map[string]any) {
				delete(p, "evidence_refs")
			},
		},
		{
			name:      "null evidence references",
			wantField: "evidence_refs",
			mutate: func(p map[string]any) {
				p["evidence_refs"] = nil
			},
		},
		{
			name:      "invalid CVSS version",
			wantField: "cvss.version",
			mutate: func(p map[string]any) {
				p["cvss"].(map[string]any)["version"] = "3.1"
			},
		},
		{
			name:      "CVSS score above maximum",
			wantField: "cvss.score",
			mutate: func(p map[string]any) {
				p["cvss"].(map[string]any)["score"] = 10.1
			},
		},
		{
			name:      "invalid CWE identifier",
			wantField: "cwe_ids[0]",
			mutate: func(p map[string]any) {
				p["cwe_ids"] = []any{"CWE-ABC"}
			},
		},
		{
			name:      "duplicate CWE identifier",
			wantField: "cwe_ids[1]",
			mutate: func(p map[string]any) {
				p["cwe_ids"] = []any{"CWE-89", "CWE-89"}
			},
		},
		{
			name:      "invalid reference URI",
			wantField: "references[0]",
			mutate: func(p map[string]any) {
				p["references"] = []any{"not-a-uri"}
			},
		},
		{
			name:      "duplicate references",
			wantField: "references[1]",
			mutate: func(p map[string]any) {
				p["references"] = []any{
					"https://example.test/advisory",
					"https://example.test/advisory",
				}
			},
		},
		{
			name:      "invalid evidence classification",
			wantField: "evidence_refs[0].classification",
			mutate: func(p map[string]any) {
				p["evidence_refs"].([]any)[0].(map[string]any)["classification"] = "secret"
			},
		},
		{
			name:      "missing redacted flag",
			wantField: "evidence_refs[0].redacted",
			mutate: func(p map[string]any) {
				delete(p["evidence_refs"].([]any)[0].(map[string]any), "redacted")
			},
		},
		{
			name:      "invalid SHA256",
			wantField: "evidence_refs[0].sha256",
			mutate: func(p map[string]any) {
				p["evidence_refs"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("g", 64)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := validFindingTestPayload()
			test.mutate(payload)

			_, errs := validateFindingTestPayload(t, payload)

			if !hasFindingFieldError(errs, test.wantField) {
				t.Fatalf(
					"expected validation error for %q, got: %+v",
					test.wantField,
					errs,
				)
			}
		})
	}
}

func TestFindingRequestRejectsUnknownProperties(t *testing.T) {
	t.Run("unknown top-level property", func(t *testing.T) {
		payload := validFindingTestPayload()
		payload["unexpected"] = true

		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}

		var request FindingRequest

		if err := json.Unmarshal(body, &request); err == nil {
			t.Fatal("expected unknown top-level property to be rejected")
		}
	})

	t.Run("unknown CVSS property", func(t *testing.T) {
		payload := validFindingTestPayload()
		payload["cvss"].(map[string]any)["unexpected"] = true

		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}

		var request FindingRequest

		if err := json.Unmarshal(body, &request); err == nil {
			t.Fatal("expected unknown CVSS property to be rejected")
		}
	})

	t.Run("unknown evidence property", func(t *testing.T) {
		payload := validFindingTestPayload()
		payload["evidence_refs"].([]any)[0].(map[string]any)["unexpected"] = true

		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}

		var request FindingRequest

		if err := json.Unmarshal(body, &request); err == nil {
			t.Fatal("expected unknown evidence property to be rejected")
		}
	})
}

func TestFindingRequestRejectsNullEvidenceItem(t *testing.T) {
	payload := validFindingTestPayload()
	payload["evidence_refs"] = []any{nil}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	var request FindingRequest

	if err := json.Unmarshal(body, &request); err == nil {
		t.Fatal("expected null evidence item to be rejected")
	}
}

func TestFindingRequestRejectsNullCWEArrayItem(t *testing.T) {
	payload := validFindingTestPayload()
	payload["cwe_ids"] = []any{nil}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	var request FindingRequest

	if err := json.Unmarshal(body, &request); err == nil {
		t.Fatal("expected null CWE array item to be rejected")
	}
}
