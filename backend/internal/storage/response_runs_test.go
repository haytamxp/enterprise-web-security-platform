package storage

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestValidateCreateResponseRun(t *testing.T) {
	valid := CreateResponseRunParams{
		ResponseRunID:  "run-1",
		IncidentID:     "incident-1",
		PlaybookID:     "playbook-1",
		IdempotencyKey: "idem-1",
	}
	if err := validateCreateResponseRun(valid); err != nil {
		t.Fatalf("valid response run rejected: %v", err)
	}

	invalid := []CreateResponseRunParams{
		{},
		{ResponseRunID: "run-1", IncidentID: "incident-1", PlaybookID: "playbook-1"},
		{ResponseRunID: strings.Repeat("r", 129), IncidentID: "incident-1", PlaybookID: "playbook-1", IdempotencyKey: "idem-1"},
		{ResponseRunID: "run-1", IncidentID: "incident-1", PlaybookID: "playbook-1", IdempotencyKey: "idem-1", RequestReason: stringPointerForResponseTest(strings.Repeat("x", 2001))},
	}
	for i, input := range invalid {
		if err := validateCreateResponseRun(input); !errors.Is(err, ErrInvalidResponseRun) {
			t.Fatalf("invalid response run case %d: expected ErrInvalidResponseRun, got %v", i, err)
		}
	}
}

func TestValidateResponseExecutionFinish(t *testing.T) {
	valid := []string{"succeeded", "failed", "skipped", "timed_out", "cancelled"}
	for _, status := range valid {
		t.Run(status, func(t *testing.T) {
			if err := validateResponseExecutionFinish(FinishResponseActionExecutionParams{Status: status}); err != nil {
				t.Fatalf("valid status %q rejected: %v", status, err)
			}
		})
	}
	invalid := []FinishResponseActionExecutionParams{
		{},
		{Status: "pending"},
		{Status: "running"},
		{Status: "succeeded", ResultSummary: stringPointerForResponseTest(strings.Repeat("x", 5001))},
		{Status: "failed", ErrorCode: stringPointerForResponseTest(strings.Repeat("e", 65))},
		{Status: "failed", ExternalReference: stringPointerForResponseTest(strings.Repeat("x", 256))},
	}
	for i, input := range invalid {
		if err := validateResponseExecutionFinish(input); !errors.Is(err, ErrInvalidResponseExecution) {
			t.Fatalf("invalid execution result case %d: expected ErrInvalidResponseExecution, got %v", i, err)
		}
	}
}

func TestSameOptionalString(t *testing.T) {
	if !sameOptionalString(nil, nil) {
		t.Fatal("nil values should match")
	}
	if sameOptionalString(nil, stringPointerForResponseTest("value")) {
		t.Fatal("nil and non-nil values should not match")
	}
	if !sameOptionalString(stringPointerForResponseTest("same"), stringPointerForResponseTest("same")) {
		t.Fatal("equal values should match")
	}
}

func TestNormalizeResponseRunReasonAndConfigRemainJSONSafe(t *testing.T) {
	config := json.RawMessage(`{"target":"192.0.2.10"}`)
	normalized, err := normalizeResponseActionConfig(config)
	if err != nil {
		t.Fatalf("normalize action config: %v", err)
	}
	if !json.Valid(normalized) {
		t.Fatalf("normalized config is not valid JSON: %s", normalized)
	}
}

func stringPointerForResponseTest(value string) *string { return &value }
