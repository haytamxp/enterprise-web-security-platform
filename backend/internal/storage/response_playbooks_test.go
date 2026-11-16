package storage

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestValidateResponseActionType(t *testing.T) {
	tests := []struct {
		name      string
		action    string
		wantValid bool
	}{
		{name: "notify", action: "notify", wantValid: true},
		{name: "block IP", action: "block_ip", wantValid: true},
		{name: "isolate host", action: "isolate_host", wantValid: true},
		{name: "disable account", action: "disable_account", wantValid: true},
		{name: "collect evidence", action: "collect_evidence", wantValid: true},
		{name: "arbitrary command rejected", action: "shell", wantValid: false},
		{name: "empty rejected", action: "", wantValid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateResponseActionType(tt.action); got != tt.wantValid {
				t.Fatalf("validateResponseActionType(%q) = %v, want %v", tt.action, got, tt.wantValid)
			}
		})
	}
}

func TestNormalizeResponseActionConfig(t *testing.T) {
	tests := []struct {
		name    string
		input   json.RawMessage
		want    string
		wantErr bool
	}{
		{name: "empty defaults to object", input: nil, want: `{}`},
		{name: "valid object", input: json.RawMessage(`{"ip_address":"192.0.2.10"}`), want: `{"ip_address":"192.0.2.10"}`},
		{name: "array rejected", input: json.RawMessage(`[]`), wantErr: true},
		{name: "null rejected", input: json.RawMessage(`null`), wantErr: true},
		{name: "string rejected", input: json.RawMessage(`"value"`), wantErr: true},
		{name: "invalid JSON rejected", input: json.RawMessage(`{`), wantErr: true},
		{name: "oversized config rejected", input: json.RawMessage(`{"data":"` + strings.Repeat("x", maxResponseActionConfigSize) + `"}`), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeResponseActionConfig(tt.input)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidResponseAction) {
					t.Fatalf("expected ErrInvalidResponseAction, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeResponseActionConfig returned error: %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("normalized config = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestValidateCreateResponsePlaybook(t *testing.T) {
	valid := CreateResponsePlaybookParams{PlaybookID: "pb-1", Name: "Contain suspicious host"}
	if err := validateCreateResponsePlaybook(valid); err != nil {
		t.Fatalf("valid playbook rejected: %v", err)
	}

	invalid := []CreateResponsePlaybookParams{
		{},
		{PlaybookID: "pb-1"},
		{PlaybookID: "pb-1", Name: strings.Repeat("n", 201)},
		{PlaybookID: strings.Repeat("p", 129), Name: "Playbook"},
	}
	for i, input := range invalid {
		if err := validateCreateResponsePlaybook(input); !errors.Is(err, ErrInvalidResponsePlaybook) {
			t.Fatalf("invalid playbook case %d: expected ErrInvalidResponsePlaybook, got %v", i, err)
		}
	}
}
