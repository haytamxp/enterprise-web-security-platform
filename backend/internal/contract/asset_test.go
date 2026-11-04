package contract

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

const validAssetJSON = `{
	"schema_version": "1.0",
	"asset_id": "asset-001",
	"tenant_id": "00000000-0000-4000-8000-000000000001",
	"name": "Customer Portal",
	"asset_type": "web_application",
	"environment": "production",
	"owner_team": "platform",
	"criticality": "high",
	"tags": ["internet-facing", "customer-data"],
	"authorization": {
		"status": "approved",
		"approved_by": "security-team",
		"approved_at": "2026-11-04T09:00:00Z",
		"expires_at": null,
		"allowed_targets": ["https://portal.example.com"],
		"excluded_targets": ["https://portal.example.com/admin"],
		"rules_of_engagement_ref": "ROE-2026-001"
	},
	"created_at": "2026-11-04T09:00:00Z",
	"updated_at": "2026-11-04T09:00:00Z"
}`

// decodeAssetJSON follows the same strict unknown-field policy as the HTTP API.
func decodeAssetJSON(data []byte) (AssetRequest, error) {
	var req AssetRequest

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		return req, err
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return req, io.ErrUnexpectedEOF
		}
		return req, err
	}

	return req, nil
}

func hasFieldError(errs []FieldError, field string) bool {
	for _, err := range errs {
		if err.Field == field {
			return true
		}
	}

	return false
}

func TestAssetRequestValidateValidPayload(t *testing.T) {
	req, err := decodeAssetJSON([]byte(validAssetJSON))
	if err != nil {
		t.Fatalf("decode valid asset: %v", err)
	}

	asset, validationErrors := req.Validate()

	if len(validationErrors) != 0 {
		t.Fatalf("expected no validation errors, got: %+v", validationErrors)
	}

	if asset.AssetID != "asset-001" {
		t.Errorf("unexpected asset ID: %q", asset.AssetID)
	}

	if asset.SchemaVersion != SchemaVersion {
		t.Errorf("unexpected schema version: %q", asset.SchemaVersion)
	}

	if asset.AssetType != "web_application" {
		t.Errorf("unexpected asset type: %q", asset.AssetType)
	}

	if asset.Authorization.Status != "approved" {
		t.Errorf("unexpected authorization status: %q",
			asset.Authorization.Status)
	}

	if len(asset.Authorization.AllowedTargets) != 1 {
		t.Errorf("expected one allowed target, got %d",
			len(asset.Authorization.AllowedTargets))
	}

	if asset.Authorization.ApprovedAt == nil {
		t.Error("expected approved_at to be populated")
	}

	if asset.Authorization.ExpiresAt != nil {
		t.Error("expected expires_at to be nil")
	}
}

func TestAssetRequestValidateRejectsInvalidFields(t *testing.T) {
	tests := []struct {
		name  string
		old   string
		new   string
		field string
	}{
		{
			name:  "unsupported schema version",
			old:   `"schema_version": "1.0"`,
			new:   `"schema_version": "2.0"`,
			field: "schema_version",
		},
		{
			name:  "null asset ID",
			old:   `"asset_id": "asset-001"`,
			new:   `"asset_id": null`,
			field: "asset_id",
		},
		{
			name:  "invalid asset type",
			old:   `"asset_type": "web_application"`,
			new:   `"asset_type": "database"`,
			field: "asset_type",
		},
		{
			name:  "invalid environment",
			old:   `"environment": "production"`,
			new:   `"environment": "unknown-value"`,
			field: "environment",
		},
		{
			name:  "invalid criticality",
			old:   `"criticality": "high"`,
			new:   `"criticality": "urgent"`,
			field: "criticality",
		},
		{
			name:  "duplicate tags",
			old:   `"tags": ["internet-facing", "customer-data"]`,
			new:   `"tags": ["internet-facing", "internet-facing"]`,
			field: "tags[1]",
		},
		{
			name:  "invalid allowed target URI",
			old:   `"https://portal.example.com"`,
			new:   `"/relative/path"`,
			field: "authorization.allowed_targets[0]",
		},
		{
			name:  "invalid approval date",
			old:   `"approved_at": "2026-11-04T09:00:00Z"`,
			new:   `"approved_at": "not-a-date"`,
			field: "authorization.approved_at",
		},
		{
			name:  "invalid created_at",
			old:   `"created_at": "2026-11-04T09:00:00Z"`,
			new:   `"created_at": null`,
			field: "created_at",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modified := strings.Replace(
				validAssetJSON,
				tt.old,
				tt.new,
				1,
			)

			if modified == validAssetJSON {
				t.Fatal("test payload replacement did not occur")
			}

			req, err := decodeAssetJSON([]byte(modified))
			if err != nil {
				t.Fatalf("unexpected JSON decoding error: %v", err)
			}

			_, validationErrors := req.Validate()

			if !hasFieldError(validationErrors, tt.field) {
				t.Errorf(
					"expected validation error for %q, got: %+v",
					tt.field,
					validationErrors,
				)
			}
		})
	}
}

func TestAssetRequestRejectsUnknownTopLevelField(t *testing.T) {
	payload := strings.TrimSuffix(validAssetJSON, "}") +
		`, "unexpected_field": true}`

	_, err := decodeAssetJSON([]byte(payload))
	if err == nil {
		t.Fatal("expected unknown top-level field to be rejected")
	}
}

func TestAssetRequestRejectsUnknownAuthorizationField(t *testing.T) {
	payload := strings.Replace(
		validAssetJSON,
		`"status": "approved",`,
		`"status": "approved", "unexpected_field": true,`,
		1,
	)

	_, err := decodeAssetJSON([]byte(payload))
	if err == nil {
		t.Fatal("expected unknown authorization field to be rejected")
	}
}

func TestAssetRequestRejectsNullTagElement(t *testing.T) {
	payload := strings.Replace(
		validAssetJSON,
		`"tags": ["internet-facing", "customer-data"]`,
		`"tags": ["internet-facing", null]`,
		1,
	)

	_, err := decodeAssetJSON([]byte(payload))
	if err == nil {
		t.Fatal("expected null tag element to be rejected")
	}
}

func TestAssetRequestRejectsMissingRequiredField(t *testing.T) {
	payload := strings.Replace(
		validAssetJSON,
		`"name": "Customer Portal",`,
		"",
		1,
	)

	req, err := decodeAssetJSON([]byte(payload))
	if err != nil {
		t.Fatalf("unexpected JSON decoding error: %v", err)
	}

	_, validationErrors := req.Validate()

	if !hasFieldError(validationErrors, "name") {
		t.Fatalf("expected missing name error, got: %+v", validationErrors)
	}
}
