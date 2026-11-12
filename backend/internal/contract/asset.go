package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// StringArray validates that every JSON array element is actually a string.
// encoding/json normally treats null as the zero value of a string, so this
// type prevents null elements from silently becoming empty strings.
type StringArray []string

func (a *StringArray) UnmarshalJSON(data []byte) error {
	var rawItems []json.RawMessage

	if err := json.Unmarshal(data, &rawItems); err != nil {
		return fmt.Errorf("must be an array of strings: %w", err)
	}

	values := make(StringArray, len(rawItems))

	for i, raw := range rawItems {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("item %d must not be null", i)
		}

		if err := json.Unmarshal(raw, &values[i]); err != nil {
			return fmt.Errorf("item %d must be a string: %w", i, err)
		}
	}

	*a = values
	return nil
}

// AssetAuthorizationRequest represents the nested authorization object
// received from the JSON API.
type AssetAuthorizationRequest struct {
	Status               Field[string]      `json:"status"`
	ApprovedBy           Field[string]      `json:"approved_by"`
	ApprovedAt           Field[string]      `json:"approved_at"`
	ExpiresAt            Field[string]      `json:"expires_at"`
	AllowedTargets       Field[StringArray] `json:"allowed_targets"`
	ExcludedTargets      Field[StringArray] `json:"excluded_targets"`
	RulesOfEngagementRef Field[string]      `json:"rules_of_engagement_ref"`
}

// UnmarshalJSON rejects unknown properties inside the authorization object.
// This preserves the contract's additionalProperties: false rule.
func (r *AssetAuthorizationRequest) UnmarshalJSON(data []byte) error {
	type wire AssetAuthorizationRequest

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var decoded wire

	if err := decoder.Decode(&decoded); err != nil {
		return err
	}

	*r = AssetAuthorizationRequest(decoded)
	return nil
}

// AssetRequest represents the raw JSON body of an Asset request.
type AssetRequest struct {
	SchemaVersion Field[string]                    `json:"schema_version"`
	AssetID       Field[string]                    `json:"asset_id"`
	TenantID      Field[string]                    `json:"tenant_id"`
	Name          Field[string]                    `json:"name"`
	AssetType     Field[string]                    `json:"asset_type"`
	Environment   Field[string]                    `json:"environment"`
	OwnerTeam     Field[string]                    `json:"owner_team"`
	Criticality   Field[string]                    `json:"criticality"`
	Tags          Field[StringArray]               `json:"tags"`
	Authorization Field[AssetAuthorizationRequest] `json:"authorization"`
	CreatedAt     Field[string]                    `json:"created_at"`
	UpdatedAt     Field[string]                    `json:"updated_at"`
}

// AssetAuthorization is the validated authorization information.
type AssetAuthorization struct {
	Status               string
	ApprovedBy           *string
	ApprovedAt           *time.Time
	ExpiresAt            *time.Time
	AllowedTargets       []string
	ExcludedTargets      []string
	RulesOfEngagementRef *string
}

// Asset is a validated Asset ready for the storage layer.
type Asset struct {
	SchemaVersion string
	AssetID       string
	TenantID      string
	Name          string
	AssetType     string
	Environment   string
	OwnerTeam     string
	Criticality   string
	Tags          []string
	Authorization AssetAuthorization
	CreatedAt     *time.Time
	UpdatedAt     *time.Time
}

// optionalContractString validates an optional string field.
// The asset contract allows empty strings for these optional properties,
// because it specifies maxLength but not minLength.
func (v *validator) optionalContractString(
	name string,
	f Field[string],
	maxLen int,
	nullable bool,
) *string {
	if !f.Present {
		return nil
	}

	if f.Null {
		if !nullable {
			v.add(name, "must not be null")
		}
		return nil
	}

	if utf8.RuneCountInString(f.Value) > maxLen {
		v.add(name, fmt.Sprintf("must be at most %d characters", maxLen))
		return nil
	}

	value := f.Value
	return &value
}

// optionalDateTime validates an optional RFC3339 date-time.
// When nullable is true, an explicit JSON null is also accepted.
func (v *validator) optionalDateTime(
	name string,
	f Field[string],
	nullable bool,
) *time.Time {
	if !f.Present {
		return nil
	}

	if f.Null {
		if !nullable {
			v.add(name, "must not be null")
		}
		return nil
	}

	parsed, err := time.Parse(time.RFC3339, f.Value)
	if err != nil {
		v.add(name, "must be a valid RFC3339 date-time")
		return nil
	}

	parsed = parsed.UTC()
	return &parsed
}

// requiredURIArray validates a required array containing absolute URIs.
func (v *validator) requiredURIArray(
	name string,
	f Field[StringArray],
) []string {
	if !f.Present {
		v.add(name, "is required")
		return nil
	}

	if f.Null {
		v.add(name, "must not be null")
		return nil
	}

	values := []string(f.Value)

	for i, value := range values {
		if !isAbsoluteURI(value) {
			v.add(
				fmt.Sprintf("%s[%d]", name, i),
				"must be a valid absolute URI",
			)
		}
	}

	return values
}

// optionalTags validates the optional tags array.
// Tags must be unique and each tag must contain at most 64 characters.
func (v *validator) optionalTags(f Field[StringArray]) []string {
	if !f.Present {
		return nil
	}

	if f.Null {
		v.add("tags", "must be an array and must not be null")
		return nil
	}

	values := []string(f.Value)
	seen := make(map[string]struct{}, len(values))

	for i, tag := range values {
		if utf8.RuneCountInString(tag) > 64 {
			v.add(
				fmt.Sprintf("tags[%d]", i),
				"must be at most 64 characters",
			)
		}

		if _, exists := seen[tag]; exists {
			v.add(
				fmt.Sprintf("tags[%d]", i),
				"must be unique",
			)
		}

		seen[tag] = struct{}{}
	}

	return values
}

// isAbsoluteURI checks that a value is a syntactically valid absolute URI.
// Schemes such as https, http, and other valid URI schemes are accepted.
func isAbsoluteURI(value string) bool {
	if value == "" {
		return false
	}

	if strings.IndexFunc(value, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) >= 0 {
		return false
	}

	parsed, err := url.Parse(value)
	if err != nil {
		return false
	}

	return parsed.Scheme != ""
}

// Validate checks the Asset request against asset.schema.json.
// The returned Asset must not be used when validation errors are present.
func (r AssetRequest) Validate() (Asset, []FieldError) {
	var v validator
	var asset Asset

	asset.SchemaVersion = SchemaVersion
	v.schemaVersion(r.SchemaVersion)

	asset.AssetID = v.requiredString("asset_id", r.AssetID, 128)
	asset.TenantID = v.requiredString("tenant_id", r.TenantID, 128)
	asset.Name = v.requiredString("name", r.Name, 256)

	asset.AssetType = v.enum(
		"asset_type",
		r.AssetType,
		"web_application",
		"api",
		"host",
		"network_device",
		"cloud_resource",
		"other",
	)

	asset.Environment = v.enum(
		"environment",
		r.Environment,
		"development",
		"test",
		"staging",
		"production",
		"unknown",
	)

	asset.OwnerTeam = v.requiredString("owner_team", r.OwnerTeam, 128)

	asset.Criticality = v.enum(
		"criticality",
		r.Criticality,
		"critical",
		"high",
		"medium",
		"low",
		"unknown",
	)

	asset.Tags = v.optionalTags(r.Tags)

	// Validate the required authorization object.
	switch {
	case !r.Authorization.Present:
		v.add("authorization", "is required")

	case r.Authorization.Null:
		v.add("authorization", "must not be null")

	default:
		authRequest := r.Authorization.Value

		asset.Authorization.Status = v.enum(
			"authorization.status",
			authRequest.Status,
			"pending",
			"approved",
			"expired",
			"revoked",
			"not_authorized",
		)

		asset.Authorization.ApprovedBy = v.optionalContractString(
			"authorization.approved_by",
			authRequest.ApprovedBy,
			128,
			true,
		)

		asset.Authorization.ApprovedAt = v.optionalDateTime(
			"authorization.approved_at",
			authRequest.ApprovedAt,
			true,
		)

		asset.Authorization.ExpiresAt = v.optionalDateTime(
			"authorization.expires_at",
			authRequest.ExpiresAt,
			true,
		)

		asset.Authorization.AllowedTargets = v.requiredURIArray(
			"authorization.allowed_targets",
			authRequest.AllowedTargets,
		)

		asset.Authorization.ExcludedTargets = v.requiredURIArray(
			"authorization.excluded_targets",
			authRequest.ExcludedTargets,
		)

		asset.Authorization.RulesOfEngagementRef =
			v.optionalContractString(
				"authorization.rules_of_engagement_ref",
				authRequest.RulesOfEngagementRef,
				512,
				true,
			)
	}

	asset.CreatedAt = v.optionalDateTime(
		"created_at",
		r.CreatedAt,
		false,
	)

	asset.UpdatedAt = v.optionalDateTime(
		"updated_at",
		r.UpdatedAt,
		false,
	)

	return asset, v.errs
}
