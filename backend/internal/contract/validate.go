package contract

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"
)

// SchemaVersion is the only payload version this API accepts.
const SchemaVersion = "1.0"

// Interim length limits (not in the P2 contract, to be confirmed with P2).
const (
	maxIDLen    = 128
	maxShortLen = 1024
	maxTextLen  = 8192
	maxEventIDs = 1000
)

type validator struct {
	errs []FieldError
}

func (v *validator) add(field, reason string) {
	v.errs = append(v.errs, FieldError{Field: field, Reason: reason})
}

// requiredString: key must be present, non-null, non-blank and within maxLen.
func (v *validator) requiredString(name string, f Field[string], maxLen int) string {
	switch {
	case !f.Present:
		v.add(name, "is required")
	case f.Null:
		v.add(name, "must not be null")
	case strings.TrimSpace(f.Value) == "":
		v.add(name, "must not be empty")
	case utf8.RuneCountInString(f.Value) > maxLen:
		v.add(name, fmt.Sprintf("must be at most %d characters", maxLen))
	default:
		return f.Value
	}
	return ""
}

// nullableString: key must be present but may be null (returns nil for null).
func (v *validator) requiredNullableString(name string, f Field[string], maxLen int) *string {
	if !f.Present {
		v.add(name, "is required (may be null)")
		return nil
	}
	return v.nullableValue(name, f, maxLen)
}

// optionalNullableString: key may be omitted or null.
func (v *validator) optionalNullableString(name string, f Field[string], maxLen int) *string {
	if !f.Present {
		return nil
	}
	return v.nullableValue(name, f, maxLen)
}

func (v *validator) nullableValue(name string, f Field[string], maxLen int) *string {
	if f.Null {
		return nil
	}
	if strings.TrimSpace(f.Value) == "" {
		v.add(name, "must not be empty (use null instead)")
		return nil
	}
	if utf8.RuneCountInString(f.Value) > maxLen {
		v.add(name, fmt.Sprintf("must be at most %d characters", maxLen))
		return nil
	}
	val := f.Value
	return &val
}

func (v *validator) optionalIP(name string, f Field[string]) *string {
	s := v.optionalNullableString(name, f, 64)
	if s == nil {
		return nil
	}
	if _, err := netip.ParseAddr(*s); err != nil {
		v.add(name, "must be a valid IPv4 or IPv6 address")
		return nil
	}
	return s
}

func (v *validator) enum(name string, f Field[string], allowed ...string) string {
	val := v.requiredString(name, f, maxIDLen)
	if val == "" {
		return ""
	}
	for _, a := range allowed {
		if val == a {
			return val
		}
	}
	v.add(name, "must be one of: "+strings.Join(allowed, ", "))
	return ""
}

func (v *validator) schemaVersion(f Field[string]) {
	if val := v.requiredString("schema_version", f, maxIDLen); val != "" && val != SchemaVersion {
		v.add("schema_version", fmt.Sprintf("unsupported version, expected %q", SchemaVersion))
	}
}

// timestamp requires RFC 3339 / ISO 8601 in UTC, i.e. ending in "Z".
func (v *validator) timestamp(f Field[string]) time.Time {
	s := v.requiredString("timestamp", f, maxIDLen)
	if s == "" {
		return time.Time{}
	}
	if !strings.HasSuffix(s, "Z") {
		v.add("timestamp", "must be a UTC ISO 8601 timestamp ending in Z, e.g. 2026-10-26T14:30:00Z")
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		v.add("timestamp", "must be a valid ISO 8601 timestamp, e.g. 2026-10-26T14:30:00Z")
		return time.Time{}
	}
	return t.UTC()
}

func (v *validator) confidence(f Field[float64]) float64 {
	switch {
	case !f.Present:
		v.add("confidence", "is required")
	case f.Null:
		v.add("confidence", "must not be null")
	case f.Value < 0 || f.Value > 1:
		v.add("confidence", "must be a number between 0.0 and 1.0")
	default:
		return f.Value
	}
	return 0
}
