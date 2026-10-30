// Package contract defines the wire format of P2 payloads and validates it.
package contract

import (
	"bytes"
	"encoding/json"
)

// Field records whether a JSON key was present, was an explicit null, or had
// a value. Plain Go structs cannot tell "omitted" from "null" from "zero
// value", which the P2 contract requires (e.g. event asset_id must be present
// but may be null).
//
// Type mismatches (a string where a number is expected, 4.5 for an int, ...)
// make json decoding fail, which the HTTP layer reports as 400.
type Field[T any] struct {
	Present bool
	Null    bool
	Value   T
}

// UnmarshalJSON is only called by encoding/json when the key exists in the
// payload, so being called at all means Present is true.
func (f *Field[T]) UnmarshalJSON(data []byte) error {
	f.Present = true
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		f.Null = true
		return nil
	}
	return json.Unmarshal(data, &f.Value)
}

// FieldError describes one validation failure. The list of these is what the
// HTTP layer will turn into a 400 response.
type FieldError struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}
