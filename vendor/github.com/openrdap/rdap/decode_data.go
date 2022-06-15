// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

package rdap

// DecodeData stores a snapshot of all fields in an RDAP object (in raw
// interface{} form), at the time of decoding. This allows the values of unknown
// fields to be retrieved.
//
// DecodeData also stores minor warnings/errors generated during decoding.
//
// DecodeData appears in each RDAP struct (e.g. rdap.Domain{}), and is populated
// during decoding. For manually constructed RDAP structs (d :=
// &rdap.Domain{Handle: "x"}...), DecodeData is not relevant and can be ignored.
//
// The snapshot values are entirely independent from other fields, and thus are
// not synchronised in any way.
type DecodeData struct {
	isKnown            map[string]bool
	values             map[string]interface{}
	overrideKnownValue map[string]bool
	notes              map[string][]string
}

// TODO (temporary, using for spew output)
func (r DecodeData) String() string {
	result := "["
	for name, notes := range r.notes {
		for _, note := range notes {
			result += "\n !!!" + name + ": " + note
		}
	}
	result += "\n"

	return result
}

// Notes returns a list of minor warnings/errors encountered while decoding the
// field |name|.
//
// |name| is the RDAP field name (not the Go field name), so "port43", not
// "Port43". For a full list of decoded field names, use Fields().
//
// The warnings/errors returned look like: "invalid JSON type, expecting float".
func (r DecodeData) Notes(name string) []string {
	if notes, ok := r.notes[name]; ok {
		return notes
	}

	return nil
}

//func (r DecodeData) OverrideValue(key string, value interface{}) {
//	r.values[key] = value
//	r.overrideKnownValue[key] = true
//}

// Value returns the value of the field |name| as an interface{}.
//
// |name| is the RDAP field name (not the Go field name), so "port43", not
// "Port43". For a full list of decoded field names, use Fields().
//
func (r DecodeData) Value(name string) interface{} {
	if v, ok := r.values[name]; ok {
		return v
	}

	return nil
}

// Fields returns a list of all RDAP field names decoded.
//
// This includes both known/unknown fields.
//
// The names returned are the RDAP field names (not the Go field names), so
// "port43", not "Port43".
func (r DecodeData) Fields() []string {
	var fields []string

	for f := range r.values {
		fields = append(fields, f)
	}

	return fields
}

// UnknownFields returns a list of unknown RDAP fields decoded.
func (r DecodeData) UnknownFields() []string {
	var fields []string

	for f := range r.values {
		if _, isKnown := r.isKnown[f]; !isKnown {
			fields = append(fields, f)
		}
	}

	return fields
}

func (r *DecodeData) init() {
	r.isKnown = map[string]bool{}
	r.values = map[string]interface{}{}
	r.overrideKnownValue = map[string]bool{}
	r.notes = map[string][]string{}
}
