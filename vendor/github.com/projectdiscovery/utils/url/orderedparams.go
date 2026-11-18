package urlutil

import (
	"bytes"
	"strings"
)

// paramEntry holds one "key" or "key=value" pair from a query string.
//
// raw, when non-empty, is the original encoded segment captured by
// Decode and is emitted verbatim by Encode. This is what allows a
// decoded query string to round-trip byte-for-byte: entries that the
// caller never touches are written back exactly as they came in.
//
// Programmatic mutations (Add, Set, Update) create entries with an
// empty raw; those follow the historical encoding path (ParamEncode +
// IncludeEquals). Del simply drops entries.
type paramEntry struct {
	key       string
	value     string
	hasEquals bool
	raw       string
}

// OrderedParams keeps query parameters in insertion order and, for
// parameters parsed from a query string, preserves the exact original
// byte form so the string round-trips through Encode unchanged.
//
// Programmatically added or mutated parameters are encoded using
// ParamEncode and the IncludeEquals flag, matching the historical
// behavior of this type.
type OrderedParams struct {
	entries []paramEntry
	// IncludeEquals controls whether "=" is appended when an empty
	// value is encoded. It applies only to programmatically
	// added/mutated parameters - parameters that came from Decode
	// keep the "=" (or lack thereof) they had originally.
	IncludeEquals bool
}

// NewOrderedParams creates a new ordered params
func NewOrderedParams() *OrderedParams {
	return &OrderedParams{}
}

// IsEmpty checks if the OrderedParams is empty
func (o *OrderedParams) IsEmpty() bool {
	return len(o.entries) == 0
}

// Update replaces every value associated with key by the given slice.
// If key already exists the replacement keeps its position in the
// insertion order; otherwise the new values are appended.
func (o *OrderedParams) Update(key string, value []string) {
	out := make([]paramEntry, 0, len(o.entries)+len(value))
	inserted := false
	for _, e := range o.entries {
		if e.key == key {
			if !inserted {
				for _, v := range value {
					out = append(out, paramEntry{key: key, value: v})
				}
				inserted = true
			}
			continue
		}
		out = append(out, e)
	}
	if !inserted {
		for _, v := range value {
			out = append(out, paramEntry{key: key, value: v})
		}
	}
	o.entries = out
}

// Iterate iterates over the OrderedParams. Entries that share a key
// are grouped and the callback receives every key exactly once, in
// the order of its first appearance, together with the full list of
// decoded values for that key.
func (o *OrderedParams) Iterate(f func(key string, value []string) bool) {
	seen := make(map[string]struct{}, len(o.entries))
	order := make([]string, 0, len(o.entries))
	groups := make(map[string][]string, len(o.entries))
	for _, e := range o.entries {
		if _, ok := seen[e.key]; !ok {
			seen[e.key] = struct{}{}
			order = append(order, e.key)
		}
		groups[e.key] = append(groups[e.key], e.value)
	}
	for _, k := range order {
		if !f(k, groups[k]) {
			return
		}
	}
}

// Add appends one entry per value to the store. Calling Add with no
// values is a no-op.
func (o *OrderedParams) Add(key string, value ...string) {
	for _, v := range value {
		o.entries = append(o.entries, paramEntry{key: key, value: v})
	}
}

// Set replaces all values of key with a single value. The position
// of the first occurrence of key is preserved; later occurrences are
// removed. If the key is missing it is appended at the end.
func (o *OrderedParams) Set(key string, value string) {
	out := make([]paramEntry, 0, len(o.entries)+1)
	inserted := false
	for _, e := range o.entries {
		if e.key == key {
			if !inserted {
				out = append(out, paramEntry{key: key, value: value})
				inserted = true
			}
			continue
		}
		out = append(out, e)
	}
	if !inserted {
		out = append(out, paramEntry{key: key, value: value})
	}
	o.entries = out
}

// Get returns the first value associated with key, or "" if absent.
func (o *OrderedParams) Get(key string) string {
	for _, e := range o.entries {
		if e.key == key {
			return e.value
		}
	}
	return ""
}

// GetAll returns every value associated with key in insertion order,
// or an empty slice if key is absent.
func (o *OrderedParams) GetAll(key string) []string {
	var out []string
	for _, e := range o.entries {
		if e.key == key {
			out = append(out, e.value)
		}
	}
	if out == nil {
		return []string{}
	}
	return out
}

// Has reports whether key is present.
func (o *OrderedParams) Has(key string) bool {
	for _, e := range o.entries {
		if e.key == key {
			return true
		}
	}
	return false
}

// Del removes every entry whose key matches.
func (o *OrderedParams) Del(key string) {
	out := o.entries[:0]
	for _, e := range o.entries {
		if e.key == key {
			continue
		}
		out = append(out, e)
	}
	o.entries = out
}

// Merge parses raw and appends its parameters to the current store.
func (o *OrderedParams) Merge(raw string) {
	o.Decode(raw)
}

// Encode returns the encoded query string. Entries that came from
// Decode are emitted verbatim, preserving the original byte form
// (including whether "=" was present and the exact escaping).
// Entries added programmatically use ParamEncode and the
// IncludeEquals flag.
func (o *OrderedParams) Encode() string {
	if len(o.entries) == 0 {
		return ""
	}
	var buf strings.Builder
	for _, e := range o.entries {
		if buf.Len() > 0 {
			buf.WriteByte('&')
		}
		if e.raw != "" {
			buf.WriteString(e.raw)
			continue
		}
		buf.WriteString(ParamEncode(e.key))
		value := ParamEncode(e.value)
		// donot specify = if parameter has no value (reference: nuclei-templates)
		if o.IncludeEquals || value != "" {
			buf.WriteByte('=')
			buf.WriteString(value)
		}
	}
	return buf.String()
}

// Decode parses raw and appends its parameters to the current store.
// Each segment's original byte form is remembered so that an
// unmodified Decode+Encode round-trip produces an identical string.
// Parameters are loosely parsed to allow any scenario.
func (o *OrderedParams) Decode(raw string) {
	if raw == "" {
		return
	}
	segments := splitSegments(raw)
	for _, pair := range segments {
		eq := strings.IndexByte(pair, '=')
		entry := paramEntry{raw: pair}
		if eq >= 0 {
			entry.key = pair[:eq]
			entry.value = pair[eq+1:]
			entry.hasEquals = true
		} else {
			entry.key = pair
		}
		o.entries = append(o.entries, entry)
	}
}

// splitSegments splits a query string on "&" (and on ";" when
// AllowLegacySeperator is set), returning each segment verbatim.
func splitSegments(raw string) []string {
	var segments []string
	var buf bytes.Buffer
	for _, r := range raw {
		switch r {
		case '&':
			segments = append(segments, buf.String())
			buf.Reset()
		case ';':
			if AllowLegacySeperator {
				segments = append(segments, buf.String())
				buf.Reset()
				continue
			}
			buf.WriteRune(r)
		default:
			buf.WriteRune(r)
		}
	}
	if buf.Len() > 0 {
		segments = append(segments, buf.String())
	}
	return segments
}

// Clone returns a deep copy of the OrderedParams.
func (o *OrderedParams) Clone() *OrderedParams {
	clone := &OrderedParams{
		IncludeEquals: o.IncludeEquals,
		entries:       append([]paramEntry(nil), o.entries...),
	}
	return clone
}
