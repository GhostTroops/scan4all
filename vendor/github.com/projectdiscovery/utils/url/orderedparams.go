package urlutil

import (
	"bytes"
	"strings"

	mapsutil "github.com/projectdiscovery/utils/maps"
)

// Only difference between OrderedParams and Params is that
// OrderedParams preserves order of parameters everythign else is same

// OrderedParams is a map that preserves the order of elements
type OrderedParams struct {
	om mapsutil.OrderedMap[string, []string]
}

// NewOrderedParams creates a new ordered params
func NewOrderedParams() *OrderedParams {
	return &OrderedParams{
		om: mapsutil.NewOrderedMap[string, []string](),
	}
}

// IsEmpty checks if the OrderedParams is empty
func (o *OrderedParams) IsEmpty() bool {
	return o.om.IsEmpty()
}

// Update is similar to Set but it takes value as slice (similar to internal implementation of url.Values)
func (o *OrderedParams) Update(key string, value []string) {
	o.om.Set(key, value)
}

// Iterate iterates over the OrderedParams
func (o *OrderedParams) Iterate(f func(key string, value []string) bool) {
	o.om.Iterate(func(key string, value []string) bool {
		return f(key, value)
	})
}

// Add Parameters to store
func (o *OrderedParams) Add(key string, value ...string) {
	if arr, ok := o.om.Get(key); ok && len(arr) > 0 {
		if len(value) != 0 {
			o.om.Set(key, append(arr, value...))
		}
	} else {
		o.om.Set(key, value)
	}
}

// Set sets the key to value and replaces if already exists
func (o *OrderedParams) Set(key string, value string) {
	o.om.Set(key, []string{value})
}

// Get returns first value of given key
func (o *OrderedParams) Get(key string) string {
	val, ok := o.om.Get(key)
	if !ok || len(val) == 0 {
		return ""
	}
	return val[0]
}

// GetAll returns all values of given key or returns empty slice if key doesn't exist
func (o *OrderedParams) GetAll(key string) []string {
	val, ok := o.om.Get(key)
	if !ok || len(val) == 0 {
		return []string{}
	}
	return val
}

// Has returns if given key exists
func (o *OrderedParams) Has(key string) bool {
	return o.om.Has(key)
}

// Del deletes values associated with key
func (o *OrderedParams) Del(key string) {
	o.om.Delete(key)
}

// Merges given paramset into existing one with base as priority
func (o *OrderedParams) Merge(raw string) {
	o.Decode(raw)
}

// Encode returns encoded parameters by preserving order
func (o *OrderedParams) Encode() string {
	if o.om.IsEmpty() {
		return ""
	}
	var buf strings.Builder
	for _, k := range o.om.GetKeys() {
		vs, _ := o.om.Get(k)
		keyEscaped := ParamEncode(k)
		for _, v := range vs {
			if buf.Len() > 0 {
				buf.WriteByte('&')
			}
			buf.WriteString(keyEscaped)
			value := ParamEncode(v)
			// donot specify = if parameter has no value (reference: nuclei-templates)
			if value != "" {
				buf.WriteRune('=')
				buf.WriteString(value)
			}
		}
	}
	return buf.String()
}

// Decode is opposite of Encode() where ("bar=baz&foo=quux") is parsed
// Parameters are loosely parsed to allow any scenario
func (o *OrderedParams) Decode(raw string) {
	if o.om.Len() == 0 {
		o.om = mapsutil.NewOrderedMap[string, []string]()
	}
	arr := []string{}
	var tbuff bytes.Buffer
	for _, v := range raw {
		switch v {
		case '&':
			arr = append(arr, tbuff.String())
			tbuff.Reset()
		case ';':
			if AllowLegacySeperator {
				arr = append(arr, tbuff.String())
				tbuff.Reset()
				continue
			}
			tbuff.WriteRune(v)
		default:
			tbuff.WriteRune(v)
		}
	}
	if tbuff.Len() > 0 {
		arr = append(arr, tbuff.String())
	}

	for _, pair := range arr {
		d := strings.SplitN(pair, "=", 2)
		if len(d) == 2 {
			o.Add(d[0], d[1])
		} else if len(d) == 1 {
			o.Add(d[0], "")
		}
	}
}

// Clone returns a copy of the ordered params
func (o *OrderedParams) Clone() *OrderedParams {
	clone := NewOrderedParams()
	o.om.Iterate(func(key string, value []string) bool {
		// this needs to be a deep copy (from reference in nuclei race condition issue)
		if len(value) != 0 {
			clone.Add(key, value...)
		} else {
			clone.Add(key, "")
		}
		return true
	})
	return clone
}
