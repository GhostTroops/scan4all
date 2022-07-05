// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

package rdap

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// VCard represents a vCard.
//
// A vCard represents information about an individual or entity. It can include
// a name, telephone number, e-mail, delivery address, and other information.
//
// There are several vCard text formats. This implementation encodes/decodes the
// jCard format used by RDAP, as defined in https://tools.ietf.org/html/rfc7095.
//
// A jCard consists of an array of properties (e.g. "fn", "tel") describing the
// individual or entity. Properties may be repeated, e.g. to represent multiple
// telephone numbers. RFC6350 documents a set of standard properties.
//
// RFC7095 describes the JSON document format, which looks like:
//   ["vcard", [
//     [
//       ["version", {}, "text", "4.0"],
//       ["fn", {}, "text", "Joe Appleseed"],
//       ["tel", {
//             "type":["work", "voice"],
//           },
//           "uri",
//           "tel:+1-555-555-1234;ext=555"
//       ],
//       ...
//     ]
//   ]
type VCard struct {
	Properties []*VCardProperty
}

// VCardProperty represents a single vCard property.
//
// Each vCard property has four fields, these are:
//    Name   Parameters                  Type   Value
//    -----  --------------------------  -----  -----------------------------
//   ["tel", {"type":["work", "voice"]}, "uri", "tel:+1-555-555-1234;ext=555"]
type VCardProperty struct {
	Name string

	// vCard parameters can be a string, or array of strings.
	//
	// To simplify our usage, single strings are represented as an array of
	// length one.
	Parameters map[string][]string
	Type       string

	// A property value can be a simple type (string/float64/bool/nil), or be
	// an array. Arrays can be nested, and can contain a mixture of types.
	//
	// Value is one of the following:
	//   * string
	//   * float64
	//   * bool
	//   * nil
	//   * []interface{}. Can contain a mixture of these five types.
	//
	// To retrieve the property value flattened into a []string, use Values().
	Value interface{}
}

// Values returns a simplified representation of the VCardProperty value.
//
// This is convenient for accessing simple unstructured data (e.g. "fn", "tel").
//
// The simplified []string representation is created by flattening the
// (potentially nested) VCardProperty value, and converting all values to strings.
func (p *VCardProperty) Values() []string {
	strings := make([]string, 0, 1)

	p.appendValueStrings(p.Value, &strings)

	return strings
}

func (p *VCardProperty) appendValueStrings(v interface{}, strings *[]string) {
	switch v := v.(type) {
	case nil:
		*strings = append(*strings, "")
	case bool:
		*strings = append(*strings, strconv.FormatBool(v))
	case float64:
		*strings = append(*strings, strconv.FormatFloat(v, 'f', -1, 64))
	case string:
		*strings = append(*strings, v)
	case []interface{}:
		for _, v2 := range v {
			p.appendValueStrings(v2, strings)
		}
	default:
		panic("Unknown type")
	}

}

// String returns the vCard as a multiline human readable string. For example:
//
//   vCard[
//     version (type=text, parameters=map[]): [4.0]
//     mixed (type=text, parameters=map[]): [abc true 42 <nil> [def false 43]]
//   ]
//
// This is intended for debugging only, and is not machine parsable.
func (v *VCard) String() string {
	s := make([]string, 0, len(v.Properties))

	for _, s2 := range v.Properties {
		s = append(s, s2.String())
	}

	return "vCard[\n" + strings.Join(s, "\n") + "\n]"
}

// String returns the VCardProperty as a human readable string. For example:
//
//     mixed (type=text, parameters=map[]): [abc true 42 <nil> [def false 43]]
//
// This is intended for debugging only, and is not machine parsable.
func (p *VCardProperty) String() string {
	return fmt.Sprintf("  %s (type=%s, parameters=%v): %v", p.Name, p.Type, p.Parameters, p.Value)
}

// NewVCard creates a VCard from jsonBlob.
func NewVCard(jsonBlob []byte) (*VCard, error) {
	var top []interface{}
	err := json.Unmarshal(jsonBlob, &top)

	if err != nil {
		return nil, err
	}

	var vcard *VCard
	vcard, err = newVCardImpl(top)

	return vcard, err
}

func newVCardImpl(src interface{}) (*VCard, error) {
	top, ok := src.([]interface{})

	if !ok || len(top) != 2 {
		return nil, vCardError("structure is not a jCard (expected len=2 top level array)")
	} else if s, ok := top[0].(string); !(ok && s == "vcard") {
		return nil, vCardError("structure is not a jCard (missing 'vcard')")
	}

	var properties []interface{}

	properties, ok = top[1].([]interface{})
	if !ok {
		return nil, vCardError("structure is not a jCard (bad properties array)")
	}

	v := &VCard{
		Properties: make([]*VCardProperty, 0, len(properties)),
	}

	var p interface{}
	for _, p = range top[1].([]interface{}) {
		var a []interface{}
		var ok bool
		a, ok = p.([]interface{})

		if !ok {
			return nil, vCardError("jCard property was not an array")
		} else if len(a) < 4 {
			return nil, vCardError("jCard property too short (>=4 array elements required)")
		}

		name, ok := a[0].(string)

		if !ok {
			return nil, vCardError("jCard property name invalid")
		}

		var parameters map[string][]string
		var err error
		parameters, err = readParameters(a[1])

		if err != nil {
			return nil, err
		}

		propertyType, ok := a[2].(string)

		if !ok {
			return nil, vCardError("jCard property type invalid")
		}

		var value interface{}
		if len(a) == 4 {
			value, err = readValue(a[3], 0)
		} else {
			value, err = readValue(a[3:], 0)
		}

		if err != nil {
			return nil, err
		}

		property := &VCardProperty{
			Name:       name,
			Type:       propertyType,
			Parameters: parameters,
			Value:      value,
		}

		v.Properties = append(v.Properties, property)
	}

	return v, nil
}

// Get returns a list of the vCard Properties with VCardProperty name |name|.
func (v *VCard) Get(name string) []*VCardProperty {
	var properties []*VCardProperty

	for _, p := range v.Properties {
		if p.Name == name {
			properties = append(properties, p)
		}
	}

	return properties
}

// GetFirst returns the first vCard Property with name |name|.
//
// TODO(tfh): Implement "pref" ordering, instead of taking the first listed property?
func (v *VCard) GetFirst(name string) *VCardProperty {
	properties := v.Get(name)

	if len(properties) == 0 {
		return nil
	}

	return properties[0]
}

func vCardError(e string) error {
	return fmt.Errorf("jCard error: %s", e)
}

func readParameters(p interface{}) (map[string][]string, error) {
	params := map[string][]string{}

	if _, ok := p.(map[string]interface{}); !ok {
		return nil, vCardError("jCard parameters invalid")
	}

	for k, v := range p.(map[string]interface{}) {
		if s, ok := v.(string); ok {
			params[k] = append(params[k], s)
		} else if arr, ok := v.([]interface{}); ok {
			for _, value := range arr {
				if s, ok := value.(string); ok {
					params[k] = append(params[k], s)
				}
			}
		}
	}

	return params, nil
}

func readValue(value interface{}, depth int) (interface{}, error) {
	switch value := value.(type) {
	case nil:
		return nil, nil
	case string:
		return value, nil
	case bool:
		return value, nil
	case float64:
		return value, nil
	case []interface{}:
		if depth == 3 {
			return "", vCardError("Structured value too deep")
		}

		result := make([]interface{}, 0, len(value))

		for _, v2 := range value {
			v3, err := readValue(v2, depth+1)

			if err != nil {
				return nil, err
			}

			result = append(result, v3)
		}

		return result, nil
	default:
		return nil, vCardError("Unknown JSON datatype in jCard value")
	}
}

func (v *VCard) getFirstPropertySingleString(name string) string {
	property := v.GetFirst(name)

	if property == nil {
		return ""
	}

	return strings.Join(property.Values(), " ")
}

// Name returns the VCard's name. e.g. "John Smith".
func (v *VCard) Name() string {
	return v.getFirstPropertySingleString("fn")
}

// POBox returns the address's PO Box.
//
// Returns empty string if no address is present.
func (v *VCard) POBox() string {
	return v.getFirstAddressField(0)
}

// ExtendedAddress returns the "extended address", e.g. an apartment
// or suite number.
//
// Returns empty string if no address is present.
func (v *VCard) ExtendedAddress() string {
	return v.getFirstAddressField(1)
}

// StreetAddress returns the street address.
//
// Returns empty string if no address is present.
func (v *VCard) StreetAddress() string {
	return v.getFirstAddressField(2)
}

// Locality returns the address locality.
//
// Returns empty string if no address is present.
func (v *VCard) Locality() string {
	return v.getFirstAddressField(3)
}

// Region returns the address region (e.g. state or province).
//
// Returns empty string if no address is present.
func (v *VCard) Region() string {
	return v.getFirstAddressField(4)
}

// PostalCode returns the address postal code (e.g. zip code).
//
// Returns empty string if no address is present.
func (v *VCard) PostalCode() string {
	return v.getFirstAddressField(5)
}

// Country returns the address country name.
//
// This is the full country name.
//
// Returns empty string if no address is present.
func (v *VCard) Country() string {
	return v.getFirstAddressField(6)
}

// Tel returns the VCard's first (voice) telephone number.
//
// Returns empty string if the VCard contains no suitable telephone number.
func (v *VCard) Tel() string {
	properties := v.Get("tel")

	for _, p := range properties {
		isVoice := false

		if types, ok := p.Parameters["type"]; ok {
			for _, t := range types {
				if t == "voice" {
					isVoice = true
					break
				}
			}
		} else {
			isVoice = true
		}

		if isVoice && len(p.Values()) > 0 {
			return (p.Values())[0]
		}
	}

	return ""
}

// Fax returns the VCard's first fax number.
//
// Returns empty string if the VCard contains no fax number.
func (v *VCard) Fax() string {
	properties := v.Get("tel")

	for _, p := range properties {
		if types, ok := p.Parameters["type"]; ok {
			for _, t := range types {
				if t == "fax" {
					if len(p.Values()) > 0 {
						return (p.Values())[0]
					}
				}
			}
		}
	}

	return ""
}

// Email returns the VCard's first email address.
//
// Returns empty string if the VCard contains no email addresses.
func (v *VCard) Email() string {
	return v.getFirstPropertySingleString("email")
}

func (v *VCard) getFirstAddressField(index int) string {
	adr := v.GetFirst("adr")
	if adr == nil {
		return ""
	}

	values := adr.Values()

	if index >= len(values) {
		return ""
	}

	return values[index]
}
