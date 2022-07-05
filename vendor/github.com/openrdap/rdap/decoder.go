// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

package rdap

import (
	"encoding/json"
	"math"
	"reflect"
	"strconv"
	"strings"
)

// Decoder decodes an RDAP response (https://tools.ietf.org/html/rfc7483) into a Go value.
//
// An RDAP response describes an object such as a Domain (data resembling "whois
// example.com"), or an IP Network (data resembling "whois 2001:db8::"). For a
// live example, see https://rdap.nic.cz/domain/ctk.cz.
//
// To decode an RDAP response:
//
//  jsonBlob := []byte(`
//    {
//      "objectClassName": "domain",
//      "rdapConformance": ["rdap_level_0"],
//      "handle":          "EXAMPLECOM",
//      "ldhName":         "example.com",
//      "entities":        []
//    }
//  `)
//
//  d := rdap.NewDecoder(jsonBlob)
//  result, err := d.Decode()
//
//  if err != nil {
//    if domain, ok := result.(*rdap.Domain); ok {
//      fmt.Printf("Domain name = %s\n", domain.LDHName)
//    }
//  }
//
// RDAP responses are decoded into the following types:
//  &rdap.Error{}                   - Responses with an errorCode value.
//  &rdap.Autnum{}                  - Responses with objectClassName="autnum".
//  &rdap.Domain{}                  - Responses with objectClassName="domain".
//  &rdap.Entity{}                  - Responses with objectClassName="entity".
//  &rdap.IPNetwork{}               - Responses with objectClassName="ip network".
//  &rdap.Nameserver{}              - Responses with objectClassName="nameserver".
//  &rdap.DomainSearchResults{}     - Responses with a domainSearchResults array.
//  &rdap.EntitySearchResults{}     - Responses with a entitySearchResults array.
//  &rdap.NameserverSearchResults{} - Responses with a nameserverSearchResults array.
//  &rdap.Help{}                    - All other valid JSON responses.
//
// Note that an RDAP server may return a different response type than expected.
//
// The decoder supports and stores unknown RDAP fields. See the DecodeData
// documentation for accessing them.
//
// Decoding is performed on a best-effort basis, with "minor error"s ignored.
// This avoids minor errors rendering a response undecodable.
type Decoder struct {
	data   []byte
	target interface{}
}

// DecoderOption sets a Decoder option.
type DecoderOption func(*Decoder)

// DecoderError represents a fatal error encountered while decoding.
type DecoderError struct {
	text string
}

func (d DecoderError) Error() string {
	return d.text
}

// NewDecoder creates a new Decoder to decode the RDAP response |jsonBlob|.
//
// |opts| is an optional list of DecoderOptions.
func NewDecoder(jsonBlob []byte, opts ...DecoderOption) *Decoder {
	d := &Decoder{
		data: jsonBlob,
	}

	// Run the DecoderOption func()s.
	for _, o := range opts {
		o(d)
	}

	return d
}

// Decode decodes the JSON document. On success, one of several values is
// returned.
//
// The possible results are:
//  &rdap.Error{}                   - Responses with an errorCode value.
//  &rdap.Autnum{}                  - Responses with objectClassName="autnum".
//  &rdap.Domain{}                  - Responses with objectClassName="domain".
//  &rdap.Entity{}                  - Responses with objectClassName="entity".
//  &rdap.IPNetwork{}               - Responses with objectClassName="ip network".
//  &rdap.Nameserver{}              - Responses with objectClassName="nameserver".
//  &rdap.DomainSearchResults{}     - Responses with a domainSearchResults array.
//  &rdap.EntitySearchResults{}     - Responses with a entitySearchResults array.
//  &rdap.NameserverSearchResults{} - Responses with a nameserverSearchResults array.
//  &rdap.Help{}                    - All other valid JSON responses.
//
// On serious errors (e.g. JSON syntax error) an error is returned. Otherwise,
// decoding is performed on a best-effort basis, and "minor errors" (such as
// incorrect JSON types) are ignored. This avoids minor errors rendering the
// whole response undecodable.
//
// Minor error messages (e.g. type conversions, type errors) are embedded within
// each result struct, see the DecodeData fields.
func (d *Decoder) Decode() (interface{}, error) {
	var s map[string]interface{}
	var err error

	// Unmarshal the JSON document.
	err = json.Unmarshal(d.data, &s)
	if err != nil {
		return nil, err
	}

	// Decode the RDAP response.
	var result interface{}
	result, err = d.decodeTopLevel(s)

	return result, err
}

// decodeTopLevel decodes the top level object |src|.
func (d *Decoder) decodeTopLevel(src map[string]interface{}) (interface{}, error) {
	// Choose the target struct type.
	if d.target != nil {
		// Target already selected, e.g. tests use this.
	} else if _, exists := src["errorCode"]; exists {
		d.target = &Error{}
	} else if o, exists := src["objectClassName"]; exists {
		if objectClassName, ok := o.(string); ok {
			switch objectClassName {
			case "autnum":
				d.target = &Autnum{}
			case "domain":
				d.target = &Domain{}
			case "entity":
				d.target = &Entity{}
			case "ip network":
				d.target = &IPNetwork{}
			case "nameserver":
				d.target = &Nameserver{}
			default:
				return nil, DecoderError{text: "objectClassName is not recognised"}
			}
		} else {
			return nil, DecoderError{text: "objectClassName is not a string"}
		}
	} else if _, exists := src["domainSearchResults"]; exists {
		d.target = &DomainSearchResults{}
	} else if _, exists := src["entitySearchResults"]; exists {
		d.target = &EntitySearchResults{}
	} else if _, exists := src["nameserverSearchResults"]; exists {
		d.target = &NameserverSearchResults{}
	}

	// Default to returning a Help{}.
	//
	// All remaining JSON documents are assumed to be Help responses. There's no
	// way of distinguishing a Help response and a valid non-RDAP response.
	if d.target == nil {
		d.target = &Help{}
	}

	// Construct the result type.
	result := reflect.New(reflect.TypeOf(d.target).Elem())

	// Decode the response into the result type.
	_, err := d.decode("", src, result, nil)

	return result.Interface(), err

}

// decode decodes the JSON structure |src| into the value |dst|.
//
// The type of |dst| is predetermined, |src| must match it, or be convertable to
// it. |dst| can be a bool, float64, struct, ptr, string, slice, map, etc.
//
// |decodeData| is optional, and is used to store raw values/note minor errors.
// |keyName| is used while storing minor errors.
//
// Returns true if |dst| was set successfully.
func (d *Decoder) decode(keyName string, src interface{}, dst reflect.Value, decodeData *DecodeData) (bool, error) {
	var success bool
	var err error

	// Choose and run the correct decoder for |dst|'s type.
	switch dst.Kind() {
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		success, err = d.decodeUint(keyName, src, dst, decodeData)
	case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		success, err = d.decodeInt(keyName, src, dst, decodeData)
	case reflect.Float64:
		success, err = d.decodeFloat64(keyName, src, dst, decodeData)
	case reflect.Bool:
		success, err = d.decodeBool(keyName, src, dst, decodeData)
	case reflect.Struct:
		success, err = d.decodeStruct(keyName, src, dst, decodeData)
	case reflect.Ptr:
		success, err = d.decodePtr(keyName, src, dst, decodeData)
	case reflect.String:
		success, err = d.decodeString(keyName, src, dst, decodeData)
	case reflect.Slice:
		success, err = d.decodeSlice(keyName, src, dst, decodeData)
	case reflect.Map:
		success, err = d.decodeMap(keyName, src, dst, decodeData)
	default:
		panic("BUG: unknown destination type")
	}

	return success, err
}

// decodeSlice decodes |src| into the slice |dst|.
//
// If a minor error is encountered while decoding a value, it is ignored and not
// returned in the resulting slice.
//
// The parameters and return variables are as per decode().
func (d *Decoder) decodeSlice(keyName string, src interface{}, dst reflect.Value, decodeData *DecodeData) (bool, error) {
	// Cast the input to a slice.
	srcSlice, ok := src.([]interface{})
	if !ok {
		d.addDecodeNote(decodeData, keyName, "invalid JSON type, expecting array")
		return false, nil
	}

	// Construct the result slice.
	result := reflect.MakeSlice(dst.Type(), 0, len(srcSlice))

	// Foreach value in the input slice...
	for _, v := range srcSlice {
		// Construct a result value for it.
		vdst := reflect.New(dst.Type().Elem())

		// Decode into the result value.
		success, err := d.decode(keyName, v, reflect.Indirect(vdst), decodeData)

		if err != nil {
			return false, err
		}

		// Only if the decode was successful, append to result slice.
		if success {
			result = reflect.Append(result, reflect.Indirect(vdst))
		}
	}

	dst.Set(result)

	return true, nil
}

// decodeMap decodes |src| into the map |dst|.
//
// Only destination maps with a string key are supported.
//
// If a minor error is encountered while decoding a map value, it is ignored and
// not returned in the resulting map.
//
// The parameters and return variables are as per decode().
func (d *Decoder) decodeMap(keyName string, src interface{}, dst reflect.Value, decodeData *DecodeData) (bool, error) {
	if dst.Type().Key().Kind() != reflect.String {
		panic("BUG: map key is not string")
	}

	srcMap, ok := src.(map[string]interface{})
	if !ok {
		d.addDecodeNote(decodeData, keyName, "invalid JSON type, expecting object")
		return false, nil
	}

	// Construct the result map.
	result := reflect.MakeMap(dst.Type())

	// Foreach |src| map key/value...
	for k, v := range srcMap {
		// Construct the result value.
		vdst := reflect.New(dst.Type().Elem())

		// Decode into the result value.
		success, err := d.decode(keyName+":"+k, v, reflect.Indirect(vdst), decodeData)

		if err != nil {
			return false, err
		}

		// If the decode was successful, add to the result map.
		if success {
			result.SetMapIndex(reflect.ValueOf(k), reflect.Indirect(vdst))
		}
	}

	dst.Set(result)

	return true, nil
}

// decodeUint decodes |src| into the uint8/16/32/64 |dst|.
//
// This function can perform type conversions, warnings/errors are noted for
// these.
//
// The parameters and return variables are as per decode().
func (d *Decoder) decodeUint(keyName string, src interface{}, dst reflect.Value, decodeData *DecodeData) (bool, error) {
	var err error
	var result uint64

	success := true

	switch src.(type) {
	case bool:
		if src.(bool) {
			result = 1
		}

		d.addDecodeNote(decodeData, keyName, "bool to uint conversion")
	case float64:
		result = uint64(src.(float64))
		d.addDecodeNote(decodeData, keyName, "float64 to uint conversion")
	case string:
		var convError error

		result, convError = strconv.ParseUint(src.(string), 10, 64)

		if convError != nil {
			result = 0
			success = false
			d.addDecodeNote(decodeData, keyName, "error converting string to uint")
		} else {
			d.addDecodeNote(decodeData, keyName, "string to uint conversion")
		}
	case nil:
		result = 0
		d.addDecodeNote(decodeData, keyName, "null to uint conversion")
	default:
		d.addDecodeNote(decodeData, keyName, "invalid JSON type, expecting float")
		success = false
	}

	if success {
		var maxVal uint64

		// Check the result number is within range of the target type.
		switch dst.Kind() {
		case reflect.Uint8:
			maxVal = math.MaxUint8
		case reflect.Uint16:
			maxVal = math.MaxUint16
		case reflect.Uint32:
			maxVal = math.MaxUint32
		case reflect.Uint64:
			maxVal = math.MaxUint64
		default:
			panic("Unexpected int type")
		}

		if result > maxVal {
			d.addDecodeNote(decodeData, keyName, "error: number too large")
			success = false
		} else {
			dst.SetUint(result)
		}
	}

	return success, err
}

// decodeInt decodes |src| into the int8/16/32/64 |dst|.
//
// This function can perform type conversions, warnings/errors are noted for
// these.
//
// The parameters and return variables are as per decode().
func (d *Decoder) decodeInt(keyName string, src interface{}, dst reflect.Value, decodeData *DecodeData) (bool, error) {
	var err error
	var result int64

	success := true

	switch src.(type) {
	case bool:
		if src.(bool) {
			result = 1
		}

		d.addDecodeNote(decodeData, keyName, "bool to int conversion")
	case float64:
		result = int64(src.(float64))
		d.addDecodeNote(decodeData, keyName, "float64 to int conversion")
	case string:
		var convError error

		result, convError = strconv.ParseInt(src.(string), 10, 64)

		if convError != nil {
			result = 0
			success = false
			d.addDecodeNote(decodeData, keyName, "error converting string to int")
		} else {
			d.addDecodeNote(decodeData, keyName, "string to int conversion")
		}
	case nil:
		result = 0
		d.addDecodeNote(decodeData, keyName, "null to int conversion")
	default:
		d.addDecodeNote(decodeData, keyName, "invalid JSON type, expecting float")
		success = false
	}

	if success {
		var minVal int64
		var maxVal int64

		// Check the result number is within range of the target type.
		switch dst.Kind() {
		case reflect.Int8:
			minVal = math.MinInt8
			maxVal = math.MaxInt8
		case reflect.Int16:
			minVal = math.MinInt16
			maxVal = math.MaxInt16
		case reflect.Int32:
			minVal = math.MinInt32
			maxVal = math.MaxInt32
		case reflect.Int64:
			minVal = math.MinInt64
			maxVal = math.MaxInt64
		default:
			panic("Unexpected int type")
		}

		if result < minVal || result > maxVal {
			d.addDecodeNote(decodeData, keyName, "error: number too small or large")
			success = false
		} else {
			dst.SetInt(result)
		}

	}

	return success, err
}

// decodeFloat64 decodes |src| into the float64 |dst|.
//
// This function can perform type conversions, warnings/errors are noted for
// these.
//
// The parameters and return variables are as per decode().
func (d *Decoder) decodeFloat64(keyName string, src interface{}, dst reflect.Value, decodeData *DecodeData) (bool, error) {
	var err error
	var result float64

	success := true

	switch src.(type) {
	case bool:
		if src.(bool) {
			result = 1.0
		}

		d.addDecodeNote(decodeData, keyName, "bool to float64 conversion")
	case float64:
		result = src.(float64)
	case string:
		var convError error

		result, convError = strconv.ParseFloat(src.(string), 64)

		if convError != nil {
			result = 0.0
			success = false
			d.addDecodeNote(decodeData, keyName, "error converting string to float64")
		} else {
			d.addDecodeNote(decodeData, keyName, "string to float64 conversion")
		}
	case nil:
		result = 0.0
		d.addDecodeNote(decodeData, keyName, "null to float64 conversion")
	default:
		d.addDecodeNote(decodeData, keyName, "invalid JSON type, expecting float")
		success = false
	}

	dst.SetFloat(result)

	return success, err
}

// decodeString decodes |src| into the string |dst|.
//
// This function can perform type conversions, warnings/errors are noted for
// these.
//
// The parameters and return variables are as per decode().
func (d *Decoder) decodeString(keyName string, src interface{}, dst reflect.Value, decodeData *DecodeData) (bool, error) {
	var err error
	var result string

	success := true

	switch src.(type) {
	case bool:
		result = strconv.FormatBool(src.(bool))
		d.addDecodeNote(decodeData, keyName, "bool to string conversion")
	case float64:
		result = strconv.FormatFloat(src.(float64), 'f', -1, 64)
		d.addDecodeNote(decodeData, keyName, "float64 to string conversion")
	case string:
		result = src.(string)
	case nil:
		result = ""
		d.addDecodeNote(decodeData, keyName, "null to empty string conversion")
	default:
		d.addDecodeNote(decodeData, keyName, "invalid JSON type, expecting string")
		success = false
	}

	dst.SetString(result)

	return success, err
}

// decodeBool decodes |src| into the bool |dst|.
//
// This function can perform type conversions, warnings/errors are noted for
// these.
//
// The parameters and return variables are as per decode().
func (d *Decoder) decodeBool(keyName string, src interface{}, dst reflect.Value, decodeData *DecodeData) (bool, error) {
	var err error
	var result bool

	success := true

	switch src.(type) {
	case bool:
		result = src.(bool)
	case float64:
		f := src.(float64)
		if f != 0 {
			result = true
		}

		d.addDecodeNote(decodeData, keyName, "float64 to bool conversion")
	case string:
		var convError error
		result, convError = strconv.ParseBool(src.(string))

		if convError != nil {
			d.addDecodeNote(decodeData, keyName, "error converting string to bool")
			result = false
			success = false
		} else {
			d.addDecodeNote(decodeData, keyName, "string to bool conversion")
		}
	case nil:
		result = false
		d.addDecodeNote(decodeData, keyName, "null to bool conversion")
	default:
		d.addDecodeNote(decodeData, keyName, "invalid JSON type, expecting bool")
		success = false
	}

	dst.SetBool(result)

	return success, err
}

// decodeStruct decodes |src| into the struct |dst|.
//
// The parameters and return variables are as per decode().
func (d *Decoder) decodeStruct(keyName string, src interface{}, dst reflect.Value, decodeData *DecodeData) (bool, error) {
	var err error

	// |src| must be a JSON object.
	srcMap, ok := src.(map[string]interface{})
	if !ok {
		d.addDecodeNote(decodeData, keyName, "invalid JSON type, expecting object")
		return false, nil
	}

	// Identify the fields in the struct we'll decode into.
	// e.g. fields["port43"] => [some reflect.Value]
	var fields map[string]reflect.Value
	var myDecodeData *DecodeData

	fields, myDecodeData = d.chooseFields(dst)

	// If the result struct has a DecodeData...
	if myDecodeData != nil {
		// Save a snapshot of each field.
		for name, value := range srcMap {
			myDecodeData.values[name] = value
		}

		// Note the fields we know about, so unknown fields can be identified.
		for name := range fields {
			myDecodeData.isKnown[name] = true
		}
	}

	// Foreach field in |srcMap|...
	for name, value := range srcMap {
		// If there's a matching Go field, decode into it...
		if _, ok := fields[name]; ok {
			_, err := d.decode(name, value, fields[name], myDecodeData)

			if err != nil {
				return false, err
			}
		}
	}

	return true, err
}

func (d *Decoder) chooseFields(v reflect.Value) (map[string]reflect.Value, *DecodeData) {
	if v.Kind() != reflect.Struct {
		panic("BUG: chooseFields called on non-struct")
	}

	var decodeData *DecodeData
	fields := map[string]reflect.Value{}

	vt := v.Type()
	for i := 0; i < vt.NumField(); i++ {
		structField := vt.Field(i)

		if structField.Type.Kind() == reflect.Ptr && structField.Type.Elem().Name() == "DecodeData" {
			if decodeData != nil {
				panic("BUG: Multiple DecodeData fields in struct")
			} else {
				decodeData = &DecodeData{}
				decodeData.init()
				v.Field(i).Set(reflect.ValueOf(decodeData))
			}
		} else {
			if structField.Anonymous {
				subFields, subDecodeData := d.chooseFields(v.Field(i))

				if subDecodeData != nil {
					if decodeData != nil {
						panic("BUG: Multiple DecodeData fields in struct")
					} else {
						decodeData = subDecodeData
					}
				}

				for k, v := range subFields {
					if _, exists := fields[k]; exists {
						panic("BUG: Duplicate field " + k + " in struct")
					}

					fields[k] = v
				}
			} else if name, ok := d.getFieldName(structField); ok {
				if _, exists := fields[name]; exists {
					panic("BUG: Duplicate field " + name + " in struct")
				}

				fields[name] = v.Field(i)

				switch fields[name].Kind() {
				case reflect.Uint8,
					reflect.Uint16,
					reflect.Uint32,
					reflect.Uint64,
					reflect.Int8,
					reflect.Int16,
					reflect.Int32,
					reflect.Int64,
					reflect.Float64,
					reflect.Bool,
					reflect.Struct,
					reflect.Ptr,
					reflect.String,
					reflect.Slice,
					reflect.Map:
					// These types are all supported.
				default:
					panic("BUG: Unsupported field type for " + name)
				}
			}
		}
	}

	return fields, decodeData
}

// getFieldName returns the RDAP field name (if any) of |sf|.
//
// Returns the field name and true if |sf| has an RDAP field name. Otherwise
// returns empty string and false.
func (d *Decoder) getFieldName(sf reflect.StructField) (string, bool) {
	// Handle non-exported fields.
	if sf.Name[0:1] != strings.ToUpper(sf.Name[0:1]) {
		if sf.Tag.Get("rdap") != "" {
			panic("BUG: rdap tag on non-exported struct field")
		}

		return "", false
	}

	// The "rdap" struct tag specifies a custom RDAP field name.
	name := sf.Tag.Get("rdap")

	// Otherwise, the RDAP field name is the Go field name, with the first
	// character lowercased.
	//
	// e.g. domain.Port43 => RDAP field name "port43".
	if name == "" {
		name = strings.ToLower(sf.Name[0:1]) + sf.Name[1:]
	}

	return name, true
}

// decodePtr decodes |src| into the ptr |dst|. The ptr is initialised to a new
// value if nil.
//
// The parameters and return variables are as per decode().
func (d *Decoder) decodePtr(keyName string, src interface{}, dst reflect.Value, decodeData *DecodeData) (bool, error) {
	var success bool
	var err error

	if dst.Type().Elem().Name() == "VCard" {
		vcard, vcardError := newVCardImpl(src)

		if vcardError == nil {
			dst.Set(reflect.ValueOf(vcard))
			success = true
		} else {
			d.addDecodeNote(decodeData, keyName, vcardError.Error())
		}
	} else {
		if dst.IsNil() {
			value := reflect.New(dst.Type().Elem())
			dst.Set(value)
		}

		success, err = d.decode(keyName, src, reflect.Indirect(dst), decodeData)
	}

	return success, err
}

// addDecodeNote adds a DecodeData note |msg| for the field |key|.
func (d *Decoder) addDecodeNote(decodeData *DecodeData, key string, msg string) {
	if decodeData == nil {
		return
	}

	if _, ok := decodeData.notes[key]; !ok {
		decodeData.notes[key] = []string{}
	}

	decodeData.notes[key] = append(decodeData.notes[key], msg)
}
