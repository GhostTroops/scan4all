package gojq

import (
	"fmt"
	"math/big"
)

// TypeOf returns the jq-flavored type name of v.
//
// This method is used by built-in type/0 function, and accepts only limited
// types (nil, bool, int, float64, *big.Int, string, []interface{},
// and map[string]interface{}).
func TypeOf(v interface{}) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case int, float64, *big.Int:
		return "number"
	case string:
		return "string"
	case []interface{}:
		return "array"
	case map[string]interface{}:
		return "object"
	default:
		panic(fmt.Sprintf("invalid type: %[1]T (%[1]v)", v))
	}
}
