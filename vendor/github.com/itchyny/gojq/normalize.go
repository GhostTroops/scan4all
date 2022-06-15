package gojq

import (
	"encoding/json"
	"math"
	"math/big"
	"strings"
)

func normalizeNumber(v json.Number) interface{} {
	if i, err := v.Int64(); err == nil && minInt <= i && i <= maxInt {
		return int(i)
	}
	if strings.ContainsAny(v.String(), ".eE") {
		if f, err := v.Float64(); err == nil {
			return f
		}
	}
	if bi, ok := new(big.Int).SetString(v.String(), 10); ok {
		return bi
	}
	if strings.HasPrefix(v.String(), "-") {
		return math.Inf(-1)
	}
	return math.Inf(1)
}

func normalizeNumbers(v interface{}) interface{} {
	switch v := v.(type) {
	case json.Number:
		return normalizeNumber(v)
	case *big.Int:
		if v.IsInt64() {
			if i := v.Int64(); minInt <= i && i <= maxInt {
				return int(i)
			}
		}
		return v
	case int64:
		if minInt <= v && v <= maxInt {
			return int(v)
		}
		return big.NewInt(v)
	case int32:
		return int(v)
	case int16:
		return int(v)
	case int8:
		return int(v)
	case uint:
		if v <= maxInt {
			return int(v)
		}
		return new(big.Int).SetUint64(uint64(v))
	case uint64:
		if v <= maxInt {
			return int(v)
		}
		return new(big.Int).SetUint64(v)
	case uint32:
		if uint64(v) <= maxInt {
			return int(v)
		}
		return new(big.Int).SetUint64(uint64(v))
	case uint16:
		return int(v)
	case uint8:
		return int(v)
	case float32:
		return float64(v)
	case []interface{}:
		for i, x := range v {
			v[i] = normalizeNumbers(x)
		}
		return v
	case map[string]interface{}:
		for k, x := range v {
			v[k] = normalizeNumbers(x)
		}
		return v
	default:
		return v
	}
}
