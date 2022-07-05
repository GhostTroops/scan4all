package gojq

import (
	"math"
	"math/big"
)

// Compare l and r, and returns jq-flavored comparison value.
//
//   -1 if l <  r
//    0 if l == r
//   +1 if l >  r
//
// This comparison is used by built-in operators and functions.
func Compare(l, r interface{}) int {
	return compare(l, r)
}

func compare(l, r interface{}) int {
	return binopTypeSwitch(l, r,
		compareInt,
		func(l, r float64) interface{} {
			switch {
			case l < r || math.IsNaN(l):
				return -1
			case l == r:
				return 0
			default:
				return 1
			}
		},
		func(l, r *big.Int) interface{} {
			return l.Cmp(r)
		},
		func(l, r string) interface{} {
			switch {
			case l < r:
				return -1
			case l == r:
				return 0
			default:
				return 1
			}
		},
		func(l, r []interface{}) interface{} {
			n := len(l)
			if len(r) < n {
				n = len(r)
			}
			for i := 0; i < n; i++ {
				if cmp := compare(l[i], r[i]); cmp != 0 {
					return cmp
				}
			}
			return compareInt(len(l), len(r))
		},
		func(l, r map[string]interface{}) interface{} {
			lk, rk := funcKeys(l), funcKeys(r)
			if cmp := compare(lk, rk); cmp != 0 {
				return cmp
			}
			for _, k := range lk.([]interface{}) {
				if cmp := compare(l[k.(string)], r[k.(string)]); cmp != 0 {
					return cmp
				}
			}
			return 0
		},
		func(l, r interface{}) interface{} {
			return compareInt(typeIndex(l), typeIndex(r))
		},
	).(int)
}

func compareInt(l, r int) interface{} {
	switch {
	case l < r:
		return -1
	case l == r:
		return 0
	default:
		return 1
	}
}

func typeIndex(v interface{}) int {
	switch v := v.(type) {
	default:
		return 0
	case bool:
		if !v {
			return 1
		}
		return 2
	case int, float64, *big.Int:
		return 3
	case string:
		return 4
	case []interface{}:
		return 5
	case map[string]interface{}:
		return 6
	}
}
