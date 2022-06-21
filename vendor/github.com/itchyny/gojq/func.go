package gojq

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/itchyny/timefmt-go"
)

//go:generate go run -modfile=go.dev.mod _tools/gen_builtin.go -i builtin.jq -o builtin.go
var builtinFuncDefs map[string][]*FuncDef

const (
	argcount0 = 1 << iota
	argcount1
	argcount2
	argcount3
)

type function struct {
	argcount int
	iter     bool
	callback func(interface{}, []interface{}) interface{}
}

func (fn function) accept(cnt int) bool {
	return fn.argcount&(1<<cnt) != 0
}

var internalFuncs map[string]function

func init() {
	internalFuncs = map[string]function{
		"empty":          argFunc0(nil),
		"path":           argFunc1(nil),
		"env":            argFunc0(nil),
		"builtins":       argFunc0(nil),
		"input":          argFunc0(nil),
		"modulemeta":     argFunc0(nil),
		"length":         argFunc0(funcLength),
		"utf8bytelength": argFunc0(funcUtf8ByteLength),
		"keys":           argFunc0(funcKeys),
		"has":            argFunc1(funcHas),
		"to_entries":     argFunc0(funcToEntries),
		"from_entries":   argFunc0(funcFromEntries),
		"add":            argFunc0(funcAdd),
		"tonumber":       argFunc0(funcToNumber),
		"tostring":       argFunc0(funcToString),
		"type":           argFunc0(funcType),
		"reverse":        argFunc0(funcReverse),
		"contains":       argFunc1(funcContains),
		"indices":        argFunc1(funcIndices),
		"index":          argFunc1(funcIndex),
		"rindex":         argFunc1(funcRindex),
		"startswith":     argFunc1(funcStartsWith),
		"endswith":       argFunc1(funcEndsWith),
		"ltrimstr":       argFunc1(funcLtrimstr),
		"rtrimstr":       argFunc1(funcRtrimstr),
		"explode":        argFunc0(funcExplode),
		"implode":        argFunc0(funcImplode),
		"split":          {argcount1 | argcount2, false, funcSplit},
		"tojson":         argFunc0(funcToJSON),
		"fromjson":       argFunc0(funcFromJSON),
		"format":         argFunc1(funcFormat),
		"_tohtml":        argFunc0(funcToHTML),
		"_touri":         argFunc0(funcToURI),
		"_tocsv":         argFunc0(funcToCSV),
		"_totsv":         argFunc0(funcToTSV),
		"_tosh":          argFunc0(funcToSh),
		"_tobase64":      argFunc0(funcToBase64),
		"_tobase64d":     argFunc0(funcToBase64d),
		"_index":         argFunc2(funcIndex2),
		"_slice":         argFunc3(funcSlice),
		"_plus":          argFunc0(funcOpPlus),
		"_negate":        argFunc0(funcOpNegate),
		"_add":           argFunc2(funcOpAdd),
		"_subtract":      argFunc2(funcOpSub),
		"_multiply":      argFunc2(funcOpMul),
		"_divide":        argFunc2(funcOpDiv),
		"_modulo":        argFunc2(funcOpMod),
		"_alternative":   argFunc2(funcOpAlt),
		"_equal":         argFunc2(funcOpEq),
		"_notequal":      argFunc2(funcOpNe),
		"_greater":       argFunc2(funcOpGt),
		"_less":          argFunc2(funcOpLt),
		"_greatereq":     argFunc2(funcOpGe),
		"_lesseq":        argFunc2(funcOpLe),
		"flatten":        {argcount0 | argcount1, false, funcFlatten},
		"_range":         {argcount3, true, funcRange},
		"min":            argFunc0(funcMin),
		"_min_by":        argFunc1(funcMinBy),
		"max":            argFunc0(funcMax),
		"_max_by":        argFunc1(funcMaxBy),
		"sort":           argFunc0(funcSort),
		"_sort_by":       argFunc1(funcSortBy),
		"_group_by":      argFunc1(funcGroupBy),
		"unique":         argFunc0(funcUnique),
		"_unique_by":     argFunc1(funcUniqueBy),
		"join":           argFunc1(funcJoin),
		"sin":            mathFunc("sin", math.Sin),
		"cos":            mathFunc("cos", math.Cos),
		"tan":            mathFunc("tan", math.Tan),
		"asin":           mathFunc("asin", math.Asin),
		"acos":           mathFunc("acos", math.Acos),
		"atan":           mathFunc("atan", math.Atan),
		"sinh":           mathFunc("sinh", math.Sinh),
		"cosh":           mathFunc("cosh", math.Cosh),
		"tanh":           mathFunc("tanh", math.Tanh),
		"asinh":          mathFunc("asinh", math.Asinh),
		"acosh":          mathFunc("acosh", math.Acosh),
		"atanh":          mathFunc("atanh", math.Atanh),
		"floor":          mathFunc("floor", math.Floor),
		"round":          mathFunc("round", math.Round),
		"nearbyint":      mathFunc("nearbyint", math.Round),
		"rint":           mathFunc("rint", math.Round),
		"ceil":           mathFunc("ceil", math.Ceil),
		"trunc":          mathFunc("trunc", math.Trunc),
		"significand":    mathFunc("significand", funcSignificand),
		"fabs":           mathFunc("fabs", math.Abs),
		"sqrt":           mathFunc("sqrt", math.Sqrt),
		"cbrt":           mathFunc("cbrt", math.Cbrt),
		"exp":            mathFunc("exp", math.Exp),
		"exp10":          mathFunc("exp10", funcExp10),
		"exp2":           mathFunc("exp2", math.Exp2),
		"expm1":          mathFunc("expm1", math.Expm1),
		"frexp":          argFunc0(funcFrexp),
		"modf":           argFunc0(funcModf),
		"log":            mathFunc("log", math.Log),
		"log10":          mathFunc("log10", math.Log10),
		"log1p":          mathFunc("log1p", math.Log1p),
		"log2":           mathFunc("log2", math.Log2),
		"logb":           mathFunc("logb", math.Logb),
		"gamma":          mathFunc("gamma", math.Gamma),
		"tgamma":         mathFunc("tgamma", math.Gamma),
		"lgamma":         mathFunc("lgamma", funcLgamma),
		"erf":            mathFunc("erf", math.Erf),
		"erfc":           mathFunc("erfc", math.Erfc),
		"j0":             mathFunc("j0", math.J0),
		"j1":             mathFunc("j1", math.J1),
		"y0":             mathFunc("y0", math.Y0),
		"y1":             mathFunc("y1", math.Y1),
		"atan2":          mathFunc2("atan2", math.Atan2),
		"copysign":       mathFunc2("copysign", math.Copysign),
		"drem":           mathFunc2("drem", funcDrem),
		"fdim":           mathFunc2("fdim", math.Dim),
		"fmax":           mathFunc2("fmax", math.Max),
		"fmin":           mathFunc2("fmin", math.Min),
		"fmod":           mathFunc2("fmod", math.Mod),
		"hypot":          mathFunc2("hypot", math.Hypot),
		"jn":             mathFunc2("jn", funcJn),
		"ldexp":          mathFunc2("ldexp", funcLdexp),
		"nextafter":      mathFunc2("nextafter", math.Nextafter),
		"nexttoward":     mathFunc2("nexttoward", math.Nextafter),
		"remainder":      mathFunc2("remainder", math.Remainder),
		"scalb":          mathFunc2("scalb", funcScalb),
		"scalbln":        mathFunc2("scalbln", funcScalbln),
		"yn":             mathFunc2("yn", funcYn),
		"pow":            mathFunc2("pow", math.Pow),
		"pow10":          mathFunc("pow10", funcExp10),
		"fma":            mathFunc3("fma", math.FMA),
		"infinite":       argFunc0(funcInfinite),
		"isfinite":       argFunc0(funcIsfinite),
		"isinfinite":     argFunc0(funcIsinfinite),
		"nan":            argFunc0(funcNan),
		"isnan":          argFunc0(funcIsnan),
		"isnormal":       argFunc0(funcIsnormal),
		"setpath":        argFunc2(funcSetpath),
		"delpaths":       argFunc1(funcDelpaths),
		"getpath":        argFunc1(funcGetpath),
		"transpose":      argFunc0(funcTranspose),
		"bsearch":        argFunc1(funcBsearch),
		"gmtime":         argFunc0(funcGmtime),
		"localtime":      argFunc0(funcLocaltime),
		"mktime":         argFunc0(funcMktime),
		"strftime":       argFunc1(funcStrftime),
		"strflocaltime":  argFunc1(funcStrflocaltime),
		"strptime":       argFunc1(funcStrptime),
		"now":            argFunc0(funcNow),
		"_match":         argFunc3(funcMatch),
		"_capture":       argFunc0(funcCapture),
		"error":          {argcount0 | argcount1, false, funcError},
		"halt":           argFunc0(funcHalt),
		"halt_error":     {argcount0 | argcount1, false, funcHaltError},
	}
}

func argFunc0(f func(interface{}) interface{}) function {
	return function{
		argcount0, false, func(v interface{}, _ []interface{}) interface{} {
			return f(v)
		},
	}
}

func argFunc1(f func(_, _ interface{}) interface{}) function {
	return function{
		argcount1, false, func(v interface{}, args []interface{}) interface{} {
			return f(v, args[0])
		},
	}
}

func argFunc2(f func(_, _, _ interface{}) interface{}) function {
	return function{
		argcount2, false, func(v interface{}, args []interface{}) interface{} {
			return f(v, args[0], args[1])
		},
	}
}

func argFunc3(f func(_, _, _, _ interface{}) interface{}) function {
	return function{
		argcount3, false, func(v interface{}, args []interface{}) interface{} {
			return f(v, args[0], args[1], args[2])
		},
	}
}

func mathFunc(name string, f func(float64) float64) function {
	return argFunc0(func(v interface{}) interface{} {
		x, ok := toFloat(v)
		if !ok {
			return &funcTypeError{name, v}
		}
		return f(x)
	})
}

func mathFunc2(name string, f func(_, _ float64) float64) function {
	return argFunc2(func(_, x, y interface{}) interface{} {
		l, ok := toFloat(x)
		if !ok {
			return &funcTypeError{name, x}
		}
		r, ok := toFloat(y)
		if !ok {
			return &funcTypeError{name, y}
		}
		return f(l, r)
	})
}

func mathFunc3(name string, f func(_, _, _ float64) float64) function {
	return argFunc3(func(_, a, b, c interface{}) interface{} {
		x, ok := toFloat(a)
		if !ok {
			return &funcTypeError{name, a}
		}
		y, ok := toFloat(b)
		if !ok {
			return &funcTypeError{name, b}
		}
		z, ok := toFloat(c)
		if !ok {
			return &funcTypeError{name, c}
		}
		return f(x, y, z)
	})
}

func funcLength(v interface{}) interface{} {
	switch v := v.(type) {
	case nil:
		return 0
	case int:
		if v >= 0 {
			return v
		}
		return -v
	case float64:
		return math.Abs(v)
	case *big.Int:
		if v.Sign() >= 0 {
			return v
		}
		return new(big.Int).Abs(v)
	case string:
		return len([]rune(v))
	case []interface{}:
		return len(v)
	case map[string]interface{}:
		return len(v)
	default:
		return &funcTypeError{"length", v}
	}
}

func funcUtf8ByteLength(v interface{}) interface{} {
	s, ok := v.(string)
	if !ok {
		return &funcTypeError{"utf8bytelength", v}
	}
	return len(s)
}

func funcKeys(v interface{}) interface{} {
	switch v := v.(type) {
	case []interface{}:
		w := make([]interface{}, len(v))
		for i := range v {
			w[i] = i
		}
		return w
	case map[string]interface{}:
		w := make([]interface{}, len(v))
		for i, k := range keys(v) {
			w[i] = k
		}
		return w
	default:
		return &funcTypeError{"keys", v}
	}
}

func keys(v map[string]interface{}) []string {
	w := make([]string, len(v))
	var i int
	for k := range v {
		w[i] = k
		i++
	}
	sort.Strings(w)
	return w
}

func values(v interface{}) ([]interface{}, bool) {
	switch v := v.(type) {
	case []interface{}:
		return v, true
	case map[string]interface{}:
		vs := make([]interface{}, len(v))
		for i, k := range keys(v) {
			vs[i] = v[k]
		}
		return vs, true
	default:
		return nil, false
	}
}

func funcHas(v, x interface{}) interface{} {
	switch v := v.(type) {
	case []interface{}:
		if x, ok := toInt(x); ok {
			return 0 <= x && x < len(v)
		}
	case map[string]interface{}:
		if x, ok := x.(string); ok {
			_, ok := v[x]
			return ok
		}
	case nil:
		return false
	}
	return &hasKeyTypeError{v, x}
}

func funcToEntries(v interface{}) interface{} {
	switch v := v.(type) {
	case []interface{}:
		w := make([]interface{}, len(v))
		for i, x := range v {
			w[i] = map[string]interface{}{"key": i, "value": x}
		}
		return w
	case map[string]interface{}:
		w := make([]interface{}, len(v))
		for i, k := range keys(v) {
			w[i] = map[string]interface{}{"key": k, "value": v[k]}
		}
		return w
	default:
		return &funcTypeError{"to_entries", v}
	}
}

func funcFromEntries(v interface{}) interface{} {
	vs, ok := v.([]interface{})
	if !ok {
		return &funcTypeError{"from_entries", v}
	}
	w := make(map[string]interface{}, len(vs))
	for _, v := range vs {
		switch v := v.(type) {
		case map[string]interface{}:
			var (
				key   string
				value interface{}
				ok    bool
			)
			for _, k := range [4]string{"key", "Key", "name", "Name"} {
				if k := v[k]; k != nil && k != false {
					if key, ok = k.(string); !ok {
						return &objectKeyNotStringError{k}
					}
					break
				}
			}
			if !ok {
				return &objectKeyNotStringError{nil}
			}
			for _, k := range [2]string{"value", "Value"} {
				if value, ok = v[k]; ok {
					break
				}
			}
			w[key] = value
		default:
			return &funcTypeError{"from_entries", v}
		}
	}
	return w
}

func funcAdd(v interface{}) interface{} {
	vs, ok := values(v)
	if !ok {
		return &funcTypeError{"add", v}
	}
	v = nil
	for _, x := range vs {
		switch x := x.(type) {
		case nil:
			continue
		case string:
			switch w := v.(type) {
			case nil:
				var sb strings.Builder
				sb.WriteString(x)
				v = &sb
				continue
			case *strings.Builder:
				w.WriteString(x)
				continue
			}
		case []interface{}:
			switch w := v.(type) {
			case nil:
				s := make([]interface{}, len(x))
				copy(s, x)
				v = s
				continue
			case []interface{}:
				v = append(w, x...)
				continue
			}
		case map[string]interface{}:
			switch w := v.(type) {
			case nil:
				m := make(map[string]interface{}, len(x))
				for k, e := range x {
					m[k] = e
				}
				v = m
				continue
			case map[string]interface{}:
				for k, e := range x {
					w[k] = e
				}
				continue
			}
		}
		if sb, ok := v.(*strings.Builder); ok {
			v = sb.String()
		}
		v = funcOpAdd(nil, v, x)
		if err, ok := v.(error); ok {
			return err
		}
	}
	if sb, ok := v.(*strings.Builder); ok {
		v = sb.String()
	}
	return v
}

func funcToNumber(v interface{}) interface{} {
	switch v := v.(type) {
	case int, float64, *big.Int:
		return v
	case string:
		if !newLexer(v).validNumber() {
			return fmt.Errorf("invalid number: %q", v)
		}
		return toNumber(v)
	default:
		return &funcTypeError{"tonumber", v}
	}
}

func toNumber(v string) interface{} {
	return normalizeNumber(json.Number(v))
}

func funcToString(v interface{}) interface{} {
	if s, ok := v.(string); ok {
		return s
	}
	return funcToJSON(v)
}

func funcType(v interface{}) interface{} {
	return TypeOf(v)
}

func funcReverse(v interface{}) interface{} {
	vs, ok := v.([]interface{})
	if !ok {
		return &funcTypeError{"reverse", v}
	}
	ws := make([]interface{}, len(vs))
	for i, v := range vs {
		ws[len(ws)-i-1] = v
	}
	return ws
}

func funcContains(v, x interface{}) interface{} {
	return binopTypeSwitch(v, x,
		func(l, r int) interface{} { return l == r },
		func(l, r float64) interface{} { return l == r },
		func(l, r *big.Int) interface{} { return l.Cmp(r) == 0 },
		func(l, r string) interface{} { return strings.Contains(l, r) },
		func(l, r []interface{}) interface{} {
		R:
			for _, r := range r {
				for _, l := range l {
					if funcContains(l, r) == true {
						continue R
					}
				}
				return false
			}
			return true
		},
		func(l, r map[string]interface{}) interface{} {
			if len(l) < len(r) {
				return false
			}
			for k, r := range r {
				if l, ok := l[k]; !ok || funcContains(l, r) != true {
					return false
				}
			}
			return true
		},
		func(l, r interface{}) interface{} {
			if l == r {
				return true
			}
			return &containsTypeError{l, r}
		},
	)
}

func funcIndices(v, x interface{}) interface{} {
	return indexFunc(v, x, indices)
}

func indices(vs, xs []interface{}) interface{} {
	var rs []interface{}
	if len(xs) == 0 {
		return rs
	}
	for i := 0; i <= len(vs)-len(xs); i++ {
		if compare(vs[i:i+len(xs)], xs) == 0 {
			rs = append(rs, i)
		}
	}
	return rs
}

func funcIndex(v, x interface{}) interface{} {
	return indexFunc(v, x, func(vs, xs []interface{}) interface{} {
		if len(xs) == 0 {
			return nil
		}
		for i := 0; i <= len(vs)-len(xs); i++ {
			if compare(vs[i:i+len(xs)], xs) == 0 {
				return i
			}
		}
		return nil
	})
}

func funcRindex(v, x interface{}) interface{} {
	return indexFunc(v, x, func(vs, xs []interface{}) interface{} {
		if len(xs) == 0 {
			return nil
		}
		for i := len(vs) - len(xs); i >= 0; i-- {
			if compare(vs[i:i+len(xs)], xs) == 0 {
				return i
			}
		}
		return nil
	})
}

func indexFunc(v, x interface{}, f func(_, _ []interface{}) interface{}) interface{} {
	switch v := v.(type) {
	case nil:
		return nil
	case []interface{}:
		switch x := x.(type) {
		case []interface{}:
			return f(v, x)
		default:
			return f(v, []interface{}{x})
		}
	case string:
		if x, ok := x.(string); ok {
			return f(explode(v), explode(x))
		}
		return &expectedStringError{x}
	default:
		return &expectedArrayError{v}
	}
}

func funcStartsWith(v, x interface{}) interface{} {
	s, ok := v.(string)
	if !ok {
		return &funcTypeError{"startswith", v}
	}
	t, ok := x.(string)
	if !ok {
		return &funcTypeError{"startswith", x}
	}
	return strings.HasPrefix(s, t)
}

func funcEndsWith(v, x interface{}) interface{} {
	s, ok := v.(string)
	if !ok {
		return &funcTypeError{"endswith", v}
	}
	t, ok := x.(string)
	if !ok {
		return &funcTypeError{"endswith", x}
	}
	return strings.HasSuffix(s, t)
}

func funcLtrimstr(v, x interface{}) interface{} {
	s, ok := v.(string)
	if !ok {
		return v
	}
	t, ok := x.(string)
	if !ok {
		return v
	}
	return strings.TrimPrefix(s, t)
}

func funcRtrimstr(v, x interface{}) interface{} {
	s, ok := v.(string)
	if !ok {
		return v
	}
	t, ok := x.(string)
	if !ok {
		return v
	}
	return strings.TrimSuffix(s, t)
}

func funcExplode(v interface{}) interface{} {
	s, ok := v.(string)
	if !ok {
		return &funcTypeError{"explode", v}
	}
	return explode(s)
}

func explode(s string) []interface{} {
	xs := make([]interface{}, len([]rune(s)))
	var i int
	for _, r := range s {
		xs[i] = int(r)
		i++
	}
	return xs
}

func funcImplode(v interface{}) interface{} {
	vs, ok := v.([]interface{})
	if !ok {
		return &funcTypeError{"implode", v}
	}
	var sb strings.Builder
	sb.Grow(len(vs))
	for _, v := range vs {
		if r, ok := toInt(v); ok && 0 <= r && r <= utf8.MaxRune {
			sb.WriteRune(rune(r))
		} else {
			return &funcTypeError{"implode", vs}
		}
	}
	return sb.String()
}

func funcSplit(v interface{}, args []interface{}) interface{} {
	s, ok := v.(string)
	if !ok {
		return &funcTypeError{"split", v}
	}
	x, ok := args[0].(string)
	if !ok {
		return &funcTypeError{"split", x}
	}
	var ss []string
	if len(args) == 1 {
		ss = strings.Split(s, x)
	} else {
		var flags string
		if args[1] != nil {
			v, ok := args[1].(string)
			if !ok {
				return &funcTypeError{"split", args[1]}
			}
			flags = v
		}
		r, err := compileRegexp(x, flags)
		if err != nil {
			return err
		}
		ss = r.Split(s, -1)
	}
	xs := make([]interface{}, len(ss))
	for i, s := range ss {
		xs[i] = s
	}
	return xs
}

func funcToJSON(v interface{}) interface{} {
	return jsonMarshal(v)
}

func funcFromJSON(v interface{}) interface{} {
	s, ok := v.(string)
	if !ok {
		return &funcTypeError{"fromjson", v}
	}
	var w interface{}
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	if err := dec.Decode(&w); err != nil {
		return err
	}
	return normalizeNumbers(w)
}

func funcFormat(v, x interface{}) interface{} {
	s, ok := x.(string)
	if !ok {
		return &funcTypeError{"format", x}
	}
	fmt := "@" + s
	f := formatToFunc(fmt)
	if f == nil {
		return &formatNotFoundError{fmt}
	}
	return internalFuncs[f.Name].callback(v, nil)
}

var htmlEscaper = strings.NewReplacer(
	`<`, "&lt;",
	`>`, "&gt;",
	`&`, "&amp;",
	`'`, "&apos;",
	`"`, "&quot;",
)

func funcToHTML(v interface{}) interface{} {
	switch x := funcToString(v).(type) {
	case string:
		return htmlEscaper.Replace(x)
	default:
		return x
	}
}

func funcToURI(v interface{}) interface{} {
	switch x := funcToString(v).(type) {
	case string:
		return url.QueryEscape(x)
	default:
		return x
	}
}

func funcToCSV(v interface{}) interface{} {
	return formatJoin("csv", v, ",", func(s string) string {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	})
}

var tsvEscaper = strings.NewReplacer(
	"\t", `\t`,
	"\r", `\r`,
	"\n", `\n`,
	"\\", `\\`,
)

func funcToTSV(v interface{}) interface{} {
	return formatJoin("tsv", v, "\t", tsvEscaper.Replace)
}

func funcToSh(v interface{}) interface{} {
	if _, ok := v.([]interface{}); !ok {
		v = []interface{}{v}
	}
	return formatJoin("sh", v, " ", func(s string) string {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	})
}

func formatJoin(typ string, v interface{}, sep string, escape func(string) string) interface{} {
	vs, ok := v.([]interface{})
	if !ok {
		return &funcTypeError{"@" + typ, v}
	}
	ss := make([]string, len(vs))
	for i, v := range vs {
		switch v := v.(type) {
		case []interface{}, map[string]interface{}:
			return &formatRowError{typ, v}
		case string:
			ss[i] = escape(v)
		default:
			if s := jsonMarshal(v); s != "null" || typ == "sh" {
				ss[i] = s
			}
		}
	}
	return strings.Join(ss, sep)
}

func funcToBase64(v interface{}) interface{} {
	switch x := funcToString(v).(type) {
	case string:
		return base64.StdEncoding.EncodeToString([]byte(x))
	default:
		return x
	}
}

func funcToBase64d(v interface{}) interface{} {
	switch x := funcToString(v).(type) {
	case string:
		if i := strings.IndexRune(x, base64.StdPadding); i >= 0 {
			x = x[:i]
		}
		y, err := base64.RawStdEncoding.DecodeString(x)
		if err != nil {
			return err
		}
		return string(y)
	default:
		return x
	}
}

func funcIndex2(_, v, x interface{}) interface{} {
	switch x := x.(type) {
	case string:
		switch v := v.(type) {
		case nil:
			return nil
		case map[string]interface{}:
			return v[x]
		default:
			return &expectedObjectError{v}
		}
	case int, float64, *big.Int:
		i, _ := toInt(x)
		switch v := v.(type) {
		case nil:
			return nil
		case []interface{}:
			return index(v, i)
		case string:
			return indexString(v, i)
		default:
			return &expectedArrayError{v}
		}
	case []interface{}:
		switch v := v.(type) {
		case nil:
			return nil
		case []interface{}:
			return indices(v, x)
		default:
			return &expectedArrayError{v}
		}
	case map[string]interface{}:
		if v == nil {
			return nil
		}
		start, ok := x["start"]
		if !ok {
			return &expectedStartEndError{x}
		}
		end, ok := x["end"]
		if !ok {
			return &expectedStartEndError{x}
		}
		return funcSlice(nil, v, end, start)
	default:
		switch v.(type) {
		case []interface{}:
			return &arrayIndexNotNumberError{x}
		case string:
			return &stringIndexNotNumberError{x}
		default:
			return &objectKeyNotStringError{x}
		}
	}
}

func index(vs []interface{}, i int) interface{} {
	i = clampIndex(i, -1, len(vs))
	if 0 <= i && i < len(vs) {
		return vs[i]
	}
	return nil
}

func indexString(s string, i int) interface{} {
	l := len([]rune(s))
	i = clampIndex(i, -1, l)
	if 0 <= i && i < l {
		for _, r := range s {
			if i--; i < 0 {
				return string(r)
			}
		}
	}
	return nil
}

func funcSlice(_, v, e, s interface{}) (r interface{}) {
	switch v := v.(type) {
	case nil:
		return nil
	case []interface{}:
		return slice(v, e, s)
	case string:
		return sliceString(v, e, s)
	default:
		return &expectedArrayError{v}
	}
}

func slice(vs []interface{}, e, s interface{}) interface{} {
	var start, end int
	if s != nil {
		if i, ok := toInt(s); ok {
			start = clampIndex(i, 0, len(vs))
		} else {
			return &arrayIndexNotNumberError{s}
		}
	}
	if e != nil {
		if i, ok := toInt(e); ok {
			end = clampIndex(i, start, len(vs))
		} else {
			return &arrayIndexNotNumberError{e}
		}
	} else {
		end = len(vs)
	}
	return vs[start:end]
}

func sliceString(v string, e, s interface{}) interface{} {
	var start, end int
	l := len([]rune(v))
	if s != nil {
		if i, ok := toInt(s); ok {
			start = clampIndex(i, 0, l)
		} else {
			return &stringIndexNotNumberError{s}
		}
	}
	if e != nil {
		if i, ok := toInt(e); ok {
			end = clampIndex(i, start, l)
		} else {
			return &stringIndexNotNumberError{e}
		}
	} else {
		end = l
	}
	if start < l {
		for i := range v {
			if start--; start < 0 {
				start = i
				break
			}
		}
	} else {
		start = len(v)
	}
	if end < l {
		for i := range v {
			if end--; end < 0 {
				end = i
				break
			}
		}
	} else {
		end = len(v)
	}
	return v[start:end]
}

func clampIndex(i, min, max int) int {
	if i < 0 {
		i += max
	}
	if i < min {
		return min
	} else if i < max {
		return i
	} else {
		return max
	}
}

func funcFlatten(v interface{}, args []interface{}) interface{} {
	vs, ok := values(v)
	if !ok {
		return &funcTypeError{"flatten", v}
	}
	var depth float64
	if len(args) == 0 {
		depth = -1
	} else {
		depth, ok = toFloat(args[0])
		if !ok {
			return &funcTypeError{"flatten", args[0]}
		}
		if depth < 0 {
			return &flattenDepthError{depth}
		}
	}
	return flatten(nil, vs, depth)
}

func flatten(xs, vs []interface{}, depth float64) []interface{} {
	for _, v := range vs {
		if vs, ok := v.([]interface{}); ok && depth != 0 {
			xs = flatten(xs, vs, depth-1)
		} else {
			xs = append(xs, v)
		}
	}
	return xs
}

type rangeIter struct {
	value, end, step interface{}
}

func (iter *rangeIter) Next() (interface{}, bool) {
	if compare(iter.step, 0)*compare(iter.value, iter.end) >= 0 {
		return nil, false
	}
	v := iter.value
	iter.value = funcOpAdd(nil, v, iter.step)
	return v, true
}

func funcRange(_ interface{}, xs []interface{}) interface{} {
	for _, x := range xs {
		switch x.(type) {
		case int, float64, *big.Int:
		default:
			return &funcTypeError{"range", x}
		}
	}
	return &rangeIter{xs[0], xs[1], xs[2]}
}

func funcMin(v interface{}) interface{} {
	vs, ok := v.([]interface{})
	if !ok {
		return &funcTypeError{"min", v}
	}
	return minMaxBy(vs, vs, true)
}

func funcMinBy(v, x interface{}) interface{} {
	vs, ok := v.([]interface{})
	if !ok {
		return &funcTypeError{"min_by", v}
	}
	xs, ok := x.([]interface{})
	if !ok {
		return &funcTypeError{"min_by", x}
	}
	if len(vs) != len(xs) {
		return &lengthMismatchError{"min_by", vs, xs}
	}
	return minMaxBy(vs, xs, true)
}

func funcMax(v interface{}) interface{} {
	vs, ok := v.([]interface{})
	if !ok {
		return &funcTypeError{"max", v}
	}
	return minMaxBy(vs, vs, false)
}

func funcMaxBy(v, x interface{}) interface{} {
	vs, ok := v.([]interface{})
	if !ok {
		return &funcTypeError{"max_by", v}
	}
	xs, ok := x.([]interface{})
	if !ok {
		return &funcTypeError{"max_by", x}
	}
	if len(vs) != len(xs) {
		return &lengthMismatchError{"max_by", vs, xs}
	}
	return minMaxBy(vs, xs, false)
}

func minMaxBy(vs, xs []interface{}, isMin bool) interface{} {
	if len(vs) == 0 {
		return nil
	}
	i, j, x := 0, 0, xs[0]
	for i++; i < len(xs); i++ {
		if compare(x, xs[i]) > 0 == isMin {
			j, x = i, xs[i]
		}
	}
	return vs[j]
}

type sortItem struct {
	value, key interface{}
}

func sortItems(name string, v, x interface{}) ([]*sortItem, error) {
	vs, ok := v.([]interface{})
	if !ok {
		return nil, &funcTypeError{name, v}
	}
	xs, ok := x.([]interface{})
	if !ok {
		return nil, &funcTypeError{name, x}
	}
	if len(vs) != len(xs) {
		return nil, &lengthMismatchError{name, vs, xs}
	}
	items := make([]*sortItem, len(vs))
	for i, v := range vs {
		items[i] = &sortItem{v, xs[i]}
	}
	sort.SliceStable(items, func(i, j int) bool {
		return compare(items[i].key, items[j].key) < 0
	})
	return items, nil
}

func funcSort(v interface{}) interface{} {
	return sortBy("sort", v, v)
}

func funcSortBy(v, x interface{}) interface{} {
	return sortBy("sort_by", v, x)
}

func sortBy(name string, v, x interface{}) interface{} {
	items, err := sortItems(name, v, x)
	if err != nil {
		return err
	}
	rs := make([]interface{}, len(items))
	for i, x := range items {
		rs[i] = x.value
	}
	return rs
}

func funcGroupBy(v, x interface{}) interface{} {
	items, err := sortItems("group_by", v, x)
	if err != nil {
		return err
	}
	var rs []interface{}
	var last interface{}
	for i, r := range items {
		if i == 0 || compare(last, r.key) != 0 {
			rs, last = append(rs, []interface{}{r.value}), r.key
		} else {
			rs[len(rs)-1] = append(rs[len(rs)-1].([]interface{}), r.value)
		}
	}
	return rs
}

func funcUnique(v interface{}) interface{} {
	return uniqueBy("unique", v, v)
}

func funcUniqueBy(v, x interface{}) interface{} {
	return uniqueBy("unique_by", v, x)
}

func uniqueBy(name string, v, x interface{}) interface{} {
	items, err := sortItems(name, v, x)
	if err != nil {
		return err
	}
	var rs []interface{}
	var last interface{}
	for i, r := range items {
		if i == 0 || compare(last, r.key) != 0 {
			rs, last = append(rs, r.value), r.key
		}
	}
	return rs
}

func funcJoin(v, x interface{}) interface{} {
	vs, ok := values(v)
	if !ok {
		return &funcTypeError{"join", v}
	}
	if len(vs) == 0 {
		return ""
	}
	sep, ok := x.(string)
	if len(vs) > 1 && !ok {
		return &funcTypeError{"join", x}
	}
	ss := make([]string, len(vs))
	for i, v := range vs {
		switch v := v.(type) {
		case nil:
		case string:
			ss[i] = v
		case bool:
			if v {
				ss[i] = "true"
			} else {
				ss[i] = "false"
			}
		case int, float64, *big.Int:
			ss[i] = jsonMarshal(v)
		default:
			return &joinTypeError{v}
		}
	}
	return strings.Join(ss, sep)
}

func funcSignificand(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) || v == 0.0 {
		return v
	}
	return math.Float64frombits((math.Float64bits(v) & 0x800fffffffffffff) | 0x3ff0000000000000)
}

func funcExp10(v float64) float64 {
	return math.Pow(10, v)
}

func funcFrexp(v interface{}) interface{} {
	x, ok := toFloat(v)
	if !ok {
		return &funcTypeError{"frexp", v}
	}
	f, e := math.Frexp(x)
	return []interface{}{f, e}
}

func funcModf(v interface{}) interface{} {
	x, ok := toFloat(v)
	if !ok {
		return &funcTypeError{"modf", v}
	}
	i, f := math.Modf(x)
	return []interface{}{f, i}
}

func funcLgamma(v float64) float64 {
	v, _ = math.Lgamma(v)
	return v
}

func funcDrem(l, r float64) float64 {
	x := math.Remainder(l, r)
	if x == 0.0 {
		return math.Copysign(x, l)
	}
	return x
}

func funcJn(l, r float64) float64 {
	return math.Jn(int(l), r)
}

func funcLdexp(l, r float64) float64 {
	return math.Ldexp(l, int(r))
}

func funcScalb(l, r float64) float64 {
	return l * math.Pow(2, r)
}

func funcScalbln(l, r float64) float64 {
	return l * math.Pow(2, r)
}

func funcYn(l, r float64) float64 {
	return math.Yn(int(l), r)
}

func funcInfinite(interface{}) interface{} {
	return math.Inf(1)
}

func funcIsfinite(v interface{}) interface{} {
	x, ok := toFloat(v)
	return ok && !math.IsInf(x, 0)
}

func funcIsinfinite(v interface{}) interface{} {
	x, ok := toFloat(v)
	return ok && math.IsInf(x, 0)
}

func funcNan(interface{}) interface{} {
	return math.NaN()
}

func funcIsnan(v interface{}) interface{} {
	x, ok := toFloat(v)
	if !ok {
		if v == nil {
			return false
		}
		return &funcTypeError{"isnan", v}
	}
	return math.IsNaN(x)
}

func funcIsnormal(v interface{}) interface{} {
	x, ok := toFloat(v)
	return ok && !math.IsNaN(x) && !math.IsInf(x, 0) && x != 0.0
}

func funcSetpath(v, p, n interface{}) interface{} {
	path, ok := p.([]interface{})
	if !ok {
		return &funcTypeError{"setpath", p}
	}
	var err error
	if v, err = update(v, path, n); err != nil {
		if err, ok := err.(*funcTypeError); ok {
			err.name = "setpath"
		}
		return err
	}
	return v
}

func funcDelpaths(v, p interface{}) interface{} {
	paths, ok := p.([]interface{})
	if !ok {
		return &funcTypeError{"delpaths", p}
	}
	// Fills the paths with an empty value and then delete them. We cannot delete
	// in each loop because array indices should not change. For example,
	//   jq -n "[0, 1, 2, 3] | delpaths([[1], [2]])" #=> [0, 3].
	var empty struct{}
	var err error
	for _, p := range paths {
		path, ok := p.([]interface{})
		if !ok {
			return &funcTypeError{"delpaths", p}
		}
		if v, err = update(v, path, empty); err != nil {
			return err
		}
	}
	return deleteEmpty(v)
}

func update(v interface{}, path []interface{}, n interface{}) (interface{}, error) {
	if len(path) == 0 {
		return n, nil
	}
	switch p := path[0].(type) {
	case string:
		switch v := v.(type) {
		case nil:
			return updateObject(nil, p, path[1:], n)
		case map[string]interface{}:
			return updateObject(v, p, path[1:], n)
		case struct{}:
			return v, nil
		default:
			return nil, &expectedObjectError{v}
		}
	case int, float64, *big.Int:
		i, _ := toInt(p)
		switch v := v.(type) {
		case nil:
			return updateArrayIndex(nil, i, path[1:], n)
		case []interface{}:
			return updateArrayIndex(v, i, path[1:], n)
		case struct{}:
			return v, nil
		default:
			return nil, &expectedArrayError{v}
		}
	case map[string]interface{}:
		switch v := v.(type) {
		case nil:
			return updateArraySlice(nil, p, path[1:], n)
		case []interface{}:
			return updateArraySlice(v, p, path[1:], n)
		case struct{}:
			return v, nil
		default:
			return nil, &expectedArrayError{v}
		}
	default:
		switch v.(type) {
		case []interface{}:
			return nil, &arrayIndexNotNumberError{p}
		default:
			return nil, &objectKeyNotStringError{p}
		}
	}
}

func updateObject(v map[string]interface{}, k string, path []interface{}, n interface{}) (interface{}, error) {
	x, ok := v[k]
	if !ok && n == struct{}{} {
		return v, nil
	}
	u, err := update(x, path, n)
	if err != nil {
		return nil, err
	}
	w := make(map[string]interface{}, len(v)+1)
	for k, v := range v {
		w[k] = v
	}
	w[k] = u
	return w, nil
}

func updateArrayIndex(v []interface{}, i int, path []interface{}, n interface{}) (interface{}, error) {
	var x interface{}
	if j := clampIndex(i, -1, len(v)); j < 0 {
		if n == struct{}{} {
			return v, nil
		}
		return nil, &funcTypeError{v: i}
	} else if j < len(v) {
		i = j
		x = v[i]
	} else {
		if n == struct{}{} {
			return v, nil
		}
		if i >= 0x8000000 {
			return nil, &arrayIndexTooLargeError{i}
		}
	}
	u, err := update(x, path, n)
	if err != nil {
		return nil, err
	}
	l := len(v)
	if i >= l {
		l = i + 1
	}
	w := make([]interface{}, l)
	copy(w, v)
	w[i] = u
	return w, nil
}

func updateArraySlice(v []interface{}, m map[string]interface{}, path []interface{}, n interface{}) (interface{}, error) {
	s, ok := m["start"]
	if !ok {
		return nil, &expectedStartEndError{m}
	}
	e, ok := m["end"]
	if !ok {
		return nil, &expectedStartEndError{m}
	}
	var start, end int
	if i, ok := toInt(s); ok {
		start = clampIndex(i, 0, len(v))
	}
	if i, ok := toInt(e); ok {
		end = clampIndex(i, start, len(v))
	} else {
		end = len(v)
	}
	if start == end && n == struct{}{} {
		return v, nil
	}
	u, err := update(v[start:end], path, n)
	if err != nil {
		return nil, err
	}
	switch u := u.(type) {
	case []interface{}:
		w := make([]interface{}, len(v)-(end-start)+len(u))
		copy(w, v[:start])
		copy(w[start:], u)
		copy(w[start+len(u):], v[end:])
		return w, nil
	case struct{}:
		w := make([]interface{}, len(v))
		copy(w, v)
		for i := start; i < end; i++ {
			w[i] = u
		}
		return w, nil
	default:
		return nil, &expectedArrayError{u}
	}
}

func deleteEmpty(v interface{}) interface{} {
	switch v := v.(type) {
	case struct{}:
		return nil
	case map[string]interface{}:
		for k, w := range v {
			if w == struct{}{} {
				delete(v, k)
			} else {
				v[k] = deleteEmpty(w)
			}
		}
		return v
	case []interface{}:
		var j int
		for _, w := range v {
			if w != struct{}{} {
				v[j] = deleteEmpty(w)
				j++
			}
		}
		for i := j; i < len(v); i++ {
			v[i] = nil
		}
		return v[:j]
	default:
		return v
	}
}

func funcGetpath(v, p interface{}) interface{} {
	keys, ok := p.([]interface{})
	if !ok {
		return &funcTypeError{"getpath", p}
	}
	u := v
	for _, x := range keys {
		switch v.(type) {
		case nil, []interface{}, map[string]interface{}:
			v = funcIndex2(nil, v, x)
			if _, ok := v.(error); ok {
				return &getpathError{u, p}
			}
		default:
			return &getpathError{u, p}
		}
	}
	return v
}

func funcTranspose(v interface{}) interface{} {
	vss, ok := v.([]interface{})
	if !ok {
		return &funcTypeError{"transpose", v}
	}
	if len(vss) == 0 {
		return []interface{}{}
	}
	var l int
	for _, vs := range vss {
		vs, ok := vs.([]interface{})
		if !ok {
			return &funcTypeError{"transpose", v}
		}
		if k := len(vs); l < k {
			l = k
		}
	}
	wss := make([][]interface{}, l)
	xs := make([]interface{}, l)
	for i, k := 0, len(vss); i < l; i++ {
		s := make([]interface{}, k)
		wss[i] = s
		xs[i] = s
	}
	for i, vs := range vss {
		for j, v := range vs.([]interface{}) {
			wss[j][i] = v
		}
	}
	return xs
}

func funcBsearch(v, t interface{}) interface{} {
	vs, ok := v.([]interface{})
	if !ok {
		return &funcTypeError{"bsearch", v}
	}
	i := sort.Search(len(vs), func(i int) bool {
		return compare(vs[i], t) >= 0
	})
	if i < len(vs) && compare(vs[i], t) == 0 {
		return i
	}
	return -i - 1
}

func funcGmtime(v interface{}) interface{} {
	if v, ok := toFloat(v); ok {
		return epochToArray(v, time.UTC)
	}
	return &funcTypeError{"gmtime", v}
}

func funcLocaltime(v interface{}) interface{} {
	if v, ok := toFloat(v); ok {
		return epochToArray(v, time.Local)
	}
	return &funcTypeError{"localtime", v}
}

func epochToArray(v float64, loc *time.Location) []interface{} {
	t := time.Unix(int64(v), int64((v-math.Floor(v))*1e9)).In(loc)
	return []interface{}{
		t.Year(),
		int(t.Month()) - 1,
		t.Day(),
		t.Hour(),
		t.Minute(),
		float64(t.Second()) + float64(t.Nanosecond())/1e9,
		int(t.Weekday()),
		t.YearDay() - 1,
	}
}

func funcMktime(v interface{}) interface{} {
	if a, ok := v.([]interface{}); ok {
		t, err := arrayToTime("mktime", a, time.UTC)
		if err != nil {
			return err
		}
		return timeToEpoch(t)
	}
	return &funcTypeError{"mktime", v}
}

func timeToEpoch(t time.Time) float64 {
	return float64(t.Unix()) + float64(t.Nanosecond())/1e9
}

func funcStrftime(v, x interface{}) interface{} {
	if w, ok := toFloat(v); ok {
		v = epochToArray(w, time.UTC)
	}
	if a, ok := v.([]interface{}); ok {
		if format, ok := x.(string); ok {
			t, err := arrayToTime("strftime", a, time.UTC)
			if err != nil {
				return err
			}
			return timefmt.Format(t, format)
		}
		return &funcTypeError{"strftime", x}
	}
	return &funcTypeError{"strftime", v}
}

func funcStrflocaltime(v, x interface{}) interface{} {
	if w, ok := toFloat(v); ok {
		v = epochToArray(w, time.Local)
	}
	if a, ok := v.([]interface{}); ok {
		if format, ok := x.(string); ok {
			t, err := arrayToTime("strflocaltime", a, time.Local)
			if err != nil {
				return err
			}
			return timefmt.Format(t, format)
		}
		return &funcTypeError{"strflocaltime", x}
	}
	return &funcTypeError{"strflocaltime", v}
}

func funcStrptime(v, x interface{}) interface{} {
	if v, ok := v.(string); ok {
		if format, ok := x.(string); ok {
			t, err := timefmt.Parse(v, format)
			if err != nil {
				return err
			}
			var s time.Time
			if t == s {
				return &funcTypeError{"strptime", v}
			}
			return epochToArray(timeToEpoch(t), time.UTC)
		}
		return &funcTypeError{"strptime", x}
	}
	return &funcTypeError{"strptime", v}
}

func arrayToTime(name string, a []interface{}, loc *time.Location) (time.Time, error) {
	var t time.Time
	if len(a) != 8 {
		return t, &funcTypeError{name, a}
	}
	var y, m, d, h, min, sec, nsec int
	if x, ok := toInt(a[0]); ok {
		y = x
	} else {
		return t, &funcTypeError{name, a}
	}
	if x, ok := toInt(a[1]); ok {
		m = x + 1
	} else {
		return t, &funcTypeError{name, a}
	}
	if x, ok := toInt(a[2]); ok {
		d = x
	} else {
		return t, &funcTypeError{name, a}
	}
	if x, ok := toInt(a[3]); ok {
		h = x
	} else {
		return t, &funcTypeError{name, a}
	}
	if x, ok := toInt(a[4]); ok {
		min = x
	} else {
		return t, &funcTypeError{name, a}
	}
	if x, ok := toFloat(a[5]); ok {
		sec = int(x)
		nsec = int((x - math.Floor(x)) * 1e9)
	} else {
		return t, &funcTypeError{name, a}
	}
	return time.Date(y, time.Month(m), d, h, min, sec, nsec, loc), nil
}

func funcNow(interface{}) interface{} {
	return timeToEpoch(time.Now())
}

func funcMatch(v, re, fs, testing interface{}) interface{} {
	var flags string
	if fs != nil {
		v, ok := fs.(string)
		if !ok {
			return &funcTypeError{"match", fs}
		}
		flags = v
	}
	s, ok := v.(string)
	if !ok {
		return &funcTypeError{"match", v}
	}
	restr, ok := re.(string)
	if !ok {
		return &funcTypeError{"match", v}
	}
	r, err := compileRegexp(restr, flags)
	if err != nil {
		return err
	}
	var xs [][]int
	if strings.ContainsRune(flags, 'g') && testing != true {
		xs = r.FindAllStringSubmatchIndex(s, -1)
	} else {
		got := r.FindStringSubmatchIndex(s)
		if testing == true {
			return got != nil
		}
		if got != nil {
			xs = [][]int{got}
		}
	}
	res, names := make([]interface{}, len(xs)), r.SubexpNames()
	for i, x := range xs {
		captures := make([]interface{}, (len(x)-2)/2)
		for j := 1; j < len(x)/2; j++ {
			var name interface{}
			if n := names[j]; n != "" {
				name = n
			}
			if x[j*2] < 0 {
				captures[j-1] = map[string]interface{}{
					"name":   name,
					"offset": -1,
					"length": 0,
					"string": nil,
				}
				continue
			}
			captures[j-1] = map[string]interface{}{
				"name":   name,
				"offset": len([]rune(s[:x[j*2]])),
				"length": len([]rune(s[:x[j*2+1]])) - len([]rune(s[:x[j*2]])),
				"string": s[x[j*2]:x[j*2+1]],
			}
		}
		res[i] = map[string]interface{}{
			"offset":   len([]rune(s[:x[0]])),
			"length":   len([]rune(s[:x[1]])) - len([]rune(s[:x[0]])),
			"string":   s[x[0]:x[1]],
			"captures": captures,
		}
	}
	return res
}

func compileRegexp(re, flags string) (*regexp.Regexp, error) {
	if strings.IndexFunc(flags, func(r rune) bool {
		return r != 'g' && r != 'i' && r != 'm'
	}) >= 0 {
		return nil, fmt.Errorf("unsupported regular expression flag: %q", flags)
	}
	re = strings.ReplaceAll(re, "(?<", "(?P<")
	if strings.ContainsRune(flags, 'i') {
		re = "(?i)" + re
	}
	if strings.ContainsRune(flags, 'm') {
		re = "(?s)" + re
	}
	r, err := regexp.Compile(re)
	if err != nil {
		return nil, fmt.Errorf("invalid regular expression %q: %s", re, err)
	}
	return r, nil
}

func funcCapture(v interface{}) interface{} {
	vs, ok := v.(map[string]interface{})
	if !ok {
		return &expectedObjectError{v}
	}
	v = vs["captures"]
	captures, ok := v.([]interface{})
	if !ok {
		return &expectedArrayError{v}
	}
	w := make(map[string]interface{}, len(captures))
	for _, capture := range captures {
		if capture, ok := capture.(map[string]interface{}); ok {
			if name, ok := capture["name"].(string); ok {
				w[name] = capture["string"]
			}
		}
	}
	return w
}

func funcError(v interface{}, args []interface{}) interface{} {
	if len(args) > 0 {
		v = args[0]
	}
	code := 5
	if v == nil {
		code = 0
	}
	return &exitCodeError{v, code, false}
}

func funcHalt(interface{}) interface{} {
	return &exitCodeError{nil, 0, true}
}

func funcHaltError(v interface{}, args []interface{}) interface{} {
	code := 5
	if len(args) > 0 {
		var ok bool
		if code, ok = toInt(args[0]); !ok {
			return &funcTypeError{"halt_error", args[0]}
		}
	}
	return &exitCodeError{v, code, true}
}

func toInt(x interface{}) (int, bool) {
	switch x := x.(type) {
	case int:
		return x, true
	case float64:
		return floatToInt(x), true
	case *big.Int:
		if x.IsInt64() {
			if i := x.Int64(); minInt <= i && i <= maxInt {
				return int(i), true
			}
		}
		if x.Sign() > 0 {
			return maxInt, true
		}
		return minInt, true
	default:
		return 0, false
	}
}

func floatToInt(x float64) int {
	if minInt <= x && x <= maxInt {
		return int(x)
	}
	if x > 0 {
		return maxInt
	}
	return minInt
}

func toFloat(x interface{}) (float64, bool) {
	switch x := x.(type) {
	case int:
		return float64(x), true
	case float64:
		return x, true
	case *big.Int:
		return bigToFloat(x), true
	default:
		return 0.0, false
	}
}

func bigToFloat(x *big.Int) float64 {
	if x.IsInt64() {
		return float64(x.Int64())
	}
	if f, err := strconv.ParseFloat(x.String(), 64); err == nil {
		return f
	}
	return math.Inf(x.Sign())
}
