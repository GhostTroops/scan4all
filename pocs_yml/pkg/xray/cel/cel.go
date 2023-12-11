package cel

import (
	"github.com/GhostTroops/scan4all/pocs_yml/pkg/xray/structs"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"strings"
	"sync"
)

type RequestFuncType func(rule structs.Rule) error

var (
	CustomLibPool = sync.Pool{
		New: func() interface{} {
			return CustomLib{}
		},
	}
)

// 自定义Lib库，包含变量和函数

type Env = cel.Env
type CustomLib struct {
	envOptions     []cel.EnvOption
	programOptions []cel.ProgramOption
}

// 执行表达式
func Evaluate(env *cel.Env, expression string, params map[string]interface{}) (ref.Val, error) {
	ast, iss := env.Compile(expression)
	err := iss.Err()
	if err != nil {
		return nil, err
	}
	prg, err := env.Program(ast)
	if err != nil {
		return nil, err
	}
	out, _, err := prg.Eval(params)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func UrlTypeToString(u *structs.UrlType) string {
	var buf strings.Builder
	if u.Scheme != "" {
		buf.WriteString(u.Scheme)
		buf.WriteByte(':')
	}
	if u.Scheme != "" || u.Host != "" {
		if u.Host != "" || u.Path != "" {
			buf.WriteString("//")
		}
		if h := u.Host; h != "" {
			buf.WriteString(u.Host)
		}
	}
	path := u.Path
	if path != "" && path[0] != '/' && u.Host != "" {
		buf.WriteString("/")
	}
	if buf.Len() == 0 {
		if i := strings.IndexByte(path, ':'); i > -1 && strings.IndexByte(path[:i], '/') == -1 {
			buf.WriteString("./")
		}
	}
	buf.WriteString(path)

	if u.Query != "" {
		buf.WriteByte('?')
		buf.WriteString(u.Query)
	}
	if u.Fragment != "" {
		buf.WriteByte('#')
		buf.WriteString(u.Fragment)
	}
	return buf.String()
}

func NewEnv(c *CustomLib) (*cel.Env, error) {
	return cel.NewEnv(cel.Lib(c))
}

func NewEnvOption() CustomLib {
	c := CustomLibPool.Get().(CustomLib)
	reg := types.NewEmptyRegistry()

	c.envOptions = NewFunctionDefineOptions(reg)

	c.programOptions = NewFunctionImplOptions(reg)
	return c
}

func PutCustomLib(c CustomLib) {
	CustomLibPool.Put(c)
}

// 声明环境中的变量类型和函数
func (c *CustomLib) CompileOptions() []cel.EnvOption {
	return c.envOptions
}

func (c *CustomLib) ProgramOptions() []cel.ProgramOption {
	return c.programOptions
}

func (c *CustomLib) UpdateCompileOption(k string, t *exprpb.Type) {
	c.envOptions = append(c.envOptions, cel.Declarations(decls.NewVar(k, t)))
}

func (c *CustomLib) DefineRuleFunction(requestFunc RequestFuncType, ruleName string, rule structs.Rule, function func(requestFunc RequestFuncType, ruleName string, rule structs.Rule) (bool, error)) {
	c.envOptions = append(c.envOptions, cel.Declarations(
		decls.NewFunction(ruleName,
			decls.NewOverload(ruleName,
				[]*exprpb.Type{},
				decls.Bool)),
	))

	c.programOptions = append(c.programOptions, cel.Functions(
		&functions.Overload{
			Operator: ruleName,
			Function: func(values ...ref.Val) ref.Val {
				r, err := function(requestFunc, ruleName, rule)
				if err != nil {
					r = false
				}
				return types.Bool(r)
			},
		}))
}
