package core

import (
	"github.com/hktalent/jaeles/libs"
	"github.com/hktalent/jaeles/utils"
	"github.com/robertkrimen/otto"
)

// RoutineRunner runner struct
type RoutineRunner struct {
	Input       string
	SendingType string
	Opt         libs.Options
	Sign        libs.Signature
	Routines    []libs.Routine
	Results     map[string]bool
	Target      map[string]string
}

// InitRoutine init routine task
func InitRoutine(url string, sign libs.Signature, opt libs.Options) (RoutineRunner, error) {
	var routine RoutineRunner
	routine.Input = url
	routine.Opt = opt
	routine.Sign = sign

	routine.Results = make(map[string]bool)
	routine.Target = MoreVariables(ParseTarget(routine.Input), routine.Sign, routine.Opt)
	routine.ParseRoutines(&sign)

	return routine, nil
}

// ParseRoutines parse routine
func (r *RoutineRunner) ParseRoutines(sign *libs.Signature) {
	var routines []libs.Routine

	for _, rawRoutine := range sign.Routines {
		var routine libs.Routine
		routine.Signs = ResolveHeader(rawRoutine.Signs, r.Target)
		for _, logic := range rawRoutine.Logics {
			logic.Expression = ResolveVariable(logic.Expression, r.Target)
			logic.Invokes = ResolveDetection(logic.Invokes, r.Target)
			routine.Logics = append(routine.Logics, logic)
		}
		routines = append(routines, routine)
	}

	r.Routines = routines
}

// Start start the routine
func (r *RoutineRunner) Start() {
	for _, routine := range r.Routines {
		r.StartRunner(routine)
		if len(r.Results) == 0 {
			continue
		}

		for _, logic := range routine.Logics {
			IsPassed := r.DoExpression(logic.Expression)
			utils.DebugF("Expression: %s -- %v", logic.Expression, IsPassed)

			if IsPassed {
				// set new level
				r.Opt.Level = logic.Level
				r.DoInvokes(logic.Invokes)
			}
		}
	}
}

// Start start the routine
func (r *RoutineRunner) StartRunner(routine libs.Routine) {

	for _, Signs := range routine.Signs {
		for key, signFile := range Signs {
			utils.DebugF("Start runner for: %s", key)
			sign, err := ParseSign(signFile)
			if err != nil {
				utils.ErrorF("Error parsing YAML sign: %v", signFile)
				continue
			}

			// Forced to send sign as serial
			//sign.Single = true

			job := libs.Job{
				URL:  r.Input,
				Sign: sign,
			}

			runner, err := InitRunner(job.URL, job.Sign, r.Opt)
			if err != nil {
				utils.ErrorF("Error create new runner: %v", err)
			}
			runner.InRoutine = true
			runner.Sending()
			utils.DebugF("Done runner for: %s", key)

			// set result here
			for _, rec := range runner.Records {
				if rec.IsVulnerable {
					_, exist := r.Results[key]
					if exist {
						continue
					}
					r.Results[key] = true
				}
			}
		}
	}

}

// DoExpression start the routine
func (r *RoutineRunner) DoExpression(expression string) bool {
	vm := otto.New()
	// export value
	for k, v := range r.Results {
		vm.Set(k, func(call otto.FunctionCall) otto.Value {
			result, _ := vm.ToValue(v)
			return result
		})
	}

	result, _ := vm.Run(expression)
	analyzeResult, err := result.Export()

	if err != nil || analyzeResult == nil {
		return false
	}
	return analyzeResult.(bool)
}

// DoExpression start the routine
func (r *RoutineRunner) DoInvokes(invokes []string) {
	for _, signFile := range invokes {
		sign, err := ParseSign(signFile)
		if err != nil {
			utils.ErrorF("Error parsing YAML sign: %v", signFile)
			continue
		}
		job := libs.Job{
			URL:  r.Input,
			Sign: sign,
		}

		runner, err := InitRunner(job.URL, job.Sign, r.Opt)
		if err != nil {
			utils.ErrorF("Error create new runner: %v", err)
		}
		runner.Sending()
	}

}
