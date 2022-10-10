package core

import (
	"fmt"
	"net/http/cookiejar"

	"github.com/remeh/sizedwaitgroup"
	"go.uber.org/atomic"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/workflows"
)

const workflowStepExecutionError = "[%s] Could not execute workflow step: %s\n"

// executeWorkflow runs a workflow on an input and returns true or false
func (e *Engine) executeWorkflow(input string, w *workflows.Workflow) bool {
	results := &atomic.Bool{}

	// at this point we should be at the start root execution of a workflow tree, hence we create global shared instances
	workflowCookieJar, _ := cookiejar.New(nil)
	ctxArgs := contextargs.New()
	ctxArgs.Input = input
	ctxArgs.CookieJar = workflowCookieJar

	swg := sizedwaitgroup.New(w.Options.Options.TemplateThreads)
	for _, template := range w.Workflows {
		swg.Add()
		func(template *workflows.WorkflowTemplate) {
			if err := e.runWorkflowStep(template, ctxArgs, results, &swg, w); err != nil {
				gologger.Warning().Msgf(workflowStepExecutionError, template.Template, err)
			}
			swg.Done()
		}(template)
	}
	swg.Wait()
	return results.Load()
}

// runWorkflowStep runs a workflow step for the workflow. It executes the workflow
// in a recursive manner running all subtemplates and matchers.
func (e *Engine) runWorkflowStep(template *workflows.WorkflowTemplate, input *contextargs.Context, results *atomic.Bool, swg *sizedwaitgroup.SizedWaitGroup, w *workflows.Workflow) error {
	var firstMatched bool
	var err error
	var mainErr error

	if len(template.Matchers) == 0 {
		for _, executer := range template.Executers {
			executer.Options.Progress.AddToTotal(int64(executer.Executer.Requests()))

			// Don't print results with subtemplates, only print results on template.
			if len(template.Subtemplates) > 0 {
				err = executer.Executer.ExecuteWithResults(input, func(result *output.InternalWrappedEvent) {
					if result.OperatorsResult == nil {
						return
					}
					if len(result.Results) > 0 {
						firstMatched = true
					}

					if result.OperatorsResult != nil && result.OperatorsResult.Extracts != nil {
						for k, v := range result.OperatorsResult.Extracts {
							// normalize items:
							switch len(v) {
							case 0, 1:
								// - key:[item] => key: item
								input.Set(k, v[0])
							default:
								// - key:[item_0, ..., item_n] => key0:item_0, keyn:item_n
								for vIdx, vVal := range v {
									normalizedKIdx := fmt.Sprintf("%s%d", k, vIdx)
									input.Set(normalizedKIdx, vVal)
								}
								// also add the original name with full slice
								input.Set(k, v)
							}
						}
					}
				})
			} else {
				var matched bool
				matched, err = executer.Executer.Execute(input)
				if matched {
					firstMatched = true
				}
			}
			if err != nil {
				if w.Options.HostErrorsCache != nil {
					w.Options.HostErrorsCache.MarkFailed(input.Input, err)
				}
				if len(template.Executers) == 1 {
					mainErr = err
				} else {
					gologger.Warning().Msgf(workflowStepExecutionError, template.Template, err)
				}
				continue
			}
		}
	}
	if len(template.Subtemplates) == 0 {
		results.CompareAndSwap(false, firstMatched)
	}
	if len(template.Matchers) > 0 {
		for _, executer := range template.Executers {
			executer.Options.Progress.AddToTotal(int64(executer.Executer.Requests()))

			err := executer.Executer.ExecuteWithResults(input, func(event *output.InternalWrappedEvent) {
				if event.OperatorsResult == nil {
					return
				}

				if event.OperatorsResult.Extracts != nil {
					for k, v := range event.OperatorsResult.Extracts {
						input.Set(k, v)
					}
				}

				for _, matcher := range template.Matchers {
					if !matcher.Match(event.OperatorsResult) {
						continue
					}

					for _, subtemplate := range matcher.Subtemplates {
						swg.Add()

						go func(subtemplate *workflows.WorkflowTemplate) {
							if err := e.runWorkflowStep(subtemplate, input, results, swg, w); err != nil {
								gologger.Warning().Msgf(workflowStepExecutionError, subtemplate.Template, err)
							}
							swg.Done()
						}(subtemplate)
					}
				}
			})
			if err != nil {
				if len(template.Executers) == 1 {
					mainErr = err
				} else {
					gologger.Warning().Msgf(workflowStepExecutionError, template.Template, err)
				}
				continue
			}
		}
		return mainErr
	}
	if len(template.Subtemplates) > 0 && firstMatched {
		for _, subtemplate := range template.Subtemplates {
			swg.Add()

			go func(template *workflows.WorkflowTemplate) {
				if err := e.runWorkflowStep(template, input, results, swg, w); err != nil {
					gologger.Warning().Msgf(workflowStepExecutionError, template.Template, err)
				}
				swg.Done()
			}(subtemplate)
		}
	}
	return mainErr
}
