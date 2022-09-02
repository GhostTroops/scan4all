package loader

import (
	"os"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader/filter"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/parsers"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils/stats"
	"github.com/projectdiscovery/nuclei/v2/pkg/workflows"
)

// Config contains the configuration options for the loader
type Config struct {
	Templates                []string
	TemplateURLs             []string
	Workflows                []string
	WorkflowURLs             []string
	ExcludeTemplates         []string
	IncludeTemplates         []string
	RemoteTemplateDomainList []string

	Tags              []string
	ExcludeTags       []string
	Protocols         templateTypes.ProtocolTypes
	ExcludeProtocols  templateTypes.ProtocolTypes
	Authors           []string
	Severities        severity.Severities
	ExcludeSeverities severity.Severities
	IncludeTags       []string
	IncludeIds        []string
	ExcludeIds        []string
	IncludeConditions []string

	Catalog            catalog.Catalog
	ExecutorOptions    protocols.ExecuterOptions
	TemplatesDirectory string
}

// Store is a storage for loaded nuclei templates
type Store struct {
	tagFilter      *filter.TagFilter
	pathFilter     *filter.PathFilter
	config         *Config
	finalTemplates []string
	finalWorkflows []string

	templates []*templates.Template
	workflows []*templates.Template

	preprocessor templates.Preprocessor
}

// NewConfig returns a new loader config
func NewConfig(options *types.Options, templateConfig *config.Config, catalog catalog.Catalog, executerOpts protocols.ExecuterOptions) *Config {
	loaderConfig := Config{
		Templates:                options.Templates,
		Workflows:                options.Workflows,
		RemoteTemplateDomainList: options.RemoteTemplateDomainList,
		TemplateURLs:             options.TemplateURLs,
		WorkflowURLs:             options.WorkflowURLs,
		ExcludeTemplates:         options.ExcludedTemplates,
		Tags:                     options.Tags,
		ExcludeTags:              options.ExcludeTags,
		IncludeTemplates:         options.IncludeTemplates,
		Authors:                  options.Authors,
		Severities:               options.Severities,
		ExcludeSeverities:        options.ExcludeSeverities,
		IncludeTags:              options.IncludeTags,
		IncludeIds:               options.IncludeIds,
		ExcludeIds:               options.ExcludeIds,
		TemplatesDirectory:       templateConfig.TemplatesDirectory,
		Protocols:                options.Protocols,
		ExcludeProtocols:         options.ExcludeProtocols,
		IncludeConditions:        options.IncludeConditions,
		Catalog:                  catalog,
		ExecutorOptions:          executerOpts,
	}
	return &loaderConfig
}

// New creates a new template store based on provided configuration
func New(config *Config) (*Store, error) {
	tagFilter, err := filter.New(&filter.Config{
		Tags:              config.Tags,
		ExcludeTags:       config.ExcludeTags,
		Authors:           config.Authors,
		Severities:        config.Severities,
		ExcludeSeverities: config.ExcludeSeverities,
		IncludeTags:       config.IncludeTags,
		IncludeIds:        config.IncludeIds,
		ExcludeIds:        config.ExcludeIds,
		Protocols:         config.Protocols,
		ExcludeProtocols:  config.ExcludeProtocols,
		IncludeConditions: config.IncludeConditions,
	})
	if err != nil {
		return nil, err
	}
	// Create a tag filter based on provided configuration
	store := &Store{
		config:    config,
		tagFilter: tagFilter,
		pathFilter: filter.NewPathFilter(&filter.PathFilterConfig{
			IncludedTemplates: config.IncludeTemplates,
			ExcludedTemplates: config.ExcludeTemplates,
		}, config.Catalog),
		finalTemplates: config.Templates,
		finalWorkflows: config.Workflows,
	}

	urlBasedTemplatesProvided := len(config.TemplateURLs) > 0 || len(config.WorkflowURLs) > 0
	if urlBasedTemplatesProvided {
		remoteTemplates, remoteWorkflows, err := getRemoteTemplatesAndWorkflows(config.TemplateURLs, config.WorkflowURLs, config.RemoteTemplateDomainList)
		if err != nil {
			return store, err
		}
		store.finalTemplates = append(store.finalTemplates, remoteTemplates...)
		store.finalWorkflows = append(store.finalWorkflows, remoteWorkflows...)
	}

	// Handle a dot as the current working directory
	if len(store.finalTemplates) == 1 && store.finalTemplates[0] == "." {
		currentDirectory, err := os.Getwd()
		if err != nil {
			return nil, errors.Wrap(err, "could not get current directory")
		}
		store.finalTemplates = []string{currentDirectory}
	}
	// Handle a case with no templates or workflows, where we use base directory
	if len(store.finalTemplates) == 0 && len(store.finalWorkflows) == 0 && !urlBasedTemplatesProvided {
		store.finalTemplates = []string{config.TemplatesDirectory}
	}
	return store, nil
}

// Templates returns all the templates in the store
func (store *Store) Templates() []*templates.Template {
	return store.templates
}

// Workflows returns all the workflows in the store
func (store *Store) Workflows() []*templates.Template {
	return store.workflows
}

// RegisterPreprocessor allows a custom preprocessor to be passed to the store to run against templates
func (store *Store) RegisterPreprocessor(preprocessor templates.Preprocessor) {
	store.preprocessor = preprocessor
}

// Load loads all the templates from a store, performs filtering and returns
// the complete compiled templates for a nuclei execution configuration.
func (store *Store) Load() {
	store.templates = store.LoadTemplates(store.finalTemplates)
	store.workflows = store.LoadWorkflows(store.finalWorkflows)
}

var templateIDPathMap map[string]string

func init() {
	templateIDPathMap = make(map[string]string)
}

// ValidateTemplates takes a list of templates and validates them
// erroring out on discovering any faulty templates.
func (store *Store) ValidateTemplates() error {
	templatePaths := store.config.Catalog.GetTemplatesPath(store.finalTemplates)
	workflowPaths := store.config.Catalog.GetTemplatesPath(store.finalWorkflows)

	filteredTemplatePaths := store.pathFilter.Match(templatePaths)
	filteredWorkflowPaths := store.pathFilter.Match(workflowPaths)

	if areTemplatesValid(store, filteredTemplatePaths) && areWorkflowsValid(store, filteredWorkflowPaths) {
		return nil
	}
	return errors.New("errors occured during template validation")
}

func areWorkflowsValid(store *Store, filteredWorkflowPaths map[string]struct{}) bool {
	return areWorkflowOrTemplatesValid(store, filteredWorkflowPaths, true, func(templatePath string, tagFilter *filter.TagFilter) (bool, error) {
		return parsers.LoadWorkflow(templatePath, store.config.Catalog)
	})
}

func areTemplatesValid(store *Store, filteredTemplatePaths map[string]struct{}) bool {
	return areWorkflowOrTemplatesValid(store, filteredTemplatePaths, false, func(templatePath string, tagFilter *filter.TagFilter) (bool, error) {
		return parsers.LoadTemplate(templatePath, store.tagFilter, nil, store.config.Catalog)
	})
}

func areWorkflowOrTemplatesValid(store *Store, filteredTemplatePaths map[string]struct{}, isWorkflow bool, load func(templatePath string, tagFilter *filter.TagFilter) (bool, error)) bool {
	areTemplatesValid := true

	for templatePath := range filteredTemplatePaths {
		if _, err := load(templatePath, store.tagFilter); err != nil {
			if isParsingError("Error occurred loading template %s: %s\n", templatePath, err) {
				areTemplatesValid = false
				continue
			}
		}

		template, err := templates.Parse(templatePath, store.preprocessor, store.config.ExecutorOptions)
		if err != nil {
			if isParsingError("Error occurred parsing template %s: %s\n", templatePath, err) {
				areTemplatesValid = false
			}
		} else {
			if existingTemplatePath, found := templateIDPathMap[template.ID]; !found {
				templateIDPathMap[template.ID] = templatePath
			} else {
				areTemplatesValid = false
				gologger.Warning().Msgf("Found duplicate template ID during validation '%s' => '%s': %s\n", templatePath, existingTemplatePath, template.ID)
			}
			if !isWorkflow && len(template.Workflows) > 0 {
				continue
			}
		}
		if isWorkflow {
			if !areWorkflowTemplatesValid(store, template.Workflows) {
				areTemplatesValid = false
				continue
			}
		}
	}
	return areTemplatesValid
}

func areWorkflowTemplatesValid(store *Store, workflows []*workflows.WorkflowTemplate) bool {
	for _, workflow := range workflows {
		if !areWorkflowTemplatesValid(store, workflow.Subtemplates) {
			return false
		}
		_, err := store.config.Catalog.GetTemplatePath(workflow.Template)
		if err != nil {
			if isParsingError("Error occurred loading template %s: %s\n", workflow.Template, err) {
				return false
			}
		}
	}
	return true
}

func isParsingError(message string, template string, err error) bool {
	if err == templates.ErrCreateTemplateExecutor {
		return false
	}
	if err == filter.ErrExcluded {
		return false
	}
	gologger.Error().Msgf(message, template, err)
	return true
}

// LoadTemplates takes a list of templates and returns paths for them
func (store *Store) LoadTemplates(templatesList []string) []*templates.Template {
	includedTemplates := store.config.Catalog.GetTemplatesPath(templatesList)
	templatePathMap := store.pathFilter.Match(includedTemplates)

	loadedTemplates := make([]*templates.Template, 0, len(templatePathMap))
	for templatePath := range templatePathMap {
		loaded, err := parsers.LoadTemplate(templatePath, store.tagFilter, nil, store.config.Catalog)
		if loaded || store.pathFilter.MatchIncluded(templatePath) {
			parsed, err := templates.Parse(templatePath, store.preprocessor, store.config.ExecutorOptions)
			if err != nil {
				stats.Increment(parsers.RuntimeWarningsStats)
				gologger.Warning().Msgf("Could not parse template %s: %s\n", templatePath, err)
			} else if parsed != nil {
				if len(parsed.RequestsHeadless) > 0 && !store.config.ExecutorOptions.Options.Headless {
					gologger.Warning().Msgf("Headless flag is required for headless template %s\n", templatePath)
				} else {
					loadedTemplates = append(loadedTemplates, parsed)
				}
			}
		} else if err != nil {
			gologger.Warning().Msgf("Could not load template %s: %s\n", templatePath, err)
		}
	}
	return loadedTemplates
}

// LoadWorkflows takes a list of workflows and returns paths for them
func (store *Store) LoadWorkflows(workflowsList []string) []*templates.Template {
	includedWorkflows := store.config.Catalog.GetTemplatesPath(workflowsList)
	workflowPathMap := store.pathFilter.Match(includedWorkflows)

	loadedWorkflows := make([]*templates.Template, 0, len(workflowPathMap))
	for workflowPath := range workflowPathMap {
		loaded, err := parsers.LoadWorkflow(workflowPath, store.config.Catalog)
		if err != nil {
			gologger.Warning().Msgf("Could not load workflow %s: %s\n", workflowPath, err)
		}
		if loaded {
			parsed, err := templates.Parse(workflowPath, store.preprocessor, store.config.ExecutorOptions)
			if err != nil {
				gologger.Warning().Msgf("Could not parse workflow %s: %s\n", workflowPath, err)
			} else if parsed != nil {
				loadedWorkflows = append(loadedWorkflows, parsed)
			}
		}
	}
	return loadedWorkflows
}

// LoadTemplatesWithTags takes a list of templates and extra tags
// returning templates that match.
func (store *Store) LoadTemplatesWithTags(templatesList, tags []string) []*templates.Template {
	includedTemplates := store.config.Catalog.GetTemplatesPath(templatesList)
	templatePathMap := store.pathFilter.Match(includedTemplates)

	loadedTemplates := make([]*templates.Template, 0, len(templatePathMap))
	for templatePath := range templatePathMap {
		loaded, err := parsers.LoadTemplate(templatePath, store.tagFilter, tags, store.config.Catalog)
		if loaded || store.pathFilter.MatchIncluded(templatePath) {
			parsed, err := templates.Parse(templatePath, store.preprocessor, store.config.ExecutorOptions)
			if err != nil {
				stats.Increment(parsers.RuntimeWarningsStats)
				gologger.Warning().Msgf("Could not parse template %s: %s\n", templatePath, err)
			} else if parsed != nil {
				if len(parsed.RequestsHeadless) > 0 && !store.config.ExecutorOptions.Options.Headless {
					gologger.Warning().Msgf("Headless flag is required for headless template %s\n", templatePath)
				} else {
					loadedTemplates = append(loadedTemplates, parsed)
				}
			}
		} else if err != nil {
			gologger.Warning().Msgf("Could not load template %s: %s\n", templatePath, err)
		}
	}
	return loadedTemplates
}
