package parsers

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader/filter"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/cache"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils/stats"
)

const (
	mandatoryFieldMissingTemplate = "mandatory '%s' field is missing"
	invalidFieldFormatTemplate    = "invalid field format for '%s' (allowed format is %s)"
)

// LoadTemplate returns true if the template is valid and matches the filtering criteria.
func LoadTemplate(templatePath string, tagFilter *filter.TagFilter, extraTags []string, catalog catalog.Catalog) (bool, error) {
	template, templateParseError := ParseTemplate(templatePath, catalog)
	if templateParseError != nil {
		return false, templateParseError
	}

	if len(template.Workflows) > 0 {
		return false, nil
	}

	if validationError := validateTemplateFields(template); validationError != nil {
		stats.Increment(SyntaxErrorStats)
		return false, validationError
	}

	return isTemplateInfoMetadataMatch(tagFilter, template, extraTags)
}

// LoadWorkflow returns true if the workflow is valid and matches the filtering criteria.
func LoadWorkflow(templatePath string, catalog catalog.Catalog) (bool, error) {
	template, templateParseError := ParseTemplate(templatePath, catalog)
	if templateParseError != nil {
		return false, templateParseError
	}

	if len(template.Workflows) > 0 {
		if validationError := validateTemplateFields(template); validationError != nil {
			return false, validationError
		}
		return true, nil
	}

	return false, nil
}

func isTemplateInfoMetadataMatch(tagFilter *filter.TagFilter, template *templates.Template, extraTags []string) (bool, error) {
	match, err := tagFilter.Match(template, extraTags)

	if err == filter.ErrExcluded {
		return false, filter.ErrExcluded
	}

	return match, err
}

func validateTemplateFields(template *templates.Template) error {
	info := template.Info

	var errors []string

	if utils.IsBlank(info.Name) {
		errors = append(errors, fmt.Sprintf(mandatoryFieldMissingTemplate, "name"))
	}

	if info.Authors.IsEmpty() {
		errors = append(errors, fmt.Sprintf(mandatoryFieldMissingTemplate, "author"))
	}

	if template.ID == "" {
		errors = append(errors, fmt.Sprintf(mandatoryFieldMissingTemplate, "id"))
	} else if !templateIDRegexp.MatchString(template.ID) {
		errors = append(errors, fmt.Sprintf(invalidFieldFormatTemplate, "id", templateIDRegexp.String()))
	}

	if len(errors) > 0 {
		return fmt.Errorf(strings.Join(errors, ", "))
	}

	return nil
}

var (
	parsedTemplatesCache *cache.Templates
	ShouldValidate       bool
	NoStrictSyntax       bool
	templateIDRegexp     = regexp.MustCompile(`^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$`)
)

const (
	SyntaxWarningStats   = "syntax-warnings"
	SyntaxErrorStats     = "syntax-errors"
	RuntimeWarningsStats = "runtime-warnings"
)

func init() {

	parsedTemplatesCache = cache.New()

	stats.NewEntry(SyntaxWarningStats, "Found %d templates with syntax warning (use -validate flag for further examination)")
	stats.NewEntry(SyntaxErrorStats, "Found %d templates with syntax error (use -validate flag for further examination)")
	stats.NewEntry(RuntimeWarningsStats, "Found %d templates with runtime error (use -validate flag for further examination)")
}

// ParseTemplate parses a template and returns a *templates.Template structure
func ParseTemplate(templatePath string, catalog catalog.Catalog) (*templates.Template, error) {
	if value, err := parsedTemplatesCache.Has(templatePath); value != nil {
		return value.(*templates.Template), err
	}
	data, err := utils.ReadFromPathOrURL(templatePath, catalog)
	if err != nil {
		return nil, err
	}

	template := &templates.Template{}
	if NoStrictSyntax {
		err = yaml.Unmarshal(data, template)
	} else {
		err = yaml.UnmarshalStrict(data, template)
	}
	if err != nil {
		stats.Increment(SyntaxErrorStats)
		return nil, err
	}
	parsedTemplatesCache.Store(templatePath, template, nil)
	return template, nil
}
