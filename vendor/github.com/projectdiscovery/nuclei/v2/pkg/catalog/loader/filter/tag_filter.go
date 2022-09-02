package filter

import (
	"errors"
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/common/dsl"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
)

// TagFilter is used to filter nuclei templates for tag based execution
type TagFilter struct {
	allowedTags       map[string]struct{}
	severities        map[severity.Severity]struct{}
	excludeSeverities map[severity.Severity]struct{}
	authors           map[string]struct{}
	block             map[string]struct{}
	matchAllows       map[string]struct{}
	types             map[types.ProtocolType]struct{}
	excludeTypes      map[types.ProtocolType]struct{}
	allowedIds        map[string]struct{}
	excludeIds        map[string]struct{}
	includeConditions map[string]*govaluate.EvaluableExpression
}

// ErrExcluded is returned for excluded templates
var ErrExcluded = errors.New("the template was excluded")

// Match filters templates based on user provided tags, authors, extraTags and severity.
// If the template contains tags specified in the deny-list, it will not be matched
// unless it is explicitly specified by user using the includeTags (matchAllows field).
// Matching rule: (tag1 OR tag2...) AND (author1 OR author2...) AND (severity1 OR severity2...) AND (extraTags1 OR extraTags2...)
// Returns true if the template matches the filter criteria, false otherwise.
func (tagFilter *TagFilter) Match(template *templates.Template, extraTags []string) (bool, error) {
	templateTags := template.Info.Tags.ToSlice()
	for _, templateTag := range templateTags {
		_, blocked := tagFilter.block[templateTag]
		_, allowed := tagFilter.matchAllows[templateTag]

		if blocked && !allowed { // the whitelist has precedence over the blacklist
			return false, ErrExcluded
		}
	}

	if !isExtraTagMatch(extraTags, templateTags) {
		return false, nil
	}

	if !isTagMatch(tagFilter, templateTags) {
		return false, nil
	}

	if !isAuthorMatch(tagFilter, template.Info.Authors.ToSlice()) {
		return false, nil
	}

	if !isSeverityMatch(tagFilter, template.Info.SeverityHolder.Severity) {
		return false, nil
	}

	if !isTemplateTypeMatch(tagFilter, template.Type()) {
		return false, nil
	}

	if !isIdMatch(tagFilter, strings.ToLower(template.ID)) {
		return false, nil
	}

	if !isConditionMatch(tagFilter, template) {
		return false, nil
	}

	return true, nil
}

func isSeverityMatch(tagFilter *TagFilter, templateSeverity severity.Severity) bool {
	if (len(tagFilter.excludeSeverities) == 0 && len(tagFilter.severities) == 0) || templateSeverity == severity.Undefined {
		return true
	}

	included := true
	if len(tagFilter.severities) > 0 {
		_, included = tagFilter.severities[templateSeverity]
	}

	excluded := false
	if len(tagFilter.excludeSeverities) > 0 {
		_, excluded = tagFilter.excludeSeverities[templateSeverity]
	}

	return included && !excluded
}

func isAuthorMatch(tagFilter *TagFilter, templateAuthors []string) bool {
	if len(tagFilter.authors) == 0 {
		return true
	}

	templateAuthorMap := toMap(templateAuthors)
	for requiredAuthor := range tagFilter.authors {
		if _, ok := templateAuthorMap[requiredAuthor]; ok {
			return true
		}
	}

	return false
}

func isExtraTagMatch(extraTags []string, templateTags []string) bool {
	if len(extraTags) == 0 {
		return true
	}

	templatesTagMap := toMap(templateTags)
	for _, extraTag := range extraTags {
		if _, ok := templatesTagMap[extraTag]; ok {
			return true
		}
	}

	return false
}

func isTagMatch(tagFilter *TagFilter, templateTags []string) bool {
	if len(tagFilter.allowedTags) == 0 {
		return true
	}

	for _, templateTag := range templateTags {
		if _, ok := tagFilter.allowedTags[templateTag]; ok {
			return true
		}
	}

	return false
}

func isTemplateTypeMatch(tagFilter *TagFilter, templateType types.ProtocolType) bool {
	if len(tagFilter.excludeTypes) == 0 && len(tagFilter.types) == 0 {
		return true
	}
	if templateType.String() == "" || templateType == types.InvalidProtocol {
		return true
	}

	included := true
	if len(tagFilter.types) > 0 {
		_, included = tagFilter.types[templateType]
	}

	excluded := false
	if len(tagFilter.excludeTypes) > 0 {
		_, excluded = tagFilter.excludeTypes[templateType]
	}

	return included && !excluded
}

func isIdMatch(tagFilter *TagFilter, templateId string) bool {
	if len(tagFilter.excludeIds) == 0 && len(tagFilter.allowedIds) == 0 {
		return true
	}
	included := true
	if len(tagFilter.allowedIds) > 0 {
		_, included = tagFilter.allowedIds[templateId]
	}

	excluded := false
	if len(tagFilter.excludeIds) > 0 {
		_, excluded = tagFilter.excludeIds[templateId]
	}

	return included && !excluded
}

func isConditionMatch(tagFilter *TagFilter, template *templates.Template) bool {
	if len(tagFilter.includeConditions) == 0 {
		return true
	}

	// attempts to unwrap fields to their basic types
	// mapping must be manual because of various abstraction layers, custom marshaling and forceful validation
	parameters := map[string]interface{}{
		"id":          template.ID,
		"name":        template.Info.Name,
		"description": template.Info.Description,
		"tags":        template.Info.Tags.ToSlice(),
		"authors":     template.Info.Authors.ToSlice(),
		"severity":    template.Info.SeverityHolder.Severity.String(),
	}
	for k, v := range template.Info.Metadata {
		parameters[k] = v
	}
	for _, expr := range tagFilter.includeConditions {
		result, err := expr.Evaluate(parameters)
		// in case of errors  => skip
		if err != nil {
			// Using debug as the failure here might be legitimate (eg. template not having optional metadata fields => missing required fields)
			gologger.Debug().Msgf("The expression condition couldn't be evaluated correctly for template \"%s\": %s\n", template.ID, err)
			return false
		}
		resultBool, ok := result.(bool)
		// in case the result is not boolean => skip
		if !ok {
			return false
		}
		// in case the result is false => skip
		if !resultBool {
			return false
		}
	}

	return true
}

type Config struct {
	Tags              []string
	ExcludeTags       []string
	Authors           []string
	Severities        severity.Severities
	ExcludeSeverities severity.Severities
	IncludeTags       []string
	IncludeIds        []string
	ExcludeIds        []string
	Protocols         types.ProtocolTypes
	ExcludeProtocols  types.ProtocolTypes
	IncludeConditions []string
}

// New returns a tag filter for nuclei tag based execution
//
// It takes into account Tags, Severities, ExcludeSeverities, Authors, IncludeTags, ExcludeTags, Conditions.
func New(config *Config) (*TagFilter, error) {
	filter := &TagFilter{
		allowedTags:       make(map[string]struct{}),
		authors:           make(map[string]struct{}),
		severities:        make(map[severity.Severity]struct{}),
		excludeSeverities: make(map[severity.Severity]struct{}),
		block:             make(map[string]struct{}),
		matchAllows:       make(map[string]struct{}),
		types:             make(map[types.ProtocolType]struct{}),
		excludeTypes:      make(map[types.ProtocolType]struct{}),
		allowedIds:        make(map[string]struct{}),
		excludeIds:        make(map[string]struct{}),
		includeConditions: make(map[string]*govaluate.EvaluableExpression),
	}
	for _, tag := range config.ExcludeTags {
		for _, val := range splitCommaTrim(tag) {
			if _, ok := filter.block[val]; !ok {
				filter.block[val] = struct{}{}
			}
		}
	}
	for _, tag := range config.Severities {
		if _, ok := filter.severities[tag]; !ok {
			filter.severities[tag] = struct{}{}
		}
	}
	for _, tag := range config.ExcludeSeverities {
		if _, ok := filter.excludeSeverities[tag]; !ok {
			filter.excludeSeverities[tag] = struct{}{}
		}
	}
	for _, tag := range config.Authors {
		for _, val := range splitCommaTrim(tag) {
			if _, ok := filter.authors[val]; !ok {
				filter.authors[val] = struct{}{}
			}
		}
	}
	for _, tag := range config.Tags {
		for _, val := range splitCommaTrim(tag) {
			if _, ok := filter.allowedTags[val]; !ok {
				filter.allowedTags[val] = struct{}{}
			}
			delete(filter.block, val)
		}
	}
	for _, tag := range config.IncludeTags {
		for _, val := range splitCommaTrim(tag) {
			if _, ok := filter.matchAllows[val]; !ok {
				filter.matchAllows[val] = struct{}{}
			}
			delete(filter.block, val)
		}
	}
	for _, tag := range config.Protocols {
		if _, ok := filter.types[tag]; !ok {
			filter.types[tag] = struct{}{}
		}
	}
	for _, tag := range config.ExcludeProtocols {
		if _, ok := filter.excludeTypes[tag]; !ok {
			filter.excludeTypes[tag] = struct{}{}
		}
	}
	for _, id := range config.ExcludeIds {
		for _, val := range splitCommaTrim(id) {
			if _, ok := filter.block[val]; !ok {
				filter.excludeIds[val] = struct{}{}
			}
		}
	}
	for _, id := range config.IncludeIds {
		for _, val := range splitCommaTrim(id) {
			if _, ok := filter.allowedIds[val]; !ok {
				filter.allowedIds[val] = struct{}{}
			}
			delete(filter.excludeIds, val)
		}
	}
	for _, includeCondition := range config.IncludeConditions {
		compiled, err := govaluate.NewEvaluableExpressionWithFunctions(includeCondition, dsl.HelperFunctions)
		if err != nil {
			return nil, err
		}
		filter.includeConditions[includeCondition] = compiled
	}
	return filter, nil
}

/*
TODO similar logic is used over and over again. It should be extracted and reused
Changing []string and string data types that hold string slices to StringSlice would be the preferred solution,
which implicitly does the normalization before any other calls starting to use it.
*/
func splitCommaTrim(value string) []string {
	if !strings.Contains(value, ",") {
		return []string{strings.ToLower(value)}
	}
	split := strings.Split(value, ",")
	final := make([]string, len(split))
	for i, value := range split {
		final[i] = strings.ToLower(strings.TrimSpace(value))
	}
	return final
}

func toMap(slice []string) map[string]struct{} {
	result := make(map[string]struct{}, len(slice))
	for _, value := range slice {
		if _, ok := result[value]; !ok {
			result[value] = struct{}{}
		}
	}
	return result
}
