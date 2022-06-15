package variables

import (
	"github.com/alecthomas/jsonschema"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
)

// Variable is a key-value pair of strings that can be used
// throughout template.
type Variable struct {
	utils.InsertionOrderedStringMap `yaml:"-" json:"-"`
}

func (variables *Variable) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		Type:        "map[string]string",
		Title:       "variables for the request",
		Description: "Additional variables for the request",
	}
	return gotType
}

func (variables *Variable) UnmarshalYAML(unmarshal func(interface{}) error) error {
	variables.InsertionOrderedStringMap = utils.InsertionOrderedStringMap{}
	if err := unmarshal(&variables.InsertionOrderedStringMap); err != nil {
		return err
	}
	evaluated := variables.Evaluate(map[string]interface{}{})
	for k, v := range evaluated {
		variables.Set(k, v)
	}
	return nil
}

// Evaluate returns a finished map of variables based on set values
func (variables *Variable) Evaluate(values map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, variables.Len())
	variables.ForEach(func(key string, value interface{}) {
		result[key] = evaluateVariableValue(types.ToString(value), values, result)
	})
	return result
}

// evaluateVariableValue expression and returns final value
func evaluateVariableValue(expression string, values, processing map[string]interface{}) string {
	finalMap := generators.MergeMaps(values, processing)

	result, err := expressions.Evaluate(expression, finalMap)
	if err != nil {
		return expression
	}
	return result
}
