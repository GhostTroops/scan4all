package structs

import (
	"gopkg.in/yaml.v2"
)

var ORDER = 0

// 参考 pocassist/blob/master/poc/rule/rule.go
// 单个规则
type Rule struct {
	Request    RuleRequest   `yaml:"request"`
	Expression string        `yaml:"expression"`
	Output     yaml.MapSlice `yaml:"output"`
	order      int
}

type ruleAlias struct {
	Request    RuleRequest   `yaml:"request"`
	Expression string        `yaml:"expression"`
	Output     yaml.MapSlice `yaml:"output"`
}

// 用于帮助yaml解析，保证Rule有序
type RuleMapItem struct {
	Key   string
	Value Rule
}

// 用于帮助yaml解析，保证Rule有序
type RuleMapSlice []RuleMapItem

type RuleRequest struct {
	Cache           bool              `yaml:"cache"`
	Method          string            `yaml:"method"`
	Path            string            `yaml:"path"`
	Headers         map[string]string `yaml:"headers"`
	Body            string            `yaml:"body"`
	FollowRedirects bool              `yaml:"follow_redirects"`
	Content         string            `yaml:"content"`
	ReadTimeout     string            `yaml:"read_timeout"`
	ConnectionID    string            `yaml:"connection_id"`
}

type Infos struct {
	ID         string `yaml:"id"`
	Name       string `yaml:"name"`
	Version    string `yaml:"version"`
	Type       string `yaml:"type"`
	Confidence int    `yaml:"confidence"`
}

type HostInfo struct {
	Hostname string `yaml:"hostname"`
}

type Vulnerability struct {
	ID    string `yaml:"id"`
	Match string `yaml:"match"`
}

type FingerPrint struct {
	Infos    []Infos  `yaml:"infos"`
	HostInfo HostInfo `yaml:"host_info"`
}
type Detail struct {
	Author        string        `yaml:"author"`
	Links         []string      `yaml:"links"`
	FingerPrint   FingerPrint   `yaml:"fingerprint"`
	Vulnerability Vulnerability `yaml:"vulnerability"`
	Description   string        `yaml:"description"`
	Version       string        `yaml:"version"`
	Tags          string        `yaml:"tags"`
}

type SetMapSlice = yaml.MapSlice
type PayloadsMapSlice = yaml.MapSlice

type Payloads struct {
	Continue bool             `yaml:"continue,omitempty"`
	Payloads PayloadsMapSlice `yaml:"payloads"`
}

type Poc struct {
	Name       string       `yaml:"name"`
	Transport  string       `yaml:"transport"`
	Set        SetMapSlice  `yaml:"set"`
	Payloads   Payloads     `yaml:"payloads"`
	Rules      RuleMapSlice `yaml:"rules"`
	Expression string       `yaml:"expression"`
	Detail     Detail       `yaml:"detail"`
}

func (r *Rule) UnmarshalYAML(unmarshal func(interface{}) error) error {

	var tmp ruleAlias
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	r.Request = tmp.Request
	r.Expression = tmp.Expression
	r.Output = tmp.Output
	r.order = ORDER

	ORDER += 1

	return nil
}

func (m *RuleMapSlice) UnmarshalYAML(unmarshal func(interface{}) error) error {
	ORDER = 0

	tempMap := make(map[string]Rule, 1)
	err := unmarshal(&tempMap)
	if err != nil {
		return err
	}

	newRuleSlice := make([]RuleMapItem, len(tempMap))

	for roleName, role := range tempMap {
		if role.order < len(tempMap) {
			newRuleSlice[role.order] = RuleMapItem{
				Key:   roleName,
				Value: role,
			}
		}
	}

	*m = RuleMapSlice(newRuleSlice)

	return nil
}
