package structs

import "gopkg.in/yaml.v2"

// 参考 pocassist/blob/master/poc/rule/rule.go
// 单个规则
type Rule struct {
	Method          string            `yaml:"method"`
	Path            string            `yaml:"path"`
	Headers         map[string]string `yaml:"headers"`
	Body            string            `yaml:"body"`
	Search          string            `yaml:"search"`
	FollowRedirects bool              `yaml:"follow_redirects"`
	Expression      string            `yaml:"expression"`
}

type Detail struct {
	Author      string   `yaml:"author"`
	Links       []string `yaml:"links"`
	Description string   `yaml:"description"`
	Version     string   `yaml:"version"`
	Tags        string   `yaml:"tags"`
}

// Rules 和 Groups 只能存在一个
type Poc struct {
	Params []string          `yaml:"params"`
	Name   string            `yaml:"name"`
	Set    yaml.MapSlice     `yaml:"set"`
	Rules  []Rule            `yaml:"rules"`
	Groups map[string][]Rule `yaml:"groups"`
	Detail Detail            `yaml:"detail"`
}
