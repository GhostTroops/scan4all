package wappalyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// DefaultRuntimeTimeout is the maximum runtime evidence collection time used
// when [RuntimeOptions.Timeout] is zero.
const DefaultRuntimeTimeout = 10 * time.Second

// RuntimeCollector collects browser runtime evidence for a complete rule set.
// Collect must process the rule set as one batch and stop when ctx is done.
type RuntimeCollector interface {
	Collect(ctx context.Context, rules RuntimeRules) (RuntimeEvidence, error)
}

// RuntimeOptions configures optional runtime fingerprinting.
type RuntimeOptions struct {
	// Collector reads the caller-owned runtime environment.
	Collector RuntimeCollector
	// Timeout bounds collection. Zero uses [DefaultRuntimeTimeout].
	Timeout time.Duration
}

// RuntimeRules describes the browser state that a [RuntimeCollector] must
// inspect. The rule strings are data and must not be evaluated as source code.
type RuntimeRules struct {
	// JavaScriptProperties contains dot-separated, own-property chains rooted at window.
	JavaScriptProperties []string `json:"javascriptProperties,omitempty"`
	// DOM contains the rendered selectors and values that must be collected.
	DOM []RuntimeDOMRule `json:"dom,omitempty"`
	// Scripts requests inline and loaded external script content.
	Scripts bool `json:"scripts,omitempty"`
}

// RuntimeDOMRule describes the evidence required for one DOM selector.
type RuntimeDOMRule struct {
	Selector string `json:"selector"`
	Exists   bool   `json:"exists,omitempty"`
	Text     bool   `json:"text,omitempty"`
	// Attributes and Properties contain names, not executable expressions.
	Attributes []string `json:"attributes,omitempty"`
	Properties []string `json:"properties,omitempty"`
}

// RuntimeEvidence contains values observed from a rendered page. Map presence
// means that a JavaScript property exists. Text entries must be non-empty.
type RuntimeEvidence struct {
	// JavaScriptProperties maps each observed chain to its scalar string value.
	// Strings and numbers keep their text; other defined values use their truth value.
	JavaScriptProperties map[string]string `json:"javascriptProperties,omitempty"`
	// DOM is keyed by the exact selector from [RuntimeRules.DOM].
	DOM map[string]RuntimeDOMEvidence `json:"dom,omitempty"`
	// Scripts contains script response or inline source text.
	Scripts []string `json:"scripts,omitempty"`
}

// RuntimeDOMEvidence contains rendered values for one DOM selector.
type RuntimeDOMEvidence struct {
	Exists bool     `json:"exists,omitempty"`
	Text   []string `json:"text,omitempty"`
	// Attributes includes a value only when the node has the attribute.
	Attributes map[string][]string `json:"attributes,omitempty"`
	// Properties includes a value only when the node has the own property.
	Properties map[string][]string `json:"properties,omitempty"`
}

// RuntimeRules returns an isolated, deterministic copy of the runtime rule
// set. Callers can use it to implement a custom [RuntimeCollector].
func (s *Wappalyze) RuntimeRules() RuntimeRules {
	return cloneRuntimeRules(s.runtimeRules)
}

// FingerprintWithRuntime identifies technologies from passive response data
// and from one batch of browser runtime evidence. The returned map includes
// usable passive and partial runtime matches when collection returns an error.
func (s *Wappalyze) FingerprintWithRuntime(
	ctx context.Context,
	headers map[string][]string,
	body []byte,
	options RuntimeOptions,
) (map[string]struct{}, error) {
	uniqueFingerprints := NewUniqueFingerprints()
	s.addPassiveFingerprints(uniqueFingerprints, headers, body)
	if ctx == nil {
		return uniqueFingerprints.GetValues(), fmt.Errorf("runtime fingerprinting: context is nil")
	}
	if options.Collector == nil {
		return uniqueFingerprints.GetValues(), fmt.Errorf("runtime fingerprinting: collector is nil")
	}
	if options.Timeout < 0 {
		return uniqueFingerprints.GetValues(), fmt.Errorf("runtime fingerprinting: timeout must not be negative")
	}
	if err := ctx.Err(); err != nil {
		return uniqueFingerprints.GetValues(), fmt.Errorf("runtime fingerprinting: %w", err)
	}

	timeout := options.Timeout
	if timeout == 0 {
		timeout = DefaultRuntimeTimeout
	}
	runtimeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	evidence, err := options.Collector.Collect(runtimeCtx, cloneRuntimeRules(s.runtimeRules))
	s.mergeRuntimeEvidence(uniqueFingerprints, evidence)
	if err == nil {
		err = runtimeCtx.Err()
	}
	if err != nil {
		return uniqueFingerprints.GetValues(), fmt.Errorf("collect runtime evidence: %w", err)
	}

	return uniqueFingerprints.GetValues(), nil
}

func (s *Wappalyze) mergeRuntimeEvidence(uniqueFingerprints UniqueFingerprints, evidence RuntimeEvidence) {
	foldedScripts := make([]string, len(evidence.Scripts))
	for i, script := range evidence.Scripts {
		foldedScripts[i] = strings.ToLower(script)
	}

	for application, fingerprint := range s.fingerprints.Apps {
		var confidence int
		var version string

		addMatch := func(pattern *ParsedPattern, value, folded string) {
			if pattern == nil {
				return
			}
			valid, detectedVersion := pattern.evaluate(value, folded)
			if !valid {
				return
			}

			confidence += pattern.Confidence
			if confidence > 100 {
				confidence = 100
			}
			if detectedVersion != "" && (version == "" || isMoreSpecific(detectedVersion, version)) {
				version = detectedVersion
			}
		}

		for property, pattern := range fingerprint.js {
			if value, ok := evidence.JavaScriptProperties[property]; ok {
				addMatch(pattern, value, "")
			}
		}

		for selector, rules := range fingerprint.runtimeDOM {
			observed, ok := evidence.DOM[selector]
			if !ok {
				continue
			}
			if observed.Exists {
				addMatch(rules.exists, "", "")
			}
			for _, value := range observed.Text {
				if value != "" {
					addMatch(rules.text, value, "")
				}
			}
			for name, pattern := range rules.attributes {
				for _, value := range observed.Attributes[name] {
					addMatch(pattern, value, "")
				}
			}
			for name, pattern := range rules.properties {
				for _, value := range observed.Properties[name] {
					addMatch(pattern, value, "")
				}
			}
		}

		for i, script := range evidence.Scripts {
			if script == "" {
				continue
			}
			for _, pattern := range fingerprint.script {
				addMatch(pattern, script, foldedScripts[i])
			}
		}

		if confidence == 0 {
			continue
		}
		uniqueFingerprints.SetIfNotExists(application, version, confidence)
		for _, implied := range fingerprint.implies {
			uniqueFingerprints.SetIfNotExists(implied, "", confidence)
		}
	}
}

func compileRuntimeRules(fingerprints *CompiledFingerprints) RuntimeRules {
	javascript := make(map[string]struct{})
	dom := make(map[string]*RuntimeDOMRule)
	var scripts bool

	for _, fingerprint := range fingerprints.Apps {
		for property := range fingerprint.js {
			javascript[property] = struct{}{}
		}
		if len(fingerprint.script) > 0 {
			scripts = true
		}

		for selector, compiled := range fingerprint.runtimeDOM {
			if compiled.exists == nil && compiled.text == nil && len(compiled.attributes) == 0 && len(compiled.properties) == 0 {
				continue
			}
			rule, ok := dom[selector]
			if !ok {
				rule = &RuntimeDOMRule{Selector: selector}
				dom[selector] = rule
			}
			rule.Exists = rule.Exists || compiled.exists != nil
			rule.Text = rule.Text || compiled.text != nil
			rule.Attributes = appendMapKeys(rule.Attributes, compiled.attributes)
			rule.Properties = appendMapKeys(rule.Properties, compiled.properties)
		}
	}

	rules := RuntimeRules{Scripts: scripts}
	for property := range javascript {
		rules.JavaScriptProperties = append(rules.JavaScriptProperties, property)
	}
	sort.Strings(rules.JavaScriptProperties)

	for _, rule := range dom {
		sort.Strings(rule.Attributes)
		sort.Strings(rule.Properties)
		rules.DOM = append(rules.DOM, *rule)
	}
	sort.Slice(rules.DOM, func(i, j int) bool {
		return rules.DOM[i].Selector < rules.DOM[j].Selector
	})

	return rules
}

func appendMapKeys(values []string, patterns map[string]*ParsedPattern) []string {
	seen := make(map[string]struct{}, len(values)+len(patterns))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	for value := range patterns {
		if _, ok := seen[value]; ok {
			continue
		}
		values = append(values, value)
		seen[value] = struct{}{}
	}
	return values
}

func cloneRuntimeRules(rules RuntimeRules) RuntimeRules {
	cloned := RuntimeRules{
		JavaScriptProperties: append([]string(nil), rules.JavaScriptProperties...),
		DOM:                  make([]RuntimeDOMRule, len(rules.DOM)),
		Scripts:              rules.Scripts,
	}
	for i, rule := range rules.DOM {
		cloned.DOM[i] = RuntimeDOMRule{
			Selector:   rule.Selector,
			Exists:     rule.Exists,
			Text:       rule.Text,
			Attributes: append([]string(nil), rule.Attributes...),
			Properties: append([]string(nil), rule.Properties...),
		}
	}
	return cloned
}
