package wappalyzer

import (
	"fmt"
)

// Fingerprints contains a map of fingerprints for tech detection
type Fingerprints struct {
	// Apps is organized as <name, fingerprint>
	Apps map[string]*Fingerprint `json:"apps"`
}

// Fingerprint is a single piece of information about a tech validated and normalized
type Fingerprint struct {
	Cats        []int                             `json:"cats"`
	CSS         []string                          `json:"css"`
	Cookies     map[string]string                 `json:"cookies"`
	Dom         map[string]map[string]interface{} `json:"dom"`
	JS          map[string]string                 `json:"js"`
	Headers     map[string]string                 `json:"headers"`
	HTML        []string                          `json:"html"`
	Script      []string                          `json:"scripts"`
	ScriptSrc   []string                          `json:"scriptSrc"`
	Meta        map[string][]string               `json:"meta"`
	Implies     []string                          `json:"implies"`
	Description string                            `json:"description"`
	Website     string                            `json:"website"`
	CPE         string                            `json:"cpe"`
	Icon        string                            `json:"icon"`
}

// CompiledFingerprints contains a map of fingerprints for tech detection
type CompiledFingerprints struct {
	// Apps is organized as <name, fingerprint>
	Apps map[string]*CompiledFingerprint
	// htmlIndex and scriptIndex find patterns whose literals occur in one scan.
	htmlIndex   *literalIndex
	scriptIndex *scriptLiteralIndex
}

// CompiledFingerprint contains the compiled fingerprints from the tech json
type CompiledFingerprint struct {
	// cats contain categories that are implicit with this tech
	cats []int
	// implies contains technologies that are implicit with this tech
	implies []string
	// description contains fingerprint description
	description string
	// website contains a URL associated with the fingerprint
	website string
	// icon contains a Icon associated with the fingerprint
	icon string
	// cookies contains fingerprints for target cookies
	cookies map[string]*ParsedPattern
	// js contains fingerprints for the js file
	js map[string]*ParsedPattern
	// dom contains fingerprints for the target dom
	dom map[string]map[string]*ParsedPattern
	// runtimeDOM preserves the DOM rule subtype needed for runtime collection.
	runtimeDOM map[string]*compiledDOMRule
	// headers contains fingerprints for target headers
	headers map[string]*ParsedPattern
	// html contains fingerprints for the target HTML
	html []*ParsedPattern
	// script contains fingerprints for scripts
	script []*ParsedPattern
	// scriptSrc contains fingerprints for script srcs
	scriptSrc []*ParsedPattern
	// meta contains fingerprints for meta tags
	meta map[string][]*ParsedPattern
	// cpe contains the cpe for a fingerpritn
	cpe string
}

type compiledDOMRule struct {
	exists     *ParsedPattern
	text       *ParsedPattern
	attributes map[string]*ParsedPattern
	properties map[string]*ParsedPattern
}

func (f *CompiledFingerprint) GetJSRules() map[string]*ParsedPattern {
	return f.js
}

func (f *CompiledFingerprint) GetDOMRules() map[string]map[string]*ParsedPattern {
	return f.dom
}

// AppInfo contains basic information about an App.
type AppInfo struct {
	Description string
	Website     string
	CPE         string
	Icon        string
	Categories  []string
}

// CatsInfo contains basic information about an App.
type CatsInfo struct {
	Cats []int
}

// part is the part of the fingerprint to match
type part int

// parts that can be matched
const (
	cookiesPart part = iota + 1
	jsPart
	headersPart
	htmlPart
	scriptSrcPart
	metaPart
)

// loadPatterns loads the fingerprint patterns and compiles regexes
func compileFingerprint(fingerprint *Fingerprint) *CompiledFingerprint {
	compiled := &CompiledFingerprint{
		cats:        fingerprint.Cats,
		implies:     fingerprint.Implies,
		description: fingerprint.Description,
		website:     fingerprint.Website,
		icon:        fingerprint.Icon,
		dom:         make(map[string]map[string]*ParsedPattern),
		runtimeDOM:  make(map[string]*compiledDOMRule),
		cookies:     make(map[string]*ParsedPattern),
		js:          make(map[string]*ParsedPattern),
		headers:     make(map[string]*ParsedPattern),
		html:        make([]*ParsedPattern, 0, len(fingerprint.HTML)),
		script:      make([]*ParsedPattern, 0, len(fingerprint.Script)),
		scriptSrc:   make([]*ParsedPattern, 0, len(fingerprint.ScriptSrc)),
		meta:        make(map[string][]*ParsedPattern),
		cpe:         fingerprint.CPE,
	}

	for selector, patterns := range fingerprint.Dom {
		legacyRules := make(map[string]*ParsedPattern)
		runtimeRule := &compiledDOMRule{
			attributes: make(map[string]*ParsedPattern),
			properties: make(map[string]*ParsedPattern),
		}

		if value, ok := patterns["exists"]; ok {
			runtimeRule.exists = compileDOMPattern(value)
			if runtimeRule.exists != nil {
				legacyRules["main"] = runtimeRule.exists
			}
		}
		if value, ok := patterns["text"]; ok {
			runtimeRule.text = compileDOMPattern(value)
			if runtimeRule.text != nil {
				legacyRules["main"] = runtimeRule.text
			}
		}

		runtimeRule.attributes = compileDOMPatternMap(patterns["attributes"])
		for name, pattern := range runtimeRule.attributes {
			legacyRules[name] = pattern
		}
		runtimeRule.properties = compileDOMPatternMap(patterns["properties"])

		compiled.dom[selector] = legacyRules
		compiled.runtimeDOM[selector] = runtimeRule
	}

	for header, pattern := range fingerprint.Cookies {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.cookies[header] = fingerprint
	}

	for k, pattern := range fingerprint.JS {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.js[k] = fingerprint
	}

	for header, pattern := range fingerprint.Headers {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.headers[header] = fingerprint
	}

	for _, pattern := range fingerprint.HTML {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.html = append(compiled.html, fingerprint)
	}

	for _, pattern := range fingerprint.Script {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.script = append(compiled.script, fingerprint)
	}

	for _, pattern := range fingerprint.ScriptSrc {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.scriptSrc = append(compiled.scriptSrc, fingerprint)
	}

	for meta, patterns := range fingerprint.Meta {
		var compiledList []*ParsedPattern

		for _, pattern := range patterns {
			fingerprint, err := ParsePattern(pattern)
			if err != nil {
				continue
			}
			compiledList = append(compiledList, fingerprint)
		}
		compiled.meta[meta] = compiledList
	}
	return compiled
}

func compileDOMPattern(value interface{}) *ParsedPattern {
	pattern, ok := value.(string)
	if !ok {
		return nil
	}

	compiled, err := ParsePattern(pattern)
	if err != nil {
		return nil
	}

	return compiled
}

func compileDOMPatternMap(value interface{}) map[string]*ParsedPattern {
	compiled := make(map[string]*ParsedPattern)

	switch patterns := value.(type) {
	case map[string]interface{}:
		for name, pattern := range patterns {
			if parsed := compileDOMPattern(pattern); parsed != nil {
				compiled[name] = parsed
			}
		}
	case map[string]string:
		for name, pattern := range patterns {
			if parsed := compileDOMPattern(pattern); parsed != nil {
				compiled[name] = parsed
			}
		}
	}

	return compiled
}

// matchString matches an ASCII-lowercased string. checkBody passes the body
// from bytes.ToLower, so this does not fold it again.
func (f *CompiledFingerprints) matchString(data string, part part) []matchPartResult {
	switch part {
	case htmlPart:
		if f.htmlIndex != nil {
			return f.htmlIndex.match(data, data)
		}
	case scriptSrcPart:
		if f.scriptIndex != nil {
			return f.scriptIndex.match(data, data)
		}
	}
	return f.matchStringScan(data, data, part)
}

func (f *CompiledFingerprints) matchStringScan(data, folded string, part part) []matchPartResult {
	var matched bool
	var technologies []matchPartResult

	for app, fingerprint := range f.Apps {
		var version string
		var confidence int

		switch part {
		case jsPart:
			for _, pattern := range fingerprint.js {
				if valid, versionString := pattern.evaluate(data, folded); valid {
					matched = true
					if pattern.Confidence > confidence {
						confidence = pattern.Confidence
					}
					if versionString != "" && (version == "" || isMoreSpecific(versionString, version)) {
						version = versionString
					}
				}
			}
		case scriptSrcPart:
			for _, pattern := range fingerprint.scriptSrc {
				if valid, versionString := pattern.evaluate(data, folded); valid {
					matched = true
					if pattern.Confidence > confidence {
						confidence = pattern.Confidence
					}
					if versionString != "" && (version == "" || isMoreSpecific(versionString, version)) {
						version = versionString
					}
				}
			}
		case htmlPart:
			for _, pattern := range fingerprint.html {
				if valid, versionString := pattern.evaluate(data, folded); valid {
					matched = true
					if pattern.Confidence > confidence {
						confidence = pattern.Confidence
					}
					if versionString != "" && (version == "" || isMoreSpecific(versionString, version)) {
						version = versionString
					}
				}
			}
		}

		// If no match, continue with the next fingerprint
		if !matched {
			continue
		}

		// Append the technologies as well as implied ones
		technologies = append(technologies, matchPartResult{
			application: app,
			version:     version,
			confidence:  confidence,
		})
		if len(fingerprint.implies) > 0 {
			for _, implies := range fingerprint.implies {
				technologies = append(technologies, matchPartResult{
					application: implies,
					confidence:  confidence,
				})
			}
		}
		matched = false
	}
	return technologies
}

// matchKeyValue matches a key-value store map for the fingerprints
func (f *CompiledFingerprints) matchKeyValueString(key, value string, part part) []matchPartResult {
	var matched bool
	var technologies []matchPartResult

	for app, fingerprint := range f.Apps {
		var version string
		var confidence int

		switch part {
		case cookiesPart:
			for data, pattern := range fingerprint.cookies {
				if data != key {
					continue
				}

				if valid, versionString := pattern.Evaluate(value); valid {
					matched = true
					if pattern.Confidence > confidence {
						confidence = pattern.Confidence
					}
					if versionString != "" && (version == "" || isMoreSpecific(versionString, version)) {
						version = versionString
					}
				}
			}
		case headersPart:
			for data, pattern := range fingerprint.headers {
				if data != key {
					continue
				}

				if valid, versionString := pattern.Evaluate(value); valid {
					matched = true
					if pattern.Confidence > confidence {
						confidence = pattern.Confidence
					}
					if versionString != "" && (version == "" || isMoreSpecific(versionString, version)) {
						version = versionString
					}
				}
			}
		case metaPart:
			for data, patterns := range fingerprint.meta {
				if data != key {
					continue
				}

				for _, pattern := range patterns {
					if valid, versionString := pattern.Evaluate(value); valid {
						matched = true
						if pattern.Confidence > confidence {
							confidence = pattern.Confidence
						}
						if versionString != "" && (version == "" || isMoreSpecific(versionString, version)) {
							version = versionString
						}
					}
				}
			}
		}

		// If no match, continue with the next fingerprint
		if !matched {
			continue
		}

		technologies = append(technologies, matchPartResult{
			application: app,
			version:     version,
			confidence:  confidence,
		})
		if len(fingerprint.implies) > 0 {
			for _, implies := range fingerprint.implies {
				technologies = append(technologies, matchPartResult{
					application: implies,
					confidence:  confidence,
				})
			}
		}
		matched = false
	}
	return technologies
}

// matchMapString matches a key-value store map for the fingerprints
func (f *CompiledFingerprints) matchMapString(keyValue map[string]string, part part) []matchPartResult {
	var matched bool
	var technologies []matchPartResult

	for app, fingerprint := range f.Apps {
		var version string
		var confidence int

		switch part {
		case cookiesPart:
			for data, pattern := range fingerprint.cookies {
				value, ok := keyValue[data]
				if !ok {
					continue
				}
				if pattern == nil {
					matched = true
					continue
				}
				if valid, versionString := pattern.Evaluate(value); valid {
					matched = true
					if pattern.Confidence > confidence {
						confidence = pattern.Confidence
					}
					if versionString != "" && (version == "" || isMoreSpecific(versionString, version)) {
						version = versionString
					}
				}
			}
		case headersPart:
			for data, pattern := range fingerprint.headers {
				value, ok := keyValue[data]
				if !ok {
					continue
				}

				if valid, versionString := pattern.Evaluate(value); valid {
					matched = true
					if pattern.Confidence > confidence {
						confidence = pattern.Confidence
					}
					if versionString != "" && (version == "" || isMoreSpecific(versionString, version)) {
						version = versionString
					}
				}
			}
		case metaPart:
			for data, patterns := range fingerprint.meta {
				value, ok := keyValue[data]
				if !ok {
					continue
				}

				for _, pattern := range patterns {
					if valid, versionString := pattern.Evaluate(value); valid {
						matched = true
						if pattern.Confidence > confidence {
							confidence = pattern.Confidence
						}
						if versionString != "" && (version == "" || isMoreSpecific(versionString, version)) {
							version = versionString
						}
					}
				}
			}
		}

		// If no match, continue with the next fingerprint
		if !matched {
			continue
		}

		technologies = append(technologies, matchPartResult{
			application: app,
			version:     version,
			confidence:  confidence,
		})
		if len(fingerprint.implies) > 0 {
			for _, implies := range fingerprint.implies {
				technologies = append(technologies, matchPartResult{
					application: implies,
					confidence:  confidence,
				})
			}
		}
		matched = false
	}
	return technologies
}

func FormatAppVersion(app, version string) string {
	if version == "" {
		return app
	}
	return fmt.Sprintf("%s:%s", app, version)
}

// GetFingerprints returns the fingerprint string from wappalyzer
func GetFingerprints() string {
	return fingerprints
}
