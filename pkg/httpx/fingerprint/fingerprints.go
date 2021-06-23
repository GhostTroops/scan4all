package wappalyzer

import "regexp"

// Fingerprints contains a map of fingerprints for tech detection
type Fingerprints struct {
	// Apps is organized as <name, fingerprint>
	Apps map[string]*Fingerprint `json:"apps"`
}

// Fingerprint is a single piece of information about a tech validated and normalized
type Fingerprint struct {
	Cookies map[string]string   `json:"cookies"`
	JS      []string            `json:"js"`
	Headers map[string]string   `json:"headers"`
	HTML    []string            `json:"html"`
	CSS     []string            `json:"css"`
	Script  []string            `json:"script"`
	Meta    map[string][]string `json:"meta"`
	Implies []string            `json:"implies"`
}

// CompiledFingerprints contains a map of fingerprints for tech detection
type CompiledFingerprints struct {
	// Apps is organized as <name, fingerprint>
	Apps map[string]*CompiledFingerprint
}

// CompiledFingerprint contains the compiled fingerprints from the tech json
type CompiledFingerprint struct {
	// implies contains technologies that are implicit with this tech
	implies []string
	// cookies contains fingerprints for target cookies
	cookies map[string]*regexp.Regexp
	// js contains fingerprints for the js file
	js []*regexp.Regexp
	// headers contains fingerprints for target headers
	headers map[string]*regexp.Regexp
	// html contains fingerprints for the target HTML
	html []*regexp.Regexp
	// script contains fingerprints for script tags
	script []*regexp.Regexp
	// meta contains fingerprints for meta tags
	meta map[string][]*regexp.Regexp
}

// part is the part of the fingerprint to match
type part int

// parts that can be matched
const (
	cookiesPart part = iota + 1
	jsPart
	headersPart
	htmlPart
	scriptPart
	metaPart
)

// loadPatterns loads the fingerprint patterns and compiles regexes
func compileFingerprint(fingerprint *Fingerprint) *CompiledFingerprint {
	compiled := &CompiledFingerprint{
		implies: fingerprint.Implies,
		cookies: make(map[string]*regexp.Regexp),
		js:      make([]*regexp.Regexp, 0, len(fingerprint.JS)),
		headers: make(map[string]*regexp.Regexp),
		html:    make([]*regexp.Regexp, 0, len(fingerprint.HTML)),
		script:  make([]*regexp.Regexp, 0, len(fingerprint.Script)),
		meta:    make(map[string][]*regexp.Regexp),
	}

	for header, pattern := range fingerprint.Cookies {
		fingerprint, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		compiled.cookies[header] = fingerprint
	}

	for _, pattern := range fingerprint.JS {
		fingerprint, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		compiled.js = append(compiled.js, fingerprint)
	}

	for header, pattern := range fingerprint.Headers {
		fingerprint, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		compiled.headers[header] = fingerprint
	}

	for _, pattern := range fingerprint.HTML {
		fingerprint, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		compiled.html = append(compiled.html, fingerprint)
	}

	for _, pattern := range fingerprint.Script {
		fingerprint, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		compiled.script = append(compiled.script, fingerprint)
	}

	for meta, patterns := range fingerprint.Meta {
		var compiledList []*regexp.Regexp

		for _, pattern := range patterns {
			fingerprint, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			compiledList = append(compiledList, fingerprint)
		}
		compiled.meta[meta] = compiledList
	}
	return compiled
}

// matchString matches a string for the fingerprints
func (f *CompiledFingerprints) matchString(data string, part part) []string {
	var matched bool
	var technologies []string

	for app, fingerprint := range f.Apps {
		switch part {
		case jsPart:
			for _, pattern := range fingerprint.js {
				if pattern.MatchString(data) {
					matched = true
				}
			}
		case scriptPart:
			for _, pattern := range fingerprint.script {
				if pattern.MatchString(data) {
					matched = true
				}
			}
		case htmlPart:
			for _, pattern := range fingerprint.html {
				if pattern.MatchString(data) {
					matched = true
				}
			}
		}

		// If no match, continue with the next fingerprint
		if !matched {
			continue
		}

		// Append the technologies as well as implied ones
		technologies = append(technologies, app)
		if len(fingerprint.implies) > 0 {
			technologies = append(technologies, fingerprint.implies...)
		}
		matched = false
	}
	return technologies
}

// matchKeyValue matches a key-value store map for the fingerprints
func (f *CompiledFingerprints) matchKeyValueString(key, value string, part part) []string {
	var matched bool
	var technologies []string

	for app, fingerprint := range f.Apps {
		switch part {
		case cookiesPart:
			for data, pattern := range fingerprint.cookies {
				if data != key {
					continue
				}

				if pattern.MatchString(value) {
					matched = true
					break
				}
			}
		case headersPart:
			for data, pattern := range fingerprint.headers {
				if data != key {
					continue
				}

				if pattern.MatchString(value) {
					matched = true
					break
				}
			}
		case metaPart:
			for data, patterns := range fingerprint.meta {
				if data != key {
					continue
				}

				for _, pattern := range patterns {
					if pattern.MatchString(value) {
						matched = true
						break
					}
				}
			}
		}

		// If no match, continue with the next fingerprint
		if !matched {
			continue
		}

		// Append the technologies as well as implied ones
		technologies = append(technologies, app)
		if len(fingerprint.implies) > 0 {
			technologies = append(technologies, fingerprint.implies...)
		}
		matched = false
	}
	return technologies
}

// matchMapString matches a key-value store map for the fingerprints
func (f *CompiledFingerprints) matchMapString(keyValue map[string]string, part part) []string {
	var matched bool
	var technologies []string

	for app, fingerprint := range f.Apps {
		switch part {
		case cookiesPart:
			for data, pattern := range fingerprint.cookies {
				value, ok := keyValue[data]
				if !ok {
					continue
				}

				if pattern.MatchString(value) {
					matched = true
					break
				}
			}
		case headersPart:
			for data, pattern := range fingerprint.headers {
				value, ok := keyValue[data]
				if !ok {
					continue
				}

				if pattern.MatchString(value) {
					matched = true
					break
				}
			}
		case metaPart:
			for data, patterns := range fingerprint.meta {
				value, ok := keyValue[data]
				if !ok {
					continue
				}
				for _, pattern := range patterns {
					if pattern.MatchString(value) {
						matched = true
						break
					}
				}
			}
		}

		// If no match, continue with the next fingerprint
		if !matched {
			continue
		}

		// Append the technologies as well as implied ones
		technologies = append(technologies, app)
		if len(fingerprint.implies) > 0 {
			technologies = append(technologies, fingerprint.implies...)
		}
		matched = false
	}
	return technologies
}
