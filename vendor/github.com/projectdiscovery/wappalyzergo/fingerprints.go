package wappalyzer

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Fingerprints contains a map of fingerprints for tech detection
type Fingerprints struct {
	// Apps is organized as <name, fingerprint>
	Apps map[string]*Fingerprint `json:"apps"`
}

// Fingerprint is a single piece of information about a tech validated and normalized
type Fingerprint struct {
	Cookies     map[string]string   `json:"cookies"`
	JS          []string            `json:"js"`
	Headers     map[string]string   `json:"headers"`
	HTML        []string            `json:"html"`
	CSS         []string            `json:"css"`
	Script      []string            `json:"scripts"`
	Meta        map[string][]string `json:"meta"`
	Implies     []string            `json:"implies"`
	Description string              `json:"description"`
	Website     string              `json:"website"`
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
	// description contains fingerprint description
	description string
	// website contains a URL associated with the fingerprint
	website string
	// cookies contains fingerprints for target cookies
	cookies map[string]*versionRegex
	// js contains fingerprints for the js file
	js []*versionRegex
	// headers contains fingerprints for target headers
	headers map[string]*versionRegex
	// html contains fingerprints for the target HTML
	html []*versionRegex
	// script contains fingerprints for script tags
	script []*versionRegex
	// meta contains fingerprints for meta tags
	meta map[string][]*versionRegex
}

// AppInfo contains basic information about an App.
type AppInfo struct {
	Description string
	Website     string
}

type versionRegex struct {
	regex     *regexp.Regexp
	skipRegex bool
	group     int
}

const versionPrefix = "version:\\"

// newVersionRegex creates a new version matching regex
// TODO: handles simple group cases only as of now (no ternary)
func newVersionRegex(value string) (*versionRegex, error) {
	splitted := strings.Split(value, "\\;")
	if len(splitted) == 0 {
		return nil, nil
	}

	compiled, err := regexp.Compile(splitted[0])
	if err != nil {
		return nil, err
	}
	skipRegex := splitted[0] == ""
	regex := &versionRegex{regex: compiled, skipRegex: skipRegex}
	for _, part := range splitted {
		if strings.HasPrefix(part, versionPrefix) {
			group := strings.TrimPrefix(part, versionPrefix)
			if parsed, err := strconv.Atoi(group); err == nil {
				regex.group = parsed
			}
		}
	}
	return regex, nil
}

// MatchString returns true if a version regex matched.
// The found version is also returned if any.
func (v *versionRegex) MatchString(value string) (bool, string) {
	if v.skipRegex {
		return true, ""
	}
	matches := v.regex.FindAllStringSubmatch(value, -1)
	if len(matches) == 0 {
		return false, ""
	}

	var version string
	if v.group > 0 {
		for _, match := range matches {
			version = match[v.group]
		}
	}
	return true, version
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
		implies:     fingerprint.Implies,
		description: fingerprint.Description,
		website:     fingerprint.Website,
		cookies:     make(map[string]*versionRegex),
		js:          make([]*versionRegex, 0, len(fingerprint.JS)),
		headers:     make(map[string]*versionRegex),
		html:        make([]*versionRegex, 0, len(fingerprint.HTML)),
		script:      make([]*versionRegex, 0, len(fingerprint.Script)),
		meta:        make(map[string][]*versionRegex),
	}

	for header, pattern := range fingerprint.Cookies {
		fingerprint, err := newVersionRegex(pattern)
		if err != nil {
			continue
		}
		compiled.cookies[header] = fingerprint
	}

	for _, pattern := range fingerprint.JS {
		fingerprint, err := newVersionRegex(pattern)
		if err != nil {
			continue
		}
		compiled.js = append(compiled.js, fingerprint)
	}

	for header, pattern := range fingerprint.Headers {
		fingerprint, err := newVersionRegex(pattern)
		if err != nil {
			continue
		}
		compiled.headers[header] = fingerprint
	}

	for _, pattern := range fingerprint.HTML {
		fingerprint, err := newVersionRegex(pattern)
		if err != nil {
			continue
		}
		compiled.html = append(compiled.html, fingerprint)
	}

	for _, pattern := range fingerprint.Script {
		fingerprint, err := newVersionRegex(pattern)
		if err != nil {
			continue
		}
		compiled.script = append(compiled.script, fingerprint)
	}

	for meta, patterns := range fingerprint.Meta {
		var compiledList []*versionRegex

		for _, pattern := range patterns {
			fingerprint, err := newVersionRegex(pattern)
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
		var version string

		switch part {
		case jsPart:
			for _, pattern := range fingerprint.js {
				if valid, versionString := pattern.MatchString(data); valid {
					matched = true
					version = versionString
				}
			}
		case scriptPart:
			for _, pattern := range fingerprint.script {
				if valid, versionString := pattern.MatchString(data); valid {
					matched = true
					version = versionString
				}
			}
		case htmlPart:
			for _, pattern := range fingerprint.html {
				if valid, versionString := pattern.MatchString(data); valid {
					matched = true
					version = versionString
				}
			}
		}

		// If no match, continue with the next fingerprint
		if !matched {
			continue
		}

		if version != "" {
			app = formatAppVersion(app, version)
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
		var version string

		switch part {
		case cookiesPart:
			for data, pattern := range fingerprint.cookies {
				if data != key {
					continue
				}

				if valid, versionString := pattern.MatchString(value); valid {
					matched = true
					version = versionString
					break
				}
			}
		case headersPart:
			for data, pattern := range fingerprint.headers {
				if data != key {
					continue
				}

				if valid, versionString := pattern.MatchString(value); valid {
					matched = true
					version = versionString
					break
				}
			}
		case metaPart:
			for data, patterns := range fingerprint.meta {
				if data != key {
					continue
				}

				for _, pattern := range patterns {
					if valid, versionString := pattern.MatchString(value); valid {
						matched = true
						version = versionString
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
		if version != "" {
			app = formatAppVersion(app, version)
		}
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
		var version string

		switch part {
		case cookiesPart:
			for data, pattern := range fingerprint.cookies {
				value, ok := keyValue[data]
				if !ok {
					continue
				}
				if pattern == nil {
					matched = true
				}
				if valid, versionString := pattern.MatchString(value); valid {
					matched = true
					version = versionString
					break
				}
			}
		case headersPart:
			for data, pattern := range fingerprint.headers {
				value, ok := keyValue[data]
				if !ok {
					continue
				}

				if valid, versionString := pattern.MatchString(value); valid {
					matched = true
					version = versionString
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
					if valid, versionString := pattern.MatchString(value); valid {
						matched = true
						version = versionString
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
		if version != "" {
			app = formatAppVersion(app, version)
		}
		technologies = append(technologies, app)
		if len(fingerprint.implies) > 0 {
			technologies = append(technologies, fingerprint.implies...)
		}
		matched = false
	}
	return technologies
}

func formatAppVersion(app, version string) string {
	return fmt.Sprintf("%s:%s", app, version)
}

// GetFingerprints returns the fingerprint string from wappalyzer
func GetFingerprints() string {
	return fingerprints
}
