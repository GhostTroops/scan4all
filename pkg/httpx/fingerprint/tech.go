package wappalyzer

import (
	"bytes"
	"encoding/json"
	"strings"
)

// Wappalyze is a client for working with tech detection
type Wappalyze struct {
	fingerprints *CompiledFingerprints
}

// New creates a new tech detection instance
func New() (*Wappalyze, error) {
	wappalyze := &Wappalyze{
		fingerprints: &CompiledFingerprints{
			Apps: make(map[string]*CompiledFingerprint),
		},
	}

	err := wappalyze.loadFingerprints()
	if err != nil {
		return nil, err
	}
	return wappalyze, nil
}

// loadFingerprints loads the fingerprints and compiles them
func (s *Wappalyze) loadFingerprints() error {
	var fingerprintsStruct Fingerprints
	err := json.Unmarshal([]byte(fingerprints), &fingerprintsStruct)
	if err != nil {
		return err
	}

	for i, fingerprint := range fingerprintsStruct.Apps {
		s.fingerprints.Apps[i] = compileFingerprint(fingerprint)
	}
	return nil
}

// Fingerprint identifies technologies on a target based on
// headers and response recieved.
//
// Body should not be mutated while this function is being called or it may
// lead to unexpected things.
func (s *Wappalyze) Fingerprint(headers map[string][]string, body []byte) map[string]struct{} {
	uniqueFingerprints := make(map[string]struct{})

	// Lowercase everything that we have recieved to check
	normalizedBody := bytes.ToLower(body)
	normalizedHeaders := s.normalizeHeaders(headers)

	// Run header based fingerprinting if the number
	// of header checks if more than 0.
	for _, application := range s.checkHeaders(normalizedHeaders) {
		if _, ok := uniqueFingerprints[application]; !ok {
			uniqueFingerprints[application] = struct{}{}
		}
	}

	cookies := s.findSetCookie(normalizedHeaders)
	// Run cookie based fingerprinting if we have a set-cookie header
	if len(cookies) > 0 {
		for _, application := range s.checkCookies(cookies) {
			if _, ok := uniqueFingerprints[application]; !ok {
				uniqueFingerprints[application] = struct{}{}
			}
		}
	}

	// Check for stuff in the body finally
	bodyTech := s.checkBody(normalizedBody)
	for _, application := range bodyTech {
		if _, ok := uniqueFingerprints[application]; !ok {
			uniqueFingerprints[application] = struct{}{}
		}
	}
	return uniqueFingerprints
}

// FingerprintWithTitle identifies technologies on a target based on
// headers and response recieved. It also returns the title of the page.
//
// Body should not be mutated while this function is being called or it may
// lead to unexpected things.
func (s *Wappalyze) FingerprintWithTitle(headers map[string][]string, body []byte) (map[string]struct{}, string) {
	uniqueFingerprints := make(map[string]struct{})

	// Lowercase everything that we have recieved to check
	normalizedBody := bytes.ToLower(body)
	normalizedHeaders := s.normalizeHeaders(headers)

	// Run header based fingerprinting if the number
	// of header checks if more than 0.
	for _, application := range s.checkHeaders(normalizedHeaders) {
		if _, ok := uniqueFingerprints[application]; !ok {
			uniqueFingerprints[application] = struct{}{}
		}
	}

	cookies := s.findSetCookie(normalizedHeaders)
	// Run cookie based fingerprinting if we have a set-cookie header
	if len(cookies) > 0 {
		for _, application := range s.checkCookies(cookies) {
			if _, ok := uniqueFingerprints[application]; !ok {
				uniqueFingerprints[application] = struct{}{}
			}
		}
	}

	// Check for stuff in the body finally
	if strings.Contains(normalizedHeaders["content-type"], "text/html") {
		bodyTech := s.checkBody(normalizedBody)
		for _, application := range bodyTech {
			if _, ok := uniqueFingerprints[application]; !ok {
				uniqueFingerprints[application] = struct{}{}
			}
		}
		title := s.getTitle(body)
		return uniqueFingerprints, title
	}
	return uniqueFingerprints, ""
}
