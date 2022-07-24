package wappalyzer

import (
	"bytes"
	"unsafe"

	"golang.org/x/net/html"
)

// checkBody checks for fingerprints in the HTML body
func (s *Wappalyze) checkBody(body []byte) []string {
	var technologies []string

	bodyString := unsafeToString(body)

	technologies = append(
		technologies,
		s.fingerprints.matchString(bodyString, htmlPart)...,
	)

	// Tokenize the HTML document and check for fingerprints as required
	tokenizer := html.NewTokenizer(bytes.NewReader(body))

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return technologies
		case html.StartTagToken:
			token := tokenizer.Token()
			switch token.Data {
			case "script":
				// Check if the script tag has a source file to check
				source, found := getScriptSource(token)
				if found {
					// Check the script tags for script fingerprints
					technologies = append(
						technologies,
						s.fingerprints.matchString(source, scriptPart)...,
					)
					continue
				}

				// Check the text attribute of the tag for javascript based technologies.
				// The next token should be the contents of the script tag
				if tokenType := tokenizer.Next(); tokenType != html.TextToken {
					continue
				}

				// TODO: JS requires a running VM, for checking properties. Only
				// possible with headless for now :(

				// data := tokenizer.Token().Data
				// technologies = append(
				// 	technologies,
				// 	s.fingerprints.matchString(data, jsPart)...,
				// )
			case "meta":
				// For meta tag, we are only interested in name and content attributes.
				name, content, found := getMetaNameAndContent(token)
				if !found {
					continue
				}
				technologies = append(
					technologies,
					s.fingerprints.matchKeyValueString(name, content, metaPart)...,
				)
			}
		case html.SelfClosingTagToken:
			token := tokenizer.Token()
			if token.Data != "meta" {
				continue
			}

			// Parse the meta tag and check for tech
			name, content, found := getMetaNameAndContent(token)
			if !found {
				continue
			}
			technologies = append(
				technologies,
				s.fingerprints.matchKeyValueString(name, content, metaPart)...,
			)
		}
	}
}

func (s *Wappalyze) getTitle(body []byte) string {
	var title string

	// Tokenize the HTML document and check for fingerprints as required
	tokenizer := html.NewTokenizer(bytes.NewReader(body))

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return title
		case html.StartTagToken:
			token := tokenizer.Token()
			switch token.Data {
			case "title":
				// Next text token will be the actual title of the page
				if tokenType := tokenizer.Next(); tokenType != html.TextToken {
					continue
				}
				title = tokenizer.Token().Data
			}
		}
	}
}

// getMetaNameAndContent gets name and content attributes from meta html token
func getMetaNameAndContent(token html.Token) (string, string, bool) {
	if len(token.Attr) < keyValuePairLength {
		return "", "", false
	}

	var name, content string
	for _, attr := range token.Attr {
		switch attr.Key {
		case "name":
			name = attr.Val
		case "content":
			content = attr.Val
		}
	}
	return name, content, true
}

// getScriptSource gets src tag from a script tag
func getScriptSource(token html.Token) (string, bool) {
	if len(token.Attr) < 1 {
		return "", false
	}

	var source string
	for _, attr := range token.Attr {
		switch attr.Key {
		case "src":
			source = attr.Val
		}
	}
	return source, true
}

// unsafeToString converts a byte slice to string and does it with
// zero allocations.
//
// NOTE: This function should only be used if its certain that the underlying
// array has not been manipulated.
//
// Reference - https://github.com/golang/go/issues/25484
func unsafeToString(data []byte) string {
	return *(*string)(unsafe.Pointer(&data))
}
