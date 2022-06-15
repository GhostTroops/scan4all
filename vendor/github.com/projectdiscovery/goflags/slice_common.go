package goflags

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/fileutil"
)

var quotes = []rune{'"', '\'', '`'}

func isQuote(char rune) (bool, rune) {
	for _, quote := range quotes {
		if quote == char {
			return true, quote
		}
	}
	return false, 0
}

func searchPart(value string, stop rune) (bool, string) {
	var result string
	for _, char := range value {
		if char != stop {
			result += string(char)
		} else {
			return true, result
		}
	}
	return false, result
}

func ToString(slice []string) string {
	defaultBuilder := &strings.Builder{}
	defaultBuilder.WriteString("[")
	for i, k := range slice {
		defaultBuilder.WriteString("\"")
		defaultBuilder.WriteString(k)
		defaultBuilder.WriteString("\"")
		if i != len(slice)-1 {
			defaultBuilder.WriteString(", ")
		}
	}
	defaultBuilder.WriteString("]")
	return defaultBuilder.String()
}

type Options struct {
	IsFromFile func(string) bool
	IsEmpty    func(string) bool
	Normalize  func(string) string
}

func toStringSlice(value string, options Options) ([]string, error) {
	var result []string

	addPartToResult := func(part string) {
		if !options.IsEmpty(part) {
			if options.Normalize != nil {
				part = options.Normalize(part)
			}
			result = append(result, part)
		}
	}
	if fileutil.FileExists(value) && options.IsFromFile != nil && options.IsFromFile(value) {
		linesChan, err := fileutil.ReadFile(value)
		if err != nil {
			return nil, err
		}
		for line := range linesChan {
			addPartToResult(line)
		}
	} else {
		index := 0
		for index < len(value) {
			char := rune(value[index])
			if isQuote, quote := isQuote(char); isQuote {
				quoteFound, part := searchPart(value[index+1:], quote)

				if !quoteFound {
					return nil, errors.New("Unclosed quote in path")
				}

				index += len(part) + 2

				addPartToResult(part)
			} else {
				commaFound, part := searchPart(value[index:], ',')

				if commaFound {
					index += len(part) + 1
				} else {
					index += len(part)
				}

				addPartToResult(part)
			}
		}
	}

	return result, nil
}

func isEmpty(s string) bool {
	return strings.TrimSpace(s) == ""
}

func normalizeTrailingParts(s string) string {
	return strings.TrimSpace(s)
}

func normalize(s string) string {
	return strings.TrimSpace(strings.Trim(strings.TrimSpace(s), string(quotes)))
}

func normalizeLowercase(s string) string {
	return strings.TrimSpace(strings.Trim(strings.TrimSpace(strings.ToLower(s)), string(quotes)))
}
