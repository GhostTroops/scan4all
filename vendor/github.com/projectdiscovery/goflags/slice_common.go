package goflags

import (
	"strings"

	"github.com/pkg/errors"
	fileutil "github.com/projectdiscovery/utils/file"
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
	// IsFromFile determines if the values are from file
	IsFromFile func(string) bool
	// IsEmpty determines if the values are empty
	IsEmpty func(string) bool
	// Normalize the value (eg. removing trailing spaces)
	Normalize func(string) string
	// IsRaw determines if the value should be considered as a raw string
	IsRaw func(string) bool
}

// ToStringSlice converts a value to string slice based on options
func ToStringSlice(value string, options Options) ([]string, error) {
	var result []string
	if options.IsEmpty == nil && options.IsFromFile == nil && options.Normalize == nil {
		return []string{value}, nil
	}

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
	} else if options.IsRaw != nil && options.IsRaw(value) {
		addPartToResult(value)
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

func isFromFile(_ string) bool {
	return true
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
