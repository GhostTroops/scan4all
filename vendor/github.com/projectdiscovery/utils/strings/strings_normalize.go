package stringsutil

import (
	"strings"
	"unicode"

	"github.com/microcosm-cc/bluemonday"
)

type NormalizeOptions struct {
	TrimSpaces    bool
	TrimCutset    string
	StripHTML     bool
	Lowercase     bool
	Uppercase     bool
	StripComments bool
}

var DefaultNormalizeOptions NormalizeOptions = NormalizeOptions{
	TrimSpaces: true,
	StripHTML:  true,
}

var HTMLPolicy *bluemonday.Policy = bluemonday.StrictPolicy()

func NormalizeWithOptions(data string, options NormalizeOptions) string {
	if options.TrimSpaces {
		data = strings.TrimSpace(data)
	}

	if options.TrimCutset != "" {
		data = strings.Trim(data, options.TrimCutset)
	}

	if options.Lowercase {
		data = strings.ToLower(data)
	}

	if options.Uppercase {
		data = strings.ToUpper(data)
	}

	if options.StripHTML {
		data = HTMLPolicy.Sanitize(data)
	}

	if options.StripComments {
		if cut := strings.IndexAny(data, "#"); cut >= 0 {
			data = strings.TrimRightFunc(data[:cut], unicode.IsSpace)
		}
	}

	return data
}

func Normalize(data string) string {
	return NormalizeWithOptions(data, DefaultNormalizeOptions)
}
