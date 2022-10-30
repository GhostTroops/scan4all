package core

import (
	"bytes"
	"github.com/Masterminds/sprig/v3"
	"github.com/hktalent/jaeles/utils"
	"regexp"
	"strings"
	"text/template"
)

// ResolveVariable resolve template from signature file
func ResolveVariable(format string, data map[string]string) string {
	if strings.TrimSpace(format) == "" {
		return format
	}
	_, exist := data["original"]
	if !exist {
		data["original"] = ""
	}
	realFormat, err := template.New("").Funcs(sprig.TxtFuncMap()).Parse(format)
	// when template contain {{
	if err != nil {
		r, rerr := regexp.Compile(`\{\{[^.]`)
		if rerr != nil {
			return format
		}
		matches := r.FindStringSubmatch(format)
		if len(matches) > 0 {
			for _, m := range matches {
				new := strings.Replace(m, `{{`, `{{"{{"}}`, -1)
				format = strings.Replace(format, m, new, -1)
			}
		}
		// parse it again
		realFormat, err = template.New("").Funcs(sprig.TxtFuncMap()).Parse(format)
		if err != nil {
			utils.ErrorF("improper template format %v", format)
			return format
		}
	}
	t := template.Must(realFormat, err)

	buf := &bytes.Buffer{}
	err = t.Execute(buf, data)
	if err != nil {
		return format
	}
	return buf.String()
}

// AltResolveVariable just like ResolveVariable but looking for [[.var]]
func AltResolveVariable(format string, data map[string]string) string {
	if strings.TrimSpace(format) == "" {
		return format
	}
	realFormat, err := template.New("").Delims("[[", "]]").Funcs(sprig.TxtFuncMap()).Parse(format)
	_, exist := data["original"]
	if !exist {
		data["original"] = ""
	}

	// when template contain [[
	if err != nil {
		r, rerr := regexp.Compile(`\[\[[^.]`)
		if rerr != nil {
			return format
		}
		matches := r.FindStringSubmatch(format)
		if len(matches) > 0 {
			for _, m := range matches {
				new := strings.Replace(m, `[[`, `[["[["]]`, -1)
				format = strings.Replace(format, m, new, -1)
			}
		}
		// parse it again
		realFormat, err = template.New("").Funcs(sprig.TxtFuncMap()).Parse(format)
		if err != nil {
			utils.ErrorF("improper template format %v", format)
			return format
		}
	}
	t := template.Must(realFormat, err)

	buf := &bytes.Buffer{}
	err = t.Execute(buf, data)
	if err != nil {
		return format
	}
	return buf.String()
}
