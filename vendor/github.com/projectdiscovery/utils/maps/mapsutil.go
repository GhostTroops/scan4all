package mapsutil

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/exp/constraints"
	extmaps "golang.org/x/exp/maps"
)

// Merge merges the inputted maps into a new one.
// Be aware: In case of duplicated keys in multiple maps,
// the one ending in the result is unknown a priori.
func Merge[K comparable, V any](maps ...map[K]V) (result map[K]V) {
	result = make(map[K]V)

	for _, m := range maps {
		for k, v := range m {
			result[k] = v
		}
	}

	return
}

const defaultFormat = "%s"

// HTTPToMap Converts HTTP to Matcher Map
func HTTPToMap(resp *http.Response, body, headers string, duration time.Duration, format string) (m map[string]interface{}) {
	m = make(map[string]interface{})

	if format == "" {
		format = defaultFormat
	}

	m[fmt.Sprintf(format, "content_length")] = resp.ContentLength
	m[fmt.Sprintf(format, "status_code")] = resp.StatusCode

	for k, v := range resp.Header {
		k = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(k, "-", "_")))
		m[fmt.Sprintf(format, k)] = strings.Join(v, " ")
	}

	m[fmt.Sprintf(format, "all_headers")] = headers
	m[fmt.Sprintf(format, "body")] = body

	if r, err := httputil.DumpResponse(resp, true); err == nil {
		m[fmt.Sprintf(format, "raw")] = string(r)
	}

	// Converts duration to seconds (floating point) for DSL syntax
	m[fmt.Sprintf(format, "duration")] = duration.Seconds()

	return m
}

// DNSToMap Converts DNS to Matcher Map
func DNSToMap(msg *dns.Msg, format string) (m map[string]interface{}) {
	m = make(map[string]interface{})

	if format == "" {
		format = defaultFormat
	}

	m[fmt.Sprintf(format, "rcode")] = msg.Rcode

	var qs string

	for _, question := range msg.Question {
		qs += fmt.Sprintln(question.String())
	}

	m[fmt.Sprintf(format, "question")] = qs

	var exs string
	for _, extra := range msg.Extra {
		exs += fmt.Sprintln(extra.String())
	}

	m[fmt.Sprintf(format, "extra")] = exs

	var ans string
	for _, answer := range msg.Answer {
		ans += fmt.Sprintln(answer.String())
	}

	m[fmt.Sprintf(format, "answer")] = ans

	var nss string
	for _, ns := range msg.Ns {
		nss += fmt.Sprintln(ns.String())
	}

	m[fmt.Sprintf(format, "ns")] = nss
	m[fmt.Sprintf(format, "raw")] = msg.String()

	return m
}

// HTTPRequestToMap Converts HTTP Request to Matcher Map
func HTTPRequestToMap(req *http.Request) (map[string]interface{}, error) {
	m := make(map[string]interface{})
	var headers string
	for k, v := range req.Header {
		k = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(k, "-", "_")))
		vv := strings.Join(v, " ")
		m[k] = strings.Join(v, " ")
		headers += fmt.Sprintf("%s: %s", k, vv)
	}

	m["all_headers"] = headers

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewBuffer(body))
	m["body"] = string(body)

	reqdump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, err
	}
	reqdumpString := string(reqdump)
	m["raw"] = reqdumpString
	m["request"] = reqdumpString

	return m, nil
}

// HTTPResponseToMap Converts HTTP Response to Matcher Map
func HTTPResponseToMap(resp *http.Response) (map[string]interface{}, error) {
	m := make(map[string]interface{})

	m["content_length"] = resp.ContentLength
	m["status_code"] = resp.StatusCode
	var headers string
	for k, v := range resp.Header {
		k = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(k, "-", "_")))
		vv := strings.Join(v, " ")
		m[k] = vv
		headers += fmt.Sprintf("%s: %s", k, vv)
	}
	m["all_headers"] = headers

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewBuffer(body))
	m["body"] = string(body)

	if r, err := httputil.DumpResponse(resp, true); err == nil {
		responseString := string(r)
		m["raw"] = responseString
		m["response"] = responseString
	}

	return m, nil
}

// GetKeys returns the map's keys.
func GetKeys[K comparable, V any](maps ...map[K]V) []K {
	var keys []K
	for _, m := range maps {
		keys = append(keys, extmaps.Keys(m)...)
	}
	return keys
}

// GetValues returns the map's values.
func GetValues[K comparable, V any](maps ...map[K]V) []V {
	var values []V
	for _, m := range maps {
		values = append(values, extmaps.Values(m)...)
	}
	return values
}

// Difference returns the inputted map without the keys specified as input.
func Difference[K comparable, V any](m map[K]V, keys ...K) map[K]V {
	for _, key := range keys {
		delete(m, key)
	}

	return m
}

// Flatten takes a map and returns a new one where nested maps are replaced
// by dot-delimited keys.
func Flatten(m map[string]any, separator string) map[string]any {
	if separator == "" {
		separator = "."
	}
	o := make(map[string]any)
	for k, v := range m {
		switch child := v.(type) {
		case map[string]any:
			nm := Flatten(child, separator)
			for nk, nv := range nm {
				o[k+separator+nk] = nv
			}
		default:
			o[k] = v
		}
	}
	return o
}

// Walk a map and visit all the edge key:value pairs
func Walk(m map[string]any, callback func(k string, v any)) {
	for k, v := range m {
		switch child := v.(type) {
		case map[string]any:
			Walk(child, callback)
		default:
			callback(k, v)
		}
	}
}

// Clear the map passed as parameter
func Clear[K comparable, V any](mm ...map[K]V) {
	for _, m := range mm {
		extmaps.Clear(m)
	}
}

// SliceToMap returns a map having as keys the elements in
// even positions and as values the elements in odd positions.
// If the number of elements is odd the default value applies.
func SliceToMap[T comparable](s []T, dflt T) map[T]T {
	result := map[T]T{}

	for i := 0; i < len(s); i += 2 {
		if i+1 < len(s) {
			result[s[i]] = s[i+1]
		} else {
			result[s[i]] = dflt
		}
	}
	return result
}

// IsEmpty checks if a map is empty.
func IsEmpty[K comparable, V any](m map[K]V) bool {
	return len(m) == 0
}

// GetSortedKeys returns the map's keys sorted.
func GetSortedKeys[K constraints.Ordered, V any](maps ...map[K]V) []K {
	keys := GetKeys(maps...)
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	return keys
}
