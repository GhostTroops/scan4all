package goflags

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	fileutil "github.com/projectdiscovery/utils/file"
)

const (
	kvSep = "="
)

// RuntimeMap is a runtime only map of interfaces
type RuntimeMap struct {
	kv map[string]interface{}
}

func (runtimeMap RuntimeMap) String() string {
	defaultBuilder := &strings.Builder{}
	defaultBuilder.WriteString("{")

	keys := make([]string, 0, len(runtimeMap.kv))
	for key := range runtimeMap.kv {
		keys = append(keys, key)
	}

	sort.Strings(keys)
	for i, key := range keys {
		if i > 0 {
			defaultBuilder.WriteString(kvSep)
		}
		fmt.Fprintf(defaultBuilder, "\"%s\"=\"%s\"", key, runtimeMap.kv[key])
	}

	defaultBuilder.WriteString("}")

	return defaultBuilder.String()
}

// Set inserts a value to the map. Format: key=value
func (runtimeMap *RuntimeMap) Set(value string) error {
	if runtimeMap.kv == nil {
		runtimeMap.kv = make(map[string]interface{})
	}
	var k, v string
	if idxSep := strings.Index(value, kvSep); idxSep > 0 {
		k = value[:idxSep]
		v = value[idxSep+1:]
	} else {
		// this could be a file if so check and load it
		if fileutil.FileExists(value) {
			f, err := os.Open(value)
			if err != nil {
				return err
			}
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				text := scanner.Text()
				if idxSep := strings.Index(text, kvSep); idxSep > 0 {
					runtimeMap.kv[text[:idxSep]] = text[idxSep+1:]
				}
			}
			if err := scanner.Err(); err != nil {
				return err
			}
		}
	}
	// note:
	// - inserting multiple times the same key will override the previous value
	// - empty string is legitimate value
	if k != "" {
		runtimeMap.kv[k] = v
	}
	return nil
}

// Del removes the specified key
func (runtimeMap *RuntimeMap) Del(key string) error {
	if runtimeMap.kv == nil {
		return errors.New("empty runtime map")
	}
	delete(runtimeMap.kv, key)
	return nil
}

// IsEmpty specifies if the underlying map is empty
func (runtimeMap *RuntimeMap) IsEmpty() bool {
	return len(runtimeMap.kv) == 0
}

// AsMap returns the internal map as reference - changes are allowed
func (runtimeMap *RuntimeMap) AsMap() map[string]interface{} {
	return runtimeMap.kv
}
