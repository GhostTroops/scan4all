package goflags

import (
	"errors"
	"fmt"
	"strings"

	stringsutil "github.com/projectdiscovery/utils/strings"
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

	var items string
	for k, v := range runtimeMap.kv {
		items += fmt.Sprintf("\"%s\"=\"%s\"%s", k, v, kvSep)
	}
	defaultBuilder.WriteString(stringsutil.TrimSuffixAny(items, ",", "="))
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
	return runtimeMap.kv == nil || len(runtimeMap.kv) == 0
}

// AsMap returns the internal map as reference - changes are allowed
func (runtimeMap *RuntimeMap) AsMap() map[string]interface{} {
	return runtimeMap.kv
}
