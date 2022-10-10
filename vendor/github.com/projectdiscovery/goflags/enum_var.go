package goflags

import (
	"fmt"
	"strings"
)

type EnumVariable int8

func (e *EnumVariable) String() string {
	return fmt.Sprintf("%v", *e)
}

type AllowdTypes map[string]EnumVariable

func (a AllowdTypes) String() string {
	var str string
	for k := range a {
		str += fmt.Sprintf("%s, ", k)
	}
	return strings.TrimSuffix(str, ", ")
}

type EnumVar struct {
	allowedTypes AllowdTypes
	value        *string
}

func (e *EnumVar) String() string {
	if e.value != nil {
		return *e.value
	}
	return ""
}

func (e *EnumVar) Set(value string) error {
	_, ok := e.allowedTypes[value]
	if !ok {
		return fmt.Errorf("allowed values are %v", e.allowedTypes.String())
	}
	*e.value = value
	return nil
}
