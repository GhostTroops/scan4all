package goflags

import (
	"fmt"
	"strings"
)

type EnumSliceVar struct {
	allowedTypes AllowdTypes
	value        *[]string
}

func (e *EnumSliceVar) String() string {
	if e.value != nil {
		return strings.Join(*e.value, ",")
	}
	return ""
}

func (e *EnumSliceVar) Set(value string) error {
	values := strings.Split(value, ",")
	for _, v := range values {
		_, ok := e.allowedTypes[v]
		if !ok {
			return fmt.Errorf("allowed values are %v", e.allowedTypes.String())
		}
	}
	*e.value = values
	return nil
}
