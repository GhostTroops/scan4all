package env

import (
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	TLS_VERIFY = os.Getenv("TLS_VERIFY") == "true"
	DEBUG      = os.Getenv("DEBUG") == "true"
)

// ExpandWithEnv updates string variables to their corresponding environment values.
// If the variables does not exist, they're set to empty strings.
func ExpandWithEnv(variables ...*string) {
	for _, variable := range variables {
		if variable == nil {
			continue
		}
		*variable = os.Getenv(strings.TrimPrefix(*variable, "$"))
	}
}

// EnvType is a type that can be used as a type for environment variables.
type EnvType interface {
	~string | ~int | ~bool | ~float64 | time.Duration | ~rune
}

// GetEnvOrDefault returns the value of the environment variable or the default value if the variable is not set.
// in requested type.
func GetEnvOrDefault[T EnvType](key string, defaultValue T) T {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	switch any(defaultValue).(type) {
	case string:
		return any(value).(T)
	case int:
		intVal, err := strconv.Atoi(value)
		if err != nil || value == "" {
			return defaultValue
		}
		return any(intVal).(T)
	case bool:
		boolVal, err := strconv.ParseBool(value)
		if err != nil || value == "" {
			return defaultValue
		}
		return any(boolVal).(T)
	case float64:
		floatVal, err := strconv.ParseFloat(value, 64)
		if err != nil || value == "" {
			return defaultValue
		}
		return any(floatVal).(T)
	case time.Duration:
		durationVal, err := time.ParseDuration(value)
		if err != nil || value == "" {
			return defaultValue
		}
		return any(durationVal).(T)
	}
	return defaultValue
}
