package goflags

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// AuthVar handles authentication tokens with support for:
// - Direct value: -auth TOKEN
// - Interactive prompt: -auth (prompts for masked input)
// - Environment variable fallback
type AuthVar struct {
	field  *string
	envKey string
}

func (a *AuthVar) Set(value string) error {
	if isBoolLikeValue(value) {
		token, err := promptForToken()
		if err != nil {
			return err
		}
		*a.field = token
	} else {
		*a.field = value
	}

	if a.envKey != "" && *a.field != "" {
		os.Setenv(a.envKey, *a.field)
	}
	return nil
}

func (a *AuthVar) IsBoolFlag() bool {
	return true
}

func (a *AuthVar) String() string {
	if a.field == nil {
		return ""
	}
	return *a.field
}

func isBoolLikeValue(value string) bool {
	switch value {
	case "true", "TRUE", "True", "t", "T", "1":
		return true
	}
	return false
}

func promptForToken() (string, error) {
	fmt.Print("Enter authentication token: ")
	token, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("failed to read token: %w", err)
	}
	return string(token), nil
}

func (flagSet *FlagSet) AuthVar(field *string, long, envKey, usage string) *FlagData {
	return flagSet.AuthVarP(field, long, "", envKey, usage)
}

func (flagSet *FlagSet) AuthVarP(field *string, long, short, envKey, usage string) *FlagData {
	if field == nil {
		panic(fmt.Errorf("field cannot be nil for flag -%v", long))
	}

	if envKey != "" {
		if envValue := os.Getenv(envKey); envValue != "" {
			*field = envValue
		}
	}

	authVar := &AuthVar{
		field:  field,
		envKey: envKey,
	}

	flagData := &FlagData{
		usage:        usage,
		long:         long,
		defaultValue: "",
	}

	if short != "" {
		flagData.short = short
		flagSet.CommandLine.Var(authVar, short, usage)
		flagSet.flagKeys.Set(short, flagData)
	}
	flagSet.CommandLine.Var(authVar, long, usage)
	flagSet.flagKeys.Set(long, flagData)
	return flagData
}
