// ==========================================================================
// Filename: shared/flags.go
// Version: 1.2.0-20260429
// Date: 2026-04-29 11:47 CEST
// Update Trail:
//   - 1.2.0-20260429: Migrated OptionalIntFlag from clean-dom to shared
//                     for suite-wide CLI parameter standardization.
//   - 1.0.0: Initial StringSlice implementation.
// Description: Centralized command-line flag structures for aggrip-go.
//              Provides native support for multi-argument string flags and
//              optional boolean-integer toggles.
// ==========================================================================

package shared

import (
	"fmt"
	"strconv"
	"strings"
)

// StringSlice implements flag.Value to allow multiple CLI arguments natively.
// Replacing duplicate custom pre-parsers across the suite.
type StringSlice []string

// String fulfills the standard library flag.Value interface.
func (s *StringSlice) String() string {
	return strings.Join(*s, " ")
}

// Set fulfills the standard library flag.Value interface natively appending values.
func (s *StringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// OptionalIntFlag implements a custom flag construct allowing a parameter
// to act as both a boolean toggle and an integer receiver cleanly.
// This natively supports syntax like --flag and --flag=5.
type OptionalIntFlag struct {
	Value  int
	Active bool
}

// String fulfills the flag.Value interface returning the string representation.
func (i *OptionalIntFlag) String() string {
	if !i.Active {
		return "0"
	}
	return strconv.Itoa(i.Value)
}

// Set fulfills the flag.Value interface, parsing the assigned string payload safely.
func (i *OptionalIntFlag) Set(s string) error {
	i.Active = true
	// "true" is natively passed by the flag package if the argument lacks an equal sign
	if s == "true" {
		i.Value = 10 // Enterprise default routing specification
		return nil
	}
	if s == "false" {
		i.Active = false
		return nil
	}
	val, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("invalid integer format: %v", err)
	}
	if val < 1 {
		return fmt.Errorf("value must be >= 1")
	}
	i.Value = val
	return nil
}

// IsBoolFlag signals the internal Go flag package that this construct
// natively allows omitted values without triggering parse failures.
func (i *OptionalIntFlag) IsBoolFlag() bool {
	return true
}

