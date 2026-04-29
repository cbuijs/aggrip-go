// ==========================================================================
// Filename: shared/flags.go
// Version: 1.0.0
// Date: 2026-04-29 10:48 CEST
// Description: Centralized command-line flag structures for aggrip-go.
//              Provides native support for multi-argument string flags.
// ==========================================================================

package shared

import "strings"

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

