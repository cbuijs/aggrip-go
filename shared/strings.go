// ==========================================================================
// Filename: shared/strings.go
// Version: 1.6.0-20260429
// Date: 2026-04-29 14:46 CEST
// Description: Centralized string manipulation and reversal utilities driving
//              O(N log N) deduplication trees.
//
// Update Trail:
//   - 1.6.0-20260429: Migrated IsASCII and GetDomainParents natively into central bounds.
// ==========================================================================

package shared

import (
	"strings"
	"unicode"
)

// ReverseASCII performs a high-speed reverse of an ASCII string safely.
// Bypasses the overhead of full rune translation for pure network domains.
func ReverseASCII(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		b[len(s)-1-i] = s[i]
	}
	return string(b)
}

// ReverseStr performs a rapid rune-level reverse string operation for 
// O(N log N) deduplication sorting. Explicitly handles Unicode IDNA safely.
func ReverseStr(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// IsASCII runs a high-speed boundary check verifying if a string strictly
// consists of standard ASCII characters natively. Bypasses Go standard package
// string allocations for extreme performance gains during concurrent parallel stream ingestions.
func IsASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// GetDomainParents yields an explicit slice of domains traversing bottom-up 
// completely toward the root apex natively. Facilitates high-speed mathematical 
// subset evaluations dynamically guarding against nested explicit exclusion configurations safely.
func GetDomainParents(domain string) []string {
	var parents []string
	for {
		parents = append(parents, domain)
		idx := strings.IndexByte(domain, '.')
		if idx == -1 {
			break
		}
		// Safely advance past the matched dot limit
		domain = domain[idx+1:]
	}
	return parents
}

