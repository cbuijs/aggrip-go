/*
==========================================================================
Filename: clean-dom/validator.go
Version: 1.0.9-20260424
Date: 2026-04-24 09:01 CEST
Description: Handles strict and lenient structural boundaries, RFC 
             enforcement, IP bypasses, and low-level string manipulation.
==========================================================================
*/

package main

import (
	"net/netip"
	"strings"
)

// isFastIP runs a rapid heuristic bypass checking if a token resembles an IP.
func isFastIP(token string) bool {
	if len(token) == 0 {
		return false
	}
	c := token[0]
	if (c >= '0' && c <= '9') || c == ':' {
		_, err := netip.ParseAddr(token)
		return err == nil
	}
	return false
}

// isPlausibleDomain is a high-speed pre-ingestion check to silently drop obvious 
// non-domain garbage (like URLs, regexes, paths from Adblock lists) before they 
// pollute memory or trigger structural validation logs natively.
func isPlausibleDomain(domain string) bool {
	for i := 0; i < len(domain); i++ {
		c := domain[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '*' {
			continue
		}
		return false
	}
	return true
}

// isValidDomainStructural replaces slow regex engines with a high-speed native byte evaluator.
// Supports overriding standard bounds using the lessStrict flag and allowTLD flag.
func isValidDomainStructural(domain string, lessStrict bool, allowTLD bool) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	
	// Fast structural edge bounds
	if domain[0] == '.' || domain[len(domain)-1] == '.' {
		return false
	}

	parts := strings.Split(domain, ".")
	if !allowTLD && len(parts) < 2 {
		return false // Must contain at least a TLD identifier
	}
	if len(parts) == 0 {
		return false
	}

	for _, part := range parts {
		l := len(part)
		if l == 0 || l > 63 {
			return false
		}
		
		// Blocks cannot start or end with standard hyphens per RFC
		if part[0] == '-' || part[l-1] == '-' {
			return false
		}
		
		// Enforce underscore boundary blocks unless less-strict is actively toggled
		if !lessStrict && (part[0] == '_' || part[l-1] == '_') {
			return false
		}

		for j := 0; j < l; j++ {
			c := part[j]
			valid := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'
			
			// Open regex parity boundaries for legacy non-compliant feeds
			if !valid && lessStrict {
				if c == '_' || c == '*' {
					valid = true
				}
			}
			if !valid {
				return false
			}
		}
	}
	return true
}

// hasNumericTLD evaluates domains strictly against RFC 3696 enforcing alphabetic TLD boundaries.
func hasNumericTLD(domain string) bool {
	parts := strings.Split(domain, ".")
	if len(parts) == 0 {
		return false
	}
	tld := parts[len(parts)-1]
	
	for i := 0; i < len(tld); i++ {
		if tld[i] < '0' || tld[i] > '9' {
			return false // Safe, found an alphabetic or non-numeric character
		}
	}
	return true // TLD is entirely numeric (e.g., 201.22.83)
}

// getParents yields a slice of domains traveling bottom-up toward the apex natively.
func getParents(domain string) []string {
	var parents []string
	for {
		parents = append(parents, domain)
		idx := strings.IndexByte(domain, '.')
		if idx == -1 {
			break
		}
		// Safely advance past the matched dot
		domain = domain[idx+1:]
	}
	return parents
}

// reverseStr performs a rapid rune-level reverse string operation for O(N log N) deduplication sorting.
func reverseStr(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// extractDomainForSort strictly pulls the root domain from a string array index safely handling comments
func extractDomainForSort(item string) string {
	if strings.HasPrefix(item, "#") {
		clean := strings.TrimSpace(strings.TrimPrefix(item, "#"))
		return strings.SplitN(clean, " - ", 2)[0]
	}
	return item
}

