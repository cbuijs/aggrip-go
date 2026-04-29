// ==========================================================================
// Filename: shared/validation.go
// Version: 1.0.0
// Date: 2026-04-29 10:48 CEST
// Description: Centralized high-performance heuristics and validation utilities.
// ==========================================================================

package shared

import "net/netip"

// IsFastIPStrict runs a strict heuristic check using netip to ensure 
// valid IP structures (IPv4/IPv6). Used inherently by clean-dom.
func IsFastIPStrict(token string) bool {
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

// IsIPHeuristic runs a highly optimized heuristic to skip pure text blocks
// preventing the system from running expensive IP-parsing exceptions.
// Permits dashes '-' explicitly for IP range parsing natively.
func IsIPHeuristic(token string) bool {
	if len(token) == 0 {
		return false
	}
	c := token[0]
	return (c >= '0' && c <= '9') || c == ':' || c == '-'
}

// IsPlausibleDomain is a high-speed pre-ingestion check to silently drop obvious 
// non-domain garbage (like URLs, regexes, paths from Adblock lists) before they 
// pollute memory or trigger structural validation logs natively.
func IsPlausibleDomain(domain string) bool {
	for i := 0; i < len(domain); i++ {
		c := domain[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '*' {
			continue
		}
		return false
	}
	return true
}

// IsValidDomain performs high-speed byte-level validation without regex overhead cleanly.
// Strictly restricts payloads to alphanumeric, hyphens, and periods.
func IsValidDomain(b []byte, lessStrict bool) bool {
	for i := 0; i < len(b); i++ {
		c := b[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' {
			continue
		}
		if lessStrict && (c == '_' || c == '*') {
			continue
		}
		return false
	}
	return true
}

