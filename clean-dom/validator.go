/*
==========================================================================
Filename: clean-dom/validator.go
Version: 1.2.0-20260429
Date: 2026-04-29 11:47 CEST
Description: Handles strict and lenient structural boundaries, RFC 
             enforcement, embedded TLD dictionary mapping, and 
             low-level string validation protocols.

Update Trail:
  - 1.2.0 (2026-04-29): Transferred dictionaries and heavy TLD logic securely
                        to shared/validation.go. Cleaned up dead functions
                        like extractDomainForSort. Only local specific helpers
                        remain within this file.
  - 1.1.3 (2026-04-29): Integrated central shared library logic to replace
                        duplicated heuristic validation bounds natively.
==========================================================================
*/

package main

import (
	"strings"
)

// getParents yields a slice of domains traveling bottom-up toward the apex natively.
// Kept in local validator helpers due to format-specific context requirements.
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

