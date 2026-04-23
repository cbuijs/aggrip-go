/*
==========================================================================
 Filename: main.go
 Version: 0.18 (Go Port)
 Date: 2026-04-23 11:23 CEST
 Description: Blazing fast binary-level domain deduplicator in Golang. 
              Removes redundant subdomains when parent domains exist in 
              the feed. Prioritizes low-latency and high-performance via
              bulk reads, zero-copy byte parsing, and parallel routines.
              Supports optional less-strict validation allowing '_' and '*'.

 Changes/Fixes:
 - v0.18 (2026-04-23): Complete Go rewrite utilizing advanced concurrency,
                       memory-safe byte slicing, and zero-copy evaluations.
                       Drop-in replacement for undup.py/undup2.py.
 - v0.17 (2026-04-16): Added regex strictness validation (-l/--less-strict).
 - v0.16 (2026-04-07): Merged stripping rules, added docstrings.
 - v0.15 (2026-04-01): Original Python version.
==========================================================================
*/

package main

import (
	"bufio"
	"bytes"
	"flag"
	"io"
	"os"
	"runtime"
	"sort"
	"sync"
)

// Global constants for fast-path stripping and validation
const (
	trimBytes = " .\r\n"
	dotChar   = '.'
)

func main() {
	// ----------------------------------------------------------------------
	// Command-line flag parsing
	// Standardizes short parameters (-l) and long parameters (--less-strict)
	// ----------------------------------------------------------------------
	var lessStrict bool

	// Bind both short and long flags to the same boolean variable
	flag.BoolVar(&lessStrict, "l", false, "Allow underscores (_) and asterisks (*) in domain names")
	flag.BoolVar(&lessStrict, "less-strict", false, "Allow underscores (_) and asterisks (*) in domain names")
	
	// Customize the usage output to cleanly reflect dual-flag setup
	flag.Usage = func() {
		os.Stderr.WriteString("Usage of undup (Go):\n")
		os.Stderr.WriteString("  -l, --less-strict\n")
		os.Stderr.WriteString("        Allow underscores (_) and asterisks (*) in domain names\n")
	}
	flag.Parse()

	// ----------------------------------------------------------------------
	// Stage 1: Bulk Memory Read
	// Maximizes I/O throughput by reading the entire STDIN payload at once.
	// ----------------------------------------------------------------------
	rawData, err := io.ReadAll(os.Stdin)
	if err != nil || len(rawData) == 0 {
		return
	}

	// ----------------------------------------------------------------------
	// Stage 2: Zero-Copy Parsing and Normalization
	// We use bytes.Split to process the buffer without allocating new strings
	// for every single line. We validate and deduplicate instantly via map.
	// ----------------------------------------------------------------------
	lines := bytes.Split(rawData, []byte{'\n'})
	uniqueDomains := make(map[string]struct{}, len(lines))

	for _, line := range lines {
		// Strip leading/trailing whitespaces, carriage returns, and dots
		cleaned := bytes.Trim(line, trimBytes)
		if len(cleaned) == 0 {
			continue
		}

		// Fast-path inline ASCII lowercasing (avoids heavy strings.ToLower)
		for i := 0; i < len(cleaned); i++ {
			if cleaned[i] >= 'A' && cleaned[i] <= 'Z' {
				cleaned[i] += 32
			}
		}

		// Inline structural validation to bypass slow regular expressions
		if isValidDomain(cleaned, lessStrict) {
			// Convert to string safely only after passing all checks
			uniqueDomains[string(cleaned)] = struct{}{}
		}
	}

	if len(uniqueDomains) == 0 {
		return
	}

	// ----------------------------------------------------------------------
	// Stage 3: Concurrent Map Extraction & String Reversal
	// Reversing domain strings (e.g., com.example) allows alphabetical sorts
	// to group parents directly above their subdomains.
	// ----------------------------------------------------------------------
	revList := make([]string, 0, len(uniqueDomains))
	for dom := range uniqueDomains {
		revList = append(revList, dom)
	}

	// Leverage multi-core CPUs by sharding the string reversal workload
	numWorkers := runtime.NumCPU()
	var wg sync.WaitGroup
	chunkSize := (len(revList) + numWorkers - 1) / numWorkers

	for i := 0; i < numWorkers; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(revList) {
			end = len(revList)
		}
		if start >= end {
			break
		}

		wg.Add(1)
		// Process assigned slice segment completely lock-free
		go func(s, e int) {
			defer wg.Done()
			for j := s; j < e; j++ {
				revList[j] = reverseASCII(revList[j])
			}
		}(start, end)
	}
	wg.Wait()

	// ----------------------------------------------------------------------
	// Stage 4: TLD-Down Sort
	// Standard ascending sort on reversed domains natively groups them.
	// ----------------------------------------------------------------------
	sort.Strings(revList)

	// ----------------------------------------------------------------------
	// Stage 5: Deduplication & Buffered Output
	// We iterate over the sorted array. If the current domain starts with
	// the 'lastKept' parent domain + a dot, it is a redundant subdomain.
	// ----------------------------------------------------------------------
	outWriter := bufio.NewWriterSize(os.Stdout, 1024*1024) // 1MB Output Buffer
	defer outWriter.Flush()

	var lastKept string
	for _, curr := range revList {
		// Example: lastKept = "moc.elpmaxe"
		//          curr     = "moc.elpmaxe.bus" -> (Subdomain: drop)
		//          curr     = "moc.elpmaxe-rehto" -> (Different domain: keep)
		if len(lastKept) > 0 && len(curr) > len(lastKept) {
			// Fast prefix comparison
			if curr[:len(lastKept)] == lastKept && curr[len(lastKept)] == dotChar {
				continue // Strictly falls under the last parent; skip
			}
		}

		// Re-reverse the string back to normal and write to the output buffer
		outWriter.WriteString(reverseASCII(curr))
		outWriter.WriteByte('\n')

		lastKept = curr
	}
}

// --------------------------------------------------------------------------
// Helper Functions
// --------------------------------------------------------------------------

// isValidDomain performs high-speed byte-level validation without regex overhead.
func isValidDomain(b []byte, lessStrict bool) bool {
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

// reverseASCII performs a high-speed reverse of an ASCII string safely.
// Note: Domain payloads are strictly ASCII enforced by the isValidDomain logic.
func reverseASCII(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		b[len(s)-1-i] = s[i]
	}
	return string(b)
}

