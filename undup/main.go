/*
==========================================================================
Filename: undup/main.go
Version: v0.19-20260423
Date: 2026-04-23 11:29 CEST
Description: Blazing fast binary-level domain deduplicator in Golang. 
             Removes redundant subdomains when parent domains exist in 
             the feed. Prioritizes low-latency and high-performance via
             bulk reads, zero-copy byte parsing, and parallel routines.
             Supports optional less-strict validation allowing '_' and '*'.

Changes/Fixes:
- v0.19 (2026-04-23): Standardized CLI arguments across the aggrip-go suite.
                      Added file I/O support (-i/-o) matching aggrip to drop 
                      the strict reliance on UNIX piping, + verbose modes.
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
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"sync"
)

// Global constants for fast-path stripping and validation boundaries.
const (
	trimBytes = " .\r\n"
	dotChar   = '.'
)

var (
	inputFile   string
	outputFile  string
	lessStrict  bool
	verbose     bool
	showVersion bool
)

func init() {
	// Standardize on double-dash long flags and single-dash short flags.
	flag.StringVar(&inputFile, "input", "", "Input file path (default: STDIN)")
	flag.StringVar(&inputFile, "i", "", "Short for --input")

	flag.StringVar(&outputFile, "output", "", "Output file path (default: STDOUT)")
	flag.StringVar(&outputFile, "o", "", "Short for --output")

	flag.BoolVar(&lessStrict, "less-strict", false, "Allow underscores (_) and asterisks (*) in domain names")
	flag.BoolVar(&lessStrict, "l", false, "Short for --less-strict")

	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output to STDERR")
	flag.BoolVar(&verbose, "v", false, "Short for --verbose")

	flag.BoolVar(&showVersion, "version", false, "Show version information and exit")
	flag.BoolVar(&showVersion, "V", false, "Short for --version")

	// Customize the usage output to cleanly reflect dual-flag suite standard.
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of undup:\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -i, --input <path>     Input file path (default: STDIN)\n")
		fmt.Fprintf(os.Stderr, "  -o, --output <path>    Output file path (default: STDOUT)\n")
		fmt.Fprintf(os.Stderr, "  -l, --less-strict      Allow underscores (_) and asterisks (*) in domain names\n")
		fmt.Fprintf(os.Stderr, "  -v, --verbose          Enable verbose output to STDERR\n")
		fmt.Fprintf(os.Stderr, "  -V, --version          Show version information and exit\n")
		fmt.Fprintf(os.Stderr, "  -h, --help             Show this help message\n")
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  undup -i mixed_domains.txt -o clean_domains.txt -l -v\n")
	}
}

// logMsg prints diagnostic messages to STDERR if verbose mode is active natively.
func logMsg(msg string, args ...any) {
	if verbose {
		fmt.Fprintf(os.Stderr, "[*] "+msg+"\n", args...)
	}
}

func main() {
	// ----------------------------------------------------------------------
	// Command-line flag execution & evaluation
	// ----------------------------------------------------------------------
	flag.Parse()

	if showVersion {
		fmt.Println("undup Go Edition - Version v0.19-20260423")
		os.Exit(0)
	}

	// ----------------------------------------------------------------------
	// Stage 1: Stream Configuration
	// Intercept and reroute file I/O streams safely before execution matrix.
	// ----------------------------------------------------------------------
	var inStream *os.File = os.Stdin
	if inputFile != "" {
		var err error
		inStream, err = os.Open(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening input file: %v\n", err)
			os.Exit(1)
		}
		defer inStream.Close()
		logMsg("Input stream bound to file: %s", inputFile)
	}

	var outStream *os.File = os.Stdout
	if outputFile != "" {
		var err error
		outStream, err = os.Create(outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer outStream.Close()
		logMsg("Output stream bound to file: %s", outputFile)
	}

	// ----------------------------------------------------------------------
	// Stage 2: Bulk Memory Read
	// Maximizes I/O throughput by reading the entire payload at once directly.
	// ----------------------------------------------------------------------
	logMsg("Reading payload into memory buffer...")
	rawData, err := io.ReadAll(inStream)
	if err != nil || len(rawData) == 0 {
		return
	}

	// ----------------------------------------------------------------------
	// Stage 3: Zero-Copy Parsing and Normalization
	// We use bytes.Split to process the buffer without allocating new strings
	// for every single line. We validate and deduplicate instantly via map.
	// ----------------------------------------------------------------------
	lines := bytes.Split(rawData, []byte{'\n'})
	uniqueDomains := make(map[string]struct{}, len(lines))

	for _, line := range lines {
		// Strip leading/trailing whitespaces, carriage returns, and dots cleanly.
		cleaned := bytes.Trim(line, trimBytes)
		if len(cleaned) == 0 {
			continue
		}

		// Fast-path inline ASCII lowercasing (avoids heavy strings.ToLower natively).
		for i := 0; i < len(cleaned); i++ {
			if cleaned[i] >= 'A' && cleaned[i] <= 'Z' {
				cleaned[i] += 32
			}
		}

		// Inline structural validation to bypass slow regular expressions safely.
		if isValidDomain(cleaned, lessStrict) {
			// Convert to string safely only after passing all checks directly.
			uniqueDomains[string(cleaned)] = struct{}{}
		}
	}

	if len(uniqueDomains) == 0 {
		return
	}

	logMsg("Parsed %d unique valid domains natively.", len(uniqueDomains))

	// ----------------------------------------------------------------------
	// Stage 4: Concurrent Map Extraction & String Reversal
	// Reversing domain strings (e.g., com.example) allows alphabetical sorts
	// to group parents directly above their subdomains perfectly.
	// ----------------------------------------------------------------------
	revList := make([]string, 0, len(uniqueDomains))
	for dom := range uniqueDomains {
		revList = append(revList, dom)
	}

	// Leverage multi-core CPUs by sharding the string reversal workload natively.
	numWorkers := runtime.NumCPU()
	var wg sync.WaitGroup
	chunkSize := (len(revList) + numWorkers - 1) / numWorkers

	logMsg("Executing concurrent string reversal shard operations across %d cores...", numWorkers)

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
		// Process assigned slice segment completely lock-free rapidly.
		go func(s, e int) {
			defer wg.Done()
			for j := s; j < e; j++ {
				revList[j] = reverseASCII(revList[j])
			}
		}(start, end)
	}
	wg.Wait()

	// ----------------------------------------------------------------------
	// Stage 5: TLD-Down Sort
	// Standard ascending sort on reversed domains natively groups them securely.
	// ----------------------------------------------------------------------
	logMsg("Sorting domains by reversed Top-Level paths...")
	sort.Strings(revList)

	// ----------------------------------------------------------------------
	// Stage 6: Deduplication & Buffered Output
	// We iterate over the sorted array. If the current domain starts with
	// the 'lastKept' parent domain + a dot, it is a redundant subdomain intrinsically.
	// ----------------------------------------------------------------------
	outWriter := bufio.NewWriterSize(outStream, 1024*1024) // 1MB Output Buffer
	defer outWriter.Flush()

	var lastKept string
	droppedCount := 0

	for _, curr := range revList {
		// Example: lastKept = "moc.elpmaxe"
		//          curr     = "moc.elpmaxe.bus" -> (Subdomain: drop)
		//          curr     = "moc.elpmaxe-rehto" -> (Different domain: keep)
		if len(lastKept) > 0 && len(curr) > len(lastKept) {
			// Fast prefix comparison natively.
			if curr[:len(lastKept)] == lastKept && curr[len(lastKept)] == dotChar {
				droppedCount++
				continue // Strictly falls under the last parent; skip instantly.
			}
		}

		// Re-reverse the string back to normal and write to the output buffer directly.
		outWriter.WriteString(reverseASCII(curr))
		outWriter.WriteByte('\n')

		lastKept = curr
	}

	logMsg("Deduplication complete. Dropped %d redundant subdomains natively.", droppedCount)
	logMsg("Exported %d clean parent apex domains.", len(uniqueDomains)-droppedCount)
}

// --------------------------------------------------------------------------
// Helper Functions
// --------------------------------------------------------------------------

// isValidDomain performs high-speed byte-level validation without regex overhead cleanly.
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
// Note: Domain payloads are strictly ASCII enforced by the isValidDomain logic intrinsically.
func reverseASCII(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		b[len(s)-1-i] = s[i]
	}
	return string(b)
}

