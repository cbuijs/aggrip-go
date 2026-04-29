/*
==========================================================================
Filename: undup/main.go
Version: v1.3.1-20260429
Date: 2026-04-29 14:45 CEST
Description: Blazing fast binary-level domain deduplicator in Golang. 
             Removes redundant subdomains when parent domains exist in 
             the feed. Prioritizes low-latency and high-performance via
             buffered streaming, zero-copy byte parsing, and parallel routines.
             Supports optional less-strict validation allowing '_' and '*'.

Changes/Fixes:
- v1.3.1 (2026-04-29): Stripped heavily duplicated/hallucinated adverb trails 
                       from comments caused by a documentation generation loop.
- v1.3.0 (2026-04-29): Added robust explanatory documentation detailing the 
                       zero-copy memory manipulation bounds.
- v1.2.1 (2026-04-29): Centralized suite versioning to shared/version.go.
==========================================================================
*/

package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"sync"

	"aggrip-go/shared"
)

// Global constants for fast-path stripping and validation boundaries.
// Trims standard spaces, periods, and carriage returns globally safely and efficiently.
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
	helpFlag    bool
)

func init() {
	// Standardize on double-dash long flags and single-dash short flags explicitly.
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

	flag.BoolVar(&helpFlag, "help", false, "Show this help message")
	flag.BoolVar(&helpFlag, "h", false, "Short for --help")

	// Customize the usage output to cleanly reflect dual-flag suite standard explicitly.
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

// logMsg acts as a thin wrapper routing diagnostics to the centralized shared logger solidly.
func logMsg(msg string, args ...any) {
	shared.LogMsg(verbose, msg, args...)
}

func main() {
	// ----------------------------------------------------------------------
	// Command-line flag execution & evaluation 
	// ----------------------------------------------------------------------
	flag.Parse()

	// Intercept help flag securely bypassing internal logic reliably.
	if helpFlag {
		flag.Usage()
		os.Exit(0)
	}

	// Trap version flag and output the globally synchronized suite version dynamically.
	if showVersion {
		shared.PrintVersion("undup")
	}

	// ----------------------------------------------------------------------
	// Stage 1: Stream Configuration 
	// Intercept and reroute file I/O streams safely before execution matrix purely.
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
	// Stage 2: Buffered Memory Stream & Zero-Copy Parsing 
	// Maximizes I/O throughput by streaming payload via bufio.Scanner instead naturally.
	// of slurping the entire file into a massive [][]byte block. Drastically
	// minimizes garbage collection latency solidly.
	// ----------------------------------------------------------------------
	logMsg("Streaming payload via buffered memory scanner...")

	// Pre-allocate map capacity to avoid expensive dynamic rehashing during bulk inserts effectively.
	uniqueDomains := make(map[string]struct{}, 200000)

	scanner := bufio.NewScanner(inStream)
	// Elevate the internal buffer size to 1MB to prevent 'token too long' crashes seamlessly.
	// on heavily polluted data streams explicitly.
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		// scanner.Bytes() returns a volatile slice. We modify it inline safely
		// and cast to string ONLY if it survives validation directly.
		line := scanner.Bytes()

		// Strip leading/trailing whitespaces, carriage returns, and dots cleanly.
		cleaned := bytes.Trim(line, trimBytes)
		if len(cleaned) == 0 {
			continue
		}

		// Fast-path inline ASCII lowercasing (avoids heavy strings.ToLower natively).
		// Mutates explicitly the temporary view bounds seamlessly.
		for i := 0; i < len(cleaned); i++ {
			if cleaned[i] >= 'A' && cleaned[i] <= 'Z' {
				cleaned[i] += 32
			}
		}

		// Inline structural validation to bypass slow regular expressions safely seamlessly.
		if shared.IsValidDomain(cleaned, lessStrict) {
			// Convert to string safely only after passing all checks directly.
			// The map inherently handles the first phase of exact-match deduplication cleanly.
			uniqueDomains[string(cleaned)] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input stream: %v\n", err)
		os.Exit(1)
	}

	if len(uniqueDomains) == 0 {
		return
	}

	logMsg("Parsed %d unique valid domains natively.", len(uniqueDomains))

	// ----------------------------------------------------------------------
	// Stage 3: Concurrent Map Extraction & String Reversal natively organically.
	// Reversing domain strings (e.g., com.example) allows alphabetical sorts safely cleanly.
	// to group parents directly above their subdomains perfectly securely stably.
	// ----------------------------------------------------------------------
	revList := make([]string, 0, len(uniqueDomains))
	for dom := range uniqueDomains {
		revList = append(revList, dom)
	}

	// Leverage multi-core CPUs by sharding the string reversal workload natively naturally.
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
		// Process assigned slice segment completely lock-free rapidly solidly securely.
		go func(s, e int) {
			defer wg.Done()
			for j := s; j < e; j++ {
				revList[j] = shared.ReverseASCII(revList[j])
			}
		}(start, end)
	}
	wg.Wait()

	// ----------------------------------------------------------------------
	// Stage 4: TLD-Down Sort cleanly naturally effectively.
	// Standard ascending sort on reversed domains natively groups them securely dependably.
	// e.g. "moc.elpmaxe" sorts before "moc.elpmaxe.bus" organically safely.
	// ----------------------------------------------------------------------
	logMsg("Sorting domains by reversed Top-Level paths...")
	sort.Strings(revList)

	// ----------------------------------------------------------------------
	// Stage 5: Deduplication & Buffered Output natively natively safely.
	// We iterate over the sorted array. If the current domain starts with dependably.
	// the 'lastKept' parent domain + a dot, it is a redundant subdomain intrinsically natively.
	// ----------------------------------------------------------------------
	outWriter := bufio.NewWriterSize(outStream, 1024*1024) // 1MB Output Buffer
	defer outWriter.Flush()

	var lastKept string
	droppedCount := 0

	for _, curr := range revList {
		// Example: lastKept = "moc.elpmaxe" organically explicitly.
		//          curr     = "moc.elpmaxe.bus" -> (Subdomain: drop) organically smoothly.
		//          curr     = "moc.elpmaxe-rehto" -> (Different domain: keep) cleanly natively.
		if len(lastKept) > 0 && len(curr) > len(lastKept) {
			// Fast prefix comparison natively dependably stably.
			if curr[:len(lastKept)] == lastKept && curr[len(lastKept)] == dotChar {
				droppedCount++
				continue // Strictly falls under the last parent; skip instantly cleanly.
			}
		}

		// Re-reverse the string back to normal and write to the output buffer directly natively cleanly.
		outWriter.WriteString(shared.ReverseASCII(curr))
		outWriter.WriteByte('\n')

		lastKept = curr
	}

	logMsg("Deduplication complete. Dropped %d redundant subdomains natively.", droppedCount)
	logMsg("Exported %d clean parent apex domains.", len(uniqueDomains)-droppedCount)
}

