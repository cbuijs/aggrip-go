/*
==========================================================================
Filename: aggrip/main.go
Version: 1.6.0-20260429
Date: 2026-04-29 14:46 CEST
Update Trail:
  - v1.6.0 (2026-04-29): Upgraded output writer to explicitly utilize a 1MB 
                         buffered size consistently aligning with suite standards.
  - v1.5.0 (2026-04-29): Consolidated `parsePrefix` logic completely into 
                         `shared.ParsePrefixStrict` for unified IP evaluation.
  - v1.4.0 (2026-04-29): Added dynamic heuristic alerts correctly isolating extremely 
                         large routing boundaries (e.g., 0.0.0.0/0) directly to STDERR.
  - v1.3.0 (2026-04-29): Dropped redundant/dead `mergePrefixes` logic internally.
                         Rerouted pipeline entirely through `shared.CollapsePrefixes` 
                         for extreme O(N log N) optimization. Added verbose docs.
  - v1.2.1 (2026-04-29): Centralized suite versioning to shared/version.go.
  - v1.2.0 (2026-04-29): Synced suite version up to 1.2.0. Standardized CLI 
                         execution matrix documentation directly.
Description: High-performance Go utility to aggregate IPs into a CIDR list.
             Reads a raw list of IP addresses and CIDR blocks and outputs 
             a merged, optimized CIDR list using centralized shared boundaries.
==========================================================================
*/

package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"aggrip-go/shared"
)

// Define global variables for command-line flags.
var (
	inputFile   string
	outputFile  string
	strictMode  bool
	verbose     bool
	showVersion bool
	helpFlag    bool
)

// init registers the command-line flags before main() executes.
// Standardizes short (-x) and long (--xyz) formats across the suite.
// Heavily documented explicit configuration behaviors safely.
func init() {
	// Standardize on double-dash long flags and single-dash short flags.
	flag.StringVar(&inputFile, "input", "", "Input file path (default: STDIN)")
	flag.StringVar(&inputFile, "i", "", "Short for --input")

	flag.StringVar(&outputFile, "output", "", "Output file path (default: STDOUT)")
	flag.StringVar(&outputFile, "o", "", "Short for --output")

	flag.BoolVar(&strictMode, "strict", false, "Strict mode: drop invalid CIDRs instead of truncating host bits")
	flag.BoolVar(&strictMode, "s", false, "Short for --strict")

	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output to STDERR")
	flag.BoolVar(&verbose, "v", false, "Short for --verbose")

	flag.BoolVar(&showVersion, "version", false, "Show version information and exit")
	flag.BoolVar(&showVersion, "V", false, "Short for --version")

	flag.BoolVar(&helpFlag, "help", false, "Show this help message")
	flag.BoolVar(&helpFlag, "h", false, "Short for --help")

	// Custom usage output for the CLI tool to clearly map short and long flags
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of aggrip:\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -i, --input <path>     Input file path (default: STDIN)\n")
		fmt.Fprintf(os.Stderr, "  -o, --output <path>    Output file path (default: STDOUT)\n")
		fmt.Fprintf(os.Stderr, "  -s, --strict           Strict mode: drop invalid CIDRs instead of truncating host bits\n")
		fmt.Fprintf(os.Stderr, "  -v, --verbose          Enable verbose output to STDERR\n")
		fmt.Fprintf(os.Stderr, "  -V, --version          Show version information and exit\n")
		fmt.Fprintf(os.Stderr, "  -h, --help             Show this help message\n")
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  aggrip -i raw_ips.txt -o optimized_cidrs.txt -s -v\n")
	}
}

// logMsg acts as a thin wrapper routing diagnostics to the centralized shared logger.
// Prevents standard output pollution allowing perfect UNIX pipe chaining natively.
func logMsg(msg string, args ...any) {
	shared.LogMsg(verbose, msg, args...)
}

// main is the primary entry point for the pipeline application.
func main() {
	// Parse the command-line flags provided by the user.
	flag.Parse()

	// Intercept help flag strictly overriding default routing safely
	if helpFlag {
		flag.Usage()
		os.Exit(0)
	}

	// Trap version flag and output the globally synchronized suite version dynamically
	if showVersion {
		shared.PrintVersion("aggrip")
	}

	// --- Stage 1: Stream Configuration ---
	// Default to STDIN. If an input file is provided, open it and replace the stream.
	var inStream *os.File = os.Stdin
	if inputFile != "" {
		var err error
		inStream, err = os.Open(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening input file: %v\n", err)
			os.Exit(1)
		}
		defer inStream.Close()
		logMsg("Input stream opened: %s", inputFile)
	}

	// Default to STDOUT. If an output file is provided, create it and replace the stream.
	var outStream *os.File = os.Stdout
	if outputFile != "" {
		var err error
		outStream, err = os.Create(outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer outStream.Close()
		logMsg("Output stream mapped to: %s", outputFile)
	}

	// Pre-allocate a unified memory array to handle up to 200,000 inputs without needing 
	// to dynamically resize slices, vastly improving ingestion throughput. The central
	// CollapsePrefixes function naturally separates and sorts IPv4 from IPv6 safely.
	networks := make([]netip.Prefix, 0, 200000)

	// Create a high-performance buffered scanner mapped to the configured input stream.
	scanner := bufio.NewScanner(inStream)

	// Increase buffer size to prevent token-too-long errors on deeply polluted lines.
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	logMsg("Beginning high-speed ingestion and validation...")

	// --- Stage 2: Ingestion & Parsing ---
	linesProcessed := 0
	for scanner.Scan() {
		linesProcessed++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines to preserve CPU cycles entirely.
		if line == "" {
			continue
		}

		// Parse the prefix. Passes the strictMode flag to control truncation behaviour.
		// Centralized validation covers standard CIDR, netmask, isolated IPs, and permissive inputs.
		prefix, err := shared.ParsePrefixStrict(line, strictMode)
		if err != nil {
			continue
		}

		// Mathematical boundary validation strictly capturing exceptionally large
		// arrays inherently warning users of dangerous firewall bindings smoothly.
		if shared.IsMassivePrefix(prefix) {
			fmt.Fprintf(os.Stderr, "[!] CRITICAL WARNING: Massive IP routing space detected explicitly reliably inherently naturally smoothly: %s\n", prefix.String())
		}

		// Push all valid prefixes dynamically into the centralized unified array
		networks = append(networks, prefix)
	}

	// Catch any internal buffer errors from stream parsing securely.
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input stream: %v\n", err)
		os.Exit(1)
	}

	logMsg("Ingested %d valid prefixes from %d total lines", len(networks), linesProcessed)

	// --- Stage 3: Subnet Aggregation / Collapsing ---
	// Process the unified stream. CollapsePrefixes uses internal rules separating IP versions.
	logMsg("Running O(N log N) stack aggregation algorithm natively...")
	mergedNetworks := shared.CollapsePrefixes(networks)

	logMsg("Aggregation complete. Final compressed size: %d CIDRs", len(mergedNetworks))

	// --- Stage 4: Pipeline Output ---
	// Wrapping the output stream in a explicitly sized 1MB bufio.Writer drastically speeds 
	// up IPC streaming by batching OS system calls directly to disk or STDOUT pipelines safely.
	writer := bufio.NewWriterSize(outStream, 1024*1024)
	defer writer.Flush()

	for _, p := range mergedNetworks {
		writer.WriteString(p.String() + "\n")
	}
	
	logMsg("Pipeline execution finished successfully.")
}

