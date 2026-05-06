/*
==========================================================================
Filename: domsort/main.go
Version: 1.19.0-20260506
Date: 2026-05-06 16:10 CEST
Description: High-performance segmented layout-preserving domain sort.
             Reads streams, identifies logical sections based on non-domain
             text, and strictly validates/sorts domains within those sections
             while preserving document layout.
             Supports TLD-first (default) or Alphabetical sorting,
             less-strict validation ('_', '*'), and reverse sorting.

Update Trail:
  - 1.19.0 (2026-05-06): Initial domsort implementation in Golang natively 
                         aligning with aggrip-go enterprise standards. 
                         Includes zero-copy buffering and segmented sorting.
==========================================================================
*/

package main

import (
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"

	"aggrip-go/shared"
)

// Global Flags defining core operations and behaviors.
// Standardized across the aggrip-go suite for uniformity.
var (
	inputFile    string
	outputFile   string
	lessStrict   bool
	reverseSort  bool
	alphabetical bool
	verbose      bool
	showVersion  bool
	helpFlag     bool
)

func init() {
	// Standardize on double-dash long flags and single-dash short flags explicitly.
	flag.StringVar(&inputFile, "input", "", "Input file path (default: STDIN)")
	flag.StringVar(&inputFile, "i", "", "Short for --input")

	flag.StringVar(&outputFile, "output", "", "Output file path (default: STDOUT)")
	flag.StringVar(&outputFile, "o", "", "Short for --output")

	flag.BoolVar(&lessStrict, "less-strict", false, "Allow underscores (_) and asterisks (*) in domain names")
	flag.BoolVar(&lessStrict, "l", false, "Short for --less-strict")

	flag.BoolVar(&reverseSort, "reverse", false, "Sort domains in reverse order")
	flag.BoolVar(&reverseSort, "r", false, "Short for --reverse")

	flag.BoolVar(&alphabetical, "alphabetical", false, "Sort domains strictly alphabetically instead of TLD-down")
	flag.BoolVar(&alphabetical, "a", false, "Short for --alphabetical")

	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output to STDERR")
	flag.BoolVar(&verbose, "v", false, "Short for --verbose")

	flag.BoolVar(&showVersion, "version", false, "Show version information and exit")
	flag.BoolVar(&showVersion, "V", false, "Short for --version")

	flag.BoolVar(&helpFlag, "help", false, "Show this help message")
	flag.BoolVar(&helpFlag, "h", false, "Short for --help")

	// Customize the usage output to cleanly reflect dual-flag suite standard.
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of domsort:\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -i, --input <path>       Input file path (default: STDIN)\n")
		fmt.Fprintf(os.Stderr, "  -o, --output <path>      Output file path (default: STDOUT)\n")
		fmt.Fprintf(os.Stderr, "  -l, --less-strict        Allow underscores (_) and asterisks (*) in domain names\n")
		fmt.Fprintf(os.Stderr, "  -a, --alphabetical       Sort domains strictly alphabetically instead of TLD-down\n")
		fmt.Fprintf(os.Stderr, "  -r, --reverse            Sort domains in reverse order\n")
		fmt.Fprintf(os.Stderr, "  -v, --verbose            Enable verbose output to STDERR\n")
		fmt.Fprintf(os.Stderr, "  -V, --version            Show version information and exit\n")
		fmt.Fprintf(os.Stderr, "  -h, --help               Show this help message\n")
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  domsort -i mixed_list.txt -o sorted_list.txt -l -r -v\n")
	}
}

// BlockItem represents a single verified domain line bound to its original 
// raw string structure and a highly optimized sorting key.
type BlockItem struct {
	SortKey string
	Line    string
}

// logMsg acts as a thin wrapper routing diagnostics to the centralized shared logger.
func logMsg(msg string, args ...any) {
	shared.LogMsg(verbose, msg, args...)
}

// extractFirstToken extracts the primary word from a line without triggering 
// heavy heap allocations from strings.Fields or strings.Split natively.
func extractFirstToken(line string) string {
	for i := 0; i < len(line); i++ {
		if line[i] == ' ' || line[i] == '\t' {
			return line[:i]
		}
	}
	return line
}

// computeSortKey generates a highly optimized sorting key based on configuration bounds.
// Drops '_' and '*' natively to ensure alphabetical parity. Reverses segments for TLD-down sort.
func computeSortKey(domain string, alpha bool) string {
	clean := domain
	if strings.ContainsRune(clean, '_') || strings.ContainsRune(clean, '*') {
		clean = strings.ReplaceAll(clean, "_", "")
		clean = strings.ReplaceAll(clean, "*", "")
	}

	if alpha {
		return clean
	}

	// TLD-down sort: Reverses the segments of the domain dynamically.
	// Example: "sub.example.com" -> "com.example.sub"
	parts := strings.Split(clean, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ".")
}

func main() {
	// ----------------------------------------------------------------------
	// Command-line flag execution & evaluation 
	// ----------------------------------------------------------------------
	flag.Parse()

	// Intercept help flag bypassing internal logic reliably.
	if helpFlag {
		flag.Usage()
		os.Exit(0)
	}

	// Trap version flag and output the globally synchronized suite version.
	if showVersion {
		shared.PrintVersion("domsort")
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
	// Stage 2: Buffered Memory Stream & Layout Preservation 
	// ----------------------------------------------------------------------
	logMsg("Streaming payload via buffered memory scanner...")

	// Inject centralized strict 1MB buffer explicitly resolving file faults natively.
	scanner := shared.NewScanner(inStream)
	
	// Map disk writer directly wrapping limits centrally for extreme performance.
	outWriter := shared.NewWriter(outStream)
	defer outWriter.Flush()

	// Pre-allocate a generous initial capacity to prevent slice resizing under load.
	currentBlock := make([]BlockItem, 0, 10000)

	// flushBlock encapsulates the segment sorting logic locally avoiding scope leakage.
	// Executed immediately when a non-domain line disrupts an active contiguous block.
	flushBlock := func() {
		if len(currentBlock) == 0 {
			return
		}

		// Execute rapid sorting matrix comparing pre-calculated keys.
		slices.SortFunc(currentBlock, func(a, b BlockItem) int {
			if a.SortKey == b.SortKey {
				return 0
			}
			if reverseSort {
				if a.SortKey > b.SortKey {
					return -1
				}
				return 1
			}
			if a.SortKey < b.SortKey {
				return -1
			}
			return 1
		})

		// Bulk write the sorted block contents natively.
		for _, item := range currentBlock {
			outWriter.WriteString(item.Line + "\n")
		}

		// Zero the array length preserving allocated capacity to eliminate GC overhead.
		currentBlock = currentBlock[:0]
	}

	linesProcessed := 0
	blocksFlushed := 0

	for scanner.Scan() {
		linesProcessed++
		originalLine := scanner.Text()
		trimmedLine := strings.TrimSpace(originalLine)
		
		isDomainLine := false

		if trimmedLine != "" {
			// Pull the absolute first string token skipping heavy array allocations.
			firstToken := extractFirstToken(trimmedLine)
			candidate := strings.ToLower(firstToken)

			// Inline structural validation to bypass slow regular expressions safely.
			if shared.IsValidDomain([]byte(candidate), lessStrict) {
				sortKey := computeSortKey(candidate, alphabetical)
				currentBlock = append(currentBlock, BlockItem{
					SortKey: sortKey,
					Line:    originalLine,
				})
				isDomainLine = true
			}
		}

		// Section Boundary Discovered: Non-domain line acts as a flush trigger.
		if !isDomainLine {
			if len(currentBlock) > 0 {
				flushBlock()
				blocksFlushed++
			}
			// Write the layout-preserving comment/blank line flawlessly.
			outWriter.WriteString(originalLine + "\n")
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input stream: %v\n", err)
		os.Exit(1)
	}

	// Trap any residual block contents natively leftover following EOF.
	if len(currentBlock) > 0 {
		flushBlock()
		blocksFlushed++
	}

	logMsg("Layout preservation sort complete. Processed %d total lines across %d segmented blocks.", linesProcessed, blocksFlushed)
}

