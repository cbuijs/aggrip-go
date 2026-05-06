/*
==========================================================================
Filename: domsort/main.go
Version: 1.20.0-20260506
Date: 2026-05-06 16:26 CEST
Description: High-performance segmented layout-preserving domain sort.
             Reads streams, identifies logical sections based on non-domain
             text, and strictly validates/sorts domains within those sections
             while preserving document layout.
             Supports TLD-first (default) or Alphabetical sorting,
             less-strict validation ('_', '*'), and reverse sorting.

Update Trail:
  - 1.20.0 (2026-05-06): Added global `--undup` (-u) feature strictly removing 
                         subdomains and exact duplicates globally.
                         Added alphabetical segment sorting natively when `-a` 
                         is toggled, grouping and alphabetizing entire blocks.
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
	"sort"
	"strings"

	"aggrip-go/shared"
)

// Global Flags defining core operations and behaviors.
// Standardized across the aggrip-go suite for uniformity.
var (
	inputFile    string
	outputFile   string
	lessStrict   bool
	undupDomains bool
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

	flag.BoolVar(&undupDomains, "undup", false, "Unduplicate domains by removing subdomains if their parent exists globally")
	flag.BoolVar(&undupDomains, "u", false, "Short for --undup")

	flag.BoolVar(&reverseSort, "reverse", false, "Sort domains in reverse order")
	flag.BoolVar(&reverseSort, "r", false, "Short for --reverse")

	flag.BoolVar(&alphabetical, "alphabetical", false, "Sort domains (and segmented layout blocks) strictly alphabetically instead of TLD-down")
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
		fmt.Fprintf(os.Stderr, "  -u, --undup              Unduplicate domains by removing subdomains if their parent exists globally\n")
		fmt.Fprintf(os.Stderr, "  -a, --alphabetical       Sort domains (and segmented layout blocks) strictly alphabetically instead of TLD-down\n")
		fmt.Fprintf(os.Stderr, "  -r, --reverse            Sort domains in reverse order\n")
		fmt.Fprintf(os.Stderr, "  -v, --verbose            Enable verbose output to STDERR\n")
		fmt.Fprintf(os.Stderr, "  -V, --version            Show version information and exit\n")
		fmt.Fprintf(os.Stderr, "  -h, --help               Show this help message\n")
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  domsort -i mixed_list.txt -o sorted_list.txt -l -u -a -r -v\n")
	}
}

// BlockItem represents a single verified domain line bound to its original 
// raw string structure and a highly optimized sorting key.
type BlockItem struct {
	SortKey string
	Domain  string // Used strictly for parent/child relationship deduplication
	Line    string
}

// Section logically encapsulates a grouping of layout formatting strings (comments) 
// and the immediate sequence of parsed domains beneath them.
type Section struct {
	LayoutLines []string
	Domains     []BlockItem
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
	// Stage 2: Buffered Memory Stream & Layout Preservation Parsing 
	// Buffers complete dataset identically mapping strings securely.
	// ----------------------------------------------------------------------
	logMsg("Streaming payload via buffered memory scanner...")

	// Inject centralized strict 1MB buffer explicitly resolving file faults natively.
	scanner := shared.NewScanner(inStream)

	var sections []Section
	currentSection := Section{
		LayoutLines: make([]string, 0, 5),
		Domains:     make([]BlockItem, 0, 1000), // Pre-allocated limit bypassing reallocation thrashing
	}

	linesProcessed := 0

	for scanner.Scan() {
		linesProcessed++
		originalLine := scanner.Text()
		trimmedLine := strings.TrimSpace(originalLine)
		
		isDomainLine := false

		// Validate and parse actively detected domain strings directly.
		if trimmedLine != "" {
			// Pull the absolute first string token skipping heavy array allocations.
			firstToken := extractFirstToken(trimmedLine)
			candidate := strings.ToLower(firstToken)

			// Inline structural validation to bypass slow regular expressions safely.
			if shared.IsValidDomain([]byte(candidate), lessStrict) {
				sortKey := computeSortKey(candidate, alphabetical)
				currentSection.Domains = append(currentSection.Domains, BlockItem{
					SortKey: sortKey,
					Domain:  candidate,
					Line:    originalLine,
				})
				isDomainLine = true
			}
		}

		// Section Boundary Discovered: Non-domain line triggers new allocation bounds securely.
		if !isDomainLine {
			// Flush populated domain bounds into slice array explicitly separating new layout headers.
			if len(currentSection.Domains) > 0 {
				sections = append(sections, currentSection)
				currentSection = Section{
					LayoutLines: make([]string, 0, 5),
					Domains:     make([]BlockItem, 0, 1000),
				}
			}
			currentSection.LayoutLines = append(currentSection.LayoutLines, originalLine)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input stream: %v\n", err)
		os.Exit(1)
	}

	// Trap residual block mappings explicitly catching trailing EOF data.
	if len(currentSection.LayoutLines) > 0 || len(currentSection.Domains) > 0 {
		sections = append(sections, currentSection)
	}

	// ----------------------------------------------------------------------
	// Stage 3: Global Domain Deduplication (Optional)
	// Triggers rigorous O(N log N) deduplication traversing every segment natively.
	// ----------------------------------------------------------------------
	if undupDomains {
		logMsg("Executing global O(N log N) deduplication across all segments...")
		uniqueMap := make(map[string]struct{}, linesProcessed)
		
		// Unpack unified matrix pulling strictly validated pure domain bounds
		for _, sec := range sections {
			for _, item := range sec.Domains {
				uniqueMap[item.Domain] = struct{}{}
			}
		}
		
		// Reverses strings directly driving log(N) sequential parity matches explicitly
		revList := make([]string, 0, len(uniqueMap))
		for dom := range uniqueMap {
			revList = append(revList, shared.ReverseASCII(dom))
		}
		
		logMsg("Sorting reversed domains for parent/child evaluation...")
		sort.Strings(revList)
		
		activeDomains := make(map[string]struct{}, len(uniqueMap))
		var lastKept string
		droppedCount := 0
		
		// Assess sibling relationships dropping nested targets identical to parent arrays natively
		for _, curr := range revList {
			if len(lastKept) > 0 && len(curr) > len(lastKept) {
				if curr[:len(lastKept)] == lastKept && curr[len(lastKept)] == '.' {
					droppedCount++
					continue
				}
			}
			activeDomains[shared.ReverseASCII(curr)] = struct{}{}
			lastKept = curr
		}
		
		logMsg("Global undup dropped %d redundant subdomains. Preserving %d apex domains.", droppedCount, len(activeDomains))
		
		// Eradicate eliminated strings safely matching surviving tokens to source layout bounds
		for i := range sections {
			var filtered []BlockItem
			for _, item := range sections[i].Domains {
				if _, exists := activeDomains[item.Domain]; exists {
					filtered = append(filtered, item)
					// Actively delete token strictly preventing exact duplicates bleeding into secondary blocks
					delete(activeDomains, item.Domain) 
				}
			}
			sections[i].Domains = filtered
		}
	}

	// ----------------------------------------------------------------------
	// Stage 4: Layout-Aware Block Alphabetical Sorting (Optional)
	// Restructures entire document segments alphabetically based on header content natively.
	// ----------------------------------------------------------------------
	if alphabetical {
		logMsg("Alphabetical segment sorting active. Organizing layout bounds...")
		
		// Evaluates layout formatting cleanly resolving symbols enabling pure alphabetical targeting
		cleanLayoutKey := func(lines []string) string {
			s := strings.Join(lines, " ")
			s = strings.ReplaceAll(s, "#", "")
			s = strings.ReplaceAll(s, "!", "")
			s = strings.ReplaceAll(s, "/", "")
			return strings.ToLower(strings.TrimSpace(s))
		}

		slices.SortFunc(sections, func(a, b Section) int {
			keyA := cleanLayoutKey(a.LayoutLines)
			keyB := cleanLayoutKey(b.LayoutLines)
			
			// Deterministic fallback executing domain sort bounds natively if layout headers perfectly match
			if keyA == keyB {
				var domA, domB string
				if len(a.Domains) > 0 { domA = a.Domains[0].SortKey }
				if len(b.Domains) > 0 { domB = b.Domains[0].SortKey }
				
				if domA == domB { return 0 }
				if reverseSort {
					if domA > domB { return -1 }
					return 1
				}
				if domA < domB { return -1 }
				return 1
			}
			
			if reverseSort {
				if keyA > keyB { return -1 }
				return 1
			}
			if keyA < keyB { return -1 }
			return 1
		})
	}

	// ----------------------------------------------------------------------
	// Stage 5: Domain Internal Segment Sorting
	// Resolves sequences rigidly enclosed within specific block boundaries natively.
	// ----------------------------------------------------------------------
	logMsg("Sorting domains within segmented bounds...")
	for i := range sections {
		slices.SortFunc(sections[i].Domains, func(a, b BlockItem) int {
			if a.SortKey == b.SortKey {
				return 0
			}
			if reverseSort {
				if a.SortKey > b.SortKey { return -1 }
				return 1
			}
			if a.SortKey < b.SortKey { return -1 }
			return 1
		})
	}

	// ----------------------------------------------------------------------
	// Stage 6: Formatted Array Output
	// Dumps organized structs directly flushing buffers efficiently to disk pipelines.
	// ----------------------------------------------------------------------
	logMsg("Exporting formatted arrays directly to output stream...")
	
	// Map disk writer directly wrapping limits centrally for extreme performance.
	outWriter := shared.NewWriter(outStream)
	defer outWriter.Flush()

	blocksFlushed := 0

	for _, sec := range sections {
		// Flush structural layout comments preserving formatting spaces cleanly
		for _, layout := range sec.LayoutLines {
			outWriter.WriteString(layout + "\n")
		}
		
		// Dump fully verified bounded domains directly
		if len(sec.Domains) > 0 {
			for _, item := range sec.Domains {
				outWriter.WriteString(item.Line + "\n")
			}
			blocksFlushed++
		}
	}

	logMsg("Layout preservation sort complete. Processed %d total lines across %d segmented blocks.", linesProcessed, blocksFlushed)
}

