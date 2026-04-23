/*
==========================================================================
Filename: aggrip/main.go
Version: v0.19-20260423
Date: 2026-04-23 11:29 CEST
Update Trail:
  - v0.19-20260423: Standardized CLI parameters across all tools. Adopted 
                    -v for verbose, -V for version, and -h for help.
  - v0.18-20260423: Standardized CLI parameters. Implemented double-dash
                    for long flags and single-dash for short flags. Added
                    customized flag.Usage output to expose all options clearly.
  - v0.17-20260423: Added command-line flags (-i, -o, -s, -v) to extend 
                    usability beyond standard UNIX pipes.
  - v0.16-20260423: Initial Go translation from aggrip.py. Implemented 
                    high-speed slice-based CIDR aggregation via net/netip.
Description: High-performance Go utility to aggregate IPs into a CIDR list.
             Reads a raw list of IP addresses and CIDR blocks and outputs 
             a merged, optimized CIDR list.
==========================================================================
*/

package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
)

// Define global variables for command-line flags.
var (
	inputFile   string
	outputFile  string
	strictMode  bool
	verbose     bool
	showVersion bool
)

// init registers the command-line flags before main() executes.
// Standardizes short (-x) and long (--xyz) formats across the suite.
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

// logMsg prints diagnostic messages to STDERR if verbose mode is active.
// Keeps standard output completely clean for pipeline chaining.
func logMsg(msg string, args ...any) {
	if verbose {
		fmt.Fprintf(os.Stderr, "[*] "+msg+"\n", args...)
	}
}

// main is the primary entry point for the pipeline application.
func main() {
	// Parse the command-line flags provided by the user.
	flag.Parse()

	// Handle version output and exit early if requested.
	if showVersion {
		fmt.Println("aggrip Go Edition - Version v0.19-20260423")
		os.Exit(0)
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

	// Pre-allocate memory arrays to handle up to 100,000 inputs without needing 
	// to dynamically resize slices, vastly improving ingestion throughput.
	v4Networks := make([]netip.Prefix, 0, 100000)
	v6Networks := make([]netip.Prefix, 0, 100000)

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

		// Skip empty lines to preserve CPU cycles.
		if line == "" {
			continue
		}

		// Parse the prefix. Passes the strictMode flag to control truncation behaviour.
		// If the text is garbage or an invalid format, it gracefully skips to the next iteration.
		prefix, err := parsePrefix(line, strictMode)
		if err != nil {
			continue
		}

		// Separate IPv4 and IPv6 arrays because they operate on completely 
		// disjoint mathematical boundaries and cannot be merged together.
		if prefix.Addr().Is4() {
			v4Networks = append(v4Networks, prefix)
		} else {
			v6Networks = append(v6Networks, prefix)
		}
	}

	// Catch any internal buffer errors from stream parsing.
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input stream: %v\n", err)
		os.Exit(1)
	}

	logMsg("Ingested %d valid prefixes from %d total lines", len(v4Networks)+len(v6Networks), linesProcessed)

	// --- Stage 3: Subnet Aggregation / Collapsing ---
	// Process IPv4 and IPv6 streams independently in memory.
	logMsg("Running O(N log N) aggregation stack algorithm...")
	mergedV4 := mergePrefixes(v4Networks)
	mergedV6 := mergePrefixes(v6Networks)

	logMsg("Aggregation complete. Final IPv4 size: %d, IPv6 size: %d", len(mergedV4), len(mergedV6))

	// --- Stage 4: Pipeline Output ---
	// Wrapping the output stream in a bufio.Writer drastically speeds up IPC streaming 
	// by batching sys calls to disk or STDOUT.
	writer := bufio.NewWriter(outStream)
	defer writer.Flush()

	for _, p := range mergedV4 {
		writer.WriteString(p.String() + "\n")
	}
	for _, p := range mergedV6 {
		writer.WriteString(p.String() + "\n")
	}
	logMsg("Pipeline execution finished successfully.")
}

// parsePrefix evaluates string inputs into zero-allocation netip.Prefix objects.
// If strict is true, it strictly enforces clean host boundaries.
// If strict is false, it automatically masks and truncates dirty host bits.
func parsePrefix(s string, strict bool) (netip.Prefix, error) {
	// 1. Try standard precise parsing first.
	p, err := netip.ParsePrefix(s)
	if err == nil {
		if strict {
			// In strict mode, if the prefix doesn't match its masked mathematical 
			// boundary, it means there are dirty host bits (e.g., 192.168.1.10/24).
			if p != p.Masked() {
				return netip.Prefix{}, fmt.Errorf("strict mode: dirty host bits in CIDR")
			}
			return p, nil
		}
		// In permissive mode, Masked() automatically zeroes out trailing host bits.
		return p.Masked(), nil
	}

	// 2. If strict mode is enabled, skip advanced heuristic string splitting.
	// We only check if it is a valid isolated IP address before returning the error.
	if strict {
		addr, errAddr := netip.ParseAddr(s)
		if errAddr == nil {
			return netip.PrefixFrom(addr, addr.BitLen()), nil
		}
		return netip.Prefix{}, err
	}

	// 3. Permissive parsing: Try explicitly extracting the IP and Mask integer.
	parts := strings.SplitN(s, "/", 2)
	if len(parts) == 2 {
		addr, err := netip.ParseAddr(parts[0])
		if err != nil {
			return netip.Prefix{}, err
		}

		bits, err := strconv.Atoi(parts[1])
		// Trap bounds limits (0-32 for IPv4, 0-128 for IPv6)
		if err != nil || bits < 0 || bits > addr.BitLen() {
			return netip.Prefix{}, fmt.Errorf("invalid prefix length constraint")
		}
		
		// Re-assemble and apply Masked() to truncate any dirty host bits left over.
		return netip.PrefixFrom(addr, bits).Masked(), nil
	}

	// 4. Fallback: Parse as a single, isolated IP Address (/32 or /128).
	addr, errAddr := netip.ParseAddr(s)
	if errAddr != nil {
		return netip.Prefix{}, errAddr
	}
	
	// Create a precise host-route prefix.
	return netip.PrefixFrom(addr, addr.BitLen()).Masked(), nil
}

// mergePrefixes runs an O(N log N) time-complexity operation to compress and merge
// redundant or contiguous CIDR subnets using a sorting-stack algorithm.
func mergePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) <= 1 {
		return prefixes
	}

	// Phase 1: Sort the prefix list
	// We sort primarily by the IP Address explicitly. If the addresses are identical, 
	// we sort by ascending Prefix Length (smaller number means larger logical network).
	// This exact sorting order inherently guarantees that encompassing parent subnets 
	// will always be evaluated BEFORE their nested children in the loop.
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
		if cmp := a.Addr().Compare(b.Addr()); cmp != 0 {
			return cmp
		}
		
		// Sort largest subnet (smallest mask) first if base IPs are completely identical
		if a.Bits() < b.Bits() {
			return -1
		}
		if a.Bits() > b.Bits() {
			return 1
		}
		return 0
	})

	// Phase 2: Prefix compression using a Slice as a LIFO stack
	// We reserve capacity equal to the input to prevent runtime memory relocation.
	res := make([]netip.Prefix, 0, len(prefixes))

	for _, p := range prefixes {
		// Run a collapse cycle aggressively against the Top-Of-Stack
		for len(res) > 0 {
			top := res[len(res)-1]

			// Scenario A: Total Eclipse (Subnet fully covered)
			// Because of the ascending bit sort, if `top` contains `p`'s starting address,
			// it completely encompasses the entirety of `p`. No action needed.
			if top.Contains(p.Addr()) {
				p = netip.Prefix{} // Marks prefix as nullified/handled
				break
			}

			// Scenario B: Adjacency (Merge Siblings into a Supernet)
			// If `top` and `p` share the exact same Prefix Size...
			if top.Bits() == p.Bits() && top.Bits() > 0 {
				// We project/calculate what their shared mathematical Supernet would be.
				super := netip.PrefixFrom(top.Addr(), top.Bits()-1).Masked()
				
				// If `top` sits at the exact start of the Supernet, AND the Supernet 
				// fully covers `p`'s starting address, they are perfect binary siblings.
				if super.Addr() == top.Addr() && super.Contains(p.Addr()) {
					// We successfully found a Supernet. We pop `top` off the stack, 
					// adopt the new `super` block as our target `p`, and cycle the 
					// loop again to see if the new Supernet can merge with the NEXT Top-Of-Stack.
					res = res[:len(res)-1]
					p = super
					continue
				}
			}

			// Condition C: No relationships matched, break inner loop to push to stack.
			break
		}

		// Ensure we don't push nullified prefixes
		if p.IsValid() {
			res = append(res, p)
		}
	}

	return res
}

