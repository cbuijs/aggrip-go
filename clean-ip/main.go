/*
==========================================================================
Filename: clean-ip/main.go
Version: 1.6.0-20260429
Date: 2026-04-29 14:46 CEST
Description: Enterprise-grade IP blocklist optimizer. High-speed Go port
             of clean-ip.py. Aggregates IPs, CIDRs, ranges. Cross-references
             against allowlists, collapses redundant subnets, performs
             mathematical hole-punching, and exports to firewall formats.

Changes:
- v1.6.0 (2026-04-29): Enhanced hole-punching boundary documentation explicitly.
- v1.4.0 (2026-04-29): Implemented dynamic IsMassivePrefix telemetry accurately 
                       flagging excessive CIDR boundaries directly explicitly securely.
- v1.3.0 (2026-04-29): Implemented bounded concurrency semaphore pool preventing 
                       catastrophic system file descriptor limit exhaustion. Added 
                       extensive inline documentation spanning entire pipeline runs.
- v1.2.1 (2026-04-29): Centralized suite versioning to shared/version.go.
- v1.2.0 (2026-04-29): Consolidated heavy IP mathematics into shared/ipmath.go
                       for major code-management improvements. Standardized CLI.
==========================================================================
*/

package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"

	"aggrip-go/shared"
)

// Options holds CLI configuration mapping directly to standard execution parameters
type Options struct {
	Output            string
	RangeSep          string
	OutBlocklist      string
	OutAllowlist      string
	OptimizeAllowlist bool
	SuppressComments  bool
	Strict            bool
	Verbose           bool
	ShowVersion       bool
	Help              bool
}

// logMsg acts as a thin wrapper routing diagnostics to the centralized shared logger.
// Prevents standard output pollution seamlessly guarding system pipelines securely.
func logMsg(verbose bool, msg string, args ...any) {
	shared.LogMsg(verbose, msg, args...)
}

// --------------------------------------------------------------------------
// High-Performance Parsing & Normalization Logic
// --------------------------------------------------------------------------

// fetchAndParse streams payloads directly from disk or HTTP into memory.
// Optimized: Processes line-by-line using shared.FetchStream avoiding allocations.
func fetchAndParse(source string, strict bool, verbose bool) ([]netip.Prefix, error) {
	logMsg(verbose, "Loading data from: %s", source)

	stream, err := shared.FetchStream(source)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	var networks []netip.Prefix
	scanner := bufio.NewScanner(stream)

	// Pre-allocate a 1MB buffer for processing massive blocklists with giant lines
	// explicitly neutralizing "token too long" faults natively.
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	// Custom tokenizer dropping all spaces, tabs, equal signs, and dashes natively.
	// This inherently merges spaced ranges (1.1 1.2) and dashed ranges (1.1-1.2)
	// into uniform adjacent array tokens without allocating new strings via ReplaceAll.
	tokenizeFunc := func(c rune) bool {
		return c == ' ' || c == '\t' || c == '-' || c == '='
	}

	for scanner.Scan() {
		rawLine := scanner.Text()

		// Strip comments instantly directly manipulating string views
		if idx := strings.IndexByte(rawLine, '#'); idx != -1 {
			rawLine = rawLine[:idx]
		}
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "!") {
			continue
		}

		tokens := strings.FieldsFunc(line, tokenizeFunc)

		for i := 0; i < len(tokens); {
			token := shared.StripZeroPadding(tokens[i])

			// Fast structural checks preventing the engine from applying expensive logic
			if !shared.IsIPHeuristic(token) {
				i++
				continue
			}

			isRange := false
			prefix, err := shared.ParsePrefixStrict(token, strict)

			// Lookahead for Range Summarization:
			// Because FieldsFunc stripped dashes, ranges naturally fall to token[i+1].
			// This completely circumvents complex spacing offset tracking natively.
			if !strings.ContainsRune(token, '/') && i+1 < len(tokens) {
				nextToken := shared.StripZeroPadding(tokens[i+1])

				startIP, err1 := netip.ParseAddr(token)
				endIP, err2 := netip.ParseAddr(nextToken)

				if err1 == nil && err2 == nil && startIP.Is4() == endIP.Is4() {
					// Cisco wildcard mask exception detection (e.g. 0.0.0.255) natively
					// strictly converting formats into proper unified standard metrics natively.
					if startIP.Is4() && strings.HasPrefix(nextToken, "0.") {
						parts := strings.Split(nextToken, ".")
						if len(parts) == 4 {
							var nmParts []string
							for _, p := range parts {
								val, _ := strconv.Atoi(p)
								nmParts = append(nmParts, strconv.Itoa(255-val))
							}
							netmaskStr := token + "/" + strings.Join(nmParts, ".")
							if ciscoPfx, err := shared.ParsePrefixStrict(netmaskStr, strict); err == nil {
								if shared.IsMassivePrefix(ciscoPfx) {
									fmt.Fprintf(os.Stderr, "[!] CRITICAL WARNING: Massive IP routing space detected in '%s': %s\n", source, ciscoPfx.String())
								}
								networks = append(networks, ciscoPfx)
								i += 2 // Jump the range
								isRange = true
							}
						}
					} else {
						// Standard IP range mathematical summarization natively translating ranges into CIDRs directly
						if startIP.Compare(endIP) > 0 {
							startIP, endIP = endIP, startIP
						}
						summarized := shared.SummarizeRange(startIP, endIP)
						for _, p := range summarized {
							if shared.IsMassivePrefix(p) {
								fmt.Fprintf(os.Stderr, "[!] CRITICAL WARNING: Massive IP routing space detected in '%s': %s\n", source, p.String())
							}
							networks = append(networks, p)
						}
						i += 2 // Jump the range
						isRange = true
					}
				}
			}

			// Push standalone verified blocks natively guarding against corrupt formats
			if !isRange {
				if err == nil {
					if shared.IsMassivePrefix(prefix) {
						fmt.Fprintf(os.Stderr, "[!] CRITICAL WARNING: Massive IP routing space detected in '%s': %s\n", source, prefix.String())
					}
					networks = append(networks, prefix)
				}
				i++
			}
		}
	}
	return networks, scanner.Err()
}

// --------------------------------------------------------------------------
// Firewall Matrix Formatter Block Generation Algorithms
// --------------------------------------------------------------------------

func formatNetwork(p netip.Prefix, fmtType string, rangeSep string) string {
	switch fmtType {
	case "netmask":
		bLen := shared.AddrBitLen(p.Addr())
		b := make([]byte, bLen/8)
		for i := 0; i < p.Bits(); i++ {
			b[i/8] |= 1 << (7 - (i % 8))
		}
		var maskStr string
		if p.Addr().Is4() {
			maskStr = netip.AddrFrom4(*(*[4]byte)(b)).String()
		} else {
			maskStr = netip.AddrFrom16(*(*[16]byte)(b)).String()
		}
		return p.Addr().String() + "/" + maskStr

	case "range":
		sep := "-"
		if rangeSep == "space" {
			sep = " "
		}
		return p.Addr().String() + sep + shared.LastAddr(p).String()

	case "cisco":
		bLen := shared.AddrBitLen(p.Addr())
		b := make([]byte, bLen/8)
		for i := p.Bits(); i < bLen; i++ {
			b[i/8] |= 1 << (7 - (i % 8))
		}
		var wcStr string
		if p.Addr().Is4() {
			wcStr = netip.AddrFrom4(*(*[4]byte)(b)).String()
		} else {
			wcStr = netip.AddrFrom16(*(*[16]byte)(b)).String()
		}
		return "deny ip " + p.Addr().String() + " " + wcStr + " any"

	case "iptables":
		return "-A INPUT -s " + p.String() + " -j DROP"

	case "mikrotik":
		return "add address=" + p.String() + " list=blocklist"

	case "padded":
		if p.Addr().Is4() {
			b := p.Addr().As4()
			return fmt.Sprintf("%03d.%03d.%03d.%03d/%d", b[0], b[1], b[2], b[3], p.Bits())
		}
		var buf bytes.Buffer
		b := p.Addr().As16()
		for i := 0; i < 16; i += 2 {
			if i > 0 {
				buf.WriteString(":")
			}
			buf.WriteString(fmt.Sprintf("%04x", uint16(b[i])<<8|uint16(b[i+1])))
		}
		return fmt.Sprintf("%s/%d", buf.String(), p.Bits())

	default: // cidr
		return p.String()
	}
}

func formatAllowNetwork(p netip.Prefix, fmtType string, rangeSep string) string {
	switch fmtType {
	case "cisco":
		base := formatNetwork(p, fmtType, rangeSep)
		return strings.Replace(base, "deny", "permit", 1)
	case "iptables":
		base := formatNetwork(p, fmtType, rangeSep)
		return strings.Replace(base, "DROP", "ACCEPT", 1)
	case "mikrotik":
		base := formatNetwork(p, fmtType, rangeSep)
		return strings.Replace(base, "blocklist", "allowlist", 1)
	}
	return formatNetwork(p, fmtType, rangeSep)
}

// --------------------------------------------------------------------------
// Core Logic Entry Point
// --------------------------------------------------------------------------

func main() {
	var opts Options
	var blocklists shared.StringSlice
	var allowlists shared.StringSlice

	// Register variables for double-dash configurations. Standardized short formats included.
	flag.Var(&blocklists, "blocklist", "Path(s) or URL(s) to the IP blocklist(s) (can specify multiple times)")
	flag.Var(&blocklists, "b", "Short for --blocklist")

	flag.Var(&allowlists, "allowlist", "Optional path(s) or URL(s) to the IP allowlist(s) (can specify multiple times)")
	flag.Var(&allowlists, "a", "Short for --allowlist")

	flag.StringVar(&opts.Output, "output", "cidr", "Output format (cidr, netmask, range, cisco, iptables, mikrotik, padded)")
	flag.StringVar(&opts.Output, "o", "cidr", "Short for --output")

	flag.StringVar(&opts.RangeSep, "range-sep", "dash", "Separator for range output (space, dash)")
	flag.StringVar(&opts.OutBlocklist, "out-blocklist", "", "File path to write the blocklist output")
	flag.StringVar(&opts.OutAllowlist, "out-allowlist", "", "File path to write the allowlist output")
	flag.BoolVar(&opts.OptimizeAllowlist, "optimize-allowlist", false, "Drop unused allowlist entries")
	flag.BoolVar(&opts.SuppressComments, "suppress-comments", false, "Suppress audit log comments")

	flag.BoolVar(&opts.Strict, "strict", false, "Strict mode: Reject CIDRs with dirty host bits")
	flag.BoolVar(&opts.Strict, "s", false, "Short for --strict")

	flag.BoolVar(&opts.Verbose, "verbose", false, "Verbose: Show progress on STDERR")
	flag.BoolVar(&opts.Verbose, "v", false, "Short for --verbose")

	flag.BoolVar(&opts.ShowVersion, "version", false, "Show version information and exit")
	flag.BoolVar(&opts.ShowVersion, "V", false, "Short for --version")

	flag.BoolVar(&opts.Help, "help", false, "Show this help message")
	flag.BoolVar(&opts.Help, "h", false, "Short for --help")

	// Custom formatted usage explicitly declaring standard flags across the suite
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of clean-ip:\n\n")
		fmt.Fprintf(os.Stderr, "Core Options:\n")
		fmt.Fprintf(os.Stderr, "  -b, --blocklist <path/url>     Path(s) or URL(s) to the IP blocklist(s) (Required, can specify multiple)\n")
		fmt.Fprintf(os.Stderr, "  -a, --allowlist <path/url>     Path(s) or URL(s) to the IP allowlist(s) (Optional, can specify multiple)\n")
		fmt.Fprintf(os.Stderr, "  -o, --output <format>          Output format (cidr, netmask, range, cisco, iptables, mikrotik, padded) (default \"cidr\")\n")
		fmt.Fprintf(os.Stderr, "      --range-sep <sep>          Separator for range output (space, dash) (default \"dash\")\n")
		fmt.Fprintf(os.Stderr, "      --out-blocklist <file>     File path to write the blocklist output\n")
		fmt.Fprintf(os.Stderr, "      --out-allowlist <file>     File path to write the allowlist output\n")
		fmt.Fprintf(os.Stderr, "      --optimize-allowlist       Drop unused allowlist entries\n")
		fmt.Fprintf(os.Stderr, "      --suppress-comments        Suppress audit log comments\n")
		fmt.Fprintf(os.Stderr, "  -s, --strict                   Strict mode: Reject CIDRs with dirty host bits\n")
		fmt.Fprintf(os.Stderr, "  -v, --verbose                  Verbose: Show progress on STDERR\n")
		fmt.Fprintf(os.Stderr, "  -V, --version                  Show version information and exit\n")
		fmt.Fprintf(os.Stderr, "  -h, --help                     Show this help message\n")
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  clean-ip -b drop1.txt -b drop2.txt -a allow.txt -o iptables --out-blocklist rules.v4 -v\n")
	}

	// Native flag parsing perfectly maps the stringSlice arguments natively.
	flag.Parse()

	// Strict override mapping bypassing pipeline cleanly safely.
	if opts.Help {
		flag.Usage()
		os.Exit(0)
	}

	// Trap version flag and output the globally synchronized suite version dynamically
	if opts.ShowVersion {
		shared.PrintVersion("clean-ip")
	}

	if len(blocklists) == 0 {
		fmt.Fprintf(os.Stderr, "Error: --blocklist / -b is required.\n")
		flag.Usage()
		os.Exit(1)
	}

	logMsg(opts.Verbose, "--- Stage 1 & 2: Concurrent Ingestion ---")

	var wg sync.WaitGroup
	var rawBlocks, rawAllows []netip.Prefix
	var muBlock, muAllow sync.Mutex

	// Bounded semaphore pool cleanly limiting max active I/O workers safely.
	// Prevents network timeouts, resource thrashing, and OS limits natively.
	maxWorkers := 20
	sem := make(chan struct{}, maxWorkers)

	for _, source := range blocklists {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			sem <- struct{}{} // Lock execution token exclusively
			defer func() { <-sem }() // Clean release execution token inherently
			
			nets, err := fetchAndParse(s, opts.Strict, opts.Verbose)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading blocklist '%s': %v\n", s, err)
				return
			}
			
			muBlock.Lock()
			rawBlocks = append(rawBlocks, nets...)
			muBlock.Unlock()
		}(source)
	}

	// Employ identical bounds targeting large allowlist configurations safely.
	for _, source := range allowlists {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			
			nets, err := fetchAndParse(s, opts.Strict, opts.Verbose)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading allowlist '%s': %v\n", s, err)
				return
			}
			
			muAllow.Lock()
			rawAllows = append(rawAllows, nets...)
			muAllow.Unlock()
		}(source)
	}

	wg.Wait()

	logMsg(opts.Verbose, "--- Stage 3: Aggregating & Collapsing Subnets ---")
	// High speed array mapping inherently compressing identical parent paths cleanly.
	collapsedBlocks := shared.CollapsePrefixes(rawBlocks)
	collapsedAllows := shared.CollapsePrefixes(rawAllows)

	logMsg(opts.Verbose, "--- Stage 4: Cross-Referencing & Hole Punching ---")

	var filteredBlocks []netip.Prefix
	usedAllows := make(map[netip.Prefix]bool)
	var removedLog []string

	// Type matrix exclusively tracking hole-punch exceptions inherently directly
	type Hole struct{ allow, block netip.Prefix }
	var punchedHoles []Hole

	statsAllowlisted := 0
	statsHoles := 0

	// Pass 1: Total Eclipse Validation Phase.
	// Instantly invalidates block nodes entirely covered by explicitly allowed targets.
	// If a blocklist assigns 192.168.1.0/24, and the allowlist specifies 192.168.0.0/16,
	// the entire blocked subnet is explicitly eclipsed and dropped natively in O(1).
	for _, block := range collapsedBlocks {
		isAllowed := false
		for _, allow := range collapsedAllows {
			if block.Addr().Is4() == allow.Addr().Is4() && allow.Contains(block.Addr()) && allow.Bits() <= block.Bits() {
				usedAllows[allow] = true
				isAllowed = true
				if !opts.SuppressComments {
					removedLog = append(removedLog, fmt.Sprintf("# %s - Removed because allowlisted by encompassing subnet %s", block, allow))
				}
				statsAllowlisted++
				break
			}
		}
		if !isAllowed {
			filteredBlocks = append(filteredBlocks, block)
		}
	}

	// Pass 2: Mathematical Hole Punching internally safely bypassing allow overlaps natively.
	// If a blocklist assigns 192.168.0.0/16, but the allowlist exempts 192.168.1.0/24,
	// this engine recursively bisects the supernet (using binary Halve operations) creating 
	// a perfectly calculated array of adjacent CIDR blocks safely routing entirely around 
	// the exclusion hole without causing firewall configuration bypass leakage natively.
	var finalBlocks []netip.Prefix
	for _, block := range filteredBlocks {
		currentPieces := []netip.Prefix{block}

		for _, allow := range collapsedAllows {
			if allow.Addr().Is4() != block.Addr().Is4() {
				continue
			}
			var nextPieces []netip.Prefix
			for _, piece := range currentPieces {
				if piece.Contains(allow.Addr()) && piece.Bits() < allow.Bits() {
					usedAllows[allow] = true
					statsHoles++
					if !opts.SuppressComments {
						punchedHoles = append(punchedHoles, Hole{allow, block})
					}
					// Sub-shard the CIDR array mapping directly excluding allowed IPs dynamically
					nextPieces = append(nextPieces, shared.ExcludePrefix(piece, allow)...)
				} else {
					nextPieces = append(nextPieces, piece)
				}
			}
			currentPieces = nextPieces
		}
		finalBlocks = append(finalBlocks, currentPieces...)
	}

	// Final cleanup matrix explicitly compressing fractured arrays natively cleanly
	finalBlocks = shared.CollapsePrefixes(finalBlocks)

	var finalAllows []netip.Prefix
	var removedAllowsLog []string

	for _, allow := range collapsedAllows {
		if !opts.OptimizeAllowlist || usedAllows[allow] {
			finalAllows = append(finalAllows, allow)
		} else if !opts.SuppressComments {
			removedAllowsLog = append(removedAllowsLog, fmt.Sprintf("# %s - Removed from allowlist because it is unused", allow))
		}
	}

	logMsg(opts.Verbose, "--- Stage 5: Exporting Formats ---")

	var outB io.Writer = os.Stdout
	if opts.OutBlocklist != "" {
		f, err := os.Create(opts.OutBlocklist)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing blocklist: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		outB = f
	}

	// Wrap targets with 1MB buffered writers to maximize I/O performance massively.
	// Minimizes GC allocations bypassing system interrupt loads explicitly.
	bwBlock := bufio.NewWriterSize(outB, 1024*1024)
	defer bwBlock.Flush()

	if opts.OutAllowlist != "" {
		f, err := os.Create(opts.OutAllowlist)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing allowlist: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()

		bwAllow := bufio.NewWriterSize(f, 1024*1024)
		for _, net := range finalAllows {
			bwAllow.WriteString(formatAllowNetwork(net, opts.Output, opts.RangeSep) + "\n")
		}
		bwAllow.Flush()
	}

	// Prepend removed audit logs strictly to the top of configured payload blocks natively
	if !opts.SuppressComments {
		for _, item := range removedLog {
			bwBlock.WriteString(item + "\n")
		}
		for _, item := range removedAllowsLog {
			bwBlock.WriteString(item + "\n")
		}
	}

	// Inline stream struct to guarantee specific placement during output sequence natively.
	// Specifically protects exception comments routing immediately above their relevant networks.
	type StreamItem struct {
		isIPv4 bool
		ip     netip.Addr
		bits   int
		isRule bool
		str    string
	}
	var stream []StreamItem

	for _, net := range finalBlocks {
		stream = append(stream, StreamItem{
			isIPv4: net.Addr().Is4(),
			ip:     net.Addr(),
			bits:   net.Bits(),
			isRule: true,
			str:    formatNetwork(net, opts.Output, opts.RangeSep),
		})
	}

	for _, h := range punchedHoles {
		comment := fmt.Sprintf("# %s - Punched mathematical exception hole inside %s", h.allow, h.block)
		stream = append(stream, StreamItem{
			isIPv4: h.allow.Addr().Is4(),
			ip:     h.allow.Addr(),
			bits:   h.allow.Bits(),
			isRule: false,
			str:    comment,
		})
	}

	slices.SortFunc(stream, func(a, b StreamItem) int {
		if a.isIPv4 != b.isIPv4 {
			if a.isIPv4 {
				return -1
			}
			return 1
		}
		if cmp := a.ip.Compare(b.ip); cmp != 0 {
			return cmp
		}
		if a.bits != b.bits {
			return a.bits - b.bits
		}
		// Force comments (isRule=false) directly above the impacted rule reliably.
		if a.isRule != b.isRule {
			if !a.isRule {
				return -1
			}
			return 1
		}
		return 0
	})

	for _, item := range stream {
		bwBlock.WriteString(item.str + "\n")
	}

	if opts.Verbose {
		logMsg(true, "========== OPTIMIZATION STATS ==========")
		logMsg(true, "Total Blocks Parsed         : %d", len(rawBlocks))
		logMsg(true, "Collapsed Block Subnets     : %d", len(collapsedBlocks))
		logMsg(true, "Removed (Allowlisted)       : %d", statsAllowlisted)
		logMsg(true, "Holes Punched (Exclusions)  : %d", statsHoles)
		logMsg(true, "----------------------------------------")
		logMsg(true, "Final Active Block CIDRs    : %d", len(finalBlocks))
		if opts.OutAllowlist != "" {
			logMsg(true, "Exported Allowlist CIDRs    : %d", len(finalAllows))
		}
		logMsg(true, "========================================")
	}
}

