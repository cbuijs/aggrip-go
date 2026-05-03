/*
==========================================================================
Filename: clean-ip/main.go
Version: 1.17.0-20260503
Date: 2026-05-03 18:30 CEST
Description: Enterprise-grade IP blocklist optimizer. High-speed Go port
             of clean-ip.py. Aggregates IPs, CIDRs, ranges. Cross-references
             against allowlists, collapses redundant subnets, performs
             mathematical hole-punching, and exports to firewall formats.

Changes:
- v1.17.0 (2026-05-03): Updated formatter to explicitly push audit comments for 
                        allowlist removals natively into the allowlist export file.
- v1.15.0 (2026-05-03): Introduced PreferBlocklist logic to symmetrically invert 
                        hole-punching and eclipse evaluation bounds. Allows 
                        blocklists to safely drop and fracture allowlist bounds.
- v1.12.0 (2026-04-29): Eliminated O(N) memory scale regressions securely by
                        pre-allocating output slices matching subset limits.
                        Eliminates deep GC pressure and copying.
- v1.11.0 (2026-04-29): Eliminated sync.Mutex and sync.WaitGroup contention 
                        bottlenecks during concurrent ingestion. Refactored 
                        to utilize strict lock-free channel fan-in arrays natively.
- v1.9.0 (2026-04-29): Deprecated scattered bufio configurations substituting
                       them cleanly with globally bounded shared.NewScanner 
                       and shared.NewWriter metrics natively.
- v1.8.0 (2026-04-29): Comprehensive cleanup of adverbs across all comments.
                       Regression tested. Memory limits evaluated and secured.
- v1.7.0 (2026-04-29): Fixed critical bufio.Scanner initialization regression 
                       by properly assigning capacity to the byte slice limit.
- v1.6.0 (2026-04-29): Enhanced hole-punching boundary documentation explicitly.
- v1.4.0 (2026-04-29): Implemented dynamic IsMassivePrefix telemetry accurately 
                       flagging excessive CIDR boundaries directly.
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
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"

	"aggrip-go/shared"
)

// Options holds CLI configuration mapping directly to standard execution parameters
type Options struct {
	Output            string
	RangeSep          string
	OutBlocklist      string
	OutAllowlist      string
	OptimizeAllowlist bool
	PreferBlocklist   bool
	SuppressComments  bool
	Strict            bool
	Verbose           bool
	ShowVersion       bool
	Help              bool
}

// logMsg acts as a thin wrapper routing diagnostics to the centralized shared logger.
// Prevents standard output pollution seamlessly guarding system pipelines.
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

	// Centralized scanner neutralizing "token too long" faults natively via 1MB memory bounds.
	scanner := shared.NewScanner(stream)

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
			// This circumvents complex spacing offset tracking.
			if !strings.ContainsRune(token, '/') && i+1 < len(tokens) {
				nextToken := shared.StripZeroPadding(tokens[i+1])

				startIP, err1 := netip.ParseAddr(token)
				endIP, err2 := netip.ParseAddr(nextToken)

				if err1 == nil && err2 == nil && startIP.Is4() == endIP.Is4() {
					// Cisco wildcard mask exception detection (e.g. 0.0.0.255)
					// strictly converting formats into proper unified standard metrics.
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
						// Standard IP range mathematical summarization translating ranges into CIDRs
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
	
	flag.BoolVar(&opts.PreferBlocklist, "prefer-blocklist", false, "Reverse default preference: Blocklist takes precedence over allowlist")
	flag.BoolVar(&opts.PreferBlocklist, "p", false, "Short for --prefer-blocklist")

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
		fmt.Fprintf(os.Stderr, "  -p, --prefer-blocklist         Reverse default preference: Blocklist takes precedence over allowlist\n")
		fmt.Fprintf(os.Stderr, "      --suppress-comments        Suppress audit log comments\n")
		fmt.Fprintf(os.Stderr, "  -s, --strict                   Strict mode: Reject CIDRs with dirty host bits\n")
		fmt.Fprintf(os.Stderr, "  -v, --verbose                  Verbose: Show progress on STDERR\n")
		fmt.Fprintf(os.Stderr, "  -V, --version                  Show version information and exit\n")
		fmt.Fprintf(os.Stderr, "  -h, --help                     Show this help message\n")
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  clean-ip -b drop1.txt -b drop2.txt -a allow.txt -o iptables -p --out-blocklist rules.v4 -v\n")
	}

	// Native flag parsing maps the stringSlice arguments.
	flag.Parse()

	// Strict override mapping bypassing pipeline cleanly safely.
	if opts.Help {
		flag.Usage()
		os.Exit(0)
	}

	// Trap version flag and output the globally synchronized suite version
	if opts.ShowVersion {
		shared.PrintVersion("clean-ip")
	}

	if len(blocklists) == 0 {
		fmt.Fprintf(os.Stderr, "Error: --blocklist / -b is required.\n")
		flag.Usage()
		os.Exit(1)
	}

	logMsg(opts.Verbose, "--- Stage 1 & 2: Concurrent Ingestion ---")

	// Advanced Concurrency: processList utilizes a lock-free channel fan-in pattern
	// bypassing slow sync.Mutex slice appendages for substantial performance gains.
	processList := func(list []string, listType string) []netip.Prefix {
		if len(list) == 0 {
			return nil
		}

		ch := make(chan []netip.Prefix, len(list))

		// Bounded semaphore pool limiting max active I/O workers securely.
		// Prevents network timeouts, resource thrashing, and OS limits.
		maxWorkers := 20
		if len(list) < maxWorkers {
			maxWorkers = len(list)
		}
		sem := make(chan struct{}, maxWorkers)

		for _, source := range list {
			go func(s string) {
				sem <- struct{}{} // Lock execution token exclusively
				
				nets, err := fetchAndParse(s, opts.Strict, opts.Verbose)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error reading %s '%s': %v\n", listType, s, err)
					ch <- nil
				} else {
					ch <- nets
				}
				
				<-sem // Clean release execution token inherently
			}(source)
		}

		var aggregated []netip.Prefix
		// Pull payloads lock-free from the channel synchronizing memory directly
		for i := 0; i < len(list); i++ {
			res := <-ch
			if res != nil {
				aggregated = append(aggregated, res...)
			}
		}
		close(ch)
		return aggregated
	}

	rawBlocks := processList(blocklists, "blocklist")
	rawAllows := processList(allowlists, "allowlist")

	logMsg(opts.Verbose, "--- Stage 3: Aggregating & Collapsing Subnets ---")
	// High speed array mapping inherently compressing identical parent paths.
	collapsedBlocks := shared.CollapsePrefixes(rawBlocks)
	collapsedAllows := shared.CollapsePrefixes(rawAllows)

	logMsg(opts.Verbose, "--- Stage 4: Cross-Referencing & Hole Punching ---")

	var removedLog []string
	var removedAllowsLog []string

	// Type matrix tracking symmetric hole-punch exceptions. Base is the target being split, Hole is the exclusion matrix.
	type Hole struct{ base, hole netip.Prefix }
	var punchedHoles []Hole

	statsEclipsed := 0
	statsHoles := 0

	var finalBlocks []netip.Prefix
	var finalAllows []netip.Prefix

	if !opts.PreferBlocklist {
		// --------------------------------------------------------------------------
		// Default Mode (Allowlist Priority): Allows destroy and fracture blocks natively.
		// --------------------------------------------------------------------------
		filteredBlocks := make([]netip.Prefix, 0, len(collapsedBlocks))
		usedAllows := make(map[netip.Prefix]bool)

		// Pass 1: Total Eclipse Validation Phase.
		// Instantly invalidates block nodes entirely covered by explicitly allowed targets.
		for _, block := range collapsedBlocks {
			isAllowed := false
			for _, allow := range collapsedAllows {
				if block.Addr().Is4() == allow.Addr().Is4() && allow.Contains(block.Addr()) && allow.Bits() <= block.Bits() {
					usedAllows[allow] = true
					isAllowed = true
					if !opts.SuppressComments {
						removedLog = append(removedLog, fmt.Sprintf("# %s - Removed from blocklist (Allowlisted by encompassing subnet %s)", block, allow))
					}
					statsEclipsed++
					break
				}
			}
			if !isAllowed {
				filteredBlocks = append(filteredBlocks, block)
			}
		}

		// Pass 2: Mathematical Hole Punching to safely bypass allowlist overlaps.
		// Bypasses allowlist intersections structurally by recursively fracturing the block supernet safely.
		finalBlocks = make([]netip.Prefix, 0, len(filteredBlocks))
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
							punchedHoles = append(punchedHoles, Hole{base: block, hole: allow})
						}
						// Sub-shard the CIDR array dynamically excluding allowed IPs
						nextPieces = append(nextPieces, shared.ExcludePrefix(piece, allow)...)
					} else {
						nextPieces = append(nextPieces, piece)
					}
				}
				currentPieces = nextPieces
			}
			finalBlocks = append(finalBlocks, currentPieces...)
		}
		finalBlocks = shared.CollapsePrefixes(finalBlocks)

		// Final allowlist optimization checks natively dropping unused configurations
		finalAllows = make([]netip.Prefix, 0, len(collapsedAllows))
		for _, allow := range collapsedAllows {
			if !opts.OptimizeAllowlist || usedAllows[allow] {
				finalAllows = append(finalAllows, allow)
			} else if !opts.SuppressComments {
				removedAllowsLog = append(removedAllowsLog, fmt.Sprintf("# %s - Removed from allowlist (Unused)", allow))
			}
		}

	} else {
		// --------------------------------------------------------------------------
		// Reversed Mode (Blocklist Priority): Blocks destroy and fracture allows natively.
		// --------------------------------------------------------------------------
		filteredAllows := make([]netip.Prefix, 0, len(collapsedAllows))

		// Pass 1: Total Eclipse Validation Phase.
		// Completely invalidates allowlist domains entirely engulfed inside blocklist scopes securely.
		for _, allow := range collapsedAllows {
			isBlocked := false
			for _, block := range collapsedBlocks {
				if allow.Addr().Is4() == block.Addr().Is4() && block.Contains(allow.Addr()) && block.Bits() <= allow.Bits() {
					isBlocked = true
					if !opts.SuppressComments {
						removedAllowsLog = append(removedAllowsLog, fmt.Sprintf("# %s - Removed from allowlist (Eclipsed by blocklist subnet %s)", allow, block))
					}
					statsEclipsed++
					break
				}
			}
			if !isBlocked {
				filteredAllows = append(filteredAllows, allow)
			}
		}

		// Pass 2: Mathematical Hole Punching to enforce block precedence over conflicting allows.
		// Splits explicitly spanning allow matrices entirely around overlapping block configurations accurately.
		finalAllowsTemp := make([]netip.Prefix, 0, len(filteredAllows))
		for _, allow := range filteredAllows {
			currentPieces := []netip.Prefix{allow}

			for _, block := range collapsedBlocks {
				if block.Addr().Is4() != allow.Addr().Is4() {
					continue
				}
				var nextPieces []netip.Prefix
				for _, piece := range currentPieces {
					if piece.Contains(block.Addr()) && piece.Bits() < block.Bits() {
						statsHoles++
						if !opts.SuppressComments {
							punchedHoles = append(punchedHoles, Hole{base: allow, hole: block})
						}
						// Fracture the allow subnet explicitly guarding against the overlapping block scope
						nextPieces = append(nextPieces, shared.ExcludePrefix(piece, block)...)
					} else {
						nextPieces = append(nextPieces, piece)
					}
				}
				currentPieces = nextPieces
			}
			finalAllowsTemp = append(finalAllowsTemp, currentPieces...)
		}

		finalAllows = shared.CollapsePrefixes(finalAllowsTemp)
		finalBlocks = collapsedBlocks // Blocks remain fully intact and authoritative.

		// Optimize Allowlist in strict PreferBlocklist boundaries intrinsically
		// destroys all standalone allows as they are structurally irrelevant regarding blocking matrices.
		if opts.OptimizeAllowlist {
			if !opts.SuppressComments {
				for _, a := range finalAllows {
					removedAllowsLog = append(removedAllowsLog, fmt.Sprintf("# %s - Removed from allowlist (Optimize enabled, prefer blocklist)", a))
				}
			}
			finalAllows = nil // Clear limits
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

	// Wrap blocklist target with 1MB buffered writers centrally to maximize I/O performance.
	bwBlock := shared.NewWriter(outB)
	defer bwBlock.Flush()

	// Inline stream struct securely tracking metadata for sorted block placement.
	type StreamItem struct {
		isIPv4 bool
		ip     netip.Addr
		bits   int
		isRule bool
		str    string
	}

	// Allowlist output export logic securely aligning exception logging matrices
	if opts.OutAllowlist != "" {
		f, err := os.Create(opts.OutAllowlist)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing allowlist: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()

		bwAllow := shared.NewWriter(f)

		// Ensure allowlist removed logs (e.g. unused or eclipsed) are output securely inside the allowlist config explicitly
		if !opts.SuppressComments {
			for _, item := range removedAllowsLog {
				bwAllow.WriteString(item + "\n")
			}
		}
		
		if !opts.PreferBlocklist {
			// Direct mapping when blocklist holes do not alter standard allow sequences
			for _, net := range finalAllows {
				bwAllow.WriteString(formatAllowNetwork(net, opts.Output, opts.RangeSep) + "\n")
			}
		} else {
			// Sorting matrices explicitly aligning generated allowlist comments securely above fractured holes
			var allowStream []StreamItem
			for _, net := range finalAllows {
				allowStream = append(allowStream, StreamItem{
					isIPv4: net.Addr().Is4(),
					ip:     net.Addr(),
					bits:   net.Bits(),
					isRule: true,
					str:    formatAllowNetwork(net, opts.Output, opts.RangeSep),
				})
			}
			for _, h := range punchedHoles {
				comment := fmt.Sprintf("# %s - Punched mathematical exception hole inside allowlist bound %s", h.hole, h.base)
				allowStream = append(allowStream, StreamItem{
					isIPv4: h.base.Addr().Is4(),
					ip:     h.base.Addr(),
					bits:   h.base.Bits(),
					isRule: false,
					str:    comment,
				})
			}

			slices.SortFunc(allowStream, func(a, b StreamItem) int {
				if a.isIPv4 != b.isIPv4 {
					if a.isIPv4 { return -1 }
					return 1
				}
				if cmp := a.ip.Compare(b.ip); cmp != 0 { return cmp }
				if a.bits != b.bits { return a.bits - b.bits }
				if a.isRule != b.isRule {
					if !a.isRule { return -1 }
					return 1
				}
				return 0
			})

			for _, item := range allowStream {
				bwAllow.WriteString(item.str + "\n")
			}
		}
		bwAllow.Flush()
	}

	// Prepend removed audit logs strictly to the top of configured payload blocks natively
	if !opts.SuppressComments {
		for _, item := range removedLog {
			bwBlock.WriteString(item + "\n")
		}
		// Maintain the cross-log of removed allows in the blocklist as a comprehensive audit trail globally
		for _, item := range removedAllowsLog {
			bwBlock.WriteString(item + "\n")
		}
	}

	// Matrix sequence directly targeting blocked arrays. Sorts log alignments perfectly.
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

	if !opts.PreferBlocklist {
		for _, h := range punchedHoles {
			comment := fmt.Sprintf("# %s - Punched mathematical exception hole inside blocklist bound %s", h.hole, h.base)
			stream = append(stream, StreamItem{
				isIPv4: h.base.Addr().Is4(),
				ip:     h.base.Addr(),
				bits:   h.base.Bits(),
				isRule: false,
				str:    comment,
			})
		}
	}

	slices.SortFunc(stream, func(a, b StreamItem) int {
		if a.isIPv4 != b.isIPv4 {
			if a.isIPv4 { return -1 }
			return 1
		}
		if cmp := a.ip.Compare(b.ip); cmp != 0 { return cmp }
		if a.bits != b.bits { return a.bits - b.bits }
		// Force comments (isRule=false) directly above the impacted rule reliably.
		if a.isRule != b.isRule {
			if !a.isRule { return -1 }
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
		if !opts.PreferBlocklist {
			logMsg(true, "Removed Blocks (Eclipsed)   : %d", statsEclipsed)
			logMsg(true, "Holes Punched (in Blocks)   : %d", statsHoles)
		} else {
			logMsg(true, "Removed Allows (Eclipsed)   : %d", statsEclipsed)
			logMsg(true, "Holes Punched (in Allows)   : %d", statsHoles)
		}
		logMsg(true, "----------------------------------------")
		logMsg(true, "Final Active Block CIDRs    : %d", len(finalBlocks))
		if opts.OutAllowlist != "" {
			logMsg(true, "Exported Allowlist CIDRs    : %d", len(finalAllows))
		}
		logMsg(true, "========================================")
	}
}

