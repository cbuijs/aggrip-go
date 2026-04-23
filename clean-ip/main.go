/*
==========================================================================
Filename: clean-ip/main.go
Version: 1.1.3-20260423
Date: 2026-04-23 11:35 CEST
Description: Enterprise-grade IP blocklist optimizer. High-speed Go port
             of clean-ip.py. Aggregates IPs, CIDRs, ranges. Cross-references
             against allowlists, collapses redundant subnets, performs
             mathematical hole-punching, and exports to firewall formats.

Changes:
- v1.1.3 (2026-04-23): Updated header filename to include subdirectory.
- v1.1.2 (2026-04-23): Standardized CLI parameters across suite (-b, -a, 
                       -V, -v, -h) modifying custom parsing handlers natively.
- v1.1.1 (2026-04-23): Standardized CLI parameters. Double-dash for long flags
                       and single-dash for short flags. Added custom flag.Usage 
                       to clearly expose list args intercepted by custom parser.
- v1.1.0 (2026-04-22): Major performance overhaul. Replaced slow regex engine
                       with native string manipulation. Streamed file I/O to
                       drop memory footprint. Implemented zero-allocation 
                       FieldsFunc tokenization. Upgraded to slices.SortFunc.
                       Added 1MB buffered writers for high-speed exports.
- v1.0.1 (2026-04-22): Fixed flag.Parse() crash by preemptively intercepting 
                       nargs='+' list arguments (--blocklist/--allowlist).
- v1.0.0 (2026-04-22): Initial high-performance Go implementation.
==========================================================================
*/

package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Options holds CLI configuration mapping directly to standard execution parameters
type Options struct {
	Blocklists        []string
	Allowlists        []string
	Output            string
	RangeSep          string
	OutBlocklist      string
	OutAllowlist      string
	OptimizeAllowlist bool
	SuppressComments  bool
	Strict            bool
	Verbose           bool
	ShowVersion       bool
}

// logMsg outputs progress directly to STDERR, ensuring STDOUT remains clean
// for pipeline piping if the user requests standard output targeting.
func logMsg(verbose bool, msg string, args ...any) {
	if verbose {
		fmt.Fprintf(os.Stderr, "[*] "+msg+"\n", args...)
	}
}

// --------------------------------------------------------------------------
// High-Performance Parsing & Normalization Logic
// --------------------------------------------------------------------------

// stripZeroPadding handles malformed IPv4 formats (e.g. 010.000.000.001)
// natively without utilizing the slow Go regexp engine. It respects CIDR blocks.
func stripZeroPadding(s string) string {
	// Fast bypass: only process strings that look like IPv4 (dots, no colons)
	if !strings.ContainsRune(s, '.') || strings.ContainsRune(s, ':') {
		return s
	}
	
	base := s
	prefix := ""
	
	// Preserve the prefix length (/24) if it exists
	if idx := strings.IndexByte(s, '/'); idx != -1 {
		base = s[:idx]
		prefix = s[idx:]
	}
	
	parts := strings.Split(base, ".")
	if len(parts) != 4 {
		return s // Abort if not standard IPv4 octets
	}
	
	changed := false
	for i, p := range parts {
		trimmed := strings.TrimLeft(p, "0")
		// If trimming removed everything (e.g., "000"), it was a zero.
		if trimmed == "" {
			trimmed = "0"
		}
		if len(trimmed) != len(p) {
			parts[i] = trimmed
			changed = true
		}
	}
	
	if !changed {
		return s
	}
	return strings.Join(parts, ".") + prefix
}

// isFastIP runs a highly optimized heuristic to skip pure text blocks
// preventing the system from running expensive IP-parsing exceptions.
func isFastIP(token string) bool {
	if len(token) == 0 {
		return false
	}
	c := token[0]
	return (c >= '0' && c <= '9') || c == ':' || c == '-'
}

// fetchAndParse streams payloads directly from disk or HTTP into memory.
// Optimized: Processes line-by-line avoiding giant []string array allocations.
func fetchAndParse(source string, strict bool, verbose bool) ([]netip.Prefix, error) {
	logMsg(verbose, "Loading data from: %s", source)
	
	var reader io.Reader
	var closeFunc func() error

	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		client := &http.Client{Timeout: 15 * time.Second}
		req, err := http.NewRequest("GET", source, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		reader = resp.Body
		closeFunc = resp.Body.Close
	} else {
		f, err := os.Open(source)
		if err != nil {
			return nil, err
		}
		reader = f
		closeFunc = f.Close
	}
	defer closeFunc()

	var networks []netip.Prefix
	scanner := bufio.NewScanner(reader)
	
	// Pre-allocate a 1MB buffer for processing massive blocklists with giant lines
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
			token := stripZeroPadding(tokens[i])

			if !isFastIP(token) {
				i++
				continue
			}

			isRange := false
			prefix, err := parsePrefixStrict(token, strict)

			// Lookahead for Range Summarization:
			// Because FieldsFunc stripped dashes, ranges naturally fall to token[i+1].
			// This completely circumvents complex spacing offset tracking.
			if !strings.ContainsRune(token, '/') && i+1 < len(tokens) {
				nextToken := stripZeroPadding(tokens[i+1])

				startIP, err1 := netip.ParseAddr(token)
				endIP, err2 := netip.ParseAddr(nextToken)

				if err1 == nil && err2 == nil && startIP.Is4() == endIP.Is4() {
					// Cisco wildcard mask exception detection (e.g. 0.0.0.255)
					if startIP.Is4() && strings.HasPrefix(nextToken, "0.") {
						parts := strings.Split(nextToken, ".")
						if len(parts) == 4 {
							var nmParts []string
							for _, p := range parts {
								val, _ := strconv.Atoi(p)
								nmParts = append(nmParts, strconv.Itoa(255-val))
							}
							netmaskStr := token + "/" + strings.Join(nmParts, ".")
							if ciscoPfx, err := parsePrefixStrict(netmaskStr, strict); err == nil {
								networks = append(networks, ciscoPfx)
								i += 2 // Jump the range
								isRange = true
							}
						}
					} else {
						// Standard IP range mathematical summarization
						if startIP.Compare(endIP) > 0 {
							startIP, endIP = endIP, startIP
						}
						summarized := summarizeRange(startIP, endIP)
						networks = append(networks, summarized...)
						i += 2 // Jump the range
						isRange = true
					}
				}
			}

			if !isRange {
				if err == nil {
					networks = append(networks, prefix)
				}
				i++
			}
		}
	}
	return networks, scanner.Err()
}

// parsePrefixStrict handles both CIDR and Netmask notation safely. 
// Truncates dirty host bits safely if strict == false natively using netip.
func parsePrefixStrict(s string, strict bool) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		parts := strings.Split(s, "/")
		if len(parts) == 2 && strings.Contains(parts[1], ".") {
			maskAddr, err := netip.ParseAddr(parts[1])
			if err == nil && maskAddr.Is4() {
				b := maskAddr.As4()
				bits := 0
				for _, v := range b {
					for j := 7; j >= 0; j-- {
						if (v & (1 << j)) != 0 {
							bits++
						} else {
							break
						}
					}
				}
				s = parts[0] + "/" + strconv.Itoa(bits)
			}
		}
	}

	pfx, err := netip.ParsePrefix(s)
	if err != nil {
		addr, err2 := netip.ParseAddr(s)
		if err2 != nil {
			return netip.Prefix{}, err2
		}
		pfx = netip.PrefixFrom(addr, addr.BitLen())
	}

	if strict {
		if pfx.Addr() != pfx.Masked().Addr() {
			return netip.Prefix{}, fmt.Errorf("dirty host bits in prefix")
		}
		return pfx, nil
	}
	return pfx.Masked(), nil
}

// --------------------------------------------------------------------------
// Subnet Math & IP Logic (Replicating Python's ipaddress module natively)
// --------------------------------------------------------------------------

func addrBitLen(a netip.Addr) int {
	if a.Is4() {
		return 32
	}
	return 128
}

// lastAddr calculates the broadcast address by manipulating binary arrays directly.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().As16()
	bitLen := addrBitLen(p.Addr())
	hostBits := bitLen - p.Bits()

	for i := 0; i < hostBits; i++ {
		idx := bitLen - 1 - i
		byteIdx := idx / 8
		bitIdx := 7 - (idx % 8)
		b[byteIdx] |= (1 << bitIdx)
	}

	if p.Addr().Is4() {
		return netip.AddrFrom4(*(*[4]byte)(b[12:]))
	}
	return netip.AddrFrom16(b)
}

// maxAddr returns the mathematical limit ceiling based on IP version natively.
func maxAddr(a netip.Addr) netip.Addr {
	if a.Is4() {
		return netip.AddrFrom4([4]byte{255, 255, 255, 255})
	}
	return netip.AddrFrom16([16]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255})
}

// nextAddr manually forces an iterative increment across host bit boundaries.
func nextAddr(a netip.Addr) netip.Addr {
	b := a.As16()
	for i := 15; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
	if a.Is4() {
		return netip.AddrFrom4(*(*[4]byte)(b[12:]))
	}
	return netip.AddrFrom16(b)
}

// summarizeRange mathematically converts spanning IP-to-IP formats into optimal CIDRs
func summarizeRange(start, end netip.Addr) []netip.Prefix {
	var res []netip.Prefix
	curr := start

	for curr.Compare(end) <= 0 {
		maxLen := addrBitLen(curr)
		bits := maxLen

		for b := maxLen; b >= 0; b-- {
			p := netip.PrefixFrom(curr, b)
			if p.Masked().Addr() != curr {
				break
			}
			if lastAddr(p).Compare(end) > 0 {
				break
			}
			bits = b
		}

		p := netip.PrefixFrom(curr, bits)
		res = append(res, p)

		last := lastAddr(p)
		if last == maxAddr(curr) {
			break
		}
		curr = nextAddr(last)
	}

	return res
}

// halve mathematically splits a supernet exactly down the middle using binary XOR
func halve(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := p.Bits()
	a1 := p.Addr()
	b1 := a1.As16()

	byteIdx := bits / 8
	bitIdx := 7 - (bits % 8)
	b1[byteIdx] ^= (1 << bitIdx)

	var a2 netip.Addr
	if a1.Is4() {
		a2 = netip.AddrFrom4(*(*[4]byte)(b1[12:]))
	} else {
		a2 = netip.AddrFrom16(b1)
	}

	p1 := netip.PrefixFrom(a1, bits+1)
	p2 := netip.PrefixFrom(a2, bits+1)
	return p1, p2
}

// excludePrefix guarantees the protected subnet stays reachable 
// by fracturing the supernet block directly around it
func excludePrefix(super, sub netip.Prefix) []netip.Prefix {
	if !super.Contains(sub.Addr()) {
		return []netip.Prefix{super}
	}
	if super == sub {
		return nil
	}

	var res []netip.Prefix
	curr := super

	for curr.Bits() < sub.Bits() {
		h1, h2 := halve(curr)
		if h1.Contains(sub.Addr()) {
			res = append(res, h2)
			curr = h1
		} else {
			res = append(res, h1)
			curr = h2
		}
	}
	return res
}

// --------------------------------------------------------------------------
// Advanced Aggregation & Collapse Logic
// --------------------------------------------------------------------------

func collapsePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}

	// High-speed sorting using modern Go 1.21+ slices.SortFunc
	// eliminating all reflection-based overhead.
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
		if a.Addr().Is4() != b.Addr().Is4() {
			if a.Addr().Is4() {
				return -1
			}
			return 1
		}
		if cmp := a.Addr().Compare(b.Addr()); cmp != 0 {
			return cmp
		}
		return a.Bits() - b.Bits()
	})

	var stack []netip.Prefix
	stack = append(stack, prefixes[0])

	for i := 1; i < len(prefixes); i++ {
		curr := prefixes[i]
		last := stack[len(stack)-1]

		// Absorb total overlap intrinsically
		if last.Contains(curr.Addr()) {
			continue
		}

		stack = append(stack, curr)

		// Sweep backwards analyzing structural bounds to merge adjacencies natively
		for len(stack) >= 2 {
			p1 := stack[len(stack)-2]
			p2 := stack[len(stack)-1]

			if p1.Bits() == p2.Bits() {
				super := netip.PrefixFrom(p1.Addr(), p1.Bits()-1).Masked()
				h1, h2 := halve(super)
				if (p1 == h1 && p2 == h2) || (p1 == h2 && p2 == h1) {
					stack = stack[:len(stack)-2]
					stack = append(stack, super)
					continue
				}
			}
			break
		}
	}

	return stack
}

// --------------------------------------------------------------------------
// Firewall Matrix Formatters
// --------------------------------------------------------------------------

func formatNetwork(p netip.Prefix, fmtType string, rangeSep string) string {
	switch fmtType {
	case "netmask":
		bLen := addrBitLen(p.Addr())
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
		return p.Addr().String() + sep + lastAddr(p).String()

	case "cisco":
		bLen := addrBitLen(p.Addr())
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
// Core Logic Entry
// --------------------------------------------------------------------------

func main() {
	var opts Options
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

	// Custom formatted usage explicitly declaring list flags bypassing flag constraints
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of clean-ip:\n\n")
		fmt.Fprintf(os.Stderr, "Core Options:\n")
		fmt.Fprintf(os.Stderr, "  -b, --blocklist <path/url>...  Path(s) or URL(s) to the IP blocklist(s) (Required, accepts multiple separated by space)\n")
		fmt.Fprintf(os.Stderr, "  -a, --allowlist <path/url>...  Path(s) or URL(s) to the IP allowlist(s) (Optional, accepts multiple separated by space)\n")
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
		fmt.Fprintf(os.Stderr, "  clean-ip -b drop.txt -a allow.txt -o iptables --out-blocklist rules.v4 -v\n")
	}

	// ----------------------------------------------------------------------
	// Custom Pre-Parsing for nargs='+' Support
	// Go's standard flag.Parse() drops lists of space-separated strings.
	// We extract --blocklist and --allowlist manually to prevent crash errors.
	// ----------------------------------------------------------------------
	var standardArgs []string
	args := os.Args[1:]

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--blocklist" || arg == "-blocklist" || arg == "-b" {
			i++
			for ; i < len(args) && !strings.HasPrefix(args[i], "-"); i++ {
				opts.Blocklists = append(opts.Blocklists, args[i])
			}
			i--
		} else if arg == "--allowlist" || arg == "-allowlist" || arg == "-a" {
			i++
			for ; i < len(args) && !strings.HasPrefix(args[i], "-"); i++ {
				opts.Allowlists = append(opts.Allowlists, args[i])
			}
			i--
		} else {
			standardArgs = append(standardArgs, arg)
		}
	}

	// Override arguments feeding flag.Parse to drop lists entirely and let standard handle the rest
	os.Args = append([]string{os.Args[0]}, standardArgs...)
	flag.Parse()

	// Handle version output intercept natively
	if opts.ShowVersion {
		fmt.Println("clean-ip Go Edition - Version 1.1.3-20260423")
		os.Exit(0)
	}

	if len(opts.Blocklists) == 0 {
		fmt.Fprintf(os.Stderr, "Error: --blocklist / -b is required.\n")
		os.Exit(1)
	}

	logMsg(opts.Verbose, "--- Stage 1 & 2: Concurrent Ingestion ---")
	
	var wg sync.WaitGroup
	var rawBlocks, rawAllows []netip.Prefix
	var muBlock, muAllow sync.Mutex

	for _, source := range opts.Blocklists {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
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

	for _, source := range opts.Allowlists {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
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
	collapsedBlocks := collapsePrefixes(rawBlocks)
	collapsedAllows := collapsePrefixes(rawAllows)

	logMsg(opts.Verbose, "--- Stage 4: Cross-Referencing & Punch-Holing ---")

	var filteredBlocks []netip.Prefix
	usedAllows := make(map[netip.Prefix]bool)
	var removedLog []string
	
	type Hole struct{ allow, block netip.Prefix }
	var punchedHoles []Hole

	statsAllowlisted := 0
	statsHoles := 0

	// Pass 1: Total Eclipse
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

	// Pass 2: Mathematical Hole Punching internally safely bypassing allow overlaps
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
					nextPieces = append(nextPieces, excludePrefix(piece, allow)...)
				} else {
					nextPieces = append(nextPieces, piece)
				}
			}
			currentPieces = nextPieces
		}
		finalBlocks = append(finalBlocks, currentPieces...)
	}

	// Final cleanup matrix explicitly to optimize fragmentation boundaries
	finalBlocks = collapsePrefixes(finalBlocks)

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

	// Wrap targets with 1MB buffered writers to maximize I/O performance massively
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

	if !opts.SuppressComments {
		for _, item := range removedLog {
			bwBlock.WriteString(item + "\n")
		}
		for _, item := range removedAllowsLog {
			bwBlock.WriteString(item + "\n")
		}
	}

	// Inline stream struct to guarantee specific placement during output sequence
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
		// Force comments (isRule=false) directly above the impacted rule
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

