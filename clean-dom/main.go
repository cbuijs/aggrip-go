/*
==========================================================================
Filename: clean-dom/main.go
Version: 1.0.7-20260424
Date: 2026-04-24 14:35 CEST
Update Trail:
  - 1.0.7 (2026-04-24): Deferred structural validation to output phase 
                        to ensure invalid/TLD drops are correctly logged 
                        as comments in the generated output files natively.
  - 1.0.6 (2026-04-24): Added --allow-tld parameter to optionally permit 
                        TLD-only domains (e.g. 'com'). Updated validation 
                        and usage instructions.
  - 1.0.5 (2026-04-24): Stripped regexp for native byte-level parsing. Added
                        strict RFC validation (hasNumericTLD). Fixed --sort 
                        logic for 'alphabetically' vs 'tld'. Added -l/--less-strict.
  - 1.0.4 (2026-04-23): Standardized CLI parameters across the suite. Added
                        short parameters (-b, -a, -t, -V) and unified help output.
  - 1.0.3 (2026-04-23): Standardized CLI parameters. Added custom flag.Usage 
                        to clearly define long (--flag) and short (-f) args.
  - 1.0.2 (2026-04-22): Fixed runtime panic in getParents slice bounds.
  - 1.0.1 (2026-04-22): Fixed missing 'unicode' package import.
  - 1.0.0 (2026-04-22): Initial Go port consolidating clean-dom.py and clean-dom2.py.
Description: Enterprise-grade DNS blocklist optimizer. Features upfront 
             file format detection, concurrent bulk ingestion, punycode 
             translation, dynamic adblock routing, and O(N log N) tree 
             deduplication via reverse string sorting.
==========================================================================
*/

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/net/idna"
)

// stringSlice implements flag.Value to allow multiple CLI arguments natively.
type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, " ")
}
func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// Global Flags defining core operations and behaviors
var (
	blocklists       stringSlice
	allowlists       stringSlice
	topnlists        stringSlice
	inputFormat      string
	outputFmt        string
	allDir           string
	workDir          string
	sortAlgo         string
	outBlocklist     string
	outAllowlist     string
	optimizeAllow    bool
	suppressComments bool
	lessStrict       bool
	allowTLD         bool
	verbose          bool
	showVersion      bool
)

func init() {
	// Register variables for double-dash configurations. Standardized short formats included.
	flag.Var(&blocklists, "blocklist", "Path(s) or URL(s) to the DNS blocklist(s) (can specify multiple times)")
	flag.Var(&blocklists, "b", "Short for --blocklist")

	flag.Var(&allowlists, "allowlist", "Optional path(s) or URL(s) to the DNS allowlist(s)")
	flag.Var(&allowlists, "a", "Short for --allowlist")

	flag.Var(&topnlists, "topnlist", "Optional path(s) or URL(s) to Top-N list(s)")
	flag.Var(&topnlists, "t", "Short for --topnlist")

	flag.StringVar(&inputFormat, "input-format", "", "Strictly enforce input format: domain, hosts, adblock, routedns, squid")
	flag.StringVar(&inputFormat, "i", "", "Short for --input-format")

	flag.StringVar(&outputFmt, "output-format", "domain", "Output format: all, domain, hosts, adblock, dnsmasq, unbound, rpz, routedns, squid")
	flag.StringVar(&outputFmt, "o", "domain", "Short for --output-format")

	flag.StringVar(&allDir, "all-dir", "", "Mandatory output directory to use when output is set to 'all'")
	
	flag.StringVar(&workDir, "work-dir", "", "Directory to save unmodified raw source files")
	flag.StringVar(&workDir, "w", "", "Short for --work-dir")

	flag.StringVar(&sortAlgo, "sort", "domain", "Sorting algorithm: domain, alphabetically, tld")
	
	flag.StringVar(&outBlocklist, "out-blocklist", "", "File path to write the blocklist output (default: STDOUT)")
	flag.StringVar(&outAllowlist, "out-allowlist", "", "File path to write the allowlist output")
	
	flag.BoolVar(&optimizeAllow, "optimize-allowlist", false, "Drop unused allowlist entries")
	flag.BoolVar(&suppressComments, "suppress-comments", false, "Suppress audit log of removed domains")
	
	flag.BoolVar(&lessStrict, "less-strict", false, "Allow underscores (_) and asterisks (*) in domain names")
	flag.BoolVar(&lessStrict, "l", false, "Short for --less-strict")
	
	flag.BoolVar(&allowTLD, "allow-tld", false, "Allow Top-Level Domains (TLDs) like 'com' or 'net'")
	
	flag.BoolVar(&verbose, "verbose", false, "Show progress and statistics on STDERR")
	flag.BoolVar(&verbose, "v", false, "Short for --verbose")

	flag.BoolVar(&showVersion, "version", false, "Show version information and exit")
	flag.BoolVar(&showVersion, "V", false, "Short for --version")

	// Custom formatted usage explicitly declaring standard flags across the suite
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of clean-dom:\n\n")
		fmt.Fprintf(os.Stderr, "Core Options:\n")
		fmt.Fprintf(os.Stderr, "  -b, --blocklist <path/url>     Path(s) or URL(s) to the DNS blocklist(s) (Required, can specify multiple)\n")
		fmt.Fprintf(os.Stderr, "  -a, --allowlist <path/url>     Path(s) or URL(s) to the DNS allowlist(s) (Optional, can specify multiple)\n")
		fmt.Fprintf(os.Stderr, "  -t, --topnlist <path/url>      Path(s) or URL(s) to Top-N list(s) (Optional, can specify multiple)\n")
		fmt.Fprintf(os.Stderr, "  -i, --input-format <format>    Strictly enforce input format (domain, hosts, adblock, routedns, squid)\n")
		fmt.Fprintf(os.Stderr, "  -o, --output-format <format>   Output format (all, domain, hosts, adblock, dnsmasq, unbound, rpz, routedns, squid) (default \"domain\")\n")
		fmt.Fprintf(os.Stderr, "      --out-blocklist <file>     File path to write the blocklist output (default: STDOUT)\n")
		fmt.Fprintf(os.Stderr, "      --out-allowlist <file>     File path to write the allowlist output\n")
		fmt.Fprintf(os.Stderr, "      --all-dir <dir>            Mandatory output directory to use when output format is set to 'all'\n")
		fmt.Fprintf(os.Stderr, "  -w, --work-dir <dir>           Directory to save unmodified raw source files\n")
		fmt.Fprintf(os.Stderr, "      --sort <type>              Sorting algorithm (domain, alphabetically, tld) (default \"domain\")\n")
		fmt.Fprintf(os.Stderr, "      --optimize-allowlist       Drop unused allowlist entries\n")
		fmt.Fprintf(os.Stderr, "      --suppress-comments        Suppress audit log of removed domains\n")
		fmt.Fprintf(os.Stderr, "  -l, --less-strict              Allow underscores (_) and asterisks (*) in domain names\n")
		fmt.Fprintf(os.Stderr, "      --allow-tld                Allow Top-Level Domains (TLDs) like 'com' (Note: 'com' collapses all .com subdomains)\n")
		fmt.Fprintf(os.Stderr, "  -v, --verbose                  Show progress and statistics on STDERR\n")
		fmt.Fprintf(os.Stderr, "  -V, --version                  Show version information and exit\n")
		fmt.Fprintf(os.Stderr, "  -h, --help                     Show this help message\n")
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  clean-dom -b ads.txt -a ok.txt -o unbound --out-blocklist filter.conf -v\n")
	}
}

// logMsg prints messages to STDERR if verbose mode is enabled. Keeps STDOUT clear.
func logMsg(msg string) {
	if verbose {
		log.Printf("[*] %s\n", msg)
	}
}

// isFastIP runs a rapid heuristic bypass checking if a token resembles an IP.
func isFastIP(token string) bool {
	if len(token) == 0 {
		return false
	}
	c := token[0]
	if (c >= '0' && c <= '9') || c == ':' {
		_, err := netip.ParseAddr(token)
		return err == nil
	}
	return false
}

// isValidDomainStructural replaces slow regex engines with a high-speed native byte evaluator.
// Supports overriding standard bounds using the lessStrict flag and allowTLD flag.
func isValidDomainStructural(domain string, lessStrict bool, allowTLD bool) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	
	// Fast structural edge bounds
	if domain[0] == '.' || domain[len(domain)-1] == '.' {
		return false
	}

	parts := strings.Split(domain, ".")
	if !allowTLD && len(parts) < 2 {
		return false // Must contain at least a TLD identifier
	}
	if len(parts) == 0 {
		return false
	}

	for _, part := range parts {
		l := len(part)
		if l == 0 || l > 63 {
			return false
		}
		
		// Blocks cannot start or end with standard hyphens per RFC
		if part[0] == '-' || part[l-1] == '-' {
			return false
		}
		
		// Enforce underscore boundary blocks unless less-strict is actively toggled
		if !lessStrict && (part[0] == '_' || part[l-1] == '_') {
			return false
		}

		for j := 0; j < l; j++ {
			c := part[j]
			valid := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'
			
			// Open regex parity boundaries for legacy non-compliant feeds
			if !valid && lessStrict {
				if c == '_' || c == '*' {
					valid = true
				}
			}
			if !valid {
				return false
			}
		}
	}
	return true
}

// hasNumericTLD evaluates domains strictly against RFC 3696 enforcing alphabetic TLD boundaries.
func hasNumericTLD(domain string) bool {
	parts := strings.Split(domain, ".")
	if len(parts) == 0 {
		return false
	}
	tld := parts[len(parts)-1]
	
	for i := 0; i < len(tld); i++ {
		if tld[i] < '0' || tld[i] > '9' {
			return false // Safe, found an alphabetic or non-numeric character
		}
	}
	return true // TLD is entirely numeric (e.g., 201.22.83)
}

// detectFormat samples lines to heuristically determine the file format dynamically.
func detectFormat(lines []string) string {
	counts := map[string]int{"hosts": 0, "adblock": 0, "routedns": 0, "squid": 0, "domain": 0}
	validLines := 0

	for _, rawLine := range lines {
		if validLines >= 50 {
			break
		}
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") {
			continue
		}

		firstHash := strings.Index(line, "#")
		if firstHash != -1 {
			if firstHash == 0 {
				continue
			}
			firstSpace := strings.Index(line, " ")
			if firstSpace == -1 || firstHash < firstSpace {
				continue
			}
		}

		line = strings.TrimSpace(strings.Split(line, "#")[0])
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		firstToken := parts[0]

		if isFastIP(firstToken) {
			counts["hosts"]++
		} else if strings.HasPrefix(firstToken, "@@") || strings.HasPrefix(firstToken, "||") || strings.Contains(firstToken, "^") || strings.Contains(firstToken, "$") || strings.HasPrefix(firstToken, "/") {
			counts["adblock"]++
		} else if strings.HasPrefix(firstToken, ".") || strings.HasPrefix(firstToken, "*.") {
			counts["routedns"]++
		} else {
			counts["domain"]++
		}
		validLines++
	}

	if validLines == 0 {
		return "mixed"
	}

	bestMatch := "domain"
	maxCount := -1
	for k, v := range counts {
		if v > maxCount {
			maxCount = v
			bestMatch = k
		}
	}

	if float64(maxCount)/float64(validLines) >= 0.8 {
		return bestMatch
	}
	return "mixed"
}

// normalizeDomain sanitizes noisy domain inputs by aggressively stripping artifacts.
func normalizeDomain(d string) string {
	d = strings.TrimSpace(strings.ToLower(d))
	if strings.HasPrefix(d, "@@||") {
		d = d[4:]
	} else if strings.HasPrefix(d, "||") {
		d = d[2:]
	}
	if strings.HasSuffix(d, "^") {
		d = d[:len(d)-1]
	}
	for strings.HasPrefix(d, "*.") {
		d = d[2:]
	}
	return strings.Trim(d, ".")
}

// parseResult encapsulates extracted metadata from complex syntax parsing.
type parseResult struct {
	Domain              string
	IsAllow             bool
	DenyAllow           []string
	OriginalToken       string
	UnicodeOrig         string
	DenyAllowUnicodeMap map[string]string
}

// isASCII checks if a string contains only ASCII characters. Fast validation path.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// parseDomainToken evaluates Adblock rules, extracts modifiers ($denyallow), and ensures Punycode translation.
func parseDomainToken(token string) parseResult {
	res := parseResult{
		OriginalToken:       token,
		DenyAllow:           []string{},
		DenyAllowUnicodeMap: make(map[string]string),
	}

	if strings.HasPrefix(token, "@@") {
		res.IsAllow = true
		token = token[2:]
	}

	// Drop regex rules natively.
	if strings.HasPrefix(token, "/") {
		return res
	}

	domainPart := token
	if strings.Contains(token, "$") {
		parts := strings.SplitN(token, "$", 2)
		domainPart = parts[0]
		modifiers := parts[1]

		for _, mod := range strings.Split(modifiers, ",") {
			mod = strings.TrimSpace(mod)
			if strings.HasPrefix(mod, "denyallow=") {
				targets := strings.Split(mod[10:], "|")
				for _, da := range targets {
					cleanDa := normalizeDomain(da)
					punyDa := cleanDa
					var daOrig string

					if cleanDa != "" && !isASCII(cleanDa) {
						if p, err := idna.ToASCII(cleanDa); err == nil {
							punyDa = p
							daOrig = cleanDa
						} else {
							punyDa = ""
						}
					}

					if cleanDa != "" && punyDa != "" {
						valid := !isFastIP(punyDa)
						if valid {
							res.DenyAllow = append(res.DenyAllow, punyDa)
							if daOrig != "" {
								res.DenyAllowUnicodeMap[punyDa] = daOrig
							}
						}
					}
				}
			} else if mod != "" {
				// Contains strict unrelated modifiers; dump the rule to be absolutely safe.
				return res
			}
		}
	}

	cleanDom := normalizeDomain(domainPart)
	punyDom := cleanDom
	var domOrig string

	if cleanDom != "" && !isASCII(cleanDom) {
		if p, err := idna.ToASCII(cleanDom); err == nil {
			punyDom = p
			domOrig = cleanDom
		} else {
			punyDom = ""
		}
	}

	if cleanDom != "" && punyDom != "" {
		valid := !isFastIP(punyDom)
		if !valid {
			punyDom = ""
		}
	} else {
		punyDom = ""
	}

	res.Domain = punyDom
	res.UnicodeOrig = domOrig
	return res
}

// fetchLines retrieves string payloads natively via bulk read from HTTP or local paths.
func fetchLines(source string) ([]string, error) {
	var data []byte
	var err error

	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		req, errReq := http.NewRequest("GET", source, nil)
		if errReq != nil {
			return nil, errReq
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")
		client := &http.Client{Timeout: 15 * time.Second}
		resp, errDo := client.Do(req)
		if errDo != nil {
			return nil, errDo
		}
		defer resp.Body.Close()
		data, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
	} else {
		data, err = os.ReadFile(source)
		if err != nil {
			return nil, err
		}
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// ParsedLists contains cross-referenced parsed domains globally mapped.
type ParsedLists struct {
	Blocks      []string
	Allows      []string
	DenyAllows  []string
	Conversions []string
}

// readDomainsBulk orchestrates ingestion, heuristic format evaluation, and data extraction.
func readDomainsBulk(source string, isTopN bool, forceAllow bool, listType string) ParsedLists {
	var result ParsedLists
	lines, err := fetchLines(source)
	if err != nil {
		log.Printf("Error reading source '%s': %v\n", source, err)
		return result
	}

	detectedFmt := inputFormat
	if detectedFmt == "" {
		detectedFmt = detectFormat(lines)
	}

	logMsg(fmt.Sprintf("Bulk loading data from: %s (Format: %s)", source, strings.ToUpper(detectedFmt)))

	if workDir != "" {
		h := sha256.New()
		h.Write([]byte(source))
		hashStr := fmt.Sprintf("%x", h.Sum(nil))[:16]
		rawPath := filepath.Join(workDir, hashStr+".raw")
		
		f, err := os.Create(rawPath)
		if err == nil {
			f.WriteString(fmt.Sprintf("# Type: %s | Source: %s\n", listType, source))
			for _, l := range lines {
				f.WriteString(l + "\n")
			}
			f.Close()
		}
	}

	processParsed := func(parsed parseResult, rawToken string) {
		if parsed.Domain != "" {
			if parsed.IsAllow || forceAllow {
				result.Allows = append(result.Allows, parsed.Domain)
			} else {
				result.Blocks = append(result.Blocks, parsed.Domain)
			}
			if parsed.UnicodeOrig != "" {
				result.Conversions = append(result.Conversions, fmt.Sprintf("# %s - Converted from Unicode: %s", parsed.Domain, parsed.UnicodeOrig))
			}
		}

		if len(parsed.DenyAllow) > 0 {
			if parsed.IsAllow || forceAllow {
				result.Blocks = append(result.Blocks, parsed.DenyAllow...)
				result.DenyAllows = append(result.DenyAllows, parsed.DenyAllow...)
			} else {
				result.Allows = append(result.Allows, parsed.DenyAllow...)
			}
			for puny, orig := range parsed.DenyAllowUnicodeMap {
				result.Conversions = append(result.Conversions, fmt.Sprintf("# %s - Converted from Unicode: %s", puny, orig))
			}
		}
	}

	for _, rawLine := range lines {
		rawLine = strings.TrimSpace(rawLine)
		if rawLine == "" || strings.HasPrefix(rawLine, "!") {
			continue
		}

		firstHash := strings.Index(rawLine, "#")
		if firstHash != -1 {
			if firstHash == 0 {
				continue
			}
			firstSpace := strings.Index(rawLine, " ")
			if firstSpace == -1 || firstHash < firstSpace {
				continue
			}
		}

		line := strings.TrimSpace(strings.Split(rawLine, "#")[0])
		if line == "" {
			continue
		}

		if isTopN && strings.Contains(line, ",") {
			if inputFormat != "" && inputFormat != "domain" && inputFormat != "routedns" && inputFormat != "squid" {
				continue
			}
			parts := strings.SplitN(line, ",", 2)
			if len(parts) > 1 {
				dom := normalizeDomain(parts[1])
				punyDom := dom
				var domOrig string

				if dom != "" && !isASCII(dom) {
					if p, err := idna.ToASCII(dom); err == nil {
						punyDom = p
						domOrig = dom
					} else {
						punyDom = ""
					}
				}

				if dom != "" && punyDom != "" {
					valid := !isFastIP(punyDom)
					if valid {
						result.Blocks = append(result.Blocks, punyDom)
						if domOrig != "" {
							result.Conversions = append(result.Conversions, fmt.Sprintf("# %s - Converted from Unicode: %s", punyDom, domOrig))
						}
					}
				}
			}
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		firstToken := parts[0]

		var isHosts, isAdblock, isRoutedns, isSquid, isDomain bool

		if detectedFmt != "mixed" {
			isHosts = (detectedFmt == "hosts")
			isAdblock = (detectedFmt == "adblock")
			isRoutedns = (detectedFmt == "routedns")
			isSquid = (detectedFmt == "squid")
			isDomain = (detectedFmt == "domain")

			if isHosts && !isFastIP(firstToken) {
				continue
			}
		} else {
			isHosts = isFastIP(firstToken)
			isAdblock = !isHosts && (strings.HasPrefix(firstToken, "@@") || strings.HasPrefix(firstToken, "||") || strings.Contains(firstToken, "^") || strings.Contains(firstToken, "$") || strings.HasPrefix(firstToken, "/"))
			isRoutedns = !isHosts && !isAdblock && (strings.HasPrefix(firstToken, ".") || strings.HasPrefix(firstToken, "*."))
			isSquid = !isHosts && !isAdblock && strings.HasPrefix(firstToken, ".")
			isDomain = !isHosts && !isAdblock && !isRoutedns && !isSquid
		}

		if inputFormat != "" {
			if inputFormat == "hosts" && !isHosts {
				continue
			}
			if inputFormat == "adblock" && !isAdblock {
				continue
			}
			if inputFormat == "routedns" && !(isRoutedns || isDomain) {
				continue
			}
			if inputFormat == "squid" && !isSquid {
				continue
			}
			if inputFormat == "domain" && !isDomain {
				continue
			}
		}

		if isHosts {
			if firstToken == "0.0.0.0" || firstToken == "127.0.0.1" || firstToken == "::" || firstToken == "::1" {
				for _, part := range parts[1:] {
					processParsed(parseDomainToken(part), part)
				}
			}
			continue
		}

		processParsed(parseDomainToken(firstToken), firstToken)
	}
	return result
}

// getParents yields a slice of domains traveling bottom-up toward the apex natively.
func getParents(domain string) []string {
	var parents []string
	for {
		parents = append(parents, domain)
		idx := strings.IndexByte(domain, '.')
		if idx == -1 {
			break
		}
		// Safely advance past the matched dot
		domain = domain[idx+1:]
	}
	return parents
}

// reverseStr performs a rapid rune-level reverse string operation for O(N log N) deduplication sorting.
func reverseStr(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// extractDomainForSort strictly pulls the root domain from a string array index safely handling comments
func extractDomainForSort(item string) string {
	if strings.HasPrefix(item, "#") {
		clean := strings.TrimSpace(strings.TrimPrefix(item, "#"))
		return strings.SplitN(clean, " - ", 2)[0]
	}
	return item
}

func main() {
	log.SetFlags(0)
	flag.Parse()

	if showVersion {
		fmt.Println("clean-dom Go Edition - Version 1.0.7-20260424")
		os.Exit(0)
	}

	if len(blocklists) == 0 {
		log.Fatal("Error: At least one --blocklist must be provided.")
	}
	if outputFmt == "all" && allDir == "" {
		log.Fatal("Error: --all-dir is required when using -o all.")
	}

	if workDir != "" {
		os.MkdirAll(workDir, 0755)
	}

	var blockDomains []string
	allowDomains := make(map[string]struct{})
	denyAllowOverrides := make(map[string]struct{})
	var conversionLog []string

	logMsg("Consolidating Blocklists...")
	var wg sync.WaitGroup
	var mu sync.Mutex

	processList := func(list []string, isTopN bool, forceAllow bool, listType string) {
		for _, source := range list {
			wg.Add(1)
			go func(s string) {
				defer wg.Done()
				res := readDomainsBulk(s, isTopN, forceAllow, listType)
				mu.Lock()
				blockDomains = append(blockDomains, res.Blocks...)
				for _, a := range res.Allows {
					allowDomains[a] = struct{}{}
				}
				for _, da := range res.DenyAllows {
					denyAllowOverrides[da] = struct{}{}
				}
				conversionLog = append(conversionLog, res.Conversions...)
				mu.Unlock()
			}(source)
		}
	}

	processList(blocklists, false, false, "Blocklist")
	wg.Wait()

	if len(allowlists) > 0 {
		logMsg("Consolidating Allowlists...")
		processList(allowlists, false, true, "Allowlist")
		wg.Wait()
	}

	topnDomains := make(map[string]struct{})
	if len(topnlists) > 0 {
		logMsg("Consolidating Top-N Lists...")
		var topNBlocks []string
		for _, source := range topnlists {
			res := readDomainsBulk(source, true, false, "Top-N")
			topNBlocks = append(topNBlocks, res.Blocks...)
		}
		for _, b := range topNBlocks {
			topnDomains[b] = struct{}{}
		}
	}

	logMsg("--- Stage 4: Preparing for Deduplication ---")
	logMsg(fmt.Sprintf("Sorting %d domains by depth...", len(blockDomains)))

	// Sort blockDomains by depth (dot count) descending to properly sequence subdomains
	sort.Slice(blockDomains, func(i, j int) bool {
		return strings.Count(blockDomains[i], ".") < strings.Count(blockDomains[j], ".")
	})

	if outputFmt == "all" {
		os.MkdirAll(allDir, 0755)
	}

	buildOutputs := func(activeTopN map[string]struct{}, extSuffix string, isTopNPass bool) {
		passName := "(Full List)"
		if isTopNPass {
			passName = "(Top-N)"
		}
		logMsg(fmt.Sprintf("--- Stage 5: Processing & Optimizing %s ---", passName))

		filteredBlocks := make(map[string]struct{})
		var removedLogGeneral, removedLogDedup, removedLogParentBlocked, removedLogUnusedAllows, removedLogInvalids []string
		usedAllows := make(map[string]struct{})
		loggedInvalids := make(map[string]struct{})

		statsAllowlisted, statsTopN, statsDeduped, statsInvalidRFC, statsInvalidStruct := 0, 0, 0, 0, 0

		for _, domain := range blockDomains {
			// Validate structural boundaries and optionally TLD-only flags.
			// Deduplicate validation logs globally using map logic to prevent spam from duplicate inputs.
			if !isValidDomainStructural(domain, lessStrict, allowTLD) {
				if _, exists := loggedInvalids[domain]; !exists {
					loggedInvalids[domain] = struct{}{}
					if !suppressComments {
						removedLogInvalids = append(removedLogInvalids, fmt.Sprintf("# %s - Removed due to strict structural/TLD validation", domain))
					}
					statsInvalidStruct++
				}
				continue
			}

			// RFC strict fallback blocking (i.e. '201.22.83') 
			if hasNumericTLD(domain) {
				if _, exists := loggedInvalids[domain]; !exists {
					loggedInvalids[domain] = struct{}{}
					if !suppressComments {
						removedLogInvalids = append(removedLogInvalids, fmt.Sprintf("# %s - Removed due to strict RFC validation (all-numeric TLD)", domain))
					}
					statsInvalidRFC++
				}
				continue
			}

			parents := getParents(domain)
			allowed := false

			if len(allowDomains) > 0 {
				for _, p := range parents {
					if _, exists := allowDomains[p]; exists {
						if _, override := denyAllowOverrides[p]; !override {
							usedAllows[p] = struct{}{}
							allowed = true
							if !suppressComments {
								removedLogGeneral = append(removedLogGeneral, fmt.Sprintf("# %s - Removed because allowlisted by parent/apex %s", domain, p))
							}
							statsAllowlisted++
							break
						}
					}
				}
				if allowed {
					continue
				}
			}

			if activeTopN != nil && len(activeTopN) > 0 {
				inTopN := false
				for _, p := range parents {
					if _, ok := activeTopN[p]; ok {
						inTopN = true
						break
					}
				}
				if !inTopN {
					if !suppressComments {
						removedLogGeneral = append(removedLogGeneral, fmt.Sprintf("# %s - Removed because not present in Top-N list", domain))
					}
					statsTopN++
					continue
				}
			}

			filteredBlocks[domain] = struct{}{}
		}

		logMsg(fmt.Sprintf("Executing O(N log N) subdomain deduplication %s...", passName))

		revList := make([]string, 0, len(filteredBlocks))
		for k := range filteredBlocks {
			revList = append(revList, reverseStr(k))
		}
		sort.Strings(revList)

		finalActive := make(map[string]struct{})
		lastKept := ""

		for _, curr := range revList {
			if lastKept != "" && strings.HasPrefix(curr, lastKept) && len(curr) > len(lastKept) && curr[len(lastKept)] == '.' {
				if !suppressComments {
					removedLogDedup = append(removedLogDedup, fmt.Sprintf("# %s - Removed because redundant to blocked parent domain %s", reverseStr(curr), reverseStr(lastKept)))
				}
				statsDeduped++
				continue
			}
			finalActive[reverseStr(curr)] = struct{}{}
			lastKept = curr
		}

		logMsg(fmt.Sprintf("--- Stage 6: Generating Outputs %s ---", passName))

		adblockRules := make(map[string][]string)
		var standaloneAllows []string
		statsAllowIgnored := 0

		for allowDom := range allowDomains {
			// Ensure corrupted allow domains are skipped without polluting the firewall configurations natively.
			if !isValidDomainStructural(allowDom, lessStrict, allowTLD) || hasNumericTLD(allowDom) {
				continue
			}

			hasBlockedParent := false
			for _, parent := range getParents(allowDom) {
				if parent != allowDom {
					if _, exists := finalActive[parent]; exists {
						adblockRules[parent] = append(adblockRules[parent], allowDom)
						hasBlockedParent = true
						usedAllows[allowDom] = struct{}{}

						if outputFmt == "all" || outputFmt == "domain" || outputFmt == "dnsmasq" || outputFmt == "unbound" || outputFmt == "rpz" || outputFmt == "routedns" || outputFmt == "squid" {
							if !suppressComments {
								removedLogParentBlocked = append(removedLogParentBlocked, fmt.Sprintf("# %s - Allowlisted but blocked by parent domain %s", allowDom, parent))
							}
							statsAllowIgnored++
						}
						break
					}
				}
			}

			if !hasBlockedParent {
				if !optimizeAllow {
					standaloneAllows = append(standaloneAllows, allowDom)
				} else if _, ok := usedAllows[allowDom]; ok {
					standaloneAllows = append(standaloneAllows, allowDom)
				}
			}
		}

		var finalAllows map[string]struct{}
		if optimizeAllow {
			finalAllows = usedAllows
			for dom := range allowDomains {
				// We also drop invalid allowlists directly preventing broken config generations
				if !isValidDomainStructural(dom, lessStrict, allowTLD) || hasNumericTLD(dom) {
					continue
				}
				if _, ok := usedAllows[dom]; !ok {
					if !suppressComments {
						removedLogUnusedAllows = append(removedLogUnusedAllows, fmt.Sprintf("# %s - Removed from allowlist because it is unused", dom))
					}
				}
			}
		} else {
			finalAllows = make(map[string]struct{})
			for dom := range allowDomains {
				if isValidDomainStructural(dom, lessStrict, allowTLD) && !hasNumericTLD(dom) {
					finalAllows[dom] = struct{}{}
				}
			}
		}

		hasAllowPayload := len(finalAllows) > 0
		outputFormats := []string{outputFmt}
		if outputFmt == "all" {
			outputFormats = []string{"domain", "hosts", "adblock", "dnsmasq", "unbound", "rpz", "routedns", "squid"}
		}

		for _, fmtType := range outputFormats {
			var outBlockName, outAllowName string

			if outputFmt == "all" {
				switch fmtType {
				case "adblock":
					outBlockName = filepath.Join(allDir, fmt.Sprintf("adblock%s.txt", extSuffix))
				case "domain":
					outBlockName = filepath.Join(allDir, fmt.Sprintf("plain.black.domain%s.list", extSuffix))
					outAllowName = filepath.Join(allDir, fmt.Sprintf("plain.white.domain%s.list", extSuffix))
				case "hosts":
					outBlockName = filepath.Join(allDir, fmt.Sprintf("plain.black.hosts%s.list", extSuffix))
					outAllowName = filepath.Join(allDir, fmt.Sprintf("plain.white.hosts%s.list", extSuffix))
				case "dnsmasq":
					outBlockName = filepath.Join(allDir, fmt.Sprintf("dnsmasq-filter%s.conf", extSuffix))
				case "unbound":
					outBlockName = filepath.Join(allDir, fmt.Sprintf("unbound-filter%s.conf", extSuffix))
				case "rpz":
					outBlockName = filepath.Join(allDir, fmt.Sprintf("db.black%s.rpz", extSuffix))
					outAllowName = filepath.Join(allDir, fmt.Sprintf("db.white%s.rpz", extSuffix))
				case "routedns":
					outBlockName = filepath.Join(allDir, fmt.Sprintf("routedns.blocklist.domain%s.list", extSuffix))
					outAllowName = filepath.Join(allDir, fmt.Sprintf("routedns.allowlist.domain%s.list", extSuffix))
				case "squid":
					outBlockName = filepath.Join(allDir, fmt.Sprintf("squid.black.dstdomain%s.acl", extSuffix))
					outAllowName = filepath.Join(allDir, fmt.Sprintf("squid.allow.dstdomain%s.acl", extSuffix))
				}
			} else {
				outBlockName = outBlocklist
				outAllowName = outAllowlist
			}

			currHasBlock := len(finalActive) > 0
			if fmtType == "hosts" {
				currHasBlock = len(filteredBlocks) > 0
			}
			if fmtType == "adblock" && outAllowName == "" && len(standaloneAllows) > 0 {
				currHasBlock = true
			}

			var outBlock, outAllow *os.File
			var err error

			if outBlockName != "" && currHasBlock {
				outBlock, err = os.Create(outBlockName)
				if err != nil {
					log.Fatal(err)
				}
				defer outBlock.Close()
			} else if outputFmt != "all" && currHasBlock {
				outBlock = os.Stdout
			}

			if outAllowName != "" && hasAllowPayload {
				outAllow, err = os.Create(outAllowName)
				if err != nil {
					log.Fatal(err)
				}
				defer outAllow.Close()
			}

			if outBlock != nil {
				if fmtType == "adblock" {
					outBlock.WriteString(fmt.Sprintf("[Adblock Plus]\n! version: %d\n", time.Now().Unix()))
				} else if fmtType == "rpz" {
					outBlock.WriteString("$TTL 3600\n@ IN SOA localhost. root.localhost. 1 3600 900 2592000 300\n")
				}
			}

			if outAllow != nil {
				if fmtType == "adblock" {
					outAllow.WriteString(fmt.Sprintf("[Adblock Plus]\n! version: %d\n", time.Now().Unix()))
				} else if fmtType == "rpz" {
					outAllow.WriteString("$TTL 3600\n@ IN SOA localhost. root.localhost. 1 3600 900 2592000 300\n")
				}

				var allowSlice []string
				for k := range finalAllows {
					allowSlice = append(allowSlice, k)
				}
				sort.Strings(allowSlice)

				for _, dom := range allowSlice {
					switch fmtType {
					case "adblock":
						outAllow.WriteString(fmt.Sprintf("@@||%s^\n", dom))
					case "rpz":
						outAllow.WriteString(fmt.Sprintf("%s CNAME rpz-passthru.\n*.%s CNAME rpz-passthru.\n", dom, dom))
					case "routedns", "squid":
						outAllow.WriteString(fmt.Sprintf(".%s\n", dom))
					default:
						outAllow.WriteString(fmt.Sprintf("%s\n", dom))
					}
				}
			} else if fmtType == "adblock" && len(standaloneAllows) > 0 && outBlock != nil {
				sort.Strings(standaloneAllows)
				for _, dom := range standaloneAllows {
					outBlock.WriteString(fmt.Sprintf("@@||%s^\n", dom))
				}
			}

			if outBlock != nil {
				var outputItems []string
				if fmtType == "hosts" {
					for k := range filteredBlocks {
						outputItems = append(outputItems, k)
					}
				} else {
					for k := range finalActive {
						outputItems = append(outputItems, k)
					}
				}

				if !suppressComments {
					outputItems = append(outputItems, removedLogInvalids...)
					outputItems = append(outputItems, removedLogGeneral...)
					if fmtType != "hosts" {
						outputItems = append(outputItems, removedLogDedup...)
						outputItems = append(outputItems, removedLogParentBlocked...)
					}
					outputItems = append(outputItems, removedLogUnusedAllows...)
					
					// Add conversions natively preserving original state comments
					for _, conv := range conversionLog {
						// Cleanly strip the prefix to avoid slice bound issues
						cleanConv := strings.TrimSpace(strings.TrimPrefix(conv, "#"))
						parts := strings.SplitN(cleanConv, " - ", 2)
						if len(parts) == 2 {
							domCheck := parts[0]
							exists := false
							if fmtType == "hosts" {
								_, exists = filteredBlocks[domCheck]
							} else {
								_, exists = finalActive[domCheck]
							}
							if exists {
								outputItems = append(outputItems, conv)
							}
						}
					}
				}

				sort.Slice(outputItems, func(i, j int) bool {
					cleanI := extractDomainForSort(outputItems[i])
					cleanJ := extractDomainForSort(outputItems[j])

					var cmpI, cmpJ string
					if sortAlgo == "alphabetically" {
						cmpI = cleanI
						cmpJ = cleanJ
					} else {
						// Default standard routing algorithm natively
						cmpI = reverseStr(cleanI)
						cmpJ = reverseStr(cleanJ)
					}

					// Tie-breaker routing securely aligning comments to nodes
					if cmpI == cmpJ {
						isCommentI := strings.HasPrefix(outputItems[i], "#")
						isCommentJ := strings.HasPrefix(outputItems[j], "#")
						
						// Route comments safely above their functional domain node natively
						if isCommentI != isCommentJ {
							return isCommentI
						}
						// Safe fallback resolving comment-to-comment or node-to-node ties
						return outputItems[i] < outputItems[j]
					}
					return cmpI < cmpJ
				})

				for _, item := range outputItems {
					if strings.HasPrefix(item, "#") {
						cleanComment := strings.TrimSpace(strings.TrimPrefix(item, "#"))
						switch fmtType {
						case "adblock":
							outBlock.WriteString(fmt.Sprintf("! %s\n", cleanComment))
						case "rpz":
							outBlock.WriteString(fmt.Sprintf("; %s\n", cleanComment))
						default:
							outBlock.WriteString(fmt.Sprintf("%s\n", item))
						}
					} else {
						switch fmtType {
						case "hosts":
							outBlock.WriteString(fmt.Sprintf("0.0.0.0 %s\n", item))
						case "dnsmasq":
							outBlock.WriteString(fmt.Sprintf("address=/%s/0.0.0.0\n", item))
						case "unbound":
							outBlock.WriteString(fmt.Sprintf("local-zone: \"%s\" always_nxdomain\n", item))
						case "rpz":
							outBlock.WriteString(fmt.Sprintf("%s CNAME .\n*.%s CNAME .\n", item, item))
						case "routedns", "squid":
							outBlock.WriteString(fmt.Sprintf(".%s\n", item))
						case "adblock":
							if exc, ok := adblockRules[item]; ok && len(exc) > 0 {
								sort.Strings(exc)
								outBlock.WriteString(fmt.Sprintf("||%s^$denyallow=%s\n", item, strings.Join(exc, "|")))
							} else {
								outBlock.WriteString(fmt.Sprintf("||%s^\n", item))
							}
						default:
							outBlock.WriteString(fmt.Sprintf("%s\n", item))
						}
					}
				}
			}
		}

		if verbose {
			statsUnusedAllows := 0
			if optimizeAllow {
				statsUnusedAllows = len(validAllowDomainsCounter(allowDomains, lessStrict, allowTLD)) - len(usedAllows)
			}
			logMsg(fmt.Sprintf("========== OPTIMIZATION STATS %s ==========", passName))
			logMsg(fmt.Sprintf("Total Blocklist Domains Read: %d", len(blockDomains)))
			logMsg(fmt.Sprintf("Removed (Structural/TLD)    : %d", statsInvalidStruct))
			logMsg(fmt.Sprintf("Removed (RFC Invalid)       : %d", statsInvalidRFC))
			logMsg(fmt.Sprintf("Removed (Allowlisted)       : %d", statsAllowlisted))
			logMsg(fmt.Sprintf("Removed (Not in Top-N)      : %d", statsTopN))
			logMsg(fmt.Sprintf("Removed (Sub-domain Dedup)  : %d", statsDeduped))
			if optimizeAllow {
				logMsg(fmt.Sprintf("Dropped (Unused Allows)     : %d", statsUnusedAllows))
			}
			if outputFmt == "all" || outputFmt == "domain" || outputFmt == "dnsmasq" || outputFmt == "unbound" || outputFmt == "rpz" || outputFmt == "routedns" || outputFmt == "squid" {
				logMsg(fmt.Sprintf("Ignored Allows (Blocked)    : %d", statsAllowIgnored))
			}
			logMsg("----------------------------------------------------")
			logMsg(fmt.Sprintf("Final Active Domains        : %d (%d in HOSTS format)", len(finalActive), len(filteredBlocks)))
			if outputFmt == "all" || outAllowlist != "" {
				logMsg(fmt.Sprintf("Exported Allowlist Domains  : %d", len(finalAllows)))
			}
			logMsg("====================================================")
		}
	}

	if outputFmt == "all" && len(topnlists) > 0 {
		buildOutputs(nil, "", false)
		buildOutputs(topnDomains, ".top-n", true)
	} else {
		if len(topnlists) > 0 {
			buildOutputs(topnDomains, ".top-n", true)
		} else {
			buildOutputs(nil, "", false)
		}
	}
}

// validAllowDomainsCounter helper function for the verbose output logger cleanly validating lengths
func validAllowDomainsCounter(allowDomains map[string]struct{}, lessStrict bool, allowTLD bool) map[string]struct{} {
	valid := make(map[string]struct{})
	for dom := range allowDomains {
		if isValidDomainStructural(dom, lessStrict, allowTLD) && !hasNumericTLD(dom) {
			valid[dom] = struct{}{}
		}
	}
	return valid
}

