// main.go
/*
==========================================================================
Filename: main.go
Version: 1.0.2
Date: 2026-04-22 17:15 CEST
Update Trail:
  - 1.0.2 (2026-04-22): Fixed runtime panic in getParents slice bounds. Hardened comment trimming.
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
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/net/idna"
)

// stringSlice implements flag.Value to allow multiple CLI arguments.
type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, " ")
}
func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// Global Flags
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
	verbose          bool
)

// Pre-compiled strict regex patterns for domains
var (
	domainPattern        = regexp.MustCompile(`^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z0-9\-]{2,}$`)
	unicodeDomainPattern = regexp.MustCompile(`(?i)^([a-z0-9\x{00a1}-\x{ffff}]([a-z0-9\x{00a1}-\x{ffff}\-]{0,61}[a-z0-9\x{00a1}-\x{ffff}])?\.)+[a-z0-9\x{00a1}-\x{ffff}\-]{2,}$`)
)

func init() {
	flag.Var(&blocklists, "blocklist", "Path(s) or URL(s) to the DNS blocklist(s) (can specify multiple times)")
	flag.Var(&allowlists, "allowlist", "Optional path(s) or URL(s) to the DNS allowlist(s)")
	flag.Var(&topnlists, "topnlist", "Optional path(s) or URL(s) to Top-N list(s)")
	flag.StringVar(&inputFormat, "i", "", "Strictly enforce input format: domain, hosts, adblock, routedns, squid")
	flag.StringVar(&outputFmt, "o", "domain", "Output format: all, domain, hosts, adblock, dnsmasq, unbound, rpz, routedns, squid")
	flag.StringVar(&allDir, "all-dir", "", "Mandatory output directory to use when output is set to 'all'")
	flag.StringVar(&workDir, "w", "", "Directory to save unmodified raw source files")
	flag.StringVar(&sortAlgo, "sort", "domain", "Sorting algorithm: domain, alphabetically, tld")
	flag.StringVar(&outBlocklist, "out-blocklist", "", "File path to write the blocklist output (default: STDOUT)")
	flag.StringVar(&outAllowlist, "out-allowlist", "", "File path to write the allowlist output")
	flag.BoolVar(&optimizeAllow, "optimize-allowlist", false, "Drop unused allowlist entries")
	flag.BoolVar(&suppressComments, "suppress-comments", false, "Suppress audit log of removed domains")
	flag.BoolVar(&verbose, "v", false, "Show progress and statistics on STDERR")
}

// logMsg prints messages to STDERR if verbose mode is enabled.
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

// detectFormat samples lines to heuristically determine the file format.
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

// normalizeDomain sanitizes noisy domain inputs.
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

// parseResult encapsulates extracted metadata from Adblock syntax.
type parseResult struct {
	Domain              string
	IsAllow             bool
	DenyAllow           []string
	OriginalToken       string
	UnicodeOrig         string
	DenyAllowUnicodeMap map[string]string
}

// isASCII checks if a string contains only ASCII characters.
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

	// Drop regex rules
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
						valid := false
						if daOrig != "" {
							valid = unicodeDomainPattern.MatchString(cleanDa) && domainPattern.MatchString(punyDa) && !isFastIP(punyDa)
						} else {
							valid = domainPattern.MatchString(punyDa) && !isFastIP(punyDa)
						}

						if valid {
							res.DenyAllow = append(res.DenyAllow, punyDa)
							if daOrig != "" {
								res.DenyAllowUnicodeMap[punyDa] = daOrig
							}
						}
					}
				}
			} else if mod != "" {
				// Contains strict unrelated modifiers; dump the rule to be safe.
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
		valid := false
		if domOrig != "" {
			valid = unicodeDomainPattern.MatchString(cleanDom) && domainPattern.MatchString(punyDom) && !isFastIP(punyDom)
		} else {
			valid = domainPattern.MatchString(punyDom) && !isFastIP(punyDom)
		}
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

// ParsedLists contains cross-referenced parsed domains.
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
					valid := false
					if domOrig != "" {
						valid = unicodeDomainPattern.MatchString(dom) && domainPattern.MatchString(punyDom) && !isFastIP(punyDom)
					} else {
						valid = domainPattern.MatchString(punyDom) && !isFastIP(punyDom)
					}
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

// getParents yields a slice of domains traveling bottom-up toward the apex.
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

func main() {
	log.SetFlags(0)
	flag.Parse()

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
		var removedLogGeneral, removedLogDedup, removedLogParentBlocked, removedLogUnusedAllows []string
		usedAllows := make(map[string]struct{})

		statsAllowlisted, statsTopN, statsDeduped := 0, 0, 0

		for _, domain := range blockDomains {
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
				if _, ok := usedAllows[dom]; !ok {
					if !suppressComments {
						removedLogUnusedAllows = append(removedLogUnusedAllows, fmt.Sprintf("# %s - Removed from allowlist because it is unused", dom))
					}
				}
			}
		} else {
			finalAllows = allowDomains
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
					outputItems = append(outputItems, removedLogGeneral...)
					if fmtType != "hosts" {
						outputItems = append(outputItems, removedLogDedup...)
						outputItems = append(outputItems, removedLogParentBlocked...)
					}
					outputItems = append(outputItems, removedLogUnusedAllows...)
					
					// Add conversions
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
					cleanI := strings.Split(strings.TrimSpace(strings.TrimPrefix(outputItems[i], "#")), " - ")[0]
					cleanJ := strings.Split(strings.TrimSpace(strings.TrimPrefix(outputItems[j], "#")), " - ")[0]
					
					// Sort order: domain segments reversed, comments last
					revI := reverseStr(cleanI)
					revJ := reverseStr(cleanJ)

					if revI == revJ {
						return strings.HasPrefix(outputItems[i], "#") && !strings.HasPrefix(outputItems[j], "#")
					}
					return revI < revJ
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
				statsUnusedAllows = len(allowDomains) - len(usedAllows)
			}
			logMsg(fmt.Sprintf("========== OPTIMIZATION STATS %s ==========", passName))
			logMsg(fmt.Sprintf("Total Blocklist Domains Read: %d", len(blockDomains)))
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

