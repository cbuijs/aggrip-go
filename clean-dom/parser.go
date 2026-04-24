/*
==========================================================================
Filename: clean-dom/parser.go
Version: 1.1.5-20260424
Date: 2026-04-24 20:09 CEST
Description: Handles file I/O, format detection, Adblock translation, 
             and parallel bulk ingestion of raw list payloads. Strict
             path rejection protects DNS zone integrity.

Update Trail:
  - 1.1.5 (2026-04-24): Implemented trailing slash handler for Handshake (HNS) 
                        domains (e.g. "domain/"). URLs and standard domains 
                        with paths are strictly rejected natively.
  - 1.1.4 (2026-04-24): Added explicit block intent parsing. Adblock syntax 
                        (||) now strictly overrides file-level defaults, 
                        routing base domains and $denyallow targets 
                        correctly regardless of the source file type.
  - 1.1.3 (2026-04-24): Removed forceAllow from parseDomainToken. Token 
                        parsing is now completely context-agnostic.
  - 1.1.2 (2026-04-24): Fixed $denyallow modifier logic. Enforces strict 
                        subdomain validation, ignores contradictory modifiers 
                        on allowlist rules, and correctly maps extracted 
                        denyallow targets directly to the allowlist pipeline.
==========================================================================
*/

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"golang.org/x/net/idna"
)

// ParsedLists contains cross-referenced parsed domains globally mapped.
type ParsedLists struct {
	Blocks      []string
	Allows      []string
	DenyAllows  []string
	Conversions []string
}

// parseResult encapsulates extracted metadata from complex syntax parsing.
type parseResult struct {
	Domain              string
	IsAllow             bool
	IsBlock             bool // Captures explicit block intent (e.g., ||)
	DenyAllow           []string
	OriginalToken       string
	UnicodeOrig         string
	DenyAllowUnicodeMap map[string]string
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

// isASCII checks if a string contains only ASCII characters. Fast validation path.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// stripHnsSlash safely evaluates if a token with a trailing slash is a valid 
// Handshake (HNS) domain. If verified, it strips the slash for internal processing.
// If it is a standard URL or invalid path, it returns an empty string to signal rejection.
func stripHnsSlash(token string) string {
	if !strings.Contains(token, "/") {
		return token
	}
	
	// Ensure the slash is exclusively at the very end of the string.
	// This inherently blocks URLs containing inline paths (e.g., domain.com/ads/)
	if strings.Index(token, "/") == len(token)-1 {
		cleanNoSlash := token[:len(token)-1]
		
		// Normalize to extract the true base domain without Adblock syntax (like ||)
		norm := normalizeDomain(cleanNoSlash)
		if norm == "" {
			return ""
		}
		
		parts := strings.Split(norm, ".")
		tld := parts[len(parts)-1]
		
		// Strictly enforce that the resolved TLD exists in the Handshake dictionary.
		// Protects against non-HNS strings mistakenly attempting to pass a trailing slash.
		if IsHNSTLD(tld) {
			return cleanNoSlash
		}
	}
	return "" // Signal rejection
}

// parseDomainToken evaluates Adblock rules, extracts modifiers ($denyallow), ensures Punycode translation,
// and strictly guarantees logical mapping and parent-subdomain relationship integrities natively.
func parseDomainToken(token string) parseResult {
	origToken := token
	res := parseResult{
		OriginalToken:       origToken,
		DenyAllow:           []string{},
		DenyAllowUnicodeMap: make(map[string]string),
	}

	// 1. Strictly map specific blocklist and allowlist configurations natively.
	// Adblock explicit rule intents ALWAYS override file-level routing.
	if strings.HasPrefix(token, "@@") {
		res.IsAllow = true
		token = token[2:]
	} else if strings.HasPrefix(token, "||") {
		res.IsBlock = true
	}

	// 2. Drop regex rules natively to maintain strict DNS zone integrity.
	if strings.HasPrefix(token, "/") {
		return res
	}

	// 3. Extract the base domain target and segment out the modifiers cleanly.
	domainPart := token
	modifiers := ""
	if strings.Contains(token, "$") {
		parts := strings.SplitN(token, "$", 2)
		domainPart = parts[0]
		modifiers = parts[1]
	}

	// 4. Strict Adblock restriction: Only accept clean domains/hostnames.
	// If the domain part contains a path (indicated by a slash), drop it completely.
	// EXCEPTION: Handshake (HNS) domains are allowed to end with a trailing slash.
	if strings.Contains(domainPart, "/") {
		domainPart = stripHnsSlash(domainPart)
		if domainPart == "" {
			return res
		}
	}

	// 5. Clean and translate base domain via IDNA natively.
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
		valid := !isFastIP(punyDom) && isPlausibleDomain(punyDom)
		if !valid {
			punyDom = ""
		}
	} else {
		punyDom = ""
	}

	// If the core base domain is mathematically invalid or empty, we abort the entire rule.
	if punyDom == "" {
		return res
	}

	res.Domain = punyDom
	res.UnicodeOrig = domOrig

	// 6. Process Modifiers and strictly validate $denyallow logic and relationships.
	if modifiers != "" {
		for _, mod := range strings.Split(modifiers, ",") {
			mod = strings.TrimSpace(mod)
			if strings.HasPrefix(mod, "denyallow=") {
				
				// Logical Collision Check: Discard $denyallow parameters if the base rule is an explicit allowlist rule.
				if res.IsAllow {
					logMsg(fmt.Sprintf("Warning: Ignored contradictory $denyallow modifier in explicit allowlist rule: '%s'", origToken))
					continue
				}

				targets := strings.Split(mod[10:], "|")
				for _, da := range targets {
					da = strings.TrimSpace(da) // Safe measure to prevent bound issues
					
					// Check for Handshake trailing slashes explicitly
					if strings.Contains(da, "/") {
						da = stripHnsSlash(da)
						if da == "" {
							logMsg(fmt.Sprintf("Warning: Ignored $denyallow entry as it appears to be an invalid path/URL in rule '%s'", origToken))
							continue
						}
					}

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
						valid := !isFastIP(punyDa) && isPlausibleDomain(punyDa)
						if valid {
							// Subdomain Integrity Check: Exclusions MUST fall beneath the base domain.
							// For example, if blocking 'domain.com', allowlisting 'other.com' via denyallow is invalid.
							if punyDa == punyDom || strings.HasSuffix(punyDa, "."+punyDom) {
								res.DenyAllow = append(res.DenyAllow, punyDa)
								if daOrig != "" {
									res.DenyAllowUnicodeMap[punyDa] = daOrig
								}
							} else {
								logMsg(fmt.Sprintf("Warning: Ignored $denyallow entry '%s' as it is not a valid subdomain of base '%s' in rule '%s'", punyDa, punyDom, origToken))
							}
						}
					}
				}
			} else if mod != "" {
				// The rule contains strict unrelated modifiers we don't support (like $third-party).
				// We dump the entire rule to be absolutely safe and prevent false positives.
				return parseResult{}
			}
		}
	}

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

// readDomainsBulk orchestrates ingestion, heuristic format evaluation, and data extraction.
func readDomainsBulk(source string, isTopN bool, listType string) ParsedLists {
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

	isAllowList := (listType == "Allowlist")

	processParsed := func(parsed parseResult, rawToken string) {
		// Evaluate the true intent by letting explicit Adblock syntax override the default file type context natively.
		isEffectivelyAllow := parsed.IsAllow || (isAllowList && !parsed.IsBlock)

		if parsed.Domain != "" {
			if isEffectivelyAllow {
				result.Allows = append(result.Allows, parsed.Domain)
			} else {
				result.Blocks = append(result.Blocks, parsed.Domain)
			}
			if parsed.UnicodeOrig != "" {
				result.Conversions = append(result.Conversions, fmt.Sprintf("# %s - Converted from Unicode: %s", parsed.Domain, parsed.UnicodeOrig))
			}
		}

		if len(parsed.DenyAllow) > 0 {
			if isEffectivelyAllow {
				logMsg(fmt.Sprintf("Warning: Ignored $denyallow targets %v from allowlist rule '%s' (redundant).", parsed.DenyAllow, rawToken))
			} else {
				logMsg(fmt.Sprintf("Ingestion: Extracted validated $denyallow domain(s) %v from block rule '%s'. Adding to allowlist.", parsed.DenyAllow, rawToken))
				
				// $denyallow domains extracted strictly from a blocklist rule act as explicit allowlist overrides.
				result.Allows = append(result.Allows, parsed.DenyAllow...)
				
				for puny, orig := range parsed.DenyAllowUnicodeMap {
					result.Conversions = append(result.Conversions, fmt.Sprintf("# %s - Converted from Unicode: %s", puny, orig))
				}
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
				rawDom := strings.TrimSpace(parts[1])
				
				// Handle Handshake trailing slash exceptions natively
				if strings.Contains(rawDom, "/") {
					rawDom = stripHnsSlash(rawDom)
					if rawDom == "" {
						continue
					}
				}

				dom := normalizeDomain(rawDom)
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
					valid := !isFastIP(punyDom) && isPlausibleDomain(punyDom)
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

		// Dynamic format switching: Elevate parsing bounds securely mid-ingestion if an indicator hits.
		if detectedFmt == "mixed" {
			if strings.HasPrefix(firstToken, "@@||") || strings.HasPrefix(firstToken, "||") {
				detectedFmt = "adblock"
				logMsg(fmt.Sprintf("Dynamic format switch: Detected strong Adblock indicators. Switching format to ADBLOCK for %s", source))
			}
		}

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

