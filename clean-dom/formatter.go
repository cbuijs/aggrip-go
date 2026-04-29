/*
==========================================================================
Filename: clean-dom/formatter.go
Version: 1.1.12-20260429
Date: 2026-04-29 10:48 CEST
Description: Handles deduplication, formatting, layout mapping, output 
             generation, comment injection, and disk writing operations.

Update Trail:
  - 1.1.12 (2026-04-29): Refactored sorting to utilize `aggrip-go/shared`
                         centralized ReverseStr helper directly.
  - 1.1.11 (2026-04-25): Implemented high-speed HOSTS compression routing 
                         via capacity-bound slice buffers. Natively groups
                         domains per IP address eliminating output bloat.
  - 1.1.10 (2026-04-25): Refactored comment generation formats to strictly
                         align output comments with their target apex domains
                         regardless of the sort algorithm applied. Stripped
                         a bug causing standalone allowlist entries to be 
                         duplicated natively in unified Adblock payloads.
  - 1.1.9 (2026-04-24): Resolved function redeclaration conflict. Renamed 
                        extractDomainForSort to extractSortKey natively to 
                        prevent collision with validator.go.
  - 1.1.8 (2026-04-24): Enforced unified file priority sequence. Allowlist 
                        entries are now strictly guaranteed to output before 
                        blocklist entries across all supporting formats 
                        (Adblock, RPZ, Dnsmasq, Unbound). Adblock natively 
                        deduplicates @@|| when $denyallow is active.
  - 1.1.7 (2026-04-24): Refactored Dnsmasq and Unbound formatting to strictly 
                        output unified configs. Allowlist entries are mapped 
                        directly to the top of the generated config payload 
                        using server=/domain/# and transparent parameters.
                        Switched Dnsmasq blocks to server=/domain/ natively.
==========================================================================
*/

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aggrip-go/shared"
)

// buildOutputs executes deduplication, formatting, comment mapping, and generates target files natively.
func buildOutputs(
	blockDomains []string,
	allowDomains map[string]struct{},
	denyAllowOverrides map[string]struct{},
	conversionLog []string,
	activeTopN map[string]struct{},
	extSuffix string,
	isTopNPass bool,
) {
	passName := "(Full List)"
	if isTopNPass {
		passName = "(Top-N)"
	}
	
	logMsg("--- Stage 4: Preparing for Deduplication %s ---", passName)
	logMsg("Sorting %d domains by depth...", len(blockDomains))

	// Sort blockDomains by depth (dot count) descending to properly sequence subdomains
	sort.Slice(blockDomains, func(i, j int) bool {
		return strings.Count(blockDomains[i], ".") < strings.Count(blockDomains[j], ".")
	})

	if outputFmt == "all" {
		os.MkdirAll(allDir, 0755)
	}
	
	logMsg("--- Stage 5: Processing & Optimizing %s ---", passName)

	filteredBlocks := make(map[string]struct{})
	var removedLogGeneral, removedLogDedup, removedLogParentBlocked, removedLogUnusedAllows, removedLogInvalids []string
	usedAllows := make(map[string]struct{})
	loggedInvalids := make(map[string]struct{})

	statsAllowlisted, statsTopN, statsDeduped, statsInvalidStruct := 0, 0, 0, 0

	for _, domain := range blockDomains {
		// Validates structural boundaries, strict RFC limits, and embedded TLD dictionaries.
		// Detailed error strings automatically drive dynamic, noise-free output logs.
		err := ValidateDomain(domain, lessStrict, allowTLD)
		if err != nil {
			if _, exists := loggedInvalids[domain]; !exists {
				loggedInvalids[domain] = struct{}{}
				if !suppressComments {
					// Format aligned to map the specific domain safely above its apex equivalent
					removedLogInvalids = append(removedLogInvalids, fmt.Sprintf("# %s - Removed (Invalid): %v", domain, err))
				}
				statsInvalidStruct++
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
							// Formats the comment to explicitly extract and map against the parent/apex node natively
							removedLogGeneral = append(removedLogGeneral, fmt.Sprintf("# %s - Allowlisted subdomain removed: %s", p, domain))
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
					removedLogGeneral = append(removedLogGeneral, fmt.Sprintf("# %s - Removed (Not in Top-N list)", domain))
				}
				statsTopN++
				continue
			}
		}

		filteredBlocks[domain] = struct{}{}
	}

	logMsg("Executing O(N log N) subdomain deduplication %s...", passName)

	revList := make([]string, 0, len(filteredBlocks))
	for k := range filteredBlocks {
		revList = append(revList, shared.ReverseStr(k))
	}
	sort.Strings(revList)

	finalActive := make(map[string]struct{})
	lastKept := ""

	for _, curr := range revList {
		if lastKept != "" && strings.HasPrefix(curr, lastKept) && len(curr) > len(lastKept) && curr[len(lastKept)] == '.' {
			if !suppressComments {
				// Formats the comment placing the apex natively first for proper alphabetical sequence alignment
				removedLogDedup = append(removedLogDedup, fmt.Sprintf("# %s - Redundant subdomain removed: %s", shared.ReverseStr(lastKept), shared.ReverseStr(curr)))
			}
			statsDeduped++
			continue
		}
		finalActive[shared.ReverseStr(curr)] = struct{}{}
		lastKept = curr
	}

	logMsg("--- Stage 6: Generating Outputs %s ---", passName)

	adblockRules := make(map[string][]string)
	var standaloneAllows []string
	statsAllowIgnored := 0

	for allowDom := range allowDomains {
		// Ensure corrupted allow domains are skipped without polluting the firewall configurations natively.
		if err := ValidateDomain(allowDom, lessStrict, allowTLD); err != nil {
			continue
		}

		hasBlockedParent := false
		for _, parent := range getParents(allowDom) {
			if parent != allowDom {
				if _, exists := finalActive[parent]; exists {
					adblockRules[parent] = append(adblockRules[parent], allowDom)
					hasBlockedParent = true
					usedAllows[allowDom] = struct{}{}

					// Subdomains unblocked within a blocked parent scope act logarithmically differently than standard files
					if outputFmt != "hosts" {
						if !suppressComments {
							removedLogParentBlocked = append(removedLogParentBlocked, fmt.Sprintf("# %s - Explicitly allowed subdomain mapped: %s", parent, allowDom))
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
			if err := ValidateDomain(dom, lessStrict, allowTLD); err != nil {
				continue
			}
			if _, ok := usedAllows[dom]; !ok {
				if !suppressComments {
					removedLogUnusedAllows = append(removedLogUnusedAllows, fmt.Sprintf("# %s - Removed from allowlist (Unused)", dom))
				}
			}
		}
	} else {
		finalAllows = make(map[string]struct{})
		for dom := range allowDomains {
			if err := ValidateDomain(dom, lessStrict, allowTLD); err == nil {
				finalAllows[dom] = struct{}{}
			}
		}
	}

	hasAllowPayload := len(finalAllows) > 0 || (optimizeAllow && !suppressComments && len(removedLogUnusedAllows) > 0)
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

		// Dynamically reroute the allowlist payload directly into the blocklist output file 
		// explicitly for unified configuration structures (Dnsmasq, Unbound, Adblock, RPZ).
		var targetAllow *os.File
		if outAllow != nil {
			targetAllow = outAllow
			if fmtType == "adblock" {
				targetAllow.WriteString(fmt.Sprintf("[Adblock Plus]\n! version: %d\n", time.Now().Unix()))
			} else if fmtType == "rpz" {
				targetAllow.WriteString("$TTL 3600\n@ IN SOA localhost. root.localhost. 1 3600 900 2592000 300\n")
			}
		} else if outBlock != nil && (fmtType == "dnsmasq" || fmtType == "unbound" || fmtType == "adblock" || fmtType == "rpz") {
			targetAllow = outBlock
		}

		if targetAllow != nil && hasAllowPayload {
			var allowSlice []string

			// In unified Adblock output, we use standaloneAllows to prevent 
			// redundant @@|| rules for domains already mapped to $denyallow overrides.
			if fmtType == "adblock" && outAllow == nil {
				allowSlice = append(allowSlice, standaloneAllows...)
			} else {
				for k := range finalAllows {
					allowSlice = append(allowSlice, k)
				}
			}

			// Inject the unused allowlist comments into the allowlist slice directly
			if !suppressComments {
				allowSlice = append(allowSlice, removedLogUnusedAllows...)
			}

			// Sort the allowlist organically pulling comments above their functional nodes
			sort.Slice(allowSlice, func(i, j int) bool {
				cleanI := extractSortKey(allowSlice[i])
				cleanJ := extractSortKey(allowSlice[j])

				var cmpI, cmpJ string
				if sortAlgo == "alphabetically" {
					cmpI = cleanI
					cmpJ = cleanJ
				} else {
					cmpI = shared.ReverseStr(cleanI)
					cmpJ = shared.ReverseStr(cleanJ)
				}

				if cmpI == cmpJ {
					isCommentI := strings.HasPrefix(allowSlice[i], "#")
					isCommentJ := strings.HasPrefix(allowSlice[j], "#")
					if isCommentI != isCommentJ {
						return isCommentI
					}
					return allowSlice[i] < allowSlice[j]
				}
				return cmpI < cmpJ
			})

			for _, item := range allowSlice {
				if strings.HasPrefix(item, "#") {
					cleanComment := strings.TrimSpace(strings.TrimPrefix(item, "#"))
					switch fmtType {
					case "adblock":
						targetAllow.WriteString(fmt.Sprintf("! %s\n", cleanComment))
					case "rpz":
						targetAllow.WriteString(fmt.Sprintf("; %s\n", cleanComment))
					default:
						targetAllow.WriteString(fmt.Sprintf("# %s\n", cleanComment))
					}
					continue
				}

				switch fmtType {
				case "adblock":
					targetAllow.WriteString(fmt.Sprintf("@@||%s^\n", item))
				case "rpz":
					targetAllow.WriteString(fmt.Sprintf("%s CNAME rpz-passthru.\n*.%s CNAME rpz-passthru.\n", item, item))
				case "routedns", "squid":
					targetAllow.WriteString(fmt.Sprintf(".%s\n", item))
				case "dnsmasq":
					targetAllow.WriteString(fmt.Sprintf("server=/%s/#\n", item))
				case "unbound":
					targetAllow.WriteString(fmt.Sprintf("local-zone: \"%s\" transparent\n", item))
				default:
					targetAllow.WriteString(fmt.Sprintf("%s\n", item))
				}
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
				
				// Only map unused allows to the blocklist if a separate allowlist file was NOT generated
				// AND we didn't explicitly route them dynamically to outBlock natively via targetAllow priority.
				if outAllow == nil && fmtType != "dnsmasq" && fmtType != "unbound" && fmtType != "adblock" && fmtType != "rpz" {
					outputItems = append(outputItems, removedLogUnusedAllows...)
				}
				
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
				cleanI := extractSortKey(outputItems[i])
				cleanJ := extractSortKey(outputItems[j])

				var cmpI, cmpJ string
				if sortAlgo == "alphabetically" {
					cmpI = cleanI
					cmpJ = cleanJ
				} else {
					// Default standard routing algorithm natively
					cmpI = shared.ReverseStr(cleanI)
					cmpJ = shared.ReverseStr(cleanJ)
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

			// ----------------------------------------------------------------------
			// High-Speed HOSTS Compression Buffer
			// Capacity is strictly pre-allocated directly mapping to the target limit
			// completely preventing runtime array reallocation overhead.
			// ----------------------------------------------------------------------
			var hostsBuffer []string
			if compressHosts.Active {
				hostsBuffer = make([]string, 0, compressHosts.Value)
			}

			// Inline closure isolating the compression flush cleanly safely mapping to disk
			flushHosts := func() {
				if len(hostsBuffer) > 0 {
					outBlock.WriteString(fmt.Sprintf("0.0.0.0 %s\n", strings.Join(hostsBuffer, " ")))
					hostsBuffer = hostsBuffer[:0]
				}
			}

			for _, item := range outputItems {
				if strings.HasPrefix(item, "#") {
					cleanComment := strings.TrimSpace(strings.TrimPrefix(item, "#"))

					// Force an immediate buffer flush securely mapping hosts directly before
					// formatting structural logs to strictly protect context alignments.
					if fmtType == "hosts" && compressHosts.Active {
						flushHosts()
					}

					switch fmtType {
					case "adblock":
						outBlock.WriteString(fmt.Sprintf("! %s\n", cleanComment))
					case "rpz":
						outBlock.WriteString(fmt.Sprintf("; %s\n", cleanComment))
					default:
						outBlock.WriteString(fmt.Sprintf("# %s\n", cleanComment))
					}
				} else {
					switch fmtType {
					case "hosts":
						if compressHosts.Active {
							hostsBuffer = append(hostsBuffer, item)
							if len(hostsBuffer) >= compressHosts.Value {
								flushHosts()
							}
						} else {
							outBlock.WriteString(fmt.Sprintf("0.0.0.0 %s\n", item))
						}
					case "dnsmasq":
						outBlock.WriteString(fmt.Sprintf("server=/%s/\n", item))
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

			// Trap any residual hosts natively leftover following execution completion
			if fmtType == "hosts" && compressHosts.Active {
				flushHosts()
			}
		}
	}

	if verbose {
		statsUnusedAllows := 0
		if optimizeAllow {
			statsUnusedAllows = len(validAllowDomainsCounter(allowDomains, lessStrict, allowTLD)) - len(usedAllows)
		}
		logMsg("========== OPTIMIZATION STATS %s ==========", passName)
		logMsg("Total Blocklist Domains Read: %d", len(blockDomains))
		logMsg("Removed (Invalid/Unregistered): %d", statsInvalidStruct)
		logMsg("Removed (Allowlisted)       : %d", statsAllowlisted)
		logMsg("Removed (Not in Top-N)      : %d", statsTopN)
		logMsg("Removed (Sub-domain Dedup)  : %d", statsDeduped)
		if optimizeAllow {
			logMsg("Dropped (Unused Allows)     : %d", statsUnusedAllows)
		}
		if outputFmt != "hosts" {
			logMsg("Ignored Allows (Blocked)    : %d", statsAllowIgnored)
		}
		logMsg("----------------------------------------------------")
		logMsg("Final Active Domains        : %d (%d in HOSTS format)", len(finalActive), len(filteredBlocks))
		if outputFmt == "all" || outAllowlist != "" {
			logMsg("Exported Allowlist Domains  : %d", len(finalAllows))
		}
		logMsg("====================================================")
	}
}

// validAllowDomainsCounter helper function for the verbose output logger cleanly validating lengths
func validAllowDomainsCounter(allowDomains map[string]struct{}, lessStrict bool, allowTLD bool) map[string]struct{} {
	valid := make(map[string]struct{})
	for dom := range allowDomains {
		if err := ValidateDomain(dom, lessStrict, allowTLD); err == nil {
			valid[dom] = struct{}{}
		}
	}
	return valid
}

// extractSortKey strictly pulls the root domain from a string array index safely handling comments and Adblock prefixes
func extractSortKey(item string) string {
	if strings.HasPrefix(item, "#") {
		clean := strings.TrimSpace(strings.TrimPrefix(item, "#"))
		return strings.SplitN(clean, " - ", 2)[0]
	}
	if strings.HasPrefix(item, "@@||") {
		return strings.TrimPrefix(item, "@@||")
	}
	return item
}

