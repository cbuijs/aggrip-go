/*
==========================================================================
Filename: clean-dom/formatter.go
Version: 1.1.5-20260424
Date: 2026-04-24 10:46 CEST
Description: Handles deduplication, formatting, layout mapping, output 
             generation, comment injection, and disk writing operations.

Update Trail:
  - 1.1.5 (2026-04-24): Mapped unused allowlist comments to strictly 
                        export to the allowlist output file instead of 
                        polluting the blocklist log natively. Fixed empty 
                        payload file skips.
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
	
	logMsg(fmt.Sprintf("--- Stage 4: Preparing for Deduplication %s ---", passName))
	logMsg(fmt.Sprintf("Sorting %d domains by depth...", len(blockDomains)))

	// Sort blockDomains by depth (dot count) descending to properly sequence subdomains
	sort.Slice(blockDomains, func(i, j int) bool {
		return strings.Count(blockDomains[i], ".") < strings.Count(blockDomains[j], ".")
	})

	if outputFmt == "all" {
		os.MkdirAll(allDir, 0755)
	}
	
	logMsg(fmt.Sprintf("--- Stage 5: Processing & Optimizing %s ---", passName))

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
					removedLogInvalids = append(removedLogInvalids, fmt.Sprintf("# %s - Removed: %v", domain, err))
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
			if err := ValidateDomain(dom, lessStrict, allowTLD); err != nil {
				continue
			}
			if _, ok := usedAllows[dom]; !ok {
				if !suppressComments {
					removedLogUnusedAllows = append(removedLogUnusedAllows, fmt.Sprintf("# %s - Removed from allowlist because it is unused (does not unblock any blacklisted domains)", dom))
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

			// Inject the unused allowlist comments into the allowlist slice directly
			if !suppressComments {
				allowSlice = append(allowSlice, removedLogUnusedAllows...)
			}

			// Sort the allowlist organically pulling comments above their functional nodes
			sort.Slice(allowSlice, func(i, j int) bool {
				cleanI := extractDomainForSort(allowSlice[i])
				cleanJ := extractDomainForSort(allowSlice[j])

				var cmpI, cmpJ string
				if sortAlgo == "alphabetically" {
					cmpI = cleanI
					cmpJ = cleanJ
				} else {
					cmpI = reverseStr(cleanI)
					cmpJ = reverseStr(cleanJ)
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
						outAllow.WriteString(fmt.Sprintf("! %s\n", cleanComment))
					case "rpz":
						outAllow.WriteString(fmt.Sprintf("; %s\n", cleanComment))
					default:
						outAllow.WriteString(fmt.Sprintf("# %s\n", cleanComment))
					}
					continue
				}

				switch fmtType {
				case "adblock":
					outAllow.WriteString(fmt.Sprintf("@@||%s^\n", item))
				case "rpz":
					outAllow.WriteString(fmt.Sprintf("%s CNAME rpz-passthru.\n*.%s CNAME rpz-passthru.\n", item, item))
				case "routedns", "squid":
					outAllow.WriteString(fmt.Sprintf(".%s\n", item))
				default:
					outAllow.WriteString(fmt.Sprintf("%s\n", item))
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
				
				// Only map unused allows to the blocklist if a separate allowlist file was NOT generated
				if outAllow == nil {
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
						outBlock.WriteString(fmt.Sprintf("# %s\n", cleanComment))
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
		logMsg(fmt.Sprintf("Removed (Invalid/Unregistered): %d", statsInvalidStruct))
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

