/*
==========================================================================
Filename: clean-dom/formatter.go
Version: 1.17.0-20260503
Date: 2026-05-03 18:30 CEST
Description: Handles deduplication, formatting, layout mapping, output 
             generation, comment injection, and disk writing operations.

Update Trail:
  - 1.17.0 (2026-05-03): Comprehensive updates ensuring blocklist and allowlist 
                         outputs uniformly contain explicit audit comments whenever 
                         a domain is modified, converted, eclipsed, or dropped.
                         Fixed apex-mapping conversion log tracking logic.
  - 1.15.0 (2026-05-03): Integrated preferBlocklist logic to selectively invert 
                         collision resolution, allowing blocklists to completely 
                         eclipse overlapping allowlists natively.
  - 1.13.0 (2026-04-29): Purged dead-code loops associated with deprecated 
                         denyAllowOverrides structures, reducing O(N) limits.
  - 1.12.0 (2026-04-29): Removed dead code wrapper validAllowDomainsCounter.
                         Calculates unused allowlist stats natively during
                         the primary optimization loop avoiding O(N) penalty.
  - 1.10.0 (2026-04-29): Replaced heavy ReverseStr rune allocations with 
                         ReverseASCII zero-copy byte mapping. Punycode 
                         guarantees ASCII compliance safely. Drastically 
                         reduces GC load during O(N log N) sorting.
  - 1.9.0 (2026-04-29): Resolved critical unbuffered I/O performance bottleneck
                        by wrapping outBlock and outAllow in central 1MB Writers.
  - 1.8.0 (2026-04-29): Purged AI-hallucinated adverb trails from documentation 
                        to maintain enterprise code quality and clarity.
  - 1.6.0 (2026-04-29): Replaced local getParents with centralized shared.GetDomainParents.
  - 1.3.0 (2026-04-29): Added heavy verbose commentary natively mapping explicitly
                        detailed algorithms strictly aligning documentation.
  - 1.2.0 (2026-04-29): Standardized calls to central shared validation libraries.
  - 1.1.12 (2026-04-29): Refactored sorting to utilize `aggrip-go/shared`
                         centralized ReverseStr helper directly.
  - 1.1.11 (2026-04-25): Implemented high-speed HOSTS compression routing.
==========================================================================
*/

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aggrip-go/shared"
)

// buildOutputs executes deduplication, formatting, comment mapping, and generates target files.
// Coordinates parent-subdomain relationship structures logically.
func buildOutputs(
	blockDomains []string,
	allowDomains map[string]struct{},
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

	// Sort blockDomains by depth (dot count) descending to properly sequence subdomains.
	// Pushing deeply nested arrays to the top enables single-pass parent coverage matrices.
	sort.Slice(blockDomains, func(i, j int) bool {
		return strings.Count(blockDomains[i], ".") < strings.Count(blockDomains[j], ".")
	})

	if outputFmt == "all" {
		os.MkdirAll(allDir, 0755)
	}

	logMsg("--- Stage 5: Processing & Optimizing %s ---", passName)

	filteredBlocks := make(map[string]struct{})
	
	// Distinct audit log trackers providing transparent mapping across output environments natively.
	var removedLogGeneral, removedLogDedup, removedLogParentBlocked, removedLogUnusedAllows, removedLogInvalids []string
	var removedLogInvalidAllows, removedLogEclipsedAllows []string

	usedAllows := make(map[string]struct{})
	loggedInvalids := make(map[string]struct{})

	statsAllowlisted, statsTopN, statsDeduped, statsInvalidStruct := 0, 0, 0, 0
	statsEclipsedAllows, statsInvalidAllows := 0, 0

	for _, domain := range blockDomains {
		// Validates structural boundaries, strict RFC limits, and embedded TLD dictionaries.
		// Detailed error strings automatically drive dynamic, noise-free output logs.
		err := shared.ValidateDomain(domain, lessStrict, allowTLD)
		if err != nil {
			if _, exists := loggedInvalids[domain]; !exists {
				loggedInvalids[domain] = struct{}{}
				if !suppressComments {
					// Format aligned to map the specific domain safely above its apex equivalent.
					removedLogInvalids = append(removedLogInvalids, fmt.Sprintf("# %s - Removed from blocklist (Invalid): %v", domain, err))
				}
				statsInvalidStruct++
			}
			continue
		}

		parents := shared.GetDomainParents(domain)
		allowed := false

		// Explode hierarchy traversing deeply checking explicit exclusions dynamically.
		if len(allowDomains) > 0 {
			for _, p := range parents {
				if _, exists := allowDomains[p]; exists {
					// Enforce symmetric priority based on preferBlocklist constraints.
					// If blocklist holds priority, we completely ignore allowlist intersections during block generation.
					if !preferBlocklist {
						usedAllows[p] = struct{}{}
						allowed = true
						if !suppressComments {
							// Formats the comment to explicitly extract and map against the parent/apex node.
							removedLogGeneral = append(removedLogGeneral, fmt.Sprintf("# %s - Removed from blocklist (Covered by allowlist rule %s)", domain, p))
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
					removedLogGeneral = append(removedLogGeneral, fmt.Sprintf("# %s - Removed from blocklist (Not in Top-N list)", domain))
				}
				statsTopN++
				continue
			}
		}

		filteredBlocks[domain] = struct{}{}
	}

	logMsg("Executing O(N log N) subdomain deduplication %s...", passName)

	// Invert strings entirely aligning domains allowing lexicographical parent/child bounds.
	// Reversal maps arrays accurately. Example: moc.elpmaxe < moc.elpmaxe.bus
	// ReverseASCII is strictly safe here because domains are guaranteed Punycode (ASCII) via IDNA.
	revList := make([]string, 0, len(filteredBlocks))
	for k := range filteredBlocks {
		revList = append(revList, shared.ReverseASCII(k))
	}
	sort.Strings(revList)

	finalActive := make(map[string]struct{})
	lastKept := ""

	// Iterate linearly directly compressing string limits evaluating relationships.
	for _, curr := range revList {
		// Strict structural parity matching guaranteeing precise collision verification.
		if lastKept != "" && strings.HasPrefix(curr, lastKept) && len(curr) > len(lastKept) && curr[len(lastKept)] == '.' {
			if !suppressComments {
				// Formats the comment placing the apex first for proper alphabetical sequence alignment.
				removedLogDedup = append(removedLogDedup, fmt.Sprintf("# %s - Removed from blocklist (Redundant subdomain of %s)", shared.ReverseASCII(curr), shared.ReverseASCII(lastKept)))
			}
			statsDeduped++
			continue
		}
		finalActive[shared.ReverseASCII(curr)] = struct{}{}
		lastKept = curr
	}

	logMsg("--- Stage 6: Generating Outputs %s ---", passName)

	adblockRules := make(map[string][]string)
	var standaloneAllows []string
	statsAllowIgnored := 0

	for allowDom := range allowDomains {
		// Ensure corrupted allow domains are safely trapped, skipping them and pushing audit comments.
		if err := shared.ValidateDomain(allowDom, lessStrict, allowTLD); err != nil {
			if !suppressComments {
				removedLogInvalidAllows = append(removedLogInvalidAllows, fmt.Sprintf("# %s - Removed from allowlist (Invalid): %v", allowDom, err))
			}
			statsInvalidAllows++
			continue
		}

		hasBlockedParent := false
		isEclipsed := false

		for _, parent := range shared.GetDomainParents(allowDom) {
			if _, exists := finalActive[parent]; exists {
				if !preferBlocklist {
					if parent != allowDom {
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
				} else {
					// Inverted priority: The allow domain is completely eclipsed and disabled by the block parent
					isEclipsed = true
					if !suppressComments {
						msg := fmt.Sprintf("# %s - Removed from allowlist (Eclipsed by blocklist match: %s)", allowDom, parent)
						removedLogParentBlocked = append(removedLogParentBlocked, msg) // Audit trail mapped into blocklist
						removedLogEclipsedAllows = append(removedLogEclipsedAllows, msg) // Audit trail mapped into allowlist
					}
					statsEclipsedAllows++
					break
				}
			}
		}

		if !preferBlocklist {
			if !hasBlockedParent {
				if !optimizeAllow {
					standaloneAllows = append(standaloneAllows, allowDom)
				} else if _, ok := usedAllows[allowDom]; ok {
					standaloneAllows = append(standaloneAllows, allowDom)
				}
			}
		} else {
			if !isEclipsed {
				if !optimizeAllow {
					standaloneAllows = append(standaloneAllows, allowDom)
				}
			}
		}
	}

	var finalAllows map[string]struct{}
	statsUnusedAllows := 0 // Tracks locally preventing full structural revalidation loops later

	if optimizeAllow {
		if !preferBlocklist {
			finalAllows = usedAllows
			for dom := range allowDomains {
				// We also drop invalid allowlists directly preventing broken config generations.
				if err := shared.ValidateDomain(dom, lessStrict, allowTLD); err != nil {
					continue // Already validated and logged in the earlier loop cleanly
				}
				if _, ok := usedAllows[dom]; !ok {
					if !suppressComments {
						removedLogUnusedAllows = append(removedLogUnusedAllows, fmt.Sprintf("# %s - Removed from allowlist (Unused)", dom))
					}
					// Increment native unused statistic explicitly replacing dead validation function logic
					statsUnusedAllows++
				}
			}
		} else {
			// If blocklist is preferred and optimization is enabled, all standalone allows
			// are inherently dropped as they do not actively bypass any blocklist rules.
			finalAllows = make(map[string]struct{})
			for dom := range allowDomains {
				if err := shared.ValidateDomain(dom, lessStrict, allowTLD); err == nil {
					if !suppressComments {
						removedLogUnusedAllows = append(removedLogUnusedAllows, fmt.Sprintf("# %s - Removed from allowlist (Optimize enabled, prefer blocklist)", dom))
					}
					statsUnusedAllows++
				}
			}
		}
	} else {
		finalAllows = make(map[string]struct{})
		if !preferBlocklist {
			for dom := range allowDomains {
				if err := shared.ValidateDomain(dom, lessStrict, allowTLD); err == nil {
					finalAllows[dom] = struct{}{}
				}
			}
		} else {
			for _, dom := range standaloneAllows {
				finalAllows[dom] = struct{}{}
			}
		}
	}

	hasAllowPayload := len(finalAllows) > 0 || (!suppressComments && (len(removedLogUnusedAllows) > 0 || len(removedLogInvalidAllows) > 0 || len(removedLogEclipsedAllows) > 0))
	outputFormats := []string{outputFmt}
	if outputFmt == "all" {
		outputFormats = []string{"domain", "hosts", "adblock", "dnsmasq", "unbound", "rpz", "routedns", "squid"}
	}

	for _, fmtType := range outputFormats {
		var outBlockName, outAllowName string

		// Target configuration file assignments natively.
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

		// Initialize extreme-performance bounded writers guarding directly against slow I/O calls
		var bwBlock, bwAllow *bufio.Writer

		if outBlock != nil {
			bwBlock = shared.NewWriter(outBlock)
			if fmtType == "adblock" {
				bwBlock.WriteString(fmt.Sprintf("[Adblock Plus]\n! version: %d\n", time.Now().Unix()))
			} else if fmtType == "rpz" {
				bwBlock.WriteString("$TTL 3600\n@ IN SOA localhost. root.localhost. 1 3600 900 2592000 300\n")
			}
		}

		// Dynamically reroute the allowlist payload directly into the blocklist output file 
		// explicitly for unified configuration structures (Dnsmasq, Unbound, Adblock, RPZ).
		var bwTargetAllow *bufio.Writer
		if outAllow != nil {
			bwAllow = shared.NewWriter(outAllow)
			bwTargetAllow = bwAllow
			if fmtType == "adblock" {
				bwTargetAllow.WriteString(fmt.Sprintf("[Adblock Plus]\n! version: %d\n", time.Now().Unix()))
			} else if fmtType == "rpz" {
				bwTargetAllow.WriteString("$TTL 3600\n@ IN SOA localhost. root.localhost. 1 3600 900 2592000 300\n")
			}
		} else if bwBlock != nil && (fmtType == "dnsmasq" || fmtType == "unbound" || fmtType == "adblock" || fmtType == "rpz") {
			bwTargetAllow = bwBlock
		}

		if bwTargetAllow != nil && hasAllowPayload {
			var allowSlice []string

			// In unified Adblock output, we use standaloneAllows to prevent 
			// redundant @@|| rules for domains already mapped to $denyallow overrides accurately.
			if fmtType == "adblock" && bwAllow == nil {
				allowSlice = append(allowSlice, standaloneAllows...)
			} else {
				for k := range finalAllows {
					allowSlice = append(allowSlice, k)
				}
			}

			// Inject detailed audit comments mapping removed entries directly into the allowlist slice natively
			if !suppressComments {
				allowSlice = append(allowSlice, removedLogUnusedAllows...)
				allowSlice = append(allowSlice, removedLogInvalidAllows...)
				allowSlice = append(allowSlice, removedLogEclipsedAllows...)

				// Extract and append relevant conversions preserving audit trails inside the allowlist explicitly
				for _, conv := range conversionLog {
					cleanConv := strings.TrimSpace(strings.TrimPrefix(conv, "#"))
					parts := strings.SplitN(cleanConv, " - ", 2)
					if len(parts) == 2 {
						domCheck := parts[0]
						
						// Correctly map target domain for Apex conversions explicitly preventing them from dropping
						if strings.Contains(parts[1], "mapped to: ") {
							subParts := strings.Split(parts[1], "mapped to: ")
							if len(subParts) == 2 {
								domCheck = strings.TrimSuffix(subParts[1], ")")
							}
						}
						
						if _, exists := finalAllows[domCheck]; exists {
							allowSlice = append(allowSlice, conv)
						}
					}
				}
			}

			// Sort the allowlist organically pulling comments above their functional nodes to preserve context.
			sort.Slice(allowSlice, func(i, j int) bool {
				cleanI := extractSortKey(allowSlice[i])
				cleanJ := extractSortKey(allowSlice[j])

				var cmpI, cmpJ string
				if sortAlgo == "alphabetically" {
					cmpI = cleanI
					cmpJ = cleanJ
				} else {
					// extractSortKey strips everything but the core Punycode domain. Punycode is strictly ASCII.
					cmpI = shared.ReverseASCII(cleanI)
					cmpJ = shared.ReverseASCII(cleanJ)
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
						bwTargetAllow.WriteString(fmt.Sprintf("! %s\n", cleanComment))
					case "rpz":
						bwTargetAllow.WriteString(fmt.Sprintf("; %s\n", cleanComment))
					default:
						bwTargetAllow.WriteString(fmt.Sprintf("# %s\n", cleanComment))
					}
					continue
				}

				switch fmtType {
				case "adblock":
					bwTargetAllow.WriteString(fmt.Sprintf("@@||%s^\n", item))
				case "rpz":
					bwTargetAllow.WriteString(fmt.Sprintf("%s CNAME rpz-passthru.\n*.%s CNAME rpz-passthru.\n", item, item))
				case "routedns", "squid":
					bwTargetAllow.WriteString(fmt.Sprintf(".%s\n", item))
				case "dnsmasq":
					bwTargetAllow.WriteString(fmt.Sprintf("server=/%s/#\n", item))
				case "unbound":
					bwTargetAllow.WriteString(fmt.Sprintf("local-zone: \"%s\" transparent\n", item))
				default:
					bwTargetAllow.WriteString(fmt.Sprintf("%s\n", item))
				}
			}
		}

		if bwBlock != nil {
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
				// AND we didn't explicitly route them dynamically to bwBlock.
				if bwAllow == nil && fmtType != "dnsmasq" && fmtType != "unbound" && fmtType != "adblock" && fmtType != "rpz" {
					outputItems = append(outputItems, removedLogUnusedAllows...)
				}

				// Add conversions preserving original state comments
				for _, conv := range conversionLog {
					// Cleanly strip the prefix to avoid slice bound issues.
					cleanConv := strings.TrimSpace(strings.TrimPrefix(conv, "#"))
					parts := strings.SplitN(cleanConv, " - ", 2)
					if len(parts) == 2 {
						domCheck := parts[0]
						
						// Correctly map target domain for Apex conversions explicitly preventing them from dropping
						if strings.Contains(parts[1], "mapped to: ") {
							subParts := strings.Split(parts[1], "mapped to: ")
							if len(subParts) == 2 {
								domCheck = strings.TrimSuffix(subParts[1], ")")
							}
						}
						
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
					// extractSortKey strips everything but the core Punycode domain. Punycode is strictly ASCII.
					// Default standard routing algorithm perfectly handling reverses without rune allocation overhead.
					cmpI = shared.ReverseASCII(cleanI)
					cmpJ = shared.ReverseASCII(cleanJ)
				}

				// Tie-breaker routing safely aligning comments to nodes perfectly.
				if cmpI == cmpJ {
					isCommentI := strings.HasPrefix(outputItems[i], "#")
					isCommentJ := strings.HasPrefix(outputItems[j], "#")

					// Route comments safely above their functional domain node cleanly.
					if isCommentI != isCommentJ {
						return isCommentI
					}
					// Safe fallback resolving comment-to-comment or node-to-node ties stably.
					return outputItems[i] < outputItems[j]
				}
				return cmpI < cmpJ
			})

			// ----------------------------------------------------------------------
			// High-Speed HOSTS Compression Buffer
			// Capacity is strictly pre-allocated directly mapping to the target limit
			// preventing runtime array reallocation overhead explicitly.
			// ----------------------------------------------------------------------
			var hostsBuffer []string
			if compressHosts.Active {
				hostsBuffer = make([]string, 0, compressHosts.Value)
			}

			// Inline closure isolating the compression flush mapping to disk.
			flushHosts := func() {
				if len(hostsBuffer) > 0 {
					bwBlock.WriteString(fmt.Sprintf("0.0.0.0 %s\n", strings.Join(hostsBuffer, " ")))
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
						bwBlock.WriteString(fmt.Sprintf("! %s\n", cleanComment))
					case "rpz":
						bwBlock.WriteString(fmt.Sprintf("; %s\n", cleanComment))
					default:
						bwBlock.WriteString(fmt.Sprintf("# %s\n", cleanComment))
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
							bwBlock.WriteString(fmt.Sprintf("0.0.0.0 %s\n", item))
						}
					case "dnsmasq":
						bwBlock.WriteString(fmt.Sprintf("server=/%s/\n", item))
					case "unbound":
						bwBlock.WriteString(fmt.Sprintf("local-zone: \"%s\" always_nxdomain\n", item))
					case "rpz":
						bwBlock.WriteString(fmt.Sprintf("%s CNAME .\n*.%s CNAME .\n", item, item))
					case "routedns", "squid":
						bwBlock.WriteString(fmt.Sprintf(".%s\n", item))
					case "adblock":
						if exc, ok := adblockRules[item]; ok && len(exc) > 0 {
							sort.Strings(exc)
							bwBlock.WriteString(fmt.Sprintf("||%s^$denyallow=%s\n", item, strings.Join(exc, "|")))
						} else {
							bwBlock.WriteString(fmt.Sprintf("||%s^\n", item))
						}
					default:
						bwBlock.WriteString(fmt.Sprintf("%s\n", item))
					}
				}
			}

			// Trap any residual hosts natively leftover following execution completion.
			if fmtType == "hosts" && compressHosts.Active {
				flushHosts()
			}
		}

		// Strictly guarantee complete pipeline cache purge natively safely.
		if bwBlock != nil {
			bwBlock.Flush()
		}
		if bwAllow != nil {
			bwAllow.Flush()
		}
	}

	if verbose {
		logMsg("========== OPTIMIZATION STATS %s ==========", passName)
		logMsg("Total Blocklist Domains Read: %d", len(blockDomains))
		logMsg("Removed (Invalid/Unregistered): %d", statsInvalidStruct)
		if !preferBlocklist {
			logMsg("Removed (Allowlisted)       : %d", statsAllowlisted)
		}
		logMsg("Removed (Not in Top-N)      : %d", statsTopN)
		logMsg("Removed (Sub-domain Dedup)  : %d", statsDeduped)
		if optimizeAllow {
			logMsg("Dropped (Unused Allows)     : %d", statsUnusedAllows)
		}
		if !preferBlocklist && outputFmt != "hosts" {
			logMsg("Ignored Allows (Blocked)    : %d", statsAllowIgnored)
		}
		if preferBlocklist {
			logMsg("Dropped Allows (Eclipsed)   : %d", statsEclipsedAllows)
		}
		logMsg("----------------------------------------------------")
		logMsg("Final Active Domains        : %d (%d in HOSTS format)", len(finalActive), len(filteredBlocks))
		if outputFmt == "all" || outAllowlist != "" {
			logMsg("Exported Allowlist Domains  : %d", len(finalAllows))
			if statsInvalidAllows > 0 {
				logMsg("Dropped Allows (Invalid)    : %d", statsInvalidAllows)
			}
		}
		logMsg("====================================================")
	}
}

// extractSortKey strictly pulls the root domain from a string array index safely handling comments and Adblock prefixes.
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

