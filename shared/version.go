// ==========================================================================
// Filename: shared/version.go
// Version: 1.20.0-20260506
// Date: 2026-05-06 16:26 CEST
// Update Trail:
//   - 1.20.0-20260506: Added `--undup` (-u) feature and layout-alphabetical 
//                      sorting matrix to `domsort`. Bumped suite version.
//   - 1.19.0-20260506: Introduced `domsort` Golang port to the aggrip-go suite.
//                      Added `domsort` to go.work and release matrices. 
//                      Maintains layout-preserving segmented sorting constraints natively.
//   - 1.18.0-20260503: Introduced --report flag to clean-dom natively. Captures
//                      all domain modifications, removals, and their original
//                      sources into a structured audit file. Zero-cost memory
//                      allocation when reporting is disabled.
//   - 1.17.0-20260503: Comprehensive comment audit logs added ensuring all 
//                      removed, modified, or converted domains are explicitly
//                      tracked natively within both the generated blocklist and
//                      allowlist output configurations identically. Fixed apex mapping bugs.
//   - 1.16.0-20260503: Added --apex-only parameter to clean-dom. Integrated Public 
//                      Suffix List (PSL) natively into shared bounds for high-speed 
//                      eTLD+1 extraction and sub-domain stripping.
//   - 1.15.0-20260503: Introduced --prefer-blocklist flag to clean-dom and clean-ip 
//                      to reverse default resolution, allowing blocklists to supersede 
//                      allowlists. Updated core optimization paths and logging.
//   - 1.14.0-20260429: Addressed CLI flag regression in clean-dom mapping to 
//                      the wrong struct reference. Prevented boundary integer 
//                      panic in CollapsePrefixes for /0 routing blocks.
//                      Expanded IsValidDomain to natively accept uppercase A-Z securely.
//   - 1.13.0-20260429: Resolved critical IPv6 validation regression in shared 
//                      heuristics breaking hosts detection. Eliminated 
//                      dead-code tracking maps from clean-dom resolving memory bloat.
//   - 1.12.0-20260429: Resolved memory slice allocation scaling limits.
//                      Pre-allocated capacities in CollapsePrefixes, IP 
//                      hole-punching algorithms, and string tree generation.
//                      Purged O(N) secondary domain validation counters.
//   - 1.11.0-20260429: Executed dead-code audit. Purged ReverseStr and IsFastIP.
//                      Refactored clean-ip to use lock-free channel fan-in, 
//                      resolving sync.Mutex scaling regression.
//   - 1.10.0-20260429: Replaced heavy ReverseStr rune allocations with 
//                      ReverseASCII zero-copy byte mapping in clean-dom. 
//                      Punycode guarantees ASCII compliance safely. 
//                      Verified concurrency paths and IP tokenization.
//   - 1.9.0-20260429: Centralized high-performance 1MB buffered I/O functions.
//                     Fixed unbuffered disk writes in clean-dom formatter.
//                     Purged dead code and duplicate boilerplate.
//   - 1.8.0-20260429: Massive cleanup of AI-hallucinated adverb trails across 
//                     all tool comments. Codebase regression verification and 
//                     concurrency hardening.
//   - 1.7.0-20260429: Executed suite-wide regression audits. Fixed buffer array 
//                     allocation bug in clean-ip. Fixed HNS slash-bypass bug in 
//                     clean-dom parser. Confirmed zero dead-code pathways.
//   - 1.5.0-20260429: Consolidated `parsePrefix` into `shared/ipmath.go` entirely.
//   - 1.4.0-20260429: Added global massive CIDR range alerting across IP tools.
//   - 1.3.0-20260429: Added centralized concurrency limiters (semaphores) 
//                     across the tool suite to prevent FD exhaustion.
//   - 1.2.3-20260429: Added missing shared.IsFastIP function. Standardized.
//   - 1.2.2-20260429: Version bump. Passed regression checks. Replaced mutex 
//                     with channel fan-in. Fixed IP mask bit calculation.
//   - 1.2.1-20260429: Centralized version tracking for the aggrip-go suite.
// Description: Centralized versioning for the aggrip-go suite. Guarantees
//              all tools output identical version hashes when invoked with
//              the -V or --version flags natively.
// ==========================================================================

package shared

import (
	"fmt"
	"os"
)

// SuiteVersion defines the strictly synchronized global version for all tools natively.
// Maintains synchronized output during CLI invocations.
const SuiteVersion = "1.20.0-20260506"

// PrintVersion outputs the standardized version string for the requesting tool
// and securely exits the process to bypass execution natively. This avoids 
// duplicating fmt.Printf blocks across multiple main packages.
func PrintVersion(toolName string) {
	fmt.Printf("%s Go Edition - Version %s\n", toolName, SuiteVersion)
	os.Exit(0)
}

