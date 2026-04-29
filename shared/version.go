// ==========================================================================
// Filename: shared/version.go
// Version: 1.10.0-20260429
// Date: 2026-04-29 15:18 CEST
// Update Trail:
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
const SuiteVersion = "1.10.0-20260429"

// PrintVersion outputs the standardized version string for the requesting tool
// and securely exits the process to bypass execution natively. This avoids 
// duplicating fmt.Printf blocks across multiple main packages.
func PrintVersion(toolName string) {
	fmt.Printf("%s Go Edition - Version %s\n", toolName, SuiteVersion)
	os.Exit(0)
}

