// ==========================================================================
// Filename: shared/version.go
// Version: 1.4.0-20260429
// Date: 2026-04-29 14:45 CEST
// Update Trail:
//   - 1.4.0-20260429: Added global massive CIDR range alerting natively across 
//                     IP tools protecting against accidental /0 or /8 blackholes.
//   - 1.3.0-20260429: Added centralized concurrency limiters (semaphores) 
//                     across the tool suite to prevent FD exhaustion.
//                     Consolidated mergePrefixes from aggrip into ipmath.
//                     Fixed fragmented netmask boundary parsing regression.
//                     Added heavy, verbose documentation across all modules.
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
const SuiteVersion = "1.4.0-20260429"

// PrintVersion outputs the standardized version string for the requesting tool
// and securely exits the process to bypass execution natively. This avoids 
// duplicating fmt.Printf blocks across multiple main packages.
func PrintVersion(toolName string) {
	fmt.Printf("%s Go Edition - Version %s\n", toolName, SuiteVersion)
	os.Exit(0)
}

