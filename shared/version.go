// ==========================================================================
// Filename: shared/version.go
// Version: 1.2.1-20260429
// Date: 2026-04-29 11:52 CEST
// Update Trail:
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
const SuiteVersion = "1.2.1-20260429"

// PrintVersion outputs the standardized version string for the requesting tool
// and securely exits the process to bypass execution natively.
func PrintVersion(toolName string) {
	fmt.Printf("%s Go Edition - Version %s\n", toolName, SuiteVersion)
	os.Exit(0)
}

