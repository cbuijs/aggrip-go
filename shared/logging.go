// ==========================================================================
// Filename: shared/logging.go
// Version: 1.8.0-20260429
// Date: 2026-04-29 15:00 CEST
// Description: Centralized diagnostic logging wrapper.
// ==========================================================================

package shared

import (
	"fmt"
	"os"
)

// LogMsg outputs diagnostic messages directly to STDERR natively.
// Keeps STDOUT clean for UNIX pipeline stream chaining.
func LogMsg(verbose bool, msg string, args ...any) {
	if verbose {
		if len(args) > 0 {
			fmt.Fprintf(os.Stderr, "[*] "+msg+"\n", args...)
		} else {
			fmt.Fprintf(os.Stderr, "[*] "+msg+"\n")
		}
	}
}

