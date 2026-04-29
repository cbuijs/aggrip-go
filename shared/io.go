// ==========================================================================
// Filename: shared/io.go
// Version: 1.0.0
// Date: 2026-04-29 10:48 CEST
// Description: Centralized file and HTTP streaming utilities maximizing
//              I/O throughput for massive enterprise datasets.
// ==========================================================================

package shared

import (
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// FetchStream establishes a high-performance I/O stream from a local file path
// or remote HTTP/HTTPS URL natively. Eliminates duplicated HTTP client logic.
func FetchStream(source string) (io.ReadCloser, error) {
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		req, err := http.NewRequest("GET", source, nil)
		if err != nil {
			return nil, err
		}
		
		req.Header.Set("User-Agent", "Mozilla/5.0")
		
		// Centralized 15-second enterprise timeout limit across the suite
		client := &http.Client{Timeout: 15 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		
		return resp.Body, nil
	}

	// Fallback to local file execution natively mapping direct to disk
	return os.Open(source)
}

