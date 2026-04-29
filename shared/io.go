// ==========================================================================
// Filename: shared/io.go
// Version: 1.9.0-20260429
// Date: 2026-04-29 15:11 CEST
// Description: Centralized file and HTTP streaming utilities maximizing
//              I/O throughput for massive enterprise datasets.
// ==========================================================================

package shared

import (
	"bufio"
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

// NewScanner creates a highly optimized bufio.Scanner equipped with a 1MB maximum buffer natively.
// Explicitly neutralizes "token too long" faults on deeply polluted, massive payload lines.
func NewScanner(r io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	return scanner
}

// NewWriter creates a highly optimized bufio.Writer explicitly constrained to a 1MB internal buffer.
// Drastically accelerates throughput by batching OS system disk writes securely.
func NewWriter(w io.Writer) *bufio.Writer {
	return bufio.NewWriterSize(w, 1024*1024)
}

