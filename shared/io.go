// ==========================================================================
// Filename: shared/io.go
// Version: 1.10.0-20260518
// Date: 2026-05-18 12:49 CEST
// Update Trail:
//   - 1.10.0 (2026-05-18): Introduced FetchStreamCached providing global 
//                          ETag and Last-Modified caching capabilities. 
//                          Increased global timeout to 120 seconds.
//   - 1.9.0 (2026-04-29): Centralized file and HTTP streaming utilities maximizing
//                         I/O throughput for massive enterprise datasets.
// ==========================================================================

package shared

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
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
		
		// Centralized 120-second enterprise timeout limit across the suite
		// prevents connection drops when fetching massive multi-megabyte configurations.
		client := &http.Client{Timeout: 120 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		
		return resp.Body, nil
	}

	// Fallback to local file execution natively mapping direct to disk
	return os.Open(source)
}

// FetchStreamCached acts as a drop-in replacement for FetchStream but natively 
// buffers remote HTTP/HTTPS payloads to disk. It tracks and transmits ETag and 
// Last-Modified headers intelligently preventing redundant downloads for unmodified sources.
func FetchStreamCached(source string, cacheDir string, timeout time.Duration) (io.ReadCloser, error) {
	if !strings.HasPrefix(source, "http://") && !strings.HasPrefix(source, "https://") {
		return os.Open(source)
	}

	// Route cache natively to the system Temp directory if not explicitly mapped.
	if cacheDir == "" {
		cacheDir = os.TempDir()
	}

	// Cryptographically hash the source URL ensuring safe file boundaries.
	hash := sha256.Sum256([]byte(source))
	hashStr := hex.EncodeToString(hash[:])[:16]

	cachePath := filepath.Join(cacheDir, hashStr+".cache")
	etagPath := filepath.Join(cacheDir, hashStr+".etag")
	modPath := filepath.Join(cacheDir, hashStr+".lastmod")

	req, err := http.NewRequest("GET", source, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; aggrip-go)")

	// Retrieve local cache metrics injecting them dynamically to intercept 304 Not Modified.
	var cachedEtag, cachedMod string
	if b, err := os.ReadFile(etagPath); err == nil && len(b) > 0 {
		cachedEtag = strings.TrimSpace(string(b))
		req.Header.Set("If-None-Match", cachedEtag)
	}
	if b, err := os.ReadFile(modPath); err == nil && len(b) > 0 {
		cachedMod = strings.TrimSpace(string(b))
		req.Header.Set("If-Modified-Since", cachedMod)
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		// Fast fallback to historical cache boundaries if network completely fails natively.
		if f, errOpen := os.Open(cachePath); errOpen == nil {
			return f, nil
		}
		return nil, err
	}

	// 304 Not Modified perfectly matches cache states. Safe to inject local copy directly.
	if resp.StatusCode == http.StatusNotModified {
		resp.Body.Close()
		return os.Open(cachePath)
	}

	// Trap server failures bypassing standard bounds, attempting to return a stale cache if available.
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		if f, errOpen := os.Open(cachePath); errOpen == nil {
			return f, nil
		}
		return nil, fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
	}

	// Write directly to a temporary structure ensuring atomic file mapping protects against partial streams.
	tmpPath := cachePath + ".tmp"
	out, err := os.Create(tmpPath)
	if err != nil {
		return resp.Body, nil // Fail gracefully bypassing cache lock entirely.
	}

	_, err = io.Copy(out, resp.Body)
	out.Close()
	resp.Body.Close()

	if err == nil {
		// Atomic rename natively guaranteeing thread-safe reads upon completion
		os.Rename(tmpPath, cachePath)
		
		// Conditionally purge or apply headers verifying upstream limits.
		if etag := resp.Header.Get("ETag"); etag != "" {
			os.WriteFile(etagPath, []byte(etag), 0644)
		} else {
			os.Remove(etagPath)
		}
		
		if lastMod := resp.Header.Get("Last-Modified"); lastMod != "" {
			os.WriteFile(modPath, []byte(lastMod), 0644)
		} else {
			os.Remove(modPath)
		}
	} else {
		// Destroy fragmented configurations securely preventing corrupted logic reads.
		os.Remove(tmpPath)
		return nil, fmt.Errorf("failed to completely download and buffer cache stream: %v", err)
	}

	return os.Open(cachePath)
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

