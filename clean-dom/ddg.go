/*
==========================================================================
Filename: clean-dom/ddg.go
Version: 1.26.1-20260518
Date: 2026-05-18 10:50 CEST
Description: Handles DuckDuckGo Tracker Radar integration. Fetches the complete
             GitHub repository ZIP archive in memory, utilizing ETag/If-None-Match
             caching to prevent redundant downloads and rate-limiting. Extracts 
             JSON files concurrently, filtering domains by matching categories.
             
Update Trail:
  - 1.26.1 (2026-05-18): Added parsing support for the "Observed" category natively 
                         matching domains with an empty categories array.
  - 1.26.0 (2026-05-18): ETag headers are now extracted and logged to console 
                         as the active Version. Categories are aggregated and 
                         pushed into the SourceMap universally for comment rendering.
  - 1.25.0 (2026-05-18): Added "default" parameter parsing to automatically inject
                         best-practice blocklist and allowlist categories natively.
  - 1.24.1 (2026-05-18): Increased HTTP client timeout to 120s to prevent context
                         deadline exceeded errors on large ZIP downloads natively.
==========================================================================
*/

package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const ddgZipUrl = "https://github.com/duckduckgo/tracker-radar/archive/refs/heads/main.zip"

// Recommended enterprise best-practice DuckDuckGo categories.
const ddgDefaultBlock = "Advertising,Ad Motivated Tracking,Analytics,Audience Measurement,Action Pixels,Session Replay,Third-Party Analytics Marketing"
const ddgDefaultAllow = "CDN,SSO,Embedded Content,Non-Tracking"

// DDGDomainStruct models the JSON schema of Tracker Radar individual files natively.
type DDGDomainStruct struct {
	Domain     string   `json:"domain"`
	Categories []string `json:"categories"`
}

// fetchDuckDuckGo orchestrates the ZIP download, ETag caching, in-memory extraction, and concurrent JSON mapping.
func fetchDuckDuckGo(blockCats string, allowCats string, reportMode bool) ParsedLists {
	var result ParsedLists
	
	// Universally map sources for inline domain comment rendering
	result.SourceMap = make(map[string]string)

	// Inject default recommended categories if explicitly requested via parameters.
	if strings.ToLower(strings.TrimSpace(blockCats)) == "default" {
		blockCats = ddgDefaultBlock
	}
	if strings.ToLower(strings.TrimSpace(allowCats)) == "default" {
		allowCats = ddgDefaultAllow
	}

	// Parse categories into Hash Maps for O(1) matching constraints natively.
	blockMap := make(map[string]struct{})
	allowMap := make(map[string]struct{})

	for _, c := range strings.Split(blockCats, ",") {
		c = strings.TrimSpace(strings.ToLower(c))
		if c != "" {
			blockMap[c] = struct{}{}
		}
	}
	for _, c := range strings.Split(allowCats, ",") {
		c = strings.TrimSpace(strings.ToLower(c))
		if c != "" {
			allowMap[c] = struct{}{}
		}
	}

	if len(blockMap) == 0 && len(allowMap) == 0 {
		return result
	}

	// Determine optimal cache directory based on global configurations cleanly.
	cacheDir := os.TempDir()
	if workDir != "" {
		cacheDir = workDir
	}
	cachePath := filepath.Join(cacheDir, "aggrip_ddg_tracker_radar.zip")
	etagPath := filepath.Join(cacheDir, "aggrip_ddg_tracker_radar.etag")

	req, err := http.NewRequest("GET", ddgZipUrl, nil)
	if err != nil {
		logMsg("Error crafting request for DuckDuckGo Tracker Radar ZIP: %v", err)
		return result
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; aggrip-go)")

	// Load local ETag from cache array cleanly to check for Github updates sequentially.
	var cachedEtag string
	if b, err := os.ReadFile(etagPath); err == nil {
		cachedEtag = strings.TrimSpace(string(b))
		if cachedEtag != "" {
			req.Header.Set("If-None-Match", cachedEtag)
		}
	}

	logMsg("Checking DuckDuckGo Tracker Radar archive for updates...")

	// 120-Second timeout allowing large ZIP stream to completely flush gracefully.
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logMsg("Error fetching DuckDuckGo Tracker Radar ZIP: %v", err)
		return result
	}
	defer resp.Body.Close()

	var body []byte

	// High-speed caching logic. Bypass Github limits by reusing local arrays if Not-Modified (HTTP 304).
	if resp.StatusCode == http.StatusNotModified {
		logMsg("Archive up-to-date (HTTP 304). Loading DuckDuckGo Tracker Radar from local cache...")
		logMsg("DuckDuckGo Tracker Radar Version (ETag): %s", cachedEtag)
		
		body, err = os.ReadFile(cachePath)
		if err != nil {
			logMsg("Warning: Failed to read local ZIP cache. Proceeding to force re-download: %v", err)
			body = nil // Reset body to trigger re-download safely.
		}
	}

	if body == nil {
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotModified {
			logMsg("Unexpected HTTP status fetching DuckDuckGo Tracker Radar: %d", resp.StatusCode)
			return result
		}

		newEtag := resp.Header.Get("ETag")
		logMsg("Downloading new DuckDuckGo Tracker Radar archive from GitHub...")
		logMsg("DuckDuckGo Tracker Radar Version (ETag): %s", newEtag)

		body, err = io.ReadAll(resp.Body)
		if err != nil {
			logMsg("Error reading DuckDuckGo Tracker Radar ZIP response: %v", err)
			return result
		}

		// Write new archive byte stream and ETag limit to the local file system synchronously.
		if err := os.WriteFile(cachePath, body, 0644); err != nil {
			logMsg("Warning: Failed to write DuckDuckGo ZIP cache to disk: %v", err)
		}
		
		if newEtag != "" {
			if err := os.WriteFile(etagPath, []byte(newEtag), 0644); err != nil {
				logMsg("Warning: Failed to write DuckDuckGo ETag cache to disk: %v", err)
			}
		}
	}

	// Read buffered map safely passing limits to archive decoder natively.
	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		logMsg("Error opening DuckDuckGo Tracker Radar ZIP mapping: %v", err)
		return result
	}

	logMsg("Extracting and parsing DuckDuckGo Tracker Radar JSON domains concurrently...")

	var mu sync.Mutex
	var wg sync.WaitGroup
	// Semaphore pattern strictly limits parallel JSON decoders guarding against CPU starvation.
	sem := make(chan struct{}, 50) 

	for _, f := range zipReader.File {
		// Filter explicitly for the targeted domains directory
		if !strings.HasPrefix(f.Name, "tracker-radar-main/domains/") || !strings.HasSuffix(f.Name, ".json") {
			continue
		}

		wg.Add(1)
		go func(file *zip.File) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			rc, err := file.Open()
			if err != nil {
				return
			}
			defer rc.Close()

			var domData DDGDomainStruct
			if err := json.NewDecoder(rc).Decode(&domData); err != nil {
				return
			}

			if domData.Domain == "" {
				return
			}

			isBlock := false
			isAllow := false
			
			var matchedBlockCats []string
			var matchedAllowCats []string

			// If domain has zero categories, match it to the "observed" parameter strictly
			if len(domData.Categories) == 0 {
				if _, exists := blockMap["observed"]; exists {
					matchedBlockCats = append(matchedBlockCats, "Observed")
					isBlock = true
				}
				if _, exists := allowMap["observed"]; exists {
					matchedAllowCats = append(matchedAllowCats, "Observed")
					isAllow = true
				}
			} else {
				// Check category arrays iteratively dynamically matching user parameters
				for _, cat := range domData.Categories {
					cleanCat := strings.TrimSpace(strings.ToLower(cat))
					
					if _, exists := blockMap[cleanCat]; exists {
						matchedBlockCats = append(matchedBlockCats, cat)
						isBlock = true
					}
					if _, exists := allowMap[cleanCat]; exists {
						matchedAllowCats = append(matchedAllowCats, cat)
						isAllow = true
					}
				}
			}

			if isBlock || isAllow {
				// Process domain safely using standard mapping pipeline
				parsed := parseDomainToken(domData.Domain)
				if parsed.Domain == "" {
					return
				}

				mu.Lock()
				defer mu.Unlock()

				if isBlock {
					result.Blocks = append(result.Blocks, parsed.Domain)
					result.SourceMap[parsed.Domain] = fmt.Sprintf("Source: DuckDuckGo Tracker Radar (%s)", strings.Join(matchedBlockCats, ", "))
				}
				if isAllow {
					result.Allows = append(result.Allows, parsed.Domain)
					result.SourceMap[parsed.Domain] = fmt.Sprintf("Source: DuckDuckGo Tracker Radar (%s)", strings.Join(matchedAllowCats, ", "))
				}

				if reportMode {
					for _, r := range parsed.Reports {
						r.Source = "DuckDuckGo Tracker Radar"
						result.Reports = append(result.Reports, r)
					}
				}

				if parsed.ApexOriginal != "" {
					result.Conversions = append(result.Conversions, fmt.Sprintf("# %s - Removed (Apex only, mapped to: %s)", parsed.ApexOriginal, parsed.Domain))
				}
				if parsed.UnicodeOrig != "" {
					result.Conversions = append(result.Conversions, fmt.Sprintf("# %s - Converted from Unicode: %s", parsed.Domain, parsed.UnicodeOrig))
				}
			}
		}(f)
	}

	wg.Wait()
	logMsg("DuckDuckGo Tracker Radar parsing complete. Merged domains successfully.")

	return result
}

