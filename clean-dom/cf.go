/*
==========================================================================
Filename: clean-dom/cf.go
Version: 1.26.0-20260518
Date: 2026-05-18 10:46 CEST
Description: Handles Cloudflare Radar integration. Queries the authenticated 
             Radar Ranking API to fetch top domains by explicit categories natively.
             Supports secure API token injection via parameters or Environment.
             
Update Trail:
  - 1.26.0 (2026-05-18): Populated universal SourceMap matrix to render category
                         comments directly above output domains perfectly. Added 
                         version (7-Day Window) logging constraints natively.
  - 1.25.0 (2026-05-18): Added "default" parameter parsing to automatically inject
                         best-practice blocklist and allowlist categories natively.
  - 1.24.1 (2026-05-18): Added strict URL encoding for API category queries
                         ensuring categories with spaces do not break HTTP requests.
==========================================================================
*/

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Recommended enterprise best-practice Cloudflare categories.
const cfDefaultBlock = "Malware,Phishing,Spyware,Botnet,Command and Control,Spam"
const cfDefaultAllow = "Content Delivery Networks"

// CFRadarResponse dynamically structures the expected JSON schema from the Radar Ranking API.
type CFRadarResponse struct {
	Success bool `json:"success"`
	Result  struct {
		Ranking []struct {
			Domain string `json:"domain"`
		} `json:"ranking"`
	} `json:"result"`
}

// fetchCloudflare coordinates authenticated API requests securely targeting the Cloudflare Radar limits.
func fetchCloudflare(blockCats string, allowCats string, token string, reportMode bool) ParsedLists {
	var result ParsedLists
	
	// Universally map sources for inline domain comment rendering
	result.SourceMap = make(map[string]string)

	// Fallback to Environment Variables ensuring CI/CD pipeline automation security cleanly.
	if token == "" {
		token = os.Getenv("CF_API_TOKEN")
	}

	if token == "" {
		logMsg("Error: Cloudflare Radar Integration requires a valid API token (--cf-api-token or CF_API_TOKEN). Skipping CF Radar.")
		return result
	}

	// Inject default recommended categories if explicitly requested via parameters.
	if strings.ToLower(strings.TrimSpace(blockCats)) == "default" {
		blockCats = cfDefaultBlock
	}
	if strings.ToLower(strings.TrimSpace(allowCats)) == "default" {
		allowCats = cfDefaultAllow
	}

	blockMap := make(map[string]struct{})
	allowMap := make(map[string]struct{})

	for _, c := range strings.Split(blockCats, ",") {
		c = strings.TrimSpace(c)
		if c != "" {
			blockMap[c] = struct{}{}
		}
	}
	for _, c := range strings.Split(allowCats, ",") {
		c = strings.TrimSpace(c)
		if c != "" {
			allowMap[c] = struct{}{}
		}
	}

	if len(blockMap) == 0 && len(allowMap) == 0 {
		return result
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	// Limit simultaneous API calls ensuring we respect Cloudflare Rate Limits explicitly
	sem := make(chan struct{}, 5)

	// queryAPI fires the strict HTTP request pushing domains into the targeted array directly.
	queryAPI := func(category string, isBlock bool) {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()

		// Ensure category strings containing spaces (e.g. "Command and Control") are safely URL-encoded
		encodedCategory := url.QueryEscape(category)

		// Query Top 1000 Domains for the specified category natively using the Radar API.
		apiUrl := fmt.Sprintf("https://api.cloudflare.com/client/v4/radar/ranking/domain?category=%s&limit=1000", encodedCategory)

		req, err := http.NewRequest("GET", apiUrl, nil)
		if err != nil {
			logMsg("Error crafting Cloudflare Radar API request for category %s: %v", category, err)
			return
		}

		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: 15 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			logMsg("Error connecting to Cloudflare Radar API for category %s: %v", category, err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			logMsg("Cloudflare Radar API Error (Category: %s): HTTP %d - %s", category, resp.StatusCode, string(bodyBytes))
			return
		}

		var apiData CFRadarResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiData); err != nil {
			logMsg("Error parsing Cloudflare Radar API response for category %s: %v", category, err)
			return
		}

		if !apiData.Success {
			logMsg("Cloudflare Radar API returned success: false for category %s", category)
			return
		}

		mu.Lock()
		defer mu.Unlock()

		sourceLabel := fmt.Sprintf("Source: Cloudflare Radar (%s)", category)

		for _, item := range apiData.Result.Ranking {
			if item.Domain == "" {
				continue
			}

			parsed := parseDomainToken(item.Domain)
			if parsed.Domain == "" {
				continue
			}

			if isBlock {
				result.Blocks = append(result.Blocks, parsed.Domain)
				result.SourceMap[parsed.Domain] = sourceLabel
			} else {
				result.Allows = append(result.Allows, parsed.Domain)
				result.SourceMap[parsed.Domain] = sourceLabel
			}

			if reportMode {
				for _, r := range parsed.Reports {
					r.Source = fmt.Sprintf("Cloudflare Radar (%s)", category)
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
	}

	logMsg("Querying Cloudflare Radar Ranking API (Current 7-Day Window) for configured categories...")

	for cat := range blockMap {
		wg.Add(1)
		go queryAPI(cat, true)
	}

	for cat := range allowMap {
		wg.Add(1)
		go queryAPI(cat, false)
	}

	wg.Wait()
	logMsg("Cloudflare Radar API queries complete. Merged domains successfully.")

	return result
}

