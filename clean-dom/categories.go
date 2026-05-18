/*
==========================================================================
Filename: clean-dom/categories.go
Version: 1.26.1-20260518
Date: 2026-05-18 10:50 CEST
Description: Handles the console output of available tracking and threat 
             categories dynamically available via DuckDuckGo and Cloudflare 
             integrations. Separated to keep main pipeline logic clean.
==========================================================================
*/

package main

import (
	"fmt"
	"os"
)

// printCategories outputs the structured lists of available API classifications 
// directly to STDOUT and securely halts the application pipeline.
func printCategories() {
	fmt.Println("==========================================================================")
	fmt.Println(" AVAILABLE DOMAIN CATEGORIES FOR DDG AND CLOUDFLARE INTEGRATIONS")
	fmt.Println("==========================================================================\n")

	fmt.Println("--- DuckDuckGo Tracker Radar Categories ---")
	fmt.Println("  Use with: --ddg-block-categories / --ddg-allow-categories")
	fmt.Println("  Data Source: GitHub (In-Memory ZIP Extraction)\n")
	fmt.Println("  * Ad Motivated Tracking")
	fmt.Println("  * Advertising")
	fmt.Println("  * Analytics")
	fmt.Println("  * Audience Measurement")
	fmt.Println("  * Action Pixels")
	fmt.Println("  * Session Replay")
	fmt.Println("  * Third-Party Analytics Marketing")
	fmt.Println("  * Social Network")
	fmt.Println("  * CDN")
	fmt.Println("  * SSO")
	fmt.Println("  * Embedded Content")
	fmt.Println("  * Non-Tracking")
	fmt.Println("  * Observed (Uncategorized)")

	fmt.Println("\n--- Cloudflare Radar Categories ---")
	fmt.Println("  Use with: --cf-block-categories / --cf-allow-categories")
	fmt.Println("  Data Source: Authenticated API (--cf-api-token)\n")
	fmt.Println("  * Malware")
	fmt.Println("  * Phishing")
	fmt.Println("  * Spyware")
	fmt.Println("  * Botnet")
	fmt.Println("  * Spam")
	fmt.Println("  * Command and Control")
	fmt.Println("  * Proxy")
	fmt.Println("  * Anonymizer")
	fmt.Println("  * Adult Themes")
	fmt.Println("  * Gambling")
	fmt.Println("  * Social Media")
	fmt.Println("  * Content Delivery Networks")

	fmt.Println("\n==========================================================================")
	fmt.Println(" See CATEGORIES.md for best-practice implementations on allowlists and blocklists.")
	
	// Terminate process directly after informational output natively.
	os.Exit(0)
}

