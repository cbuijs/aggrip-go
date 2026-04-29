/*
==========================================================================
Filename: clean-dom/main.go
Version: 1.2.1-20260429
Date: 2026-04-29 11:52 CEST
Update Trail:
  - 1.2.1 (2026-04-29): Centralized suite versioning to shared/version.go.
  - 1.2.0 (2026-04-29): Synced version across aggrip-go tools. Migrated TLD
                        init validation arrays to shared namespace logic.
                        Utilized shared.OptionalIntFlag for flag standardization.
  - 1.1.9 (2026-04-29): Refactored to utilize centralized shared library.
Description: Enterprise-grade DNS blocklist optimizer. Features upfront 
             file format detection, concurrent bulk ingestion, punycode 
             translation, dynamic adblock routing, and O(N log N) tree 
             deduplication via reverse string sorting.
==========================================================================
*/

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sync"

	"aggrip-go/shared"
)

// Global Flags defining core operations and behaviors across all files in main package
var (
	blocklists       shared.StringSlice
	allowlists       shared.StringSlice
	topnlists        shared.StringSlice
	inputFormat      string
	outputFmt        string
	allDir           string
	workDir          string
	sortAlgo         string
	outBlocklist     string
	outAllowlist     string
	validTlds        string
	optimizeAllow    bool
	suppressComments bool
	lessStrict       bool
	allowTLD         bool
	compressHosts    shared.OptionalIntFlag
	verbose          bool
	showVersion      bool
	helpFlag         bool
)

func init() {
	// Register variables for double-dash configurations. Standardized short formats included.
	flag.Var(&blocklists, "blocklist", "Path(s) or URL(s) to the DNS blocklist(s) (can specify multiple times)")
	flag.Var(&blocklists, "b", "Short for --blocklist")

	flag.Var(&allowlists, "allowlist", "Optional path(s) or URL(s) to the DNS allowlist(s)")
	flag.Var(&allowlists, "a", "Short for --allowlist")

	flag.Var(&topnlists, "topnlist", "Optional path(s) or URL(s) to Top-N list(s)")
	flag.Var(&topnlists, "t", "Short for --topnlist")

	flag.StringVar(&inputFormat, "input-format", "", "Strictly enforce input format: domain, hosts, adblock, routedns, squid")
	flag.StringVar(&inputFormat, "i", "", "Short for --input-format")

	flag.StringVar(&outputFmt, "output-format", "domain", "Output format: all, domain, hosts, adblock, dnsmasq, unbound, rpz, routedns, squid")
	flag.StringVar(&outputFmt, "o", "domain", "Short for --output-format")

	flag.StringVar(&allDir, "all-dir", "", "Mandatory output directory to use when output is set to 'all'")

	flag.StringVar(&workDir, "work-dir", "", "Directory to save unmodified raw source files")
	flag.StringVar(&workDir, "w", "", "Short for --work-dir")

	flag.StringVar(&sortAlgo, "sort", "domain", "Sorting algorithm: domain, alphabetically, tld")

	flag.StringVar(&outBlocklist, "out-blocklist", "", "File path to write the blocklist output (default: STDOUT)")
	flag.StringVar(&outAllowlist, "out-allowlist", "", "File path to write the allowlist output")

	flag.StringVar(&validTlds, "valid-tlds", "iana", "Comma-separated list of allowed TLD registries: iana (default), opennic, hns, all, disable")

	flag.BoolVar(&optimizeAllow, "optimize-allowlist", false, "Drop unused allowlist entries")
	flag.BoolVar(&suppressComments, "suppress-comments", false, "Suppress audit log of removed domains")

	flag.BoolVar(&lessStrict, "less-strict", false, "Allow underscores (_) and asterisks (*) in domain names")
	flag.BoolVar(&lessStrict, "l", false, "Short for --less-strict")

	flag.BoolVar(&allowTLD, "allow-tld", false, "Allow Top-Level Domains (TLDs) like 'com' or 'net'")

	flag.Var(&compressHosts, "compress-hosts", "Compress HOSTS format output (default 10 domains per IP when flag is present)")

	flag.BoolVar(&verbose, "verbose", false, "Show progress and statistics on STDERR")
	flag.BoolVar(&verbose, "v", false, "Short for --verbose")

	flag.BoolVar(&showVersion, "version", false, "Show version information and exit")
	flag.BoolVar(&showVersion, "V", false, "Short for --version")

	flag.BoolVar(&helpFlag, "help", false, "Show this help message")
	flag.BoolVar(&helpFlag, "h", false, "Short for --help")

	// Custom formatted usage explicitly declaring standard flags across the suite
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of clean-dom:\n\n")
		fmt.Fprintf(os.Stderr, "Core Options:\n")
		fmt.Fprintf(os.Stderr, "  -b, --blocklist <path/url>     Path(s) or URL(s) to the DNS blocklist(s) (Required, can specify multiple)\n")
		fmt.Fprintf(os.Stderr, "  -a, --allowlist <path/url>     Path(s) or URL(s) to the DNS allowlist(s) (Optional, can specify multiple)\n")
		fmt.Fprintf(os.Stderr, "  -t, --topnlist <path/url>      Path(s) or URL(s) to Top-N list(s) (Optional, can specify multiple)\n")
		fmt.Fprintf(os.Stderr, "  -i, --input-format <format>    Strictly enforce input format (domain, hosts, adblock, routedns, squid)\n")
		fmt.Fprintf(os.Stderr, "  -o, --output-format <format>   Output format (all, domain, hosts, adblock, dnsmasq, unbound, rpz, routedns, squid) (default \"domain\")\n")
		fmt.Fprintf(os.Stderr, "      --out-blocklist <file>     File path to write the blocklist output (default: STDOUT)\n")
		fmt.Fprintf(os.Stderr, "      --out-allowlist <file>     File path to write the allowlist output\n")
		fmt.Fprintf(os.Stderr, "      --all-dir <dir>            Mandatory output directory to use when output format is set to 'all'\n")
		fmt.Fprintf(os.Stderr, "  -w, --work-dir <dir>           Directory to save unmodified raw source files\n")
		fmt.Fprintf(os.Stderr, "      --sort <type>              Sorting algorithm (domain, alphabetically, tld) (default \"domain\")\n")
		fmt.Fprintf(os.Stderr, "      --valid-tlds <list>        Allowed TLD registries (iana, opennic, hns, all, disable) (default \"iana\")\n")
		fmt.Fprintf(os.Stderr, "      --optimize-allowlist       Drop unused allowlist entries\n")
		fmt.Fprintf(os.Stderr, "      --suppress-comments        Suppress audit log of removed domains\n")
		fmt.Fprintf(os.Stderr, "  -l, --less-strict              Allow underscores (_) and asterisks (*) in domain names\n")
		fmt.Fprintf(os.Stderr, "      --allow-tld                Allow Top-Level Domains (TLDs) like 'com' (Note: 'com' collapses all .com subdomains)\n")
		fmt.Fprintf(os.Stderr, "      --compress-hosts[=<num>]   Compress HOSTS format output (default 10 domains per IP when flag is present)\n")
		fmt.Fprintf(os.Stderr, "  -v, --verbose                  Show progress and statistics on STDERR\n")
		fmt.Fprintf(os.Stderr, "  -V, --version                  Show version information and exit\n")
		fmt.Fprintf(os.Stderr, "  -h, --help                     Show this help message\n")
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  clean-dom -b ads.txt -o unbound --valid-tlds iana,opennic -v\n")
	}
}

// logMsg prints messages to STDERR if verbose mode is enabled. Keeps STDOUT clear.
// Thin wrapper forwarding the call to the central shared module natively.
func logMsg(msg string, args ...any) {
	shared.LogMsg(verbose, msg, args...)
}

func main() {
	log.SetFlags(0)
	flag.Parse()

	// Strictly trap help flags bypassing default runtime logic
	if helpFlag {
		flag.Usage()
		os.Exit(0)
	}

	// Trap version flag and output the globally synchronized suite version dynamically
	if showVersion {
		shared.PrintVersion("clean-dom")
	}

	if len(blocklists) == 0 {
		log.Fatal("Error: At least one --blocklist must be provided.")
	}
	if outputFmt == "all" && allDir == "" {
		log.Fatal("Error: --all-dir is required when using -o all.")
	}

	// Initialize the TLD Validation Dictionaries securely upfront in shared memory
	shared.InitTLDValidator(validTlds, verbose)

	if workDir != "" {
		os.MkdirAll(workDir, 0755)
	}

	var blockDomains []string
	allowDomains := make(map[string]struct{})
	denyAllowOverrides := make(map[string]struct{})
	var conversionLog []string

	logMsg("Consolidating Blocklists...")
	var wg sync.WaitGroup
	var mu sync.Mutex

	processList := func(list []string, isTopN bool, listType string) {
		for _, source := range list {
			wg.Add(1)
			go func(s string) {
				defer wg.Done()
				res := readDomainsBulk(s, isTopN, listType)
				mu.Lock()
				blockDomains = append(blockDomains, res.Blocks...)
				for _, a := range res.Allows {
					allowDomains[a] = struct{}{}
				}
				for _, da := range res.DenyAllows {
					denyAllowOverrides[da] = struct{}{}
				}
				conversionLog = append(conversionLog, res.Conversions...)
				mu.Unlock()
			}(source)
		}
	}

	processList(blocklists, false, "Blocklist")
	wg.Wait()

	if len(allowlists) > 0 {
		logMsg("Consolidating Allowlists...")
		processList(allowlists, false, "Allowlist")
		wg.Wait()
	}

	topnDomains := make(map[string]struct{})
	if len(topnlists) > 0 {
		logMsg("Consolidating Top-N Lists...")
		var topNBlocks []string
		for _, source := range topnlists {
			res := readDomainsBulk(source, true, "Top-N")
			topNBlocks = append(topNBlocks, res.Blocks...)
		}
		for _, b := range topNBlocks {
			topnDomains[b] = struct{}{}
		}
	}

	if outputFmt == "all" && len(topnlists) > 0 {
		buildOutputs(blockDomains, allowDomains, denyAllowOverrides, conversionLog, nil, "", false)
		buildOutputs(blockDomains, allowDomains, denyAllowOverrides, conversionLog, topnDomains, ".top-n", true)
	} else {
		if len(topnlists) > 0 {
			buildOutputs(blockDomains, allowDomains, denyAllowOverrides, conversionLog, topnDomains, ".top-n", true)
		} else {
			buildOutputs(blockDomains, allowDomains, denyAllowOverrides, conversionLog, nil, "", false)
		}
	}
}

