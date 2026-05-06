# aggrip-go

High-performance, low-latency, and secure Go utilities for optimizing, deduplicating, and managing massive DNS and IP-based blocklists and allowlists. Built for enterprise-grade public network filtering.

## Included Tools

### 1. clean-dom

**Enterprise-grade DNS Blocklist Optimizer** Consolidates multiple DNS blacklists and whitelists, deduplicates subdomains using an O(N log N) reverse-string tree sort, translates Punycode natively, and dynamically routes Adblock rules.

**Key Features:**

* **Concurrent Ingestion:** Streams massive lists via HTTP/HTTPS or local paths using Go concurrency.

* **Format Autodetection:** Upfront heuristic format detection (hosts, adblock, routedns, squid, domain).

* **Adblock Parsing:** Extracts modifiers (e.g., `$denyallow`) and translates Punycode (IDNA) automatically.

* **Native Validation & Dictionaries:** Fast byte-level payload validation. Strict RFC checking securely drops invalid anomalies (e.g., all-numeric TLDs). Features built-in, zero-dependency validation dictionaries for **IANA** (1400+ TLDs) and **OpenNIC** to strictly guarantee output sanitization. Support for decentralized/unregistered roots (Handshake) is configurable.

* **Tree Deduplication:** Rapid O(N log N) deduplication via reverse string sorting (automatically drops redundant subdomains if a parent is already blocked). *Note: If a TLD like `com` is ingested via the `--allow-tld` flag, it acts as an apex parent and correctly collapses all subdomains (e.g. `example.com`) beneath it.*

* **Multiple Outputs:** Generates ready-to-use configs for `domain`, `hosts`, `adblock`, `dnsmasq`, `unbound`, `rpz`, `routedns`, and `squid`.

* **Hosts Output Compression:** Includes optional `--compress-hosts[=<num>]` capacity routing to collapse multiple domains securely onto a single IP mapping (e.g., `0.0.0.0 dom1 dom2...`). Defaults to 10 nodes per line when the flag is triggered.

**Usage Example:**

```bash
# Standard Output Formatting
clean-dom -b https://example.com/ads.txt -a local-allow.txt -o unbound --out-blocklist unbound-filter.conf --valid-tlds iana,opennic -v

# Compressed HOSTS File Routing (Output mapping up to 15 domains per single IP line)
clean-dom -b https://example.com/ads.txt -o hosts --compress-hosts=15 --out-blocklist filter.hosts -v
```

### 2. clean-ip

**Enterprise-grade IP Blocklist Optimizer** High-speed CIDR, IP, and range aggregator. Cross-references against allowlists, collapses redundant subnets into optimal CIDR blocks, and mathematically punches holes for exclusions.

**Key Features:**

* **High-Speed I/O:** Zero-allocation tokenization (`strings.FieldsFunc`) and 1MB buffered I/O stream writers for massive firewall datasets.

* **Mathematical Hole-Punching:** Safely fractures and excludes allowlisted IPs/CIDRs from larger blocked supernets, avoiding firewall bypasses.

* **Range Summarization:** Autoconverts spaced (`1.1.1.1 1.1.1.5`) or dashed (`1.1.1.1-1.1.1.5`) IP ranges into optimal CIDR blocks natively.

* **Subnet Collapsing:** Sorts and aggregates overlapping CIDRs into the largest possible subnets to shrink firewall state tables.

* **Firewall Ready:** Exports to `cidr`, `netmask`, `range`, `cisco`, `iptables`, `mikrotik`, and `padded`.

**Usage Example:**

```bash
clean-ip -b drop.txt -a allow.txt -o iptables --out-blocklist rules.v4 -v
```

### 3. aggrip

**High-Speed IP to CIDR Aggregator** A streamlined, high-performance pipeline utility to ingest raw lists of IP addresses and CIDR blocks, outputting a merged and mathematically optimized CIDR list.

**Key Features:**

* **Stream Processing:** Designed for standard UNIX pipes (`STDIN`/`STDOUT`) with optional file flags (`-i`, `-o`) for massive datasets.

* **O(N log N) Compression:** Merges redundant or contiguous CIDR subnets using a high-speed sorting-stack algorithm.

* **Zero-Allocation Parsing:** Utilizes Go's native `net/netip` package for highly efficient, memory-safe IP and prefix evaluation.

* **Strict Boundary Enforcement:** Optional strict mode (`-s`) automatically drops invalid CIDRs instead of implicitly truncating dirty host bits.

* **Dual Stack Independence:** Processes and segregates IPv4 and IPv6 streams mathematically to prevent cross-boundary collisions.

**Usage Example:**

```bash
# Standard UNIX piping
cat raw_ips.txt | aggrip > optimized_cidrs.txt

# Direct file I/O with strict boundary enforcement
aggrip -i raw_ips.txt -o optimized_cidrs.txt -s -v
```

### 4. undup

**Blazing Fast Binary-Level Domain Deduplicator** A highly specialized, low-latency deduplication engine that removes redundant subdomains when their parent domains exist in the same feed.

**Key Features:**

* **Zero-Copy Byte Parsing:** Reads entirely from bytes arrays without heavy string allocations to maximize parsing throughput.
* **Concurrent Reversals:** Shards string reversal workloads across all available CPU cores automatically for parallel processing.
* **Strict Validation Bypass:** High-speed inline structural validation completely circumvents slow regex engine overhead.
* **Flexible I/O:** Supports standard UNIX piping or direct high-speed file streams.

**Usage Example:**

```bash
# Fast deduplication with UNIX pipes
cat domains.txt | undup > unique_domains.txt

# File I/O with less-strict parsing
undup -i mixed_domains.txt -o clean_domains.txt -l -v
```

### 5. domsort

**Segmented Layout-Preserving Domain Sorter** A high-speed utility to identify logical sections in mixed-text streams (e.g., configurations, comments) and strictly sort domains within those boundaries while preserving the exact layout of the original document.

**Key Features:**

* **Zero-Copy Buffering:** Utilizes memory arrays efficiently to evaluate section boundaries and limit heavy string allocations.
* **Intelligent Segments:** Identifies standard configurations, blank lines, or comments natively, immediately flushing and sorting active blocks before appending the non-domain text identically.
* **Sorting Algorithms:** Features TLD-down tree sorting natively (e.g., `com.example.sub`) or standard alphabetical sequences safely dropping wildcard/regex characters (`_`, `*`) for strict parity.
* **Pipeline Capable:** Readily injects into continuous UNIX streams or direct file paths.

**Usage Example:**

```bash
# UNIX piping with reverse sorting enabled
cat mixed_file.txt | domsort -r > sorted_mixed_file.txt

# Direct file I/O with alphabetical layout preservation
domsort -i raw.list -o formatted.list -a -l -v
```

## Building from Source

```bash
# Change to main parrent/root directory
cd aggrip-go

# Build aggrip
go build -ldflags="-s -w" -o aggrip ./aggrip

# Build clean-dom
go build -ldflags="-s -w" -o clean-dom ./clean-dom

# Build clean-ip
go build -ldflags="-s -w" -o clean-ip ./clean-ip

# Build domsort
go build -ldflags="-s -w" -o domsort ./domsort

# Build undup
go build -ldflags="-s -w" -o undup ./undup
```
~~~eof

~~~markdown:EXAMPLES.md
# aggrip-go Suite Examples

This document provides real-world examples of utilizing the `aggrip-go` suite with popular enterprise and community blocklists from StevenBlack, Hagezi, and OISD.

## 1. clean-dom

Consolidate multiple community blocklists, deduplicate redundant subdomains, drop invalid structures, and generate an unbound configuration file.

```bash
clean-dom \
  -b https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts \
  -b https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt \
  -b https://big.oisd.nl/domainswild \
  -o unbound \
  --out-blocklist unbound-blocklist.conf \
  -v
```

Generate a compressed HOSTS file, utilizing an explicit allowlist to prevent false positives.

```bash
clean-dom \
  -b https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts \
  -b https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt \
  -a https://raw.githubusercontent.com/hagezi/dns-blocklists/main/whitelist.txt \
  -o hosts \
  --out-blocklist /etc/hosts.adblock \
  --compress-hosts=15 \
  -v
```

## 2. clean-ip

Process Hagezi's IP-based blocklists, punch mathematical exclusions for a local allowlist, and export directly to `iptables` rules.

```bash
clean-ip \
  -b https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/doh.txt \
  -b https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/vpn.txt \
  -a local_allow_ips.txt \
  -o iptables \
  --out-blocklist iptables_drop.rules \
  -s \
  -v
```

Aggregate and optimize blocklists into standard CIDR notations for Mikrotik routers.

```bash
clean-ip \
  -b https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/tor.txt \
  -o mikrotik \
  --out-blocklist mikrotik_address_list.rsc \
  -v
```

## 3. aggrip

Stream raw IP blocklists directly from GitHub into `aggrip` to compress overlapping subsets into an optimized CIDR list via UNIX pipelines.

```bash
curl -sL https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/pro.txt | aggrip -s -v > optimized_cidrs.txt
```

Merge local and remote IP lists simultaneously, enforcing strict host-bit boundaries.

```bash
cat local_ips.txt <(curl -sL https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/doh.txt) | aggrip -o final_optimized.txt -s
```

## 4. undup

Rapidly strip redundant subdomains from a massive domain feed without performing strict RFC or TLD validation, optimizing raw input before heavy processing.

```bash
curl -sL https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | awk '{print $2}' | undup -l > unique_base_domains.txt
```

Chain `clean-dom` output directly into `undup` to enforce strict binary-level parent-child deduplication on plain domain lists.

```bash
clean-dom -b https://big.oisd.nl/domainswild -o domain | undup -o oisd_apex_only.txt -v
```

## 5. domsort

Read a mixed text configuration containing comments and whitespace boundaries, enforcing TLD-down alphabetizing securely strictly within the segmented domain rules while preserving the original layout structure entirely natively.

```bash
cat adblock_feed.txt | domsort -l -v > adblock_feed_sorted.txt
```

Enforce strict A-Z alphabetizing across domains directly ignoring layout logic, applying output directly to disk.

```bash
domsort -i raw.txt -o alphabetical.txt -a -v
```

