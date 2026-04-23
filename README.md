# aggrip-go

High-performance, low-latency, and secure Go utilities for optimizing, deduplicating, and managing massive DNS and IP-based blocklists and allowlists. Built for enterprise-grade public network filtering.

## Included Tools

### 1. clean-dom

**Enterprise-grade DNS Blocklist Optimizer** Consolidates multiple DNS blacklists and whitelists, deduplicates subdomains using an O(N log N) reverse-string tree sort, translates Punycode natively, and dynamically routes Adblock rules.

**Key Features:**

* **Concurrent Ingestion:** Streams massive lists via HTTP/HTTPS or local paths using Go concurrency.

* **Format Autodetection:** Upfront heuristic format detection (hosts, adblock, routedns, squid, domain).

* **Adblock Parsing:** Extracts modifiers (e.g., `$denyallow`) and translates Punycode (IDNA) automatically.

* **Tree Deduplication:** Rapid O(N log N) deduplication via reverse string sorting (automatically drops redundant subdomains if a parent is already blocked).

* **Multiple Outputs:** Generates ready-to-use configs for `domain`, `hosts`, `adblock`, `dnsmasq`, `unbound`, `rpz`, `routedns`, and `squid`.

**Usage Example:**

```bash
go run clean-dom/main.go --blocklist [https://example.com/ads.txt](https://example.com/ads.txt) --allowlist local-allow.txt -o unbound --out-blocklist unbound-filter.conf
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
go run clean-ip/main.go --blocklist drop.txt --allowlist allow.txt -o iptables --out-blocklist rules.v4
```

## Building from Source

Requires Go 1.25.0+ for `clean-dom` and Go 1.21+ for `clean-ip`.

```bash
# Build clean-dom
cd clean-dom
go build -ldflags="-s -w" -o clean-dom main.go

# Build clean-ip
cd ../clean-ip
go build -ldflags="-s -w" -o clean-ip main.go

