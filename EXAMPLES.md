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

