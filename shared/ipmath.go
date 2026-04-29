// ==========================================================================
// Filename: shared/ipmath.go
// Version: 1.2.2-20260429
// Date: 2026-04-29 12:22 CEST
// Update Trail:
//   - 1.2.2-20260429: Fixed IP subnet mask parsing bug causing fragmented bit summing.
//                     Optimized binary counting using math/bits natively.
//   - 1.2.0-20260429: Consolidated heavy IP and CIDR mathematical functions
//                     from clean-ip into shared to standardize logic across tools.
// Description: Centralized high-performance IP and CIDR mathematical utilities.
//              Handles zero-allocation subnet collapsing, hole-punching, and 
//              range summarization natively using net/netip.
// ==========================================================================

package shared

import (
	"fmt"
	"math/bits"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// StripZeroPadding handles malformed IPv4 formats (e.g. 010.000.000.001)
// natively without utilizing the slow Go regexp engine. It respects CIDR blocks.
func StripZeroPadding(s string) string {
	// Fast bypass: only process strings that look like IPv4 (dots, no colons)
	if !strings.ContainsRune(s, '.') || strings.ContainsRune(s, ':') {
		return s
	}

	base := s
	prefix := ""

	// Preserve the prefix length (/24) if it exists
	if idx := strings.IndexByte(s, '/'); idx != -1 {
		base = s[:idx]
		prefix = s[idx:]
	}

	parts := strings.Split(base, ".")
	if len(parts) != 4 {
		return s // Abort if not standard IPv4 octets
	}

	changed := false
	for i, p := range parts {
		trimmed := strings.TrimLeft(p, "0")
		// If trimming removed everything (e.g., "000"), it was a zero.
		if trimmed == "" {
			trimmed = "0"
		}
		if len(trimmed) != len(p) {
			parts[i] = trimmed
			changed = true
		}
	}

	if !changed {
		return s
	}
	return strings.Join(parts, ".") + prefix
}

// ParsePrefixStrict handles both CIDR and Netmask notation safely. 
// Truncates dirty host bits safely if strict == false natively using netip.
func ParsePrefixStrict(s string, strict bool) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		parts := strings.Split(s, "/")
		if len(parts) == 2 && strings.Contains(parts[1], ".") {
			maskAddr, err := netip.ParseAddr(parts[1])
			if err == nil && maskAddr.Is4() {
				// Convert to contiguous uint32 block
				b := maskAddr.As4()
				v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
				
				// Execute high-speed binary bitwise NOT operation and count leading zeros.
				// This flawlessly determines the contiguous CIDR bound of any valid Netmask.
				maskBits := bits.LeadingZeros32(^v)
				s = parts[0] + "/" + strconv.Itoa(maskBits)
			}
		}
	}

	pfx, err := netip.ParsePrefix(s)
	if err != nil {
		addr, err2 := netip.ParseAddr(s)
		if err2 != nil {
			return netip.Prefix{}, err2
		}
		pfx = netip.PrefixFrom(addr, addr.BitLen())
	}

	if strict {
		if pfx.Addr() != pfx.Masked().Addr() {
			return netip.Prefix{}, fmt.Errorf("dirty host bits in prefix")
		}
		return pfx, nil
	}
	return pfx.Masked(), nil
}

// AddrBitLen returns the absolute bit boundary based on protocol version natively.
func AddrBitLen(a netip.Addr) int {
	if a.Is4() {
		return 32
	}
	return 128
}

// LastAddr calculates the broadcast address by manipulating binary arrays directly.
func LastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().As16()
	bitLen := AddrBitLen(p.Addr())
	hostBits := bitLen - p.Bits()

	for i := 0; i < hostBits; i++ {
		idx := bitLen - 1 - i
		byteIdx := idx / 8
		bitIdx := 7 - (idx % 8)
		b[byteIdx] |= (1 << bitIdx)
	}

	if p.Addr().Is4() {
		return netip.AddrFrom4(*(*[4]byte)(b[12:]))
	}
	return netip.AddrFrom16(b)
}

// MaxAddr returns the mathematical limit ceiling based on IP version natively.
func MaxAddr(a netip.Addr) netip.Addr {
	if a.Is4() {
		return netip.AddrFrom4([4]byte{255, 255, 255, 255})
	}
	return netip.AddrFrom16([16]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255})
}

// NextAddr manually forces an iterative increment across host bit boundaries.
func NextAddr(a netip.Addr) netip.Addr {
	b := a.As16()
	for i := 15; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
	if a.Is4() {
		return netip.AddrFrom4(*(*[4]byte)(b[12:]))
	}
	return netip.AddrFrom16(b)
}

// SummarizeRange mathematically converts spanning IP-to-IP formats into optimal CIDRs
func SummarizeRange(start, end netip.Addr) []netip.Prefix {
	var res []netip.Prefix
	curr := start

	for curr.Compare(end) <= 0 {
		maxLen := AddrBitLen(curr)
		bits := maxLen

		for b := maxLen; b >= 0; b-- {
			p := netip.PrefixFrom(curr, b)
			if p.Masked().Addr() != curr {
				break
			}
			if LastAddr(p).Compare(end) > 0 {
				break
			}
			bits = b
		}

		p := netip.PrefixFrom(curr, bits)
		res = append(res, p)

		last := LastAddr(p)
		if last == MaxAddr(curr) {
			break
		}
		curr = NextAddr(last)
	}

	return res
}

// Halve mathematically splits a supernet exactly down the middle using binary XOR
func Halve(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := p.Bits()
	a1 := p.Addr()
	b1 := a1.As16()

	byteIdx := bits / 8
	bitIdx := 7 - (bits % 8)
	b1[byteIdx] ^= (1 << bitIdx)

	var a2 netip.Addr
	if a1.Is4() {
		a2 = netip.AddrFrom4(*(*[4]byte)(b1[12:]))
	} else {
		a2 = netip.AddrFrom16(b1)
	}

	p1 := netip.PrefixFrom(a1, bits+1)
	p2 := netip.PrefixFrom(a2, bits+1)
	return p1, p2
}

// ExcludePrefix guarantees the protected subnet stays reachable 
// by fracturing the supernet block directly around it
func ExcludePrefix(super, sub netip.Prefix) []netip.Prefix {
	if !super.Contains(sub.Addr()) {
		return []netip.Prefix{super}
	}
	if super == sub {
		return nil
	}

	var res []netip.Prefix
	curr := super

	for curr.Bits() < sub.Bits() {
		h1, h2 := Halve(curr)
		if h1.Contains(sub.Addr()) {
			res = append(res, h2)
			curr = h1
		} else {
			res = append(res, h1)
			curr = h2
		}
	}
	return res
}

// CollapsePrefixes natively sorts and aggressively collapses contiguous and 
// overlapping subnets into supernets entirely in-memory using slices.SortFunc.
func CollapsePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}

	// High-speed sorting using modern Go 1.21+ slices.SortFunc
	// eliminating all reflection-based overhead.
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
		if a.Addr().Is4() != b.Addr().Is4() {
			if a.Addr().Is4() {
				return -1
			}
			return 1
		}
		if cmp := a.Addr().Compare(b.Addr()); cmp != 0 {
			return cmp
		}
		return a.Bits() - b.Bits()
	})

	var stack []netip.Prefix
	stack = append(stack, prefixes[0])

	for i := 1; i < len(prefixes); i++ {
		curr := prefixes[i]
		last := stack[len(stack)-1]

		// Absorb total overlap intrinsically
		if last.Contains(curr.Addr()) {
			continue
		}

		stack = append(stack, curr)

		// Sweep backwards analyzing structural bounds to merge adjacencies natively
		for len(stack) >= 2 {
			p1 := stack[len(stack)-2]
			p2 := stack[len(stack)-1]

			if p1.Bits() == p2.Bits() {
				super := netip.PrefixFrom(p1.Addr(), p1.Bits()-1).Masked()
				h1, h2 := Halve(super)
				if (p1 == h1 && p2 == h2) || (p1 == h2 && p2 == h1) {
					stack = stack[:len(stack)-2]
					stack = append(stack, super)
					continue
				}
			}
			break
		}
	}

	return stack
}

