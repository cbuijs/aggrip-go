// ==========================================================================
// Filename: go.mod
// Version: 1.0.1
// Date: 2026-04-29 10:48 CEST
// Description: Go module definition for the cleanip high-performance tool.
//              Enforces Go 1.18+ requirement for net/netip native support.
// ==========================================================================

module clean-ip

// Require Go 1.18 minimum for net/netip memory-efficient IP data structures.
// Using 1.21 to ensure modern compiler optimizations and security patches.
go 1.21

require aggrip-go/shared v0.0.0

replace aggrip-go/shared => ../shared

