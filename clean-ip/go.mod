// ==========================================================================
// Filename: go.mod
// Version: 1.0.0
// Date: 2026-04-22 15:20 CEST
// Description: Go module definition for the cleanip high-performance tool.
//              Enforces Go 1.18+ requirement for net/netip native support.
// ==========================================================================

module clean-ip

// Require Go 1.18 minimum for net/netip memory-efficient IP data structures.
// Using 1.21 to ensure modern compiler optimizations and security patches.
go 1.21
