// ==========================================================================
// Filename: shared/strings.go
// Version: 1.0.0
// Date: 2026-04-29 10:48 CEST
// Description: Centralized string manipulation and reversal utilities driving
//              O(N log N) deduplication trees.
// ==========================================================================

package shared

// ReverseASCII performs a high-speed reverse of an ASCII string safely.
// Bypasses the overhead of full rune translation for pure network domains.
func ReverseASCII(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		b[len(s)-1-i] = s[i]
	}
	return string(b)
}

// ReverseStr performs a rapid rune-level reverse string operation for 
// O(N log N) deduplication sorting. Explicitly handles Unicode IDNA safely.
func ReverseStr(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

