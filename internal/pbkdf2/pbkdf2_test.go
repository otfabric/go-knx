// SPDX-License-Identifier: MIT

package pbkdf2

import (
	"encoding/hex"
	"testing"
)

// Test vectors of RFC 7914 section 11 (PBKDF2-HMAC-SHA256).
func TestSHA256(t *testing.T) {
	for _, tc := range []struct {
		pw, salt string
		iter, n  int
		want     string
	}{
		{"passwd", "salt", 1, 64, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"},
		{"Password", "NaCl", 80000, 64, "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"},
	} {
		got := hex.EncodeToString(SHA256([]byte(tc.pw), []byte(tc.salt), tc.iter, tc.n))
		if got != tc.want {
			t.Errorf("%s/%s/%d: got %s", tc.pw, tc.salt, tc.iter, got)
		}
	}
}
