// SPDX-License-Identifier: MIT

package keyring

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
)

var signatureAttr = regexp.MustCompile(`Signature="[^"]*"`)

// FuzzParse feeds arbitrary documents to the keyring decoder. The signature
// gates everything after the XML tree, so the harness signs each tree that
// parses with the fuzz password before handing it to Parse: the fuzzer then
// reaches the decryption and the decoding of every element. Parse must not
// panic, and a keyring it returns must have usable lookups and encode again
// to a keyring that parses.
func FuzzParse(f *testing.F) {
	const password = "x"
	hash := passwordHash(password) // PBKDF2 is slow: once, not per input
	k := &Keyring{
		Project: "fuzz", CreatedBy: "go-knx",
		Backbone: &Backbone{MulticastAddress: "224.0.23.12", Latency: 1000 * time.Millisecond, Key: Key{1, 2, 3}},
		Interfaces: []Interface{
			{Type: Tunneling, IndividualAddress: 0x110a, Host: 0x1100, HasHost: true, UserID: 2, Password: "pw", Authentication: "dev",
				Groups: map[knx.GroupAddress][]knx.IndividualAddress{0x0a03: {0x1114}}},
			{Type: USB, IndividualAddress: 0x110b},
		},
		GroupKeys: map[knx.GroupAddress]Key{0x0a03: {9}},
		Devices:   []Device{{IndividualAddress: 0x1100, ToolKey: Key{7}, HasToolKey: true, ManagementPassword: "m", Authentication: "dev", SequenceNumber: 42}},
	}
	b, err := k.Encode(password)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte(`<Keyring Signature="" Project="p" Created="2026-01-01T00:00:00" />`))
	f.Add([]byte(`<Keyring Signature=""><Backbone MulticastAddress="224.0.23.12" Latency="x" /></Keyring>`))
	// The published keyrings of the tests (other passwords: they exercise
	// the tree and, re-signed, the decryption with a wrong key).
	files, _ := filepath.Glob(filepath.Join("testdata", "*.knxkeys"))
	for _, name := range files {
		if b, err := os.ReadFile(name); err == nil {
			f.Add(b)
		}
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		root, err := parseTree(b)
		if err != nil || root.name != "Keyring" || len(b) > 1<<16 {
			// Parse fails in parseTree as well; it would only add the
			// PBKDF2 of the password first.
			return
		}
		sig, err := signature(root, hash)
		if err != nil {
			return
		}
		loc := signatureAttr.FindIndex(b)
		if loc == nil {
			return
		}
		doc := append(append(append([]byte(nil), b[:loc[0]]...), `Signature="`+base64.StdEncoding.EncodeToString(sig)+`"`...), b[loc[1]:]...)
		kr, err := Parse(doc, password)
		if err != nil {
			if kr != nil {
				t.Fatalf("keyring with error %v", err)
			}
			return
		}
		for i := range kr.Interfaces {
			_, _ = kr.Interfaces[i].Credentials()
			_ = kr.Interface(kr.Interfaces[i].IndividualAddress)
			_ = kr.Tunnels(kr.Interfaces[i].Host)
		}
		for _, d := range kr.Devices {
			_ = kr.Device(d.IndividualAddress)
		}
		_ = kr.Senders()
		_, _ = kr.DataSecure(1)
		_, _, _ = kr.BackboneKey()
		enc, err := kr.Encode(password)
		if err != nil {
			return // a value Encode refuses (ErrMalformed) is fine
		}
		if _, err := Parse(enc, password); err != nil {
			t.Fatalf("an encoded keyring does not parse: %v\n%s", err, enc)
		}
	})
}
