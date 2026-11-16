// SPDX-License-Identifier: MIT

package knx_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/datasecure"
	"github.com/otfabric/go-knx/keyring"
	"github.com/otfabric/go-knx/secure"
)

// The keys, credentials and keyring entries print and log without their
// key octets and passwords: %v, %+v, %#v, %s, %x, %X, %q and a slog record
// in text and JSON. The fields that are not secret still show.
func TestSecretsRedacted(t *testing.T) {
	octets := [16]byte{0x5A, 0xC3, 0x3C, 0xA5, 0x96, 0x69, 0x0F, 0xF0, 0x5A, 0xC3, 0x3C, 0xA5, 0x96, 0x69, 0x0F, 0xF0}
	const password, auth = "pw-of-the-user", "pw-of-the-device"
	ga := knx.MustParseGroupAddress("1/2/3")
	ia := knx.MustParseIndividualAddress("1.1.10")
	host := knx.MustParseIndividualAddress("1.1.1")
	code := secure.Key(octets)
	backbone := &keyring.Backbone{MulticastAddress: "224.0.23.12", Latency: time.Second, Key: keyring.Key(octets)}
	itf := keyring.Interface{Type: keyring.Tunneling, IndividualAddress: ia, Host: host, HasHost: true, UserID: 2,
		Password: password, Authentication: auth, Groups: map[knx.GroupAddress][]knx.IndividualAddress{ga: {host}}}
	dev := keyring.Device{IndividualAddress: host, ToolKey: keyring.Key(octets), HasToolKey: true,
		ManagementPassword: password, Authentication: auth, SequenceNumber: 77}
	kr := keyring.Keyring{Project: "project-x", CreatedBy: "ETS", Created: "2026-01-01T00:00:00Z", Backbone: backbone,
		Interfaces: []keyring.Interface{itf}, GroupKeys: map[knx.GroupAddress]keyring.Key{ga: keyring.Key(octets)}, Devices: []keyring.Device{dev}}

	for _, tc := range []struct {
		name string
		v    any
		show []string // non-secret fields the text output keeps
	}{
		{"secure.Key", secure.Key(octets), nil},
		{"secure.Credentials", secure.Credentials{UserID: 2, UserKey: secure.Key(octets), DeviceCode: &code}, []string{"UserID: 2"}},
		{"secure.Credentials without device code", secure.Credentials{UserID: 3, UserKey: secure.Key(octets)}, []string{"UserID: 3", "DeviceCode: nil"}},
		{"datasecure.Key", datasecure.Key(octets), nil},
		{"keyring.Key", keyring.Key(octets), nil},
		{"keyring.Backbone", *backbone, []string{"224.0.23.12", "1s"}},
		{"keyring.Interface", itf, []string{"Tunneling", "1.1.10", "UserID: 2", "Groups: 1"}},
		{"keyring.Device", dev, []string{"1.1.1", "SequenceNumber: 77"}},
		{"keyring.Keyring", kr, []string{"project-x", "224.0.23.12"}},
		{"*keyring.Keyring", &kr, []string{"project-x"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := fmt.Sprintf("%v|%+v|%#v|%s|%x|%X|%q", tc.v, tc.v, tc.v, tc.v, tc.v, tc.v, tc.v)
			noSecret(t, "fmt", text, octets, password, auth)
			if !strings.Contains(text, "(redacted)") {
				t.Errorf("fmt: %s, want (redacted)", text)
			}
			for _, s := range tc.show {
				if !strings.Contains(text, s) {
					t.Errorf("fmt: %s, want %q", text, s)
				}
			}
			for name, h := range map[string]func(*bytes.Buffer) slog.Handler{
				"slog text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
				"slog JSON": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
			} {
				var b bytes.Buffer
				slog.New(h(&b)).Info("configuration", "value", tc.v)
				noSecret(t, name, b.String(), octets, password, auth)
			}
		})
	}
	// The octets stay available.
	if k := secure.Key(octets); !bytes.Equal(k[:], octets[:]) {
		t.Fatal("key octets")
	}
}

// noSecret fails when out holds the key octets in hexadecimal, as Go
// array literals or in decimal, or one of the passwords.
func noSecret(t *testing.T, where, out string, key [16]byte, passwords ...string) {
	t.Helper()
	low := strings.ToLower(out)
	dec := make([]string, 4)
	for i, b := range key[:4] {
		dec[i] = strconv.Itoa(int(b))
	}
	forms := []string{hex.EncodeToString(key[:4]), fmt.Sprintf("% x", key[:4]), "0x5a", strings.Join(dec, " ")}
	for _, f := range forms {
		if strings.Contains(low, f) {
			t.Errorf("%s: %s holds the key octets (%q)", where, out, f)
		}
	}
	for _, p := range passwords {
		if strings.Contains(out, p) {
			t.Errorf("%s: %s holds the password %q", where, out, p)
		}
	}
}
