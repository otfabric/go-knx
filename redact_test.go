// SPDX-License-Identifier: MIT

package knx_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
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
	table, session := keyHolders(t, octets)

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
		{"*datasecure.Table", table, []string{"Groups: 1", "ToolKeys: 1", "Senders: 1", "Sequence: 99"}},
		{"*secure.Session", session, []string{"ID: 7"}},
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

// keyHolders returns a Data Secure table and a secure session that hold
// key in their unexported fields.
func keyHolders(t *testing.T, key [16]byte) (*datasecure.Table, *secure.Session) {
	t.Helper()
	ga := knx.MustParseGroupAddress("1/2/3")
	table, err := datasecure.NewTable(map[knx.GroupAddress]datasecure.Key{ga: datasecure.Key(key)},
		map[knx.IndividualAddress]uint64{knx.MustParseIndividualAddress("1.1.5"): 3}, 99)
	if err != nil {
		t.Fatal(err)
	}
	table.SetToolKey(knx.MustParseIndividualAddress("1.1.10"), datasecure.Key(key))
	return table, secure.NewSession(7, secure.Key(key), [6]byte{0x00, 0xFA, 1, 2, 3, 4})
}

// verbs are the directives TestSecretsRedactedEveryVerb prints with: the
// verbs of package fmt, with flags, a width and a precision, and an
// unknown one. Not %p of a value that is not a pointer, nor %w outside
// fmt.Errorf: fmt calls no method of the value for them (go vet reports
// both), so they print it as it is (LIMITATIONS.md).
var verbs = []string{"%v", "%+v", "%#v", "%s", "%q", "%#q", "%x", "% x", "%#x", "%X", "%d", "%+d", "%08d", "%-20d", "%o",
	"%O", "%#o", "%b", "%c", "%U", "%#U", "%e", "%E", "%f", "%F", "%g", "%G", "%t", "%.3d", "%T", "%z"}

// The key types, and the values that hold them, print no key octet and
// no password with the verbs of package fmt, %d and %o too, and
// encoding/json writes "(redacted)" for every key and password; a Data
// Secure table and a secure session print their redacted form.
func TestSecretsRedactedEveryVerb(t *testing.T) {
	octets := [16]byte{0x5A, 0xC3, 0x3C, 0xA5, 0x96, 0x69, 0x0F, 0xF0, 0x5A, 0xC3, 0x3C, 0xA5, 0x96, 0x69, 0x0F, 0xF0}
	const password, auth = "pw-of-the-user", "pw-of-the-device"
	ga := knx.MustParseGroupAddress("1/2/3")
	ia := knx.MustParseIndividualAddress("1.1.10")
	code := secure.Key(octets)
	table, session := keyHolders(t, octets)
	type holder struct {
		Name string
		Key  datasecure.Key
	}
	backbone := &keyring.Backbone{MulticastAddress: "224.0.23.12", Latency: time.Second, Key: keyring.Key(octets)}
	itf := keyring.Interface{Type: keyring.Tunneling, IndividualAddress: ia, UserID: 2, Password: password, Authentication: auth,
		Groups: map[knx.GroupAddress][]knx.IndividualAddress{ga: {ia}}}
	dev := keyring.Device{IndividualAddress: ia, ToolKey: keyring.Key(octets), HasToolKey: true, ManagementPassword: password, Authentication: auth}
	kr := keyring.Keyring{Project: "p", Backbone: backbone, Interfaces: []keyring.Interface{itf},
		GroupKeys: map[knx.GroupAddress]keyring.Key{ga: keyring.Key(octets)}, Devices: []keyring.Device{dev}}
	for _, tc := range []struct {
		name string
		v    any
		json bool // holds a key that encoding/json writes
	}{
		{"secure.Key", secure.Key(octets), true},
		{"*secure.Key", &code, true},
		{"datasecure.Key", datasecure.Key(octets), true},
		{"keyring.Key", keyring.Key(octets), true},
		{"[]secure.Key", []secure.Key{secure.Key(octets), secure.Key(octets)}, true},
		{"map of keyring.Key", map[knx.GroupAddress]keyring.Key{ga: keyring.Key(octets)}, true},
		{"a struct with a key", holder{Name: "x", Key: datasecure.Key(octets)}, true},
		{"secure.Credentials", secure.Credentials{UserID: 2, UserKey: secure.Key(octets), DeviceCode: &code}, true},
		{"*secure.Credentials without device code", &secure.Credentials{UserID: 3, UserKey: secure.Key(octets)}, true},
		{"keyring.Backbone", *backbone, true},
		{"*keyring.Backbone", backbone, true},
		{"keyring.Interface", itf, true},
		{"*keyring.Interface", &itf, true},
		{"keyring.Device", dev, true},
		{"[]keyring.Device", []keyring.Device{dev, dev}, true},
		{"keyring.Keyring", kr, true},
		{"*keyring.Keyring", &kr, true},
		{"*datasecure.Table", table, false},
		{"*secure.Session", session, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vs := verbs
			if reflect.ValueOf(tc.v).Kind() == reflect.Pointer {
				vs = append(vs[:len(vs):len(vs)], "%p")
			}
			for _, verb := range vs {
				out := fmt.Sprintf(verb, tc.v)
				noSecret(t, verb, out, octets, password, auth)
				if frag := octetsIn(verb, octets); strings.Contains(out, frag) {
					t.Errorf("%s: %s holds the key octets as %s prints them (%q)", verb, out, verb, frag)
				}
			}
			if out := fmt.Sprintf("%d", tc.v); !strings.Contains(out, "(redacted)") {
				t.Errorf("%%d: %s, want (redacted)", out)
			}
			b, err := json.Marshal(tc.v)
			if err != nil {
				t.Fatal(err)
			}
			out := string(b)
			noSecret(t, "encoding/json", out, octets, password, auth)
			for _, frag := range []string{"90,195,60", base64.StdEncoding.EncodeToString(octets[:6])} {
				if strings.Contains(out, frag) {
					t.Errorf("encoding/json: %s holds the key octets (%q)", out, frag)
				}
			}
			if tc.json && !strings.Contains(out, `"(redacted)"`) {
				t.Errorf("encoding/json: %s, want \"(redacted)\"", out)
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
	// A nil table or session prints as fmt prints a nil pointer.
	var nt *datasecure.Table
	var ns *secure.Session
	if got := fmt.Sprintf("%v %v %d", nt, ns, nt); got != "<nil> <nil> <nil>" {
		t.Errorf("nil table and session: %q", got)
	}
	// The octets stay available: the array marshals as before, the slice
	// in base64.
	k := secure.Key(octets)
	if b, err := json.Marshal([16]byte(k)); err != nil || !strings.HasPrefix(string(b), "[90,195,60,165,") {
		t.Errorf("json.Marshal([16]byte(k)) = %s, %v", b, err)
	}
	if b, err := json.Marshal(k[:]); err != nil || string(b) != `"`+base64.StdEncoding.EncodeToString(octets[:])+`"` {
		t.Errorf("json.Marshal(k[:]) = %s, %v", b, err)
	}
}

// octetsIn returns the start of the key octets as verb prints a [16]byte.
func octetsIn(verb string, key [16]byte) string {
	raw := strings.Trim(fmt.Sprintf(verb, key), "[]")
	f := strings.Fields(raw)
	if len(f) == 1 {
		return f[0][:min(8, len(f[0]))]
	}
	return strings.Join(f[:min(3, len(f))], " ")
}

// The verbs that String and GoString already redacted print as before:
// as fmt prints a value whose String and GoString return the same text.
func TestRedactedFormsUnchanged(t *testing.T) {
	var octets [16]byte
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%#q", "%+q", "%x", "% x", "%#x", "% #X", "%X",
		"%12v", "%-12v|", "%012v", "%#12v", "%-#12v|", "%.3s", "%12.4q", "%.2x"} {
		for name, v := range redactedStringers(octets) {
			want := fmt.Sprintf(verb, stringer(v.String()))
			if got := fmt.Sprintf(verb, v); got != want {
				t.Errorf("%s of %s = %q, want %q", verb, name, got, want)
			}
		}
	}
}

// The String and GoString methods, which fmt no longer calls since
// Format, still give the redacted text.
func TestKeyStringers(t *testing.T) {
	for name, k := range redactedStringers([16]byte{1}) {
		s, g := k.String(), k.GoString()
		if !strings.Contains(s, "(redacted)") || g != s {
			t.Errorf("%s: String %q, GoString %q, want (redacted)", name, s, g)
		}
	}
}

// redactedStringers returns the values whose Format writes their String.
func redactedStringers(octets [16]byte) map[string]interface {
	fmt.Stringer
	fmt.GoStringer
} {
	code := secure.Key(octets)
	ia := knx.MustParseIndividualAddress("1.1.10")
	return map[string]interface {
		fmt.Stringer
		fmt.GoStringer
	}{
		"secure.Key": secure.Key(octets), "datasecure.Key": datasecure.Key(octets), "keyring.Key": keyring.Key(octets),
		"secure.Credentials": secure.Credentials{UserID: 2, UserKey: secure.Key(octets), DeviceCode: &code},
		"keyring.Backbone":   keyring.Backbone{MulticastAddress: "224.0.23.12", Latency: time.Second, Key: keyring.Key(octets)},
		"keyring.Interface":  keyring.Interface{Type: keyring.Tunneling, IndividualAddress: ia, UserID: 2, Password: "pw"},
		"keyring.Device":     keyring.Device{IndividualAddress: ia, ToolKey: keyring.Key(octets), HasToolKey: true, ManagementPassword: "pw"},
	}
}

// stringer is a value whose String and GoString give the same text.
type stringer string

func (s stringer) String() string   { return string(s) }
func (s stringer) GoString() string { return string(s) }

// encoding/json writes the fields of keyring.Interface and keyring.Device
// as before, a password as "(redacted)" and one that is empty as "", also
// inside a keyring.Keyring. A type of the caller's own with the same
// fields marshals the passwords.
func TestRedactedJSONFields(t *testing.T) {
	const password, auth = "pw-of-the-user", "pw-of-the-device"
	ga := knx.MustParseGroupAddress("1/2/3")
	ia := knx.MustParseIndividualAddress("1.1.10")
	type plainInterface keyring.Interface
	type plainDevice keyring.Device
	marshal := func(v any) string {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	// redacted is a password as the JSON holds it.
	redacted := func(s string) string {
		if s == "" {
			return ""
		}
		return "(redacted)"
	}
	for _, tc := range []struct {
		name string
		itf  keyring.Interface
		dev  keyring.Device
	}{
		{"with passwords", keyring.Interface{Type: keyring.Tunneling, IndividualAddress: ia, UserID: 2, Password: password, Authentication: auth,
			Groups: map[knx.GroupAddress][]knx.IndividualAddress{ga: {ia}}},
			keyring.Device{IndividualAddress: ia, HasToolKey: true, ManagementPassword: password, Authentication: auth, SequenceNumber: 77}},
		{"one empty", keyring.Interface{Type: keyring.Tunneling, IndividualAddress: ia, Password: password},
			keyring.Device{IndividualAddress: ia, Authentication: auth}},
		{"none", keyring.Interface{Type: keyring.USB}, keyring.Device{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wi := plainInterface(tc.itf)
			wi.Password, wi.Authentication = redacted(wi.Password), redacted(wi.Authentication)
			gi := marshal(tc.itf)
			if want := marshal(wi); gi != want {
				t.Errorf("json.Marshal(Interface) = %s, want %s", gi, want)
			}
			wd := plainDevice(tc.dev)
			wd.ManagementPassword, wd.Authentication = redacted(wd.ManagementPassword), redacted(wd.Authentication)
			gd := marshal(tc.dev)
			if want := marshal(wd); gd != want {
				t.Errorf("json.Marshal(Device) = %s, want %s", gd, want)
			}
			kr := marshal(keyring.Keyring{Project: "p", Interfaces: []keyring.Interface{tc.itf}, Devices: []keyring.Device{tc.dev}})
			if !strings.Contains(kr, `"Interfaces":[`+gi+`]`) || !strings.Contains(kr, `"Devices":[`+gd+`]`) {
				t.Errorf("json.Marshal(Keyring) = %s, want the interface %s and the device %s", kr, gi, gd)
			}
			noSecret(t, "json.Marshal(Keyring)", kr, [16]byte{0x5A, 0xC3, 0x3C, 0xA5}, password, auth)
			// The restore path: a type of the caller's own with the same fields.
			if got := marshal(plainInterface(tc.itf)); !strings.Contains(got, `"Password":"`+tc.itf.Password+`"`) {
				t.Errorf("json.Marshal(plainInterface) = %s, want the password", got)
			}
			if got := marshal(plainDevice(tc.dev)); !strings.Contains(got, `"Authentication":"`+tc.dev.Authentication+`"`) {
				t.Errorf("json.Marshal(plainDevice) = %s, want the password", got)
			}
		})
	}
}
