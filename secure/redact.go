// SPDX-License-Identifier: MIT

package secure

import (
	"fmt"
	"log/slog"

	"github.com/otfabric/go-knx/internal/redact"
)

// redacted stands for a secret in text and log output.
const redacted = "(redacted)"

// String returns "(redacted)", so that %v, %s, %x and %q do not print
// the key. Use k[:] for the octets.
func (Key) String() string { return redacted }

// GoString returns "(redacted)" for %#v.
func (Key) GoString() string { return redacted }

// LogValue returns "(redacted)" for log/slog.
func (Key) LogValue() slog.Value { return slog.StringValue(redacted) }

// Format writes "(redacted)" for the verbs package fmt passes to it, %d
// too: %v, %s, %q, %x and %X as with String, %#v as with GoString. (fmt
// calls no method of the value for %p, nor for %w outside fmt.Errorf.)
func (Key) Format(s fmt.State, verb rune) { redact.Format(s, verb, redacted) }

// MarshalJSON returns the JSON string "(redacted)", so that encoding/json
// does not write the key. Marshal [16]byte(k) for the octets as before,
// or k[:] for them in base64.
func (Key) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// deviceCode is the presentation of the device authentication code.
func (c Credentials) deviceCode() string {
	if c.DeviceCode == nil {
		return "nil"
	}
	return redacted
}

// String returns the user ID with the keys redacted.
func (c Credentials) String() string {
	return fmt.Sprintf("secure.Credentials{UserID: %d, UserKey: %s, DeviceCode: %s}", c.UserID, redacted, c.deviceCode())
}

// GoString returns the user ID with the keys redacted, for %#v.
func (c Credentials) GoString() string { return c.String() }

// Format writes String for the verbs package fmt passes to it, %#v and %d
// too. (encoding/json writes the keys as "(redacted)" through Key.)
func (c Credentials) Format(s fmt.State, verb rune) { redact.Format(s, verb, c.String()) }

// LogValue returns the user ID with the keys redacted, for log/slog.
func (c Credentials) LogValue() slog.Value {
	return slog.GroupValue(slog.Int("user_id", int(c.UserID)), slog.String("user_key", redacted), slog.String("device_code", c.deviceCode()))
}

// String returns the session identifier with the session key redacted.
func (s *Session) String() string {
	if s == nil {
		return "<nil>"
	}
	return fmt.Sprintf("secure.Session{ID: %d, Key: %s}", s.ID, redacted)
}

// Format writes String for the verbs package fmt passes to it, %#v and %d
// too, so that the session key in its unexported fields is not printed.
func (s *Session) Format(f fmt.State, verb rune) { redact.Format(f, verb, s.String()) }
