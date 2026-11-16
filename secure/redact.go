// SPDX-License-Identifier: MIT

package secure

import (
	"fmt"
	"log/slog"
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

// LogValue returns the user ID with the keys redacted, for log/slog.
func (c Credentials) LogValue() slog.Value {
	return slog.GroupValue(slog.Int("user_id", int(c.UserID)), slog.String("user_key", redacted), slog.String("device_code", c.deviceCode()))
}
