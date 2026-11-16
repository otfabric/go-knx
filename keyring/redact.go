// SPDX-License-Identifier: MIT

package keyring

import (
	"fmt"
	"log/slog"
)

// redacted stands for a secret in text and log output.
const redacted = "(redacted)"

// secret is the presentation of a password: "" when there is none.
func secret(s string) string {
	if s == "" {
		return `""`
	}
	return redacted
}

// String returns "(redacted)", so that %v, %s, %x and %q do not print
// the key. Use k[:] for the octets.
func (Key) String() string { return redacted }

// GoString returns "(redacted)" for %#v.
func (Key) GoString() string { return redacted }

// LogValue returns "(redacted)" for log/slog.
func (Key) LogValue() slog.Value { return slog.StringValue(redacted) }

// String returns the backbone with its key redacted.
func (b Backbone) String() string {
	return fmt.Sprintf("keyring.Backbone{MulticastAddress: %s, Latency: %v, Key: %s}", b.MulticastAddress, b.Latency, redacted)
}

// GoString returns the backbone with its key redacted, for %#v.
func (b Backbone) GoString() string { return b.String() }

// LogValue returns the backbone with its key redacted, for log/slog.
func (b Backbone) LogValue() slog.Value {
	return slog.GroupValue(slog.String("multicast_address", b.MulticastAddress), slog.Duration("latency", b.Latency), slog.String("key", redacted))
}

// host is the presentation of the host of an interface.
func (i Interface) host() string {
	if !i.HasHost {
		return "none"
	}
	return i.Host.String()
}

// String returns the interface with its passwords redacted.
func (i Interface) String() string {
	return fmt.Sprintf("keyring.Interface{Type: %s, IndividualAddress: %s, Host: %s, UserID: %d, Password: %s, Authentication: %s, Groups: %d}",
		i.Type, i.IndividualAddress, i.host(), i.UserID, secret(i.Password), secret(i.Authentication), len(i.Groups))
}

// GoString returns the interface with its passwords redacted, for %#v.
func (i Interface) GoString() string { return i.String() }

// LogValue returns the interface with its passwords redacted, for
// log/slog.
func (i Interface) LogValue() slog.Value {
	return slog.GroupValue(slog.String("type", string(i.Type)), slog.String("individual_address", i.IndividualAddress.String()),
		slog.String("host", i.host()), slog.Int("user_id", int(i.UserID)), slog.String("password", secret(i.Password)),
		slog.String("authentication", secret(i.Authentication)), slog.Int("groups", len(i.Groups)))
}

// toolKey is the presentation of the tool key of a device.
func (d Device) toolKey() string {
	if !d.HasToolKey {
		return "none"
	}
	return redacted
}

// String returns the device with its key and passwords redacted.
func (d Device) String() string {
	return fmt.Sprintf("keyring.Device{IndividualAddress: %s, ToolKey: %s, ManagementPassword: %s, Authentication: %s, SequenceNumber: %d}",
		d.IndividualAddress, d.toolKey(), secret(d.ManagementPassword), secret(d.Authentication), d.SequenceNumber)
}

// GoString returns the device with its key and passwords redacted, for
// %#v.
func (d Device) GoString() string { return d.String() }

// LogValue returns the device with its key and passwords redacted, for
// log/slog.
func (d Device) LogValue() slog.Value {
	return slog.GroupValue(slog.String("individual_address", d.IndividualAddress.String()), slog.String("tool_key", d.toolKey()),
		slog.String("management_password", secret(d.ManagementPassword)), slog.String("authentication", secret(d.Authentication)),
		slog.Uint64("sequence_number", d.SequenceNumber))
}

// LogValue returns the project and the number of entries of the keyring,
// with no key or password, for log/slog. Its text forms (%v, %#v) redact
// the keys and passwords through the types of its fields.
func (k Keyring) LogValue() slog.Value {
	return slog.GroupValue(slog.String("project", k.Project), slog.String("created_by", k.CreatedBy), slog.String("created", k.Created),
		slog.Bool("backbone", k.Backbone != nil), slog.Int("interfaces", len(k.Interfaces)), slog.Int("group_keys", len(k.GroupKeys)),
		slog.Int("devices", len(k.Devices)))
}
