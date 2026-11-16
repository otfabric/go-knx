// SPDX-License-Identifier: MIT

package datasecure

import "log/slog"

// redacted stands for a key in text and log output.
const redacted = "(redacted)"

// String returns "(redacted)", so that %v, %s, %x and %q do not print
// the key. Use k[:] for the octets.
func (Key) String() string { return redacted }

// GoString returns "(redacted)" for %#v.
func (Key) GoString() string { return redacted }

// LogValue returns "(redacted)" for log/slog.
func (Key) LogValue() slog.Value { return slog.StringValue(redacted) }
