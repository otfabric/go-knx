// SPDX-License-Identifier: MIT

package datasecure

import (
	"fmt"
	"log/slog"

	"github.com/otfabric/go-knx/internal/redact"
)

// redacted stands for a key in text and log output.
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

// String returns the number of entries of the table and its sequence
// number, with no key.
func (t *Table) String() string {
	if t == nil {
		return "<nil>"
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return fmt.Sprintf("datasecure.Table{Groups: %d, ToolKeys: %d, Senders: %d, Sequence: %d, Keys: %s}",
		len(t.keys), len(t.toolKeys), len(t.senders), t.seq, redacted)
}

// Format writes String for the verbs package fmt passes to it, %#v and %d
// too, so that the keys in its unexported fields are not printed.
func (t *Table) Format(s fmt.State, verb rune) { redact.Format(s, verb, t.String()) }
