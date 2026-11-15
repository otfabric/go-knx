// SPDX-License-Identifier: MIT

package guard

import (
	"fmt"
	"strings"
	"testing"

	"github.com/otfabric/go-knx"
)

// recorder keeps the entries logged at error level.
type recorder struct {
	knx.Logger
	entries []string
}

func (r *recorder) Errorf(format string, a ...any) {
	r.entries = append(r.entries, fmt.Sprintf(format, a...))
}

// faults are calls that do not return normally, each with the text the
// value it ends with holds.
var faults = map[string]struct {
	call func()
	text string
}{
	"index out of range": {func() {
		var none []int
		_ = none[len(none)+1]
	}, "index out of range"},
	"interface conversion": {func() {
		var v any = "telegram"
		_ = v.(fmt.Stringer)
	}, "interface conversion"},
	"division": {func() {
		var none []int
		_ = 7 / len(none)
	}, "integer divide by zero"},
}

func TestRun(t *testing.T) {
	called := false
	if fail := Run("client.OnTelegram", func() { called = true }); fail != nil || !called {
		t.Fatalf("a call that returns: failure %v, called %t", fail, called)
	}
	for name, fault := range faults {
		t.Run(name, func(t *testing.T) {
			after := false
			fail := Run("server.Subscribe", func() {
				defer func() { after = true }()
				fault.call()
			})
			if fail == nil {
				t.Fatal("no failure for a call that does not return normally")
			}
			if !after {
				t.Error("the deferred calls of the callback did not run")
			}
			value, ok := fail.Value.(error)
			if fail.Name != "server.Subscribe" || !ok || !strings.Contains(value.Error(), fault.text) {
				t.Errorf("failure %q with %v, want server.Subscribe with an error holding %q", fail.Name, fail.Value, fault.text)
			}
			if want := fmt.Sprintf("server.Subscribe did not return normally: %v", fail.Value); fail.Error() != want {
				t.Errorf("Error() = %q, want %q", fail.Error(), want)
			}
			if !strings.Contains(string(fail.Stack), "guard.TestRun") && !strings.Contains(string(fail.Stack), "guard.init") {
				t.Errorf("the stack does not name the caller:\n%s", fail.Stack)
			}
		})
	}
}

func TestReport(t *testing.T) {
	r := &recorder{Logger: knx.NopLogger()}
	Report(r, nil)
	Report(nil, &Failure{Name: "x"})
	if len(r.entries) != 0 {
		t.Fatalf("logged %q for no failure", r.entries)
	}
	fail := Run("device.Device.Handle", faults["division"].call)
	Report(r, fail)
	if len(r.entries) != 1 {
		t.Fatalf("%d entries, want 1", len(r.entries))
	}
	got := r.entries[0]
	if !strings.HasPrefix(got, "device.Device.Handle did not return normally: runtime error: integer divide by zero\n") || !strings.Contains(got, "guard.Run") {
		t.Errorf("entry without the call, its value or its stack:\n%s", got)
	}
}
