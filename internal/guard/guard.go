// SPDX-License-Identifier: MIT

// Package guard is how the library calls code of the application on its
// own goroutines: a telegram callback of a client, a tap of a server, the
// change handler of a virtual device. A call that does not return
// normally is stopped where the library makes it and turned into a
// Failure, which the caller logs with Report once it holds no lock, so
// that the goroutine, and with it the reader or the server, goes on as if
// the call had returned.
package guard

import (
	"fmt"
	"runtime/debug"

	"github.com/otfabric/go-knx"
)

// Failure is a call of application code that did not return normally.
type Failure struct {
	// Name says what was called, for example "client.OnTelegram".
	Name string
	// Value is the value the call ended with.
	Value any
	// Stack is the stack of the goroutine where the call ended.
	Stack []byte
}

// Error describes the call, for example
// "client.OnTelegram did not return normally: index out of range".
func (f *Failure) Error() string {
	return fmt.Sprintf("%s did not return normally: %v", f.Name, f.Value)
}

// Run calls fn, the application code that name names. It returns nil when
// fn returns, and the Failure when it does not. Run does not log: the
// caller gives the Failure to Report once it holds no lock.
func Run(name string, fn func()) (fail *Failure) {
	defer func() {
		if r := recover(); r != nil {
			fail = &Failure{Name: name, Value: r, Stack: debug.Stack()}
		}
	}()
	fn()
	return nil
}

// Report logs fail through l at error level, with the value the call
// ended with and its stack. A nil fail or a nil l logs nothing.
func Report(l knx.Logger, fail *Failure) {
	if fail == nil || l == nil {
		return
	}
	l.Errorf("%v\n%s", fail, fail.Stack)
}
