// SPDX-License-Identifier: MIT

package leak

import (
	"strings"
	"testing"
)

// recorder is a testing.TB that keeps the failure instead of failing.
type recorder struct {
	testing.TB
	failure  string
	cleanups []func()
}

func (r *recorder) Helper()               {}
func (r *recorder) Cleanup(f func())      { r.cleanups = append(r.cleanups, f) }
func (r *recorder) Errorf(string, ...any) { r.failure = "failed" }

func TestWaitNamesTheLeakedGoroutine(t *testing.T) {
	before := ids(stacks())
	block := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-block
	}()
	left := ""
	for left == "" {
		left = extra(stacks(), before)
	}
	close(block)
	<-done
	if !strings.Contains(left, "leak.TestWaitNamesTheLeakedGoroutine") {
		t.Fatalf("the stack does not name the leaked goroutine:\n%s", left)
	}
}

func TestCheckIgnoresGoroutinesThatFinish(t *testing.T) {
	r := &recorder{TB: t}
	Check(r)
	done := make(chan struct{})
	go close(done)
	<-done
	for _, f := range r.cleanups {
		f()
	}
	if r.failure != "" {
		t.Fatal("a goroutine that finished was reported")
	}
}

func TestExtraKeepsWhatWasRunningBefore(t *testing.T) {
	all := []string{"goroutine 1 [running]:\nmain", "goroutine 7 [chan receive]:\nold", "goroutine 8 [chan receive]:\nnew"}
	if got := extra(all, map[int]bool{7: true}); got != all[2] {
		t.Fatalf("extra = %q", got)
	}
}

func TestBenign(t *testing.T) {
	if !benign("goroutine 9 [chan receive]:\ntesting.tRunner.func1()") {
		t.Fatal("a test runner goroutine is not the code under test")
	}
	if benign("goroutine 9 [IO wait]:\ngithub.com/otfabric/go-knx/client.(*Client).readLoop()") {
		t.Fatal("a read loop must be reported")
	}
}

func TestIDWithoutHeader(t *testing.T) {
	if id("garbage") != 0 {
		t.Fatal("id of text without a goroutine header")
	}
}
