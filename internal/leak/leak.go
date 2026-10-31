// SPDX-License-Identifier: MIT

// Package leak checks tests for goroutines they leave behind. It compares
// goroutine stacks, so a failure names the goroutine that leaked, and it has
// no dependency outside the standard library (standards/concurrency.md#leaks).
package leak

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// grace is how long goroutines get to finish after a test has closed what it
// started: a closed socket wakes a read loop at the scheduler's convenience.
const grace = 5 * time.Second

// Check records the goroutines running now and fails the test if a goroutine
// started since is still running after a grace period when the test ends.
// Tests running in parallel with this one count as its own, so Check belongs
// in tests that do not call t.Parallel.
func Check(t testing.TB) {
	t.Helper()
	before := ids(stacks())
	t.Cleanup(func() {
		t.Helper()
		if left := wait(before); left != "" {
			t.Errorf("goroutine leak:\n%s", left)
		}
	})
}

// VerifyNoLeaks runs a package's tests from TestMain and fails the run if a
// goroutine they started is still running after them:
//
//	func TestMain(m *testing.M) { leak.VerifyNoLeaks(m) }
func VerifyNoLeaks(m *testing.M) {
	before := ids(stacks())
	code := m.Run()
	if code == 0 {
		if left := wait(before); left != "" {
			fmt.Fprintf(os.Stderr, "goroutine leak after the tests:\n%s\n", left)
			code = 1
		}
	}
	os.Exit(code)
}

// wait returns the stacks of the goroutines not in before that are still
// running after the grace period, or "" once there are none.
func wait(before map[int]bool) string {
	deadline := time.Now().Add(grace)
	for {
		left := extra(stacks(), before)
		if left == "" || time.Now().After(deadline) {
			return left
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// stacks returns the stack of every goroutine, one element each.
func stacks() []string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Split(string(bytes.TrimSpace(buf[:n])), "\n\n")
		}
		buf = make([]byte, 2*len(buf))
	}
}

var header = regexp.MustCompile(`^goroutine (\d+) `)

func id(stack string) int {
	m := header.FindStringSubmatch(stack)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

func ids(all []string) map[int]bool {
	seen := make(map[int]bool, len(all))
	for _, s := range all {
		seen[id(s)] = true
	}
	return seen
}

// extra joins the stacks of goroutines not in before. The goroutine that asks
// is one of them when it did not exist yet (a t.Cleanup runs on the test's
// goroutine; a parallel subtest on its own), and so are the testing package's
// and the runtime's helpers, none of which the code under test started.
func extra(all []string, before map[int]bool) string {
	var left []string
	for i, s := range all {
		if i == 0 || before[id(s)] || benign(s) {
			continue
		}
		left = append(left, s)
	}
	return strings.Join(left, "\n\n")
}

func benign(stack string) bool {
	for _, frame := range []string{
		"testing.(*T).Run",
		"testing.tRunner",
		"testing.(*F).",
		"testing.(*M).",
		"testing.runFuzz",
		"internal/fuzz.",
		"os/signal.",
		"runtime.goexit0",
		"runtime/pprof.",
	} {
		if strings.Contains(stack, frame) {
			return true
		}
	}
	return false
}
