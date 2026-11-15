// SPDX-License-Identifier: MIT

package keyring

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/otfabric/go-knx"
)

// Allocation budgets of Parse at its limits (SECURITY.md, "Resource
// limits"): a document one step over a limit is refused as
// knx.ErrMalformed before the signature is checked, and what Parse
// allocates until then is bounded by the limit, not by the document. The
// budgets are octets per call, averaged over runs.

func allocated(runs int, f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for range runs {
		f()
	}
	runtime.ReadMemStats(&after)
	return (after.TotalAlloc - before.TotalAlloc) / uint64(runs)
}

func TestParseAllocationBudgetAtLimits(t *testing.T) {
	const open, end = `<Keyring Signature="AAAA">`, `</Keyring>`
	for _, tc := range []struct {
		name   string
		doc    string
		budget uint64
	}{
		// Refused by its length: nothing of it is read.
		{"one octet over the size limit", `<Keyring Signature="AAAA" />` + strings.Repeat(" ", maxSize-len(`<Keyring Signature="AAAA" />`)+1), 4 << 10},
		{"twice the size limit", strings.Repeat("<a/>", 2*maxSize/4), 4 << 10},
		// Refused at the first element below the deepest level: the
		// rest of the document is not read.
		{"one level over the depth limit", open + strings.Repeat("<a>", maxDepth) + strings.Repeat("</a>", maxDepth) + end, 64 << 10},
		{"a million levels", strings.Repeat("<a>", maxSize/3), 64 << 10},
		// Refused at the first element over the count: the tree built
		// until then is at most maxElements elements.
		{"one element over the element limit", open + strings.Repeat("<a/>", maxElements) + end, maxElements * 512},
		{"four times the element limit", open + strings.Repeat("<a/>", maxSize/4-16) + end, maxElements * 512},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := []byte(tc.doc)
			if _, err := Parse(doc, "x"); !errors.Is(err, knx.ErrMalformed) {
				t.Fatalf("Parse of %d octets = %v, want knx.ErrMalformed", len(doc), err)
			}
			if got := allocated(3, func() { _, _ = Parse(doc, "x") }); got > tc.budget {
				t.Errorf("%d octets allocated per call for a document of %d octets, budget %d", got, len(doc), tc.budget)
			}
		})
	}
}
