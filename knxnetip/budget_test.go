// SPDX-License-Identifier: MIT

package knxnetip

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"runtime"
	"testing"

	"github.com/otfabric/go-knx"
)

// Allocation budgets of the decoders that take a length from the wire
// (SECURITY.md, "Resource limits"). A length a peer declares must never
// size an allocation: what a decoder allocates is bounded by MaxFrameLen
// and by the octets it was given. The budgets are octets per call,
// averaged over runs; building an error allocates a little, which they
// leave room for.

// allocated returns the octets one call of f allocates, averaged over
// runs.
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

// endless is a stream that never ends: a reader that trusted a declared
// length would keep reading it.
type endless struct{ read int }

func (e *endless) Read(p []byte) (int, error) {
	clear(p)
	e.read += len(p)
	return len(p), nil
}

// ReadFrame refuses a total length above MaxFrameLen after the header:
// it reads nothing more of the stream and allocates nothing by the
// declared length. The longest frame it accepts costs one buffer of its
// length.
func TestReadFrameAllocationBudget(t *testing.T) {
	header := func(total int) []byte {
		return []byte{HeaderLen, 0x10, 0x05, 0x30, byte(total >> 8), byte(total)}
	}
	for _, tc := range []struct {
		total  int
		ok     bool
		budget uint64
	}{
		{HeaderLen, true, 512},
		{MaxFrameLen - 1, true, 2 * MaxFrameLen},
		{MaxFrameLen, true, 2 * MaxFrameLen},
		{MaxFrameLen + 1, false, 1024},
		{0x7FFF, false, 1024},
		{0x8000, false, 1024},
		{0xFFFF, false, 1024},
	} {
		t.Run(fmt.Sprintf("total length %d", tc.total), func(t *testing.T) {
			body := &endless{}
			b, err := ReadFrame(io.MultiReader(bytes.NewReader(header(tc.total)), body))
			if tc.ok {
				if err != nil || len(b) != tc.total || body.read != tc.total-HeaderLen {
					t.Fatalf("ReadFrame = %d octets, %v, %d octets of the body read; want %d, nil, %d", len(b), err, body.read, tc.total, tc.total-HeaderLen)
				}
			} else {
				if !errors.Is(err, knx.ErrMalformed) || b != nil {
					t.Fatalf("ReadFrame = %d octets, %v; want knx.ErrMalformed", len(b), err)
				}
				if body.read != 0 {
					t.Fatalf("%d octets read after the header of a frame that is refused", body.read)
				}
			}
			h := header(tc.total)
			got := allocated(200, func() {
				_, _ = ReadFrame(io.MultiReader(bytes.NewReader(h), &endless{}))
			})
			if got > tc.budget {
				t.Errorf("%d octets allocated per call, budget %d", got, tc.budget)
			}
		})
	}
}

// Parse of the longest frame allocates in proportion to the frame, never
// more: the cEMI octets of a tunnelling request and of a routing
// indication are copied once.
func TestParseAllocationBudget(t *testing.T) {
	for name, prefix := range map[string][]byte{
		"routing indication": {HeaderLen, 0x10, 0x05, 0x30, 0x04, 0x00},
		"tunnelling request": {HeaderLen, 0x10, 0x04, 0x20, 0x04, 0x00, 0x04, 0x07, 0x00, 0x00},
		"unknown service":    {HeaderLen, 0x10, 0x77, 0x77, 0x04, 0x00},
	} {
		t.Run(name, func(t *testing.T) {
			frame := append(append([]byte(nil), prefix...), make([]byte, MaxFrameLen-len(prefix))...)
			if _, err := Parse(frame); err != nil {
				t.Fatalf("Parse of a frame of %d octets: %v", len(frame), err)
			}
			const budget = 4 * MaxFrameLen
			if got := allocated(200, func() { _, _ = Parse(frame) }); got > budget {
				t.Errorf("%d octets allocated per call, budget %d", got, budget)
			}
			// One octet more is refused without a copy.
			long := append(frame, 0)
			long[4], long[5] = byte(len(long)>>8), byte(len(long))
			if _, err := Parse(long); !errors.Is(err, knx.ErrMalformed) {
				t.Fatalf("Parse of %d octets = %v, want knx.ErrMalformed", len(long), err)
			}
			if got := allocated(200, func() { _, _ = Parse(long) }); got > 1024 {
				t.Errorf("%d octets allocated per refused frame, budget 1024", got)
			}
		})
	}
}

// ParseDIBs of as many description blocks as a frame holds allocates per
// block, bounded by the octets it was given: the smallest block is two
// octets, so a frame holds at most 509.
func TestParseDIBsAllocationBudget(t *testing.T) {
	const perBlock = 160 // octets: the block, its interface value, the growth of the list
	for name, block := range map[string][]byte{
		"empty blocks of an unknown type":  {2, 0x7F},
		"blocks of two octets of data":     {4, 0x7F, 1, 2},
		"manufacturer data, the type 0xFE": {4, 0xFE, 0, 1},
	} {
		t.Run(name, func(t *testing.T) {
			n := (MaxFrameLen - HeaderLen) / len(block)
			blocks := bytes.Repeat(block, n)
			ds, err := ParseDIBs(blocks)
			if err != nil || len(ds) != n {
				t.Fatalf("ParseDIBs of %d blocks = %d blocks, %v", n, len(ds), err)
			}
			budget := uint64(n * perBlock)
			if got := allocated(100, func() { _, _ = ParseDIBs(blocks) }); got > budget {
				t.Errorf("%d octets allocated for %d blocks in %d octets, budget %d", got, n, len(blocks), budget)
			}
		})
	}
	// A block that declares more than is there is refused at once.
	declared := append([]byte{0xFF, 0x7F}, make([]byte, 16)...)
	if _, err := ParseDIBs(declared); !errors.Is(err, knx.ErrMalformed) {
		t.Fatalf("ParseDIBs of a block longer than its input = %v, want knx.ErrMalformed", err)
	}
	if got := allocated(200, func() { _, _ = ParseDIBs(declared) }); got > 1024 {
		t.Errorf("%d octets allocated per refused block, budget 1024", got)
	}
}
