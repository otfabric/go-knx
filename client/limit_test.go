// SPDX-License-Identifier: MIT

package client_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/client"
	"github.com/otfabric/go-knx/internal/leak"
)

// GroupReadAll returns once it has WithMaxResponses responses, without
// waiting out its window.
func TestGroupReadAllMaxResponses(t *testing.T) {
	leak.Check(t)
	c, l := newClient(t)
	froms := make([]knx.IndividualAddress, 20)
	for i := range froms {
		froms[i] = knx.IndividualAddress(0x1100 + i)
	}
	l.onSend = responder(t, g1, apdu.GroupValue{Data: []byte{1}, Small: true}, froms...)
	start := time.Now()
	rs, err := c.GroupReadAll(ctx(t), g1, 5*time.Second, client.WithMaxResponses(3))
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 3 {
		t.Fatalf("%d responses, want 3", len(rs))
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %v: did not stop at the limit", d)
	}
	if _, err := c.GroupReadAll(ctx(t), g1, time.Millisecond, client.WithMaxResponses(0)); !errors.Is(err, knx.ErrInvalidOption) {
		t.Fatalf("WithMaxResponses(0): %v", err)
	}
}

// A cancelled remote access reports the cancellation, not a timeout; an
// expired one reports knx.ErrTimeout.
func TestDeviceCancelIsNotTimeout(t *testing.T) {
	leak.Check(t)
	c, _ := newClient(t)
	d := c.Device(knx.MustParseIndividualAddress("1.1.5"))

	cctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	_, err := d.PropertyRead(cctx, 0, 11, 1, 1)
	if !errors.Is(err, context.Canceled) || errors.Is(err, knx.ErrTimeout) {
		t.Fatalf("cancelled: %v", err)
	}

	tctx, tcancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer tcancel()
	_, err = d.PropertyRead(tctx, 0, 11, 1, 1)
	if !errors.Is(err, knx.ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired: %v", err)
	}
}

// Property data that cannot fit a frame is refused before anything is
// sent.
func TestPropertyWriteTooLong(t *testing.T) {
	leak.Check(t)
	c, l := newClient(t)
	d := c.Device(knx.MustParseIndividualAddress("1.1.5"))
	_, err := d.PropertyWrite(ctx(t), 0, 76, 1, 1, make([]byte, client.MaxPropertyData+1))
	if !errors.Is(err, knx.ErrInvalidValue) {
		t.Fatalf("err %v", err)
	}
	l.mu.Lock()
	n := len(l.sent)
	l.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d frames sent", n)
	}
	// The largest write encodes and is sent (nobody answers here).
	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := d.PropertyWrite(short, 0, 76, 1, 1, make([]byte, client.MaxPropertyData)); !errors.Is(err, knx.ErrTimeout) {
		t.Fatalf("largest write: %v", err)
	}
	l.mu.Lock()
	n = len(l.sent)
	l.mu.Unlock()
	if n != 1 {
		t.Fatalf("largest write: %d frames sent", n)
	}
}
