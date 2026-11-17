// SPDX-License-Identifier: MIT

package client_test

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/client"
	"github.com/otfabric/go-knx/datasecure"
	"github.com/otfabric/go-knx/internal/leak"
)

// Lifecycle contract tests (TESTING.md, "Lifecycle contract matrix"). Every
// wait is on an event: a frame the fake link sent, a telegram on a
// subscription, a value on a channel. The constant wait only bounds a wait
// that would otherwise hang.

// recv returns the next value of ch, or fails the test naming what did not
// arrive.
func recv[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	var v T
	select {
	case v = <-ch:
	case <-time.After(wait):
		t.Fatalf("timed out waiting for %s", what)
	}
	return v
}

// errorLog keeps the entries logged at error level.
type errorLog struct {
	knx.Logger
	mu      sync.Mutex
	entries []string
	logged  chan struct{}
}

func newErrorLog() *errorLog {
	return &errorLog{Logger: knx.NopLogger(), logged: make(chan struct{}, 16)}
}

func (e *errorLog) Errorf(format string, a ...any) {
	e.mu.Lock()
	e.entries = append(e.entries, strings.TrimSpace(format)+" "+strings.TrimSpace(strings.Join(strs(a), " ")))
	e.mu.Unlock()
	e.logged <- struct{}{}
}

func strs(a []any) []string {
	out := make([]string, len(a))
	for i, v := range a {
		switch x := v.(type) {
		case error:
			out[i] = x.Error()
		case []byte:
			out[i] = string(x)
		case string:
			out[i] = x
		}
	}
	return out
}

func (e *errorLog) all() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.entries...)
}

// A client with Data Secure answers the individually addressed requests it
// authenticates through a queue of MaxPendingAnswers and one sending
// goroutine: however many requests arrive while the link does not take the
// answers, the client holds that many answers and no more goroutines.
func TestAnswersBounded(t *testing.T) {
	leak.Check(t)
	answersBounded(t, client.MaxPendingAnswers)
}

// WithMaxPendingAnswers sets the size of the queue of answers; a value
// outside 1..65536 keeps the default.
func TestAnswersBoundedByOption(t *testing.T) {
	leak.Check(t)
	for _, tc := range []struct {
		n, capacity int
	}{
		{1, 1}, {2, 2}, {4, 4}, {299, 299}, {300, 300}, {65536, 65536},
		{0, client.DefaultMaxPendingAnswers}, {-1, client.DefaultMaxPendingAnswers},
		{65537, client.DefaultMaxPendingAnswers}, {math.MinInt, client.DefaultMaxPendingAnswers},
		{math.MaxInt, client.DefaultMaxPendingAnswers}, {math.MaxInt32, client.DefaultMaxPendingAnswers},
	} {
		t.Run(fmt.Sprint(tc.n), func(t *testing.T) {
			answersBounded(t, tc.capacity, client.WithMaxPendingAnswers(tc.n))
		})
	}
}

// answersBounded sends 300 requests to a client whose link takes no
// answer, with a queue of capacity answers.
func answersBounded(t *testing.T, capacity int, opts ...client.Option) {
	t.Helper()
	tool, own := knx.MustParseIndividualAddress("15.15.240"), knx.MustParseIndividualAddress("15.15.255")
	toolKey := datasecure.Key{7}
	tab, err := datasecure.NewTable(nil, nil, 50)
	if err != nil {
		t.Fatal(err)
	}
	tab.SetToolKey(own, toolKey)
	const requests = 300
	l := newLink()
	sending, release := make(chan struct{}, 1), make(chan struct{})
	sent := make(chan struct{}, requests+8) // room for every request, so that no Send waits on the test
	var once sync.Once
	letGo := func() { once.Do(func() { close(release) }) }
	l.onSend = func(*link, *cemi.LData) {
		select {
		case sending <- struct{}{}:
		default:
		}
		<-release // the link takes nothing until the test lets it
		sent <- struct{}{}
	}
	c := client.New(l, append([]client.Option{client.WithSource(own), client.WithDataSecure(tab)}, opts...)...)
	defer c.Close()
	defer letGo() // before Close: a link that holds an answer holds its sender
	sub := c.Subscribe(1, g1)

	challenge := [6]byte{9, 9, 9, 9, 9, 9}
	request, err := datasecure.SyncRequest(toolKey, cemi.LDataInd, tool, own, 0, 1, [6]byte{}, challenge)
	if err != nil {
		t.Fatal(err)
	}
	// The first answer is with the link, which holds it.
	l.in <- request.Clone()
	recv(t, sending, "the first answer to reach the link")
	running := leak.Running()

	for range requests {
		l.in <- request.Clone()
	}
	// A telegram after the requests: when it arrives, the reader has
	// handled them all.
	l.in <- wr(t, g1, apdu.GroupValue{Data: []byte{1}, Small: true})
	recv(t, sub.C(), "the telegram after the requests")

	// Left names any goroutine started since Running that still runs after
	// the grace period (a count of all goroutines named none).
	if left := running.Left(); left != "" {
		t.Errorf("goroutines left by %d requests the link did not take:\n%s", requests, left)
	}
	if got, want := c.AnswersDropped(), uint64(max(requests-capacity, 0)); got != want {
		t.Errorf("%d answers dropped, want %d: %d requests, %d places in the queue", got, want, requests, capacity)
	}

	// The link takes the answers again: the one it held and the queued
	// ones are sent, in order, and nothing else.
	letGo()
	for range 1 + min(capacity, requests) {
		recv(t, sent, "an answer to be sent")
	}
	// One more request is answered: the queue has room again.
	l.in <- request.Clone()
	recv(t, sent, "the answer to a request after the queue emptied")
	l.mu.Lock()
	n := len(l.sent)
	frames := append([]*cemi.LData(nil), l.sent...)
	l.mu.Unlock()
	if want := 2 + min(capacity, requests); n != want {
		t.Errorf("%d frames sent, want %d", n, want)
	}
	for i, f := range frames {
		if _, _, err := datasecure.OpenSyncResponse(toolKey, f, challenge); err != nil {
			t.Fatalf("frame %d is not an answer to the request: %v", i, err)
		}
	}
}

// The answers end with the client: an answer the link has not taken at
// Close is given up, and Close returns.
func TestAnswersEndWithClose(t *testing.T) {
	leak.Check(t)
	tool, own := knx.MustParseIndividualAddress("15.15.240"), knx.MustParseIndividualAddress("15.15.255")
	toolKey := datasecure.Key{7}
	tab, _ := datasecure.NewTable(nil, nil, 50)
	tab.SetToolKey(own, toolKey)
	bl := &blockingLink{link: newLink(), sending: make(chan struct{}, 1)}
	c := client.New(bl, client.WithSource(own), client.WithDataSecure(tab))
	request, _ := datasecure.SyncRequest(toolKey, cemi.LDataInd, tool, own, 0, 1, [6]byte{}, [6]byte{1})
	for range 3 {
		bl.in <- request.Clone()
	}
	recv(t, bl.sending, "the first answer to reach the link")
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	if err := recv(t, closed, "Close to return"); err != nil {
		t.Fatal(err)
	}
}

// blockingLink is a link whose Send returns only when its context ends.
type blockingLink struct {
	*link
	sending chan struct{}
}

func (b *blockingLink) Send(ctx context.Context, _ cemi.Frame) error {
	select {
	case b.sending <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}

// L2: Close from several goroutines; every call returns, the link is
// closed, the subscriptions end and Done is closed.
func TestCloseConcurrently(t *testing.T) {
	leak.Check(t)
	l := newLink()
	c := client.New(l)
	sub := c.Subscribe(1)
	read := make(chan error, 1)
	l.onSend = func(*link, *cemi.LData) {} // the read request goes out; nobody answers
	go func() { _, err := c.GroupRead(context.Background(), g1); read <- err }()
	waitSent(t, l, 1)

	const closers = 8
	start := make(chan struct{})
	errs := make(chan error, closers)
	for range closers {
		go func() {
			<-start
			errs <- c.Close()
		}()
	}
	close(start)
	for range closers {
		if err := recv(t, errs, "a Close to return"); err != nil {
			t.Errorf("Close = %v", err)
		}
	}
	recv(t, c.Done(), "Done")
	if err := recv(t, read, "the pending GroupRead"); !errors.Is(err, knx.ErrClosed) {
		t.Errorf("GroupRead at Close = %v, want knx.ErrClosed", err)
	}
	if _, open := <-sub.C(); open {
		t.Error("a subscription delivered after Close")
	}
	l.mu.Lock()
	closes := l.closes
	l.mu.Unlock()
	if closes != 1 {
		t.Errorf("the link was closed %d times, want once", closes)
	}
	if c.Err() != nil || c.PendingReads() != 0 {
		t.Errorf("Err %v, %d pending reads after Close", c.Err(), c.PendingReads())
	}
}

// L6: a cancelled GroupRead returns context.Canceled and leaves nothing
// behind; a response that comes after it completes no other read, and the
// next read on the same client gets its own response.
func TestGroupReadCancelLeavesNothing(t *testing.T) {
	leak.Check(t)
	c, l := newClient(t)
	sub := c.Subscribe(4, g1, g2)
	cx, cancel := context.WithCancel(context.Background())
	read := make(chan error, 1)
	go func() { _, err := c.GroupRead(cx, g1); read <- err }()
	waitSent(t, l, 1) // the read request is on the link
	if n := c.PendingReads(); n != 1 {
		t.Fatalf("%d pending reads while GroupRead waits, want 1", n)
	}
	cancel()
	if err := recv(t, read, "the cancelled GroupRead"); !errors.Is(err, context.Canceled) || errors.Is(err, knx.ErrTimeout) {
		t.Fatalf("cancelled GroupRead = %v, want context.Canceled", err)
	}
	if n := c.PendingReads(); n != 0 {
		t.Fatalf("%d pending reads after the cancelled GroupRead, want 0", n)
	}
	// The late response reaches the subscription and no read.
	l.in <- resp(t, g1, src, apdu.GroupValue{Data: []byte{7}})
	if tg := recv(t, sub.C(), "the late response"); tg.Group != g1 || tg.Value.Data[0] != 7 {
		t.Fatalf("telegram %+v", tg)
	}
	// The next read of another group gets its own response.
	l.onSend = responder(t, g2, apdu.GroupValue{Data: []byte{9}}, src)
	r, err := c.GroupRead(ctx(t), g2)
	if err != nil || r.Group != g2 || r.Value.Data[0] != 9 {
		t.Fatalf("read after a cancelled one: %+v, %v", r, err)
	}
	if n := c.PendingReads(); n != 0 {
		t.Errorf("%d pending reads at the end", n)
	}
}

// L6 for a Device: a cancelled request frees the Device; the answer that
// comes after it is dropped and the next request gets its own.
func TestDeviceRequestAfterCancel(t *testing.T) {
	leak.Check(t)
	l := newLink()
	c := client.New(l, client.WithSource(src))
	defer c.Close()
	d := c.Device(serverAddress)
	defer d.Close()
	descriptor := func(v uint16) *cemi.LData {
		return from(apdu.TPDU{APCI: apdu.DeviceDescriptorResponseService, Data: []byte{byte(v >> 8), byte(v)}})
	}
	cx, cancel := context.WithCancel(context.Background())
	read := make(chan error, 1)
	go func() { _, err := d.DescriptorRead(cx); read <- err }()
	waitSent(t, l, 1)
	cancel()
	if err := recv(t, read, "the cancelled request"); !errors.Is(err, context.Canceled) || errors.Is(err, knx.ErrTimeout) {
		t.Fatalf("cancelled request = %v, want context.Canceled", err)
	}
	// The answer to the cancelled request comes late; the reader has it
	// once a telegram sent after it is delivered.
	sub := c.Subscribe(1, g1)
	l.in <- descriptor(0x0701)
	l.in <- wr(t, g1, apdu.GroupValue{Data: []byte{1}, Small: true})
	recv(t, sub.C(), "the telegram after the late answer")
	scripted(l, func(l *link, tp apdu.TPDU, _ int) {
		if tp.APCI == apdu.DeviceDescriptorReadService {
			l.in <- descriptor(0x07B0)
		}
	})
	if v, err := d.DescriptorRead(ctx(t)); err != nil || v != 0x07B0 {
		t.Fatalf("request after a cancelled one = %04X, %v; want 07B0 (the late answer said 0701)", v, err)
	}
}

// L2 for a Device: Close from several goroutines ends the transport
// connection once.
func TestDeviceCloseConcurrently(t *testing.T) {
	leak.Check(t)
	l := newLink()
	c := client.New(l, client.WithSource(src))
	defer c.Close()
	scripted(l, func(l *link, tp apdu.TPDU, _ int) {
		if tp.TPCI.Kind == apdu.TDataConnected {
			l.in <- from(apdu.TPDU{TPCI: apdu.TPCI{Kind: apdu.TAck}})
			l.in <- from(apdu.TPDU{TPCI: apdu.TPCI{Kind: apdu.TDataConnected}, APCI: apdu.DeviceDescriptorResponseService, Data: []byte{0x07, 0xB0}})
		}
	})
	d := c.Device(serverAddress, client.Connected())
	if _, err := d.DescriptorRead(ctx(t)); err != nil {
		t.Fatal(err)
	}
	const closers = 8
	start := make(chan struct{})
	errs := make(chan error, closers)
	for range closers {
		go func() {
			<-start
			errs <- d.Close()
		}()
	}
	close(start)
	for range closers {
		if err := recv(t, errs, "a Close to return"); err != nil {
			t.Errorf("Close = %v", err)
		}
	}
	disconnects := 0
	l.mu.Lock()
	for _, f := range l.sent {
		if tp, err := apdu.Parse(f.TPDU); err == nil && tp.TPCI.Kind == apdu.TDisconnect {
			disconnects++
		}
	}
	l.mu.Unlock()
	if disconnects != 1 {
		t.Errorf("%d T_Disconnect sent, want 1", disconnects)
	}
}

// L9: a telegram callback may call the client's methods that do not wait
// for a telegram.
func TestCallbackCallsClient(t *testing.T) {
	leak.Check(t)
	c, l := newClient(t)
	inner := make(chan client.Telegram, 1)
	var once sync.Once
	var remove func()
	remove = c.OnTelegram(func(tg client.Telegram) {
		once.Do(func() {
			if err := c.Err(); err != nil {
				t.Errorf("Err() in a callback = %v", err)
			}
			select {
			case <-c.Done():
				t.Error("Done closed in a callback")
			default:
			}
			// Subscribing, registering and removing callbacks.
			sub := c.Subscribe(1, g2)
			sub.Unsubscribe()
			c.OnTelegram(func(tg client.Telegram) {
				select {
				case inner <- tg:
				default:
				}
			})
			remove()
			if c.Link() == nil {
				t.Error("Link() in a callback")
			}
		})
	})
	l.in <- wr(t, g1, apdu.GroupValue{Data: []byte{1}, Small: true})
	l.in <- wr(t, g1, apdu.GroupValue{Data: []byte{0}, Small: true})
	// The callback registered inside the first one sees the second
	// telegram: the reader went on.
	if tg := recv(t, inner, "the second telegram"); tg.Group != g1 {
		t.Fatalf("telegram %+v", tg)
	}
}

// L10: a telegram callback ends the client by calling Close from another
// goroutine; Close completes once the callback has returned.
func TestCallbackClosesClient(t *testing.T) {
	leak.Check(t)
	l := newLink()
	c := client.New(l)
	closed := make(chan error, 1)
	inCallback := make(chan struct{})
	c.OnTelegram(func(client.Telegram) {
		go func() { closed <- c.Close() }()
		// Close has begun when the link is closed. It waits for the
		// reader, which runs this callback.
		<-l.closed
		select {
		case err := <-closed:
			t.Errorf("Close returned %v while the callback was running", err)
		default:
		}
		close(inCallback)
	})
	l.in <- wr(t, g1, apdu.GroupValue{Data: []byte{1}, Small: true})
	recv(t, inCallback, "the callback")
	if err := recv(t, closed, "Close to return after the callback"); err != nil {
		t.Fatalf("Close = %v", err)
	}
	recv(t, c.Done(), "Done")
}

// A telegram callback that does not return normally is stopped there and
// logged with its stack; the reader, the other callbacks and the
// subscriptions go on.
func TestCallbackDoesNotReturnNormally(t *testing.T) {
	leak.Check(t)
	log := newErrorLog()
	c, l := newClient(t, client.WithLogger(log))
	sub := c.Subscribe(4, g1)
	seen := make(chan byte, 4)
	c.OnTelegram(func(tg client.Telegram) {
		if tg.Value.Data[0] == 1 {
			var none []int
			_ = none[len(tg.Value.Data)] // index out of range
		}
	})
	c.OnTelegram(func(tg client.Telegram) { seen <- tg.Value.Data[0] })
	for _, v := range []byte{1, 0} {
		l.in <- wr(t, g1, apdu.GroupValue{Data: []byte{v}, Small: true})
		if tg := recv(t, sub.C(), "the telegram on the subscription"); tg.Value.Data[0] != v {
			t.Fatalf("telegram %+v", tg)
		}
	}
	recv(t, log.logged, "the entry for the callback")
	flush(t, c, l)
	entries := log.all()
	if len(entries) != 1 {
		t.Fatalf("%d entries at error level, want 1: %q", len(entries), entries)
	}
	for _, part := range []string{"client.OnTelegram did not return normally", "index out of range", "TestCallbackDoesNotReturnNormally"} {
		if !strings.Contains(entries[0], part) {
			t.Errorf("the entry does not hold %q:\n%s", part, entries[0])
		}
	}
	// Whichever callback ran first, the other one saw both telegrams.
	got := map[byte]bool{}
	for len(got) < 2 {
		got[recv(t, seen, "the other callback")] = true
	}
}
