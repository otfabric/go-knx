// SPDX-License-Identifier: MIT

package udp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/otfabric/go-knx"
)

func TestResolveEndpoint(t *testing.T) {
	ctx := context.Background()
	for in, want := range map[string]string{
		"192.168.1.10":        "192.168.1.10:3671",
		"192.168.1.10:1234":   "192.168.1.10:1234",
		":5000":               "0.0.0.0:5000",
		"":                    "0.0.0.0:3671",
		"[::ffff:10.0.0.1]:7": "10.0.0.1:7",
		"localhost:9":         "127.0.0.1:9",
	} {
		got, err := ResolveEndpoint(ctx, in, 3671)
		if err != nil || got.String() != want {
			t.Errorf("ResolveEndpoint(%q) = %v, %v; want %s", in, got, err, want)
		}
	}
	for _, in := range []string{"1.2.3.4:x", "1.2.3.4:70000", "[::1]:3671", "::1", "no-such-host.invalid"} {
		if _, err := ResolveEndpoint(ctx, in, 3671); !errors.Is(err, knx.ErrInvalidOption) {
			t.Errorf("ResolveEndpoint(%q): %v, want ErrInvalidOption", in, err)
		}
	}
}

func TestLocalIPFor(t *testing.T) {
	ip, err := LocalIPFor(netip.MustParseAddrPort("127.0.0.1:3671"))
	if err != nil || ip != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("LocalIPFor(loopback) = %v, %v", ip, err)
	}
	if _, err := LocalIPFor(netip.AddrPort{}); err == nil {
		t.Fatal("LocalIPFor of an invalid endpoint succeeded")
	}
}

func loopback(t *testing.T) *net.Interface {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Skip(err)
	}
	for i := range ifs {
		if ifs[i].Flags&net.FlagLoopback != 0 {
			return &ifs[i]
		}
	}
	t.Skip("no loopback interface")
	return nil
}

func TestInterfaces(t *testing.T) {
	lo := loopback(t)
	ifi, ip, err := InterfaceIPv4(lo.Name)
	if err != nil || ifi.Name != lo.Name || !ip.IsLoopback() {
		t.Fatalf("InterfaceIPv4(%s) = %v %v %v", lo.Name, ifi, ip, err)
	}
	got, err := InterfaceForIP(ip)
	if err != nil || got.Name != lo.Name {
		t.Fatalf("InterfaceForIP(%s) = %v %v", ip, got, err)
	}
	if _, _, err := InterfaceIPv4("no-such-interface0"); !errors.Is(err, knx.ErrInvalidOption) {
		t.Fatalf("unknown interface: %v", err)
	}
	if _, err := InterfaceForIP(netip.MustParseAddr("192.0.2.123")); !errors.Is(err, knx.ErrInvalidOption) {
		t.Fatalf("unknown address: %v", err)
	}
	// An interface without IPv4 address, if there is one.
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		addrs, _ := i.Addrs()
		has4 := false
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
				has4 = true
			}
		}
		if !has4 {
			if _, _, err := InterfaceIPv4(i.Name); !errors.Is(err, knx.ErrInvalidOption) {
				t.Fatalf("interface %s without IPv4: %v", i.Name, err)
			}
			break
		}
	}
}

func TestAddrPortOf(t *testing.T) {
	a := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5}
	if got := AddrPortOf(a); got.String() != "10.0.0.1:5" {
		t.Fatalf("AddrPortOf = %v", got)
	}
	if got := AddrPortOf(&net.TCPAddr{}); got.IsValid() {
		t.Fatalf("AddrPortOf(TCP) = %v", got)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestDatagramError(t *testing.T) {
	msgSize := &net.OpError{Op: "read", Net: "udp4", Err: errors.New("wsarecvfrom: message too long")}
	for err, want := range map[error]bool{
		nil:                                   false,
		net.ErrClosed:                         false,
		fmt.Errorf("read: %w", net.ErrClosed): false,
		timeoutErr{}:                          false,
		&net.OpError{Op: "read", Err: timeoutErr{}}: false,
		msgSize:             true,
		errors.New("reset"): true,
	} {
		if got := DatagramError(err); got != want {
			t.Errorf("DatagramError(%v) = %v, want %v", err, got, want)
		}
	}
}

func TestReadSkipsDatagramErrors(t *testing.T) {
	from := netip.MustParseAddrPort("127.0.0.1:3671")
	steps := []error{errors.New("message too long"), errors.New("connection reset"), nil}
	calls := 0
	read := func(b []byte) (int, netip.AddrPort, error) {
		err := steps[calls]
		calls++
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		return copy(b, "ok"), from, nil
	}
	buf := make([]byte, 8)
	n, got, err := Read(read, buf, nil)
	if err != nil || string(buf[:n]) != "ok" || got != from || calls != 3 {
		t.Fatalf("Read = %d %v %v after %d calls", n, got, err, calls)
	}
	for _, stop := range []error{net.ErrClosed, timeoutErr{}} {
		if _, _, err := Read(func([]byte) (int, netip.AddrPort, error) { return 0, netip.AddrPort{}, stop }, buf, nil); !errors.Is(err, stop) {
			t.Errorf("Read with %v = %v", stop, err)
		}
	}
}

// Read pauses between the reads that follow datagram errors: 5 ms after
// the first, doubling up to 1 s, so that an error that persists does not
// keep the reader busy. The clock is the bubble's (testing/synctest).
func TestReadPausesAfterDatagramErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		from := netip.MustParseAddrPort("127.0.0.1:3671")
		start := time.Now()
		var calls []time.Duration
		read := func(b []byte) (int, netip.AddrPort, error) {
			calls = append(calls, time.Since(start))
			if len(calls) <= 10 {
				return 0, netip.AddrPort{}, errors.New("connection reset by peer")
			}
			return copy(b, "ok"), from, nil
		}
		// The first read after ten errors gives the datagram: a Read that
		// does not pause returns it too, at once, and fails on the times.
		buf := make([]byte, 8)
		n, got, err := Read(read, buf, nil)
		if err != nil || string(buf[:n]) != "ok" || got != from {
			t.Fatalf("Read = %d %v %v", n, got, err)
		}
		ms := time.Millisecond
		want := []time.Duration{0, 5 * ms, 15 * ms, 35 * ms, 75 * ms, 155 * ms, 315 * ms, 635 * ms, 1275 * ms, 2275 * ms, 3275 * ms}
		if len(calls) != len(want) {
			t.Fatalf("%d reads at %v, want %d at %v", len(calls), calls, len(want), want)
		}
		for i := range want {
			if calls[i] != want[i] {
				t.Errorf("read %d at %v, want %v", i+1, calls[i], want[i])
			}
		}
		// The pauses start again with every call.
		start, calls = time.Now(), nil
		if _, _, err := Read(func(b []byte) (int, netip.AddrPort, error) {
			calls = append(calls, time.Since(start))
			if len(calls) == 1 {
				return 0, netip.AddrPort{}, errors.New("message too long")
			}
			return 0, netip.AddrPort{}, timeoutErr{}
		}, buf, nil); !errors.Is(err, timeoutErr{}) || len(calls) != 2 || calls[1] != 5*ms {
			t.Errorf("second call: %v after reads at %v, want the timeout after reads at [0s 5ms]", err, calls)
		}
	})
}

// When the owner closes during a pause, Read returns net.ErrClosed at
// once and does not read again.
func TestReadEndsWhenOwnerCloses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		done := make(chan struct{})
		calls := 0
		read := func([]byte) (int, netip.AddrPort, error) {
			if calls++; calls > 1000 {
				// A Read that does not pause ends here and fails below.
				return 0, netip.AddrPort{}, timeoutErr{}
			}
			return 0, netip.AddrPort{}, errors.New("network is down")
		}
		go func() {
			time.Sleep(100 * time.Millisecond) // in the pause of 80 ms that began at 75 ms
			close(done)
		}()
		start := time.Now()
		_, _, err := Read(read, make([]byte, 8), done)
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Read = %v, want net.ErrClosed", err)
		}
		if d := time.Since(start); d != 100*time.Millisecond || calls != 5 {
			t.Errorf("Read returned after %v and %d reads, want 100ms and 5 reads", d, calls)
		}
	})
}
