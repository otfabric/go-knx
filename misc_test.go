// SPDX-License-Identifier: MIT

package knx

import (
	"bytes"
	"context"
	"errors"
	"log"
	"log/slog"
	"net"
	"strings"
	"testing"
)

func TestState(t *testing.T) {
	for s, want := range map[State]string{
		StateDisconnected: "disconnected", StateConnecting: "connecting", StateConnected: "connected",
		StateReconnecting: "reconnecting", StateClosed: "closed", State(9): "State(9)",
	} {
		if s.String() != want {
			t.Errorf("%d.String() = %q", int(s), s.String())
		}
	}
}

func TestSentinelErrorsDistinct(t *testing.T) {
	errs := []error{ErrInvalidAddress, ErrMalformed, ErrUnsupported, ErrInvalidOption, ErrInvalidValue, ErrClosed,
		ErrTimeout, ErrConnectionLost, ErrRejected, ErrBusy, ErrNotConfirmed, ErrSecurity}
	for i, a := range errs {
		if !strings.HasPrefix(a.Error(), "knx: ") {
			t.Errorf("%q lacks the knx prefix", a)
		}
		for j, b := range errs {
			if i != j && errors.Is(a, b) {
				t.Errorf("%v matches %v", a, b)
			}
		}
	}
}

func TestStdLogger(t *testing.T) {
	var buf bytes.Buffer
	l := NewStdLogger(log.New(&buf, "", 0))
	l.Debugf("d %d", 1)
	l.Infof("i %d", 2)
	l.Warnf("w %d", 3)
	l.Errorf("e %d", 4)
	if want := "DEBUG d 1\nINFO  i 2\nWARN  w 3\nERROR e 4\n"; buf.String() != want {
		t.Fatalf("got %q, want %q", buf.String(), want)
	}
	if NewStdLogger(nil) == nil {
		t.Fatal("NewStdLogger(nil) is nil")
	}
}

func TestNopLoggers(t *testing.T) {
	// The no-op loggers accept every call.
	l := NopLogger()
	l.Debugf("x")
	l.Infof("x")
	l.Warnf("x")
	l.Errorf("x")
	if _, ok := NewSlogLogger(nil).(FieldLogger); ok {
		t.Error("NewSlogLogger(nil) should be a plain no-op logger")
	}
	fl := NewSlogFieldLogger(nil)
	fl = fl.With("k", "v")
	fl.DebugKV("m")
	fl.InfoKV("m")
	fl.WarnKV("m")
	fl.ErrorKV("m")
	fl.Debugf("m")
}

func TestSlogLogger(t *testing.T) {
	var buf bytes.Buffer
	h := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo, ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}})
	l := NewSlogLogger(h)
	fl, ok := l.(FieldLogger)
	if !ok {
		t.Fatal("not a FieldLogger")
	}
	cl, ok := l.(ContextLogger)
	if !ok {
		t.Fatal("not a ContextLogger")
	}
	de, ok := l.(interface{ DebugEnabled() bool })
	if !ok || de.DebugEnabled() {
		t.Fatal("DebugEnabled at info level")
	}
	l.Debugf("hidden %d", 1)
	l.Infof("info %d", 2)
	l.Warnf("warn %d", 3)
	l.Errorf("error %d", 4)
	fl.With("component", "test").InfoKV("kv", "n", 5)
	fl.DebugKV("hidden")
	fl.WarnKV("kvw")
	fl.ErrorKV("kve")
	ctx := context.Background()
	cl.DebugContext(ctx, "hidden")
	cl.InfoContext(ctx, "ci")
	cl.WarnContext(ctx, "cw")
	cl.ErrorContext(ctx, "ce")
	want := []string{
		`level=INFO msg="info 2"`, `level=WARN msg="warn 3"`, `level=ERROR msg="error 4"`,
		`level=INFO msg=kv component=test n=5`, `level=WARN msg=kvw`, `level=ERROR msg=kve`,
		`level=INFO msg=ci`, `level=WARN msg=cw`, `level=ERROR msg=ce`,
	}
	got := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if de := NewSlogFieldLogger(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})).(interface{ DebugEnabled() bool }); !de.DebugEnabled() {
		t.Fatal("DebugEnabled false at debug level")
	}
}

func TestNopMetrics(t *testing.T) {
	var m Metrics = NopMetrics{}
	a := &net.UDPAddr{}
	m.OnConnect(a, 1)
	m.OnDisconnect(a, 1, nil)
	m.OnFrameSent(a, 0x0420, 21)
	m.OnFrameReceived(a, 0x0421, 10)
	m.OnDecodeError(a, ErrMalformed)
	m.OnRetransmit(a, 1)
	m.OnDropped(a, "queue")
	// Embedding NopMetrics satisfies the interface.
	type custom struct{ NopMetrics }
	var _ Metrics = custom{}
}
