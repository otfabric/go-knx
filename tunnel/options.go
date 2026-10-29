// SPDX-License-Identifier: MIT

package tunnel

import (
	"fmt"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/knxnetip"
)

// Timing constants of KNXnet/IP tunnelling (KNX Standard 3/8/4).
const (
	// DefaultRequestTimeout is TUNNELLING_REQUEST_TIMEOUT: the wait for a
	// TUNNELLING_ACK before the request is repeated once.
	DefaultRequestTimeout = 1 * time.Second
	// DefaultConnectTimeout is CONNECT_REQUEST_TIMEOUT.
	DefaultConnectTimeout = 10 * time.Second
	// DefaultHeartbeatInterval is how often a CONNECTIONSTATE_REQUEST is
	// sent; servers drop a connection after CONNECTION_ALIVE_TIME
	// (120 s) without one.
	DefaultHeartbeatInterval = 60 * time.Second
	// DefaultHeartbeatTimeout is CONNECTIONSTATE_REQUEST_TIMEOUT.
	DefaultHeartbeatTimeout = 10 * time.Second
	// DefaultHeartbeatAttempts is the number of connection state requests
	// sent before the connection is considered lost.
	DefaultHeartbeatAttempts = 3
	// DefaultConfirmTimeout bounds the wait for the L_Data.con of an
	// L_Data.req. The standard leaves it to the client; 3 s covers a busy
	// TP line.
	DefaultConfirmTimeout = 3 * time.Second
	// DefaultQueueSize bounds the inbound telegram queue.
	DefaultQueueSize = 256
)

// Option configures a [Conn].
type Option func(*options) error

type options struct {
	logger            knx.Logger
	metrics           knx.Metrics
	local             string
	nat               bool
	layer             knxnetip.TunnelLayer
	address           knx.IndividualAddress
	hasAddress        bool
	requestTimeout    time.Duration
	connectTimeout    time.Duration
	heartbeatInterval time.Duration
	heartbeatTimeout  time.Duration
	heartbeatAttempts int
	confirmTimeout    time.Duration
	waitConfirm       bool
	queueSize         int
	reconnect         bool
	reconnectMin      time.Duration
	reconnectMax      time.Duration
	stateFunc         func(knx.State, error)
}

func defaultOptions() options {
	return options{
		logger:            knx.NopLogger(),
		metrics:           knx.NopMetrics{},
		layer:             knxnetip.TunnelLinkLayer,
		requestTimeout:    DefaultRequestTimeout,
		connectTimeout:    DefaultConnectTimeout,
		heartbeatInterval: DefaultHeartbeatInterval,
		heartbeatTimeout:  DefaultHeartbeatTimeout,
		heartbeatAttempts: DefaultHeartbeatAttempts,
		confirmTimeout:    DefaultConfirmTimeout,
		waitConfirm:       true,
		queueSize:         DefaultQueueSize,
		reconnectMin:      1 * time.Second,
		reconnectMax:      30 * time.Second,
	}
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: tunnel: %s", knx.ErrInvalidOption, fmt.Sprintf(format, a...))
}

// WithLogger sets the logger. Logging is silent by default.
func WithLogger(l knx.Logger) Option {
	return func(o *options) error {
		if l == nil {
			l = knx.NopLogger()
		}
		o.logger = l
		return nil
	}
}

// WithMetrics sets the metrics callbacks.
func WithMetrics(m knx.Metrics) Option {
	return func(o *options) error {
		if m == nil {
			m = knx.NopMetrics{}
		}
		o.metrics = m
		return nil
	}
}

// WithLocalAddr binds the client socket to a local address ("10.0.0.5",
// "10.0.0.5:3672", ":0"). By default it binds to every interface on an
// ephemeral port and announces the address the system routes to the
// server from.
func WithLocalAddr(addr string) Option {
	return func(o *options) error { o.local = addr; return nil }
}

// WithNAT announces the route back endpoint 0.0.0.0:0 in the HPAIs, so
// that the server answers to the source of each datagram: for clients
// behind NAT (Docker port mappings, routers). The server must support it.
func WithNAT(on bool) Option {
	return func(o *options) error { o.nat = on; return nil }
}

// WithLayer selects the tunnelling layer: link layer (default) or
// busmonitor. Raw tunnelling is not supported.
func WithLayer(l knxnetip.TunnelLayer) Option {
	return func(o *options) error {
		if l != knxnetip.TunnelLinkLayer && l != knxnetip.TunnelBusmonitor {
			return invalid("layer %s: link layer or busmonitor", l)
		}
		o.layer = l
		return nil
	}
}

// WithIndividualAddress requests a specific tunnelling address with the
// extended CRI of tunnelling v2. Servers without tunnelling v2 refuse the
// connection.
func WithIndividualAddress(a knx.IndividualAddress) Option {
	return func(o *options) error { o.address, o.hasAddress = a, true; return nil }
}

// WithRequestTimeout sets the wait for a TUNNELLING_ACK (default 1 s).
func WithRequestTimeout(d time.Duration) Option {
	return func(o *options) error {
		if d <= 0 {
			return invalid("request timeout %v", d)
		}
		o.requestTimeout = d
		return nil
	}
}

// WithConnectTimeout sets the wait for a CONNECT_RESPONSE (default 10 s).
func WithConnectTimeout(d time.Duration) Option {
	return func(o *options) error {
		if d <= 0 {
			return invalid("connect timeout %v", d)
		}
		o.connectTimeout = d
		return nil
	}
}

// WithHeartbeat sets the heartbeat interval, the wait for each
// CONNECTIONSTATE_RESPONSE and the number of attempts before the
// connection is considered lost (defaults 60 s, 10 s, 3).
func WithHeartbeat(interval, timeout time.Duration, attempts int) Option {
	return func(o *options) error {
		if interval <= 0 || timeout <= 0 || attempts < 1 {
			return invalid("heartbeat %v/%v/%d", interval, timeout, attempts)
		}
		o.heartbeatInterval, o.heartbeatTimeout, o.heartbeatAttempts = interval, timeout, attempts
		return nil
	}
}

// WithConfirm sets whether [Conn.Send] of an L_Data.req waits for its
// L_Data.con (default true) and how long (default 3 s).
func WithConfirm(wait bool, timeout time.Duration) Option {
	return func(o *options) error {
		if wait && timeout <= 0 {
			return invalid("confirm timeout %v", timeout)
		}
		o.waitConfirm = wait
		if timeout > 0 {
			o.confirmTimeout = timeout
		}
		return nil
	}
}

// WithQueueSize bounds the inbound telegram queue (default 256). When it
// is full, new telegrams are acknowledged and dropped
// (Metrics.OnDropped "queue_full").
func WithQueueSize(n int) Option {
	return func(o *options) error {
		if n < 1 || n > 1<<16 {
			return invalid("queue size %d", n)
		}
		o.queueSize = n
		return nil
	}
}

// WithReconnect makes a lost connection reconnect with exponential
// backoff between min and max, until the Conn is closed. Telegrams sent
// while reconnecting fail with knx.ErrConnectionLost.
func WithReconnect(min, max time.Duration) Option {
	return func(o *options) error {
		if min <= 0 || max < min {
			return invalid("reconnect backoff %v..%v", min, max)
		}
		o.reconnect, o.reconnectMin, o.reconnectMax = true, min, max
		return nil
	}
}

// WithStateHandler calls f on every state change, with the error that
// caused it (nil for a normal change). f must not block or call the Conn.
func WithStateHandler(f func(knx.State, error)) Option {
	return func(o *options) error { o.stateFunc = f; return nil }
}
