// SPDX-License-Identifier: MIT

package server

import (
	"fmt"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/knxnetip"
)

// Defaults.
const (
	// DefaultConnectionAliveTime is CONNECTION_ALIVE_TIME: a tunnelling
	// connection without a CONNECTIONSTATE_REQUEST for this long is
	// closed.
	DefaultConnectionAliveTime = 120 * time.Second
	// DefaultQueueSize bounds the telegrams queued for each tunnelling
	// connection.
	DefaultQueueSize = 128
	// DefaultRoutingRate bounds the ROUTING_INDICATIONs the server sends
	// per second. The standard asks routers not to flood the IP network;
	// 50 telegrams per second is the rate of a TP1 line.
	DefaultRoutingRate = 50
)

// Option configures a [Server].
type Option func(*options) error

type options struct {
	listen      string
	iface       string
	name        string
	address     knx.IndividualAddress
	tunnels     []knx.IndividualAddress
	serial      [6]byte
	mac         [6]byte
	discovery   bool
	routing     bool
	group       string
	aliveTime   time.Duration
	reqTimeout  time.Duration
	queueSize   int
	routingRate int
	logger      knx.Logger
	metrics     knx.Metrics
	progMode    bool
	ttl         int
}

func defaultOptions() options {
	return options{
		listen:      fmt.Sprintf(":%d", knxnetip.Port),
		name:        "go-knx server",
		address:     knx.MustParseIndividualAddress("15.15.0"),
		tunnels:     []knx.IndividualAddress{knx.MustParseIndividualAddress("15.15.250")},
		serial:      [6]byte{0x00, 0xFA, 0x00, 0x00, 0x00, 0x01},
		mac:         [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		discovery:   true,
		group:       "224.0.23.12:3671",
		aliveTime:   DefaultConnectionAliveTime,
		reqTimeout:  time.Second,
		queueSize:   DefaultQueueSize,
		routingRate: DefaultRoutingRate,
		logger:      knx.NopLogger(),
		metrics:     knx.NopMetrics{},
		ttl:         16,
	}
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: server: %s", knx.ErrInvalidOption, fmt.Sprintf(format, a...))
}

// WithListenAddr sets the UDP address to listen on (default ":3671").
func WithListenAddr(addr string) Option {
	return func(o *options) error { o.listen = addr; return nil }
}

// WithInterface selects the network interface whose address the server
// announces and on which it joins the multicast group (discovery,
// routing).
func WithInterface(name string) Option { return func(o *options) error { o.iface = name; return nil } }

// WithName sets the friendly name (at most 30 ISO 8859-1 characters).
func WithName(name string) Option {
	return func(o *options) error {
		if len(name) > 30 {
			return invalid("name of %d characters (at most 30)", len(name))
		}
		o.name = name
		return nil
	}
}

// WithIndividualAddress sets the server's own individual address
// (default 15.15.0).
func WithIndividualAddress(a knx.IndividualAddress) Option {
	return func(o *options) error { o.address = a; return nil }
}

// WithTunnelAddresses sets the individual addresses of the tunnelling
// connections, one per connection: their number is the connection limit
// (default one, 15.15.250).
func WithTunnelAddresses(addrs ...knx.IndividualAddress) Option {
	return func(o *options) error {
		if len(addrs) == 0 || len(addrs) > 255 {
			return invalid("%d tunnelling addresses (1..255)", len(addrs))
		}
		seen := map[knx.IndividualAddress]bool{}
		for _, a := range addrs {
			if seen[a] {
				return invalid("duplicate tunnelling address %s", a)
			}
			seen[a] = true
		}
		o.tunnels = append([]knx.IndividualAddress(nil), addrs...)
		return nil
	}
}

// WithSerial sets the KNX serial number.
func WithSerial(s [6]byte) Option { return func(o *options) error { o.serial = s; return nil } }

// WithMAC sets the MAC address announced in DEVICE_INFO.
func WithMAC(m [6]byte) Option { return func(o *options) error { o.mac = m; return nil } }

// WithDiscovery sets whether the server joins the multicast group and
// answers search requests sent to it (default true). Unicast searches
// and description requests are always answered.
func WithDiscovery(on bool) Option { return func(o *options) error { o.discovery = on; return nil } }

// WithRouting enables KNXnet/IP routing: telegrams of tunnelling clients
// and devices are sent as ROUTING_INDICATIONs to the multicast group, and
// indications from other routers are delivered to the clients and
// devices.
func WithRouting(on bool) Option { return func(o *options) error { o.routing = on; return nil } }

// WithMulticastGroup sets the routing multicast group (default
// 224.0.23.12:3671; discovery always uses 224.0.23.12).
func WithMulticastGroup(addr string) Option {
	return func(o *options) error { o.group = addr; return nil }
}

// WithMulticastTTL sets the TTL of routing indications (default 16).
func WithMulticastTTL(ttl int) Option {
	return func(o *options) error {
		if ttl < 1 || ttl > 255 {
			return invalid("TTL %d", ttl)
		}
		o.ttl = ttl
		return nil
	}
}

// WithConnectionAliveTime sets the heartbeat timeout of tunnelling
// connections (default 120 s).
func WithConnectionAliveTime(d time.Duration) Option {
	return func(o *options) error {
		if d <= 0 {
			return invalid("alive time %v", d)
		}
		o.aliveTime = d
		return nil
	}
}

// WithRequestTimeout sets the wait for a client's TUNNELLING_ACK
// (default 1 s).
func WithRequestTimeout(d time.Duration) Option {
	return func(o *options) error {
		if d <= 0 {
			return invalid("request timeout %v", d)
		}
		o.reqTimeout = d
		return nil
	}
}

// WithQueueSize bounds the telegrams queued for each tunnelling
// connection (default 128); when a queue is full, telegrams to that
// client are dropped.
func WithQueueSize(n int) Option {
	return func(o *options) error {
		if n < 1 || n > 1<<16 {
			return invalid("queue size %d", n)
		}
		o.queueSize = n
		return nil
	}
}

// WithRoutingRate bounds the routing indications sent per second
// (default 50; 0 disables the limit). Telegrams over the limit are
// dropped and counted.
func WithRoutingRate(n int) Option {
	return func(o *options) error {
		if n < 0 {
			return invalid("routing rate %d", n)
		}
		o.routingRate = n
		return nil
	}
}

// WithProgrammingMode sets the programming mode bit of DEVICE_INFO.
func WithProgrammingMode(on bool) Option {
	return func(o *options) error { o.progMode = on; return nil }
}

// WithLogger sets the logger.
func WithLogger(l knx.Logger) Option {
	return func(o *options) error {
		if l != nil {
			o.logger = l
		}
		return nil
	}
}

// WithMetrics sets the metrics callbacks.
func WithMetrics(m knx.Metrics) Option {
	return func(o *options) error {
		if m != nil {
			o.metrics = m
		}
		return nil
	}
}
