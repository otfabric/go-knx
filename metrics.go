// SPDX-License-Identifier: MIT

package knx

import "net"

// Metrics is an optional callback interface for observing connections and
// traffic of a tunnel, a routing link, a client or a server. A nil Metrics
// disables collection.
//
// The methods are called synchronously on the protocol path, possibly from
// several goroutines at once; implementations must be safe for concurrent
// use and must not block (increment a counter, send on a buffered
// channel).
//
// Embed [NopMetrics] to implement only the callbacks you need and to stay
// compatible when methods are added.
type Metrics interface {
	// OnConnect is called when a tunnelling connection was established
	// (client) or accepted (server) on channel.
	OnConnect(remote net.Addr, channel uint8)

	// OnDisconnect is called when a tunnelling connection ended. err is
	// nil when the application closed it.
	OnDisconnect(remote net.Addr, channel uint8, err error)

	// OnFrameSent is called after a KNXnet/IP frame was written. service is
	// its service type identifier, size its length on the wire.
	OnFrameSent(remote net.Addr, service uint16, size int)

	// OnFrameReceived is called for every KNXnet/IP frame read.
	OnFrameReceived(remote net.Addr, service uint16, size int)

	// OnDecodeError is called when a frame could not be decoded and was
	// dropped.
	OnDecodeError(remote net.Addr, err error)

	// OnRetransmit is called when a tunnelling request is repeated because
	// its acknowledgement did not arrive in time.
	OnRetransmit(remote net.Addr, channel uint8)

	// OnDropped is called when an inbound telegram is dropped: a full
	// queue, a duplicate, a sequence number out of order, a routing rate
	// limit. reason is a short constant string.
	OnDropped(remote net.Addr, reason string)
}

// NopMetrics is a [Metrics] that does nothing. Embed it in your own type.
type NopMetrics struct{}

// OnConnect does nothing.
func (NopMetrics) OnConnect(net.Addr, uint8) {}

// OnDisconnect does nothing.
func (NopMetrics) OnDisconnect(net.Addr, uint8, error) {}

// OnFrameSent does nothing.
func (NopMetrics) OnFrameSent(net.Addr, uint16, int) {}

// OnFrameReceived does nothing.
func (NopMetrics) OnFrameReceived(net.Addr, uint16, int) {}

// OnDecodeError does nothing.
func (NopMetrics) OnDecodeError(net.Addr, error) {}

// OnRetransmit does nothing.
func (NopMetrics) OnRetransmit(net.Addr, uint8) {}

// OnDropped does nothing.
func (NopMetrics) OnDropped(net.Addr, string) {}
