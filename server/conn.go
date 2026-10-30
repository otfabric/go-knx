// SPDX-License-Identifier: MIT

package server

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/knxnetip"
)

type ack struct {
	seq    uint8
	status knxnetip.Status
}

// connKind is the kind of a connection.
type connKind int

const (
	kindTunnel     connKind = iota // tunnelling, link layer
	kindBusmonitor                 // tunnelling, busmonitor layer
	kindDevMgmt                    // device management
)

func (k connKind) String() string {
	switch k {
	case kindBusmonitor:
		return "busmonitor"
	case kindDevMgmt:
		return "device management"
	default:
		return "tunnel"
	}
}

// peer is the sender of a frame: a UDP endpoint, or a TCP connection.
type peer struct {
	addr netip.AddrPort
	tcp  *tcpConn
	us   *udpSession // a secure session over UDP
}

// out is an item of a connection's send queue: a cEMI frame, or a
// tunnelling feature frame.
type out struct {
	cemi    []byte
	feature *knxnetip.TunnellingFeature
}

// tconn is a KNXnet/IP connection: tunnelling (link layer or
// busmonitor) or device management, over UDP or TCP.
type tconn struct {
	s       *Server
	kind    connKind
	channel uint8
	addr    knx.IndividualAddress
	ctrl    netip.AddrPort
	data    netip.AddrPort
	tcp     *tcpConn    // nil over UDP
	us      *udpSession // the secure session over UDP, if any

	mu       sync.Mutex
	rxSeq    uint8
	txSeq    uint8
	lastSeen time.Time
	infoOn   bool // tunnelling v2 interface feature info service

	queue     chan out
	ackCh     chan ack
	done      chan struct{}
	closeOnce sync.Once
}

// from accepts frames from the client: its TCP connection, or over UDP
// its address.
func (c *tconn) from(p peer) bool {
	if c.tcp != nil || p.tcp != nil {
		return c.tcp == p.tcp
	}
	if c.us != p.us {
		// A secure connection takes frames of its session only.
		return false
	}
	return p.addr.Addr() == c.ctrl.Addr() || p.addr.Addr() == c.data.Addr()
}

// send writes a frame to the client's data endpoint.
func (c *tconn) send(m knxnetip.Message) {
	if c.tcp != nil {
		c.tcp.write(m)
		return
	}
	if c.us != nil {
		c.s.writeSession(c.us, c.data, m)
		return
	}
	c.s.write(c.data, m)
}

func offerSeq(ch chan ack, v ack) {
	select {
	case ch <- v:
	default:
		select {
		case <-ch:
		default:
		}
		select {
		case ch <- v:
		default:
		}
	}
}

func (c *tconn) enqueue(o out) {
	select {
	case <-c.done:
	case c.queue <- o:
	default:
		c.s.o.metrics.OnDropped(net.UDPAddrFromAddrPort(c.data), "queue_full")
	}
}

// accept implements the receiver side of the sequence counter for a
// request of the client and acknowledges it (over UDP). It reports
// whether the request is new.
func (c *tconn) accept(p peer, seq uint8, ackType knxnetip.ServiceType) bool {
	c.mu.Lock()
	expected := c.rxSeq
	deliver, ackIt := false, false
	switch {
	case c.tcp != nil:
		// TCP delivers in order, without repetitions and without ACKs.
		c.rxSeq = seq + 1
		deliver = true
	case seq == expected:
		c.rxSeq++
		deliver, ackIt = true, true
	case seq == expected-1:
		ackIt = true
	}
	c.lastSeen = time.Now()
	c.mu.Unlock()
	fa := net.UDPAddrFromAddrPort(p.addr)
	if !deliver && !ackIt {
		c.s.o.metrics.OnDropped(fa, "sequence")
		return false
	}
	if ackIt {
		if ackType == knxnetip.DeviceConfigurationAckType {
			c.send(&knxnetip.DeviceConfigurationAck{Channel: c.channel, Seq: seq, Status: knxnetip.StatusNoError})
		} else {
			c.send(&knxnetip.TunnellingAck{Channel: c.channel, Seq: seq, Status: knxnetip.StatusNoError})
		}
	}
	if !deliver {
		c.s.o.metrics.OnDropped(fa, "duplicate")
	}
	return deliver
}

// onRequest handles a TUNNELLING_REQUEST from the client.
func (c *tconn) onRequest(p peer, m *knxnetip.TunnellingRequest) {
	if !c.accept(p, m.Seq, knxnetip.TunnellingAckType) {
		return
	}
	if c.kind != kindTunnel {
		// A busmonitor connection is receive only.
		c.s.o.logger.Debugf("server: channel %d (%s): ignore a tunnelling request", c.channel, c.kind)
		return
	}
	f, err := cemi.Parse(m.CEMI)
	if err != nil {
		c.s.o.metrics.OnDecodeError(net.UDPAddrFromAddrPort(p.addr), err)
		return
	}
	ld, ok := f.(*cemi.LData)
	if !ok || ld.MsgCode != cemi.LDataReq {
		c.s.o.logger.Debugf("server: channel %d: ignore %s", c.channel, f.Code())
		return
	}
	if ld.Source == 0 {
		ld.Source = c.addr
	}
	// Deliver first, then confirm: an L_Data.con says the telegram is on
	// the network, so the devices have it when the client learns it was
	// sent.
	con := ld.Clone()
	c.s.distribute(Telegram{Origin: FromTunnel, Channel: c.channel, Frame: ld}, c)
	con.MsgCode = cemi.LDataCon
	con.Ctrl1 &^= cemi.Ctrl1ConfirmError
	if b, err := cemi.Marshal(con); err == nil {
		c.enqueue(out{cemi: b})
	}
}

// onDeviceConfiguration handles a DEVICE_CONFIGURATION_REQUEST: a local
// device management request (M_PropRead.req...) to the server.
func (c *tconn) onDeviceConfiguration(p peer, m *knxnetip.DeviceConfigurationRequest) {
	if !c.accept(p, m.Seq, knxnetip.DeviceConfigurationAckType) {
		return
	}
	f, err := cemi.Parse(m.CEMI)
	if err != nil {
		c.s.o.metrics.OnDecodeError(net.UDPAddrFromAddrPort(p.addr), err)
		return
	}
	if resp := c.s.props.handle(f); resp != nil {
		if b, err := cemi.Marshal(resp); err == nil {
			c.enqueue(out{cemi: b})
		}
	}
}

// onFeature handles TUNNELLING_FEATURE_GET and _SET (tunnelling v2).
func (c *tconn) onFeature(p peer, m *knxnetip.TunnellingFeature) {
	if m.Type != knxnetip.TunnellingFeatureGetType && m.Type != knxnetip.TunnellingFeatureSetType {
		return
	}
	if !c.accept(p, m.Seq, knxnetip.TunnellingAckType) {
		return
	}
	value, code := c.feature(m.Type == knxnetip.TunnellingFeatureSetType, m.Feature, m.Value)
	c.enqueue(out{feature: &knxnetip.TunnellingFeature{Type: knxnetip.TunnellingFeatureResponseType, Channel: c.channel,
		Feature: m.Feature, ReturnCode: code, Value: value}})
}

// Return codes of TUNNELLING_FEATURE_RESPONSE.
const (
	featureOK          = 0x00
	featureUnsupported = 0x01 // the feature is not supported
	featureReadOnly    = 0x02 // the feature cannot be written
	featureBadValue    = 0x03 // the value is not valid for the feature
)

func (c *tconn) feature(set bool, f knxnetip.FeatureID, v []byte) ([]byte, uint8) {
	switch f {
	case knxnetip.FeatureInfoServiceEnable:
		if set {
			if len(v) != 1 || v[0] > 1 {
				return nil, featureBadValue
			}
			c.mu.Lock()
			c.infoOn = v[0] == 1
			c.mu.Unlock()
			return v, featureOK
		}
		c.mu.Lock()
		on := c.infoOn
		c.mu.Unlock()
		if on {
			return []byte{1}, featureOK
		}
		return []byte{0}, featureOK
	case knxnetip.FeatureSupportedEMIType, knxnetip.FeatureDeviceDescriptorType0, knxnetip.FeatureBusConnectionStatus,
		knxnetip.FeatureManufacturerCode, knxnetip.FeatureActiveEMIType, knxnetip.FeatureIndividualAddress,
		knxnetip.FeatureMaxAPDULength:
		if set {
			return nil, featureReadOnly
		}
	}
	switch f {
	case knxnetip.FeatureSupportedEMIType:
		return []byte{0x00, 0x04}, featureOK // cEMI
	case knxnetip.FeatureDeviceDescriptorType0:
		return []byte{byte(DeviceDescriptor >> 8), byte(DeviceDescriptor & 0xFF)}, featureOK
	case knxnetip.FeatureBusConnectionStatus:
		return []byte{0x01}, featureOK // connected
	case knxnetip.FeatureManufacturerCode:
		return []byte{c.s.o.serial[0], c.s.o.serial[1]}, featureOK
	case knxnetip.FeatureActiveEMIType:
		return []byte{0x03}, featureOK // cEMI
	case knxnetip.FeatureIndividualAddress:
		return []byte{byte(c.addr >> 8), byte(c.addr)}, featureOK
	case knxnetip.FeatureMaxAPDULength:
		return []byte{0x00, byte(MaxAPDU)}, featureOK
	default:
		return nil, featureUnsupported
	}
}

// sender sends the queued frames, one at a time. Over UDP each waits for
// its ACK and is repeated once; a second failure ends the connection.
func (c *tconn) sender() {
	defer c.s.wg.Done()
	for {
		var o out
		select {
		case <-c.done:
			return
		case <-c.s.closing:
			return
		case o = <-c.queue:
		}
		c.mu.Lock()
		seq := c.txSeq
		c.mu.Unlock()
		var req knxnetip.Message
		switch {
		case o.feature != nil:
			o.feature.Seq = seq
			req = o.feature
		case c.kind == kindDevMgmt:
			req = &knxnetip.DeviceConfigurationRequest{Channel: c.channel, Seq: seq, CEMI: o.cemi}
		default:
			req = &knxnetip.TunnellingRequest{Channel: c.channel, Seq: seq, CEMI: o.cemi}
		}
		acked := c.tcp != nil
		if acked {
			c.send(req)
		}
		for attempt := 0; attempt < 2 && !acked; attempt++ {
			if attempt > 0 {
				c.s.o.metrics.OnRetransmit(net.UDPAddrFromAddrPort(c.data), c.channel)
			}
			c.send(req)
			t := time.NewTimer(c.s.o.reqTimeout)
		wait:
			for {
				select {
				case a := <-c.ackCh:
					if a.seq != seq || a.status != knxnetip.StatusNoError {
						// A late ACK, or one with an error status: the
						// request counts as not acknowledged.
						continue
					}
					acked = true
					break wait
				case <-t.C:
					break wait
				case <-c.done:
					t.Stop()
					return
				}
			}
			t.Stop()
		}
		if !acked {
			c.s.disconnect(c, true, fmt.Errorf("%w: no acknowledgement for sequence %d", knx.ErrConnectionLost, seq))
			return
		}
		c.mu.Lock()
		c.txSeq++
		c.mu.Unlock()
	}
}
