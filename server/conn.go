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

// tconn is a tunnelling connection.
type tconn struct {
	s       *Server
	channel uint8
	addr    knx.IndividualAddress
	ctrl    netip.AddrPort
	data    netip.AddrPort

	mu       sync.Mutex
	rxSeq    uint8
	txSeq    uint8
	lastSeen time.Time

	queue     chan []byte
	ackCh     chan ack
	done      chan struct{}
	closeOnce sync.Once
}

// from accepts datagrams from the client's address.
func (c *tconn) from(a netip.AddrPort) bool {
	return a.Addr() == c.ctrl.Addr() || a.Addr() == c.data.Addr()
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

func (c *tconn) enqueue(b []byte) {
	select {
	case <-c.done:
	case c.queue <- b:
	default:
		c.s.o.metrics.OnDropped(net.UDPAddrFromAddrPort(c.data), "queue_full")
	}
}

// onRequest handles a TUNNELLING_REQUEST from the client.
func (c *tconn) onRequest(from netip.AddrPort, m *knxnetip.TunnellingRequest) {
	c.mu.Lock()
	expected := c.rxSeq
	deliver, ackIt := false, false
	switch m.Seq {
	case expected:
		c.rxSeq++
		deliver, ackIt = true, true
	case expected - 1:
		ackIt = true
	}
	c.lastSeen = time.Now()
	c.mu.Unlock()
	fa := net.UDPAddrFromAddrPort(from)
	if !ackIt {
		c.s.o.metrics.OnDropped(fa, "sequence")
		return
	}
	c.s.write(c.data, &knxnetip.TunnellingAck{Channel: c.channel, Seq: m.Seq, Status: knxnetip.StatusNoError})
	if !deliver {
		c.s.o.metrics.OnDropped(fa, "duplicate")
		return
	}
	f, err := cemi.Parse(m.CEMI)
	if err != nil {
		c.s.o.metrics.OnDecodeError(fa, err)
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
	// The confirmation: the frame as sent, marked L_Data.con without
	// error.
	con := ld.Clone()
	con.MsgCode = cemi.LDataCon
	con.Ctrl1 &^= cemi.Ctrl1ConfirmError
	if b, err := cemi.Marshal(con); err == nil {
		c.enqueue(b)
	}
	c.s.distribute(Telegram{Origin: FromTunnel, Channel: c.channel, Frame: ld}, c)
}

// sender sends the queued cEMI frames as TUNNELLING_REQUESTs, one at a
// time, repeating once without ACK; a second failure ends the
// connection.
func (c *tconn) sender() {
	defer c.s.wg.Done()
	for {
		var b []byte
		select {
		case <-c.done:
			return
		case <-c.s.closing:
			return
		case b = <-c.queue:
		}
		c.mu.Lock()
		seq := c.txSeq
		c.mu.Unlock()
		req := &knxnetip.TunnellingRequest{Channel: c.channel, Seq: seq, CEMI: b}
		acked := false
		for attempt := 0; attempt < 2 && !acked; attempt++ {
			if attempt > 0 {
				c.s.o.metrics.OnRetransmit(net.UDPAddrFromAddrPort(c.data), c.channel)
			}
			c.s.write(c.data, req)
			t := time.NewTimer(c.s.o.reqTimeout)
		wait:
			for {
				select {
				case a := <-c.ackCh:
					if a.seq != seq {
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
			c.s.disconnect(c, true, fmt.Errorf("%w: no TUNNELLING_ACK for sequence %d", knx.ErrConnectionLost, seq))
			return
		}
		c.mu.Lock()
		c.txSeq++
		c.mu.Unlock()
	}
}
