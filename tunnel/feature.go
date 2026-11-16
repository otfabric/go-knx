// SPDX-License-Identifier: MIT

package tunnel

import (
	"context"
	"fmt"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/knxnetip"
)

// FeatureError is a TUNNELLING_FEATURE_RESPONSE with a return code other
// than E_NO_ERROR.
type FeatureError struct {
	Feature    knxnetip.FeatureID
	ReturnCode uint8
}

// Error describes the failure.
func (e *FeatureError) Error() string {
	return fmt.Sprintf("tunnel: feature 0x%02X: return code 0x%02X", uint8(e.Feature), e.ReturnCode)
}

// Is matches knx.ErrRejected.
func (e *FeatureError) Is(target error) bool { return target == knx.ErrRejected }

// FeatureGet reads an interface feature of the server
// (TUNNELLING_FEATURE_GET, tunnelling v2) and returns its value. Over UDP
// the request is acknowledged and repeated like the request of Send.
func (c *Conn) FeatureGet(ctx context.Context, f knxnetip.FeatureID) ([]byte, error) {
	r, err := c.feature(ctx, knxnetip.TunnellingFeatureGetType, f, nil)
	if err != nil {
		return nil, err
	}
	return r.Value, nil
}

// FeatureSet writes an interface feature of the server
// (TUNNELLING_FEATURE_SET, tunnelling v2). Over UDP the request is
// acknowledged and repeated like the request of Send.
func (c *Conn) FeatureSet(ctx context.Context, f knxnetip.FeatureID, value []byte) error {
	_, err := c.feature(ctx, knxnetip.TunnellingFeatureSetType, f, value)
	return err
}

// feature sends a feature request and waits for its response. Over UDP
// the request is acknowledged like a tunnelling request: it is repeated
// once when no TUNNELLING_ACK arrives within the request timeout, the
// sequence number is consumed by the acknowledgement, and a request that
// is not acknowledged twice loses the connection. Over TCP there is no
// acknowledgement.
func (c *Conn) feature(ctx context.Context, t knxnetip.ServiceType, f knxnetip.FeatureID, value []byte) (*knxnetip.TunnellingFeature, error) {
	if err := c.acquire(ctx); err != nil {
		return nil, err
	}
	defer c.release()
	if err := c.settle(ctx); err != nil {
		return nil, err
	}
	c.mu.Lock()
	state, ch, seq, dataEP, gen := c.state, c.channel, c.txSeq, c.dataEP, c.gen
	c.mu.Unlock()
	switch state {
	case knx.StateConnected:
	case knx.StateClosed:
		return nil, knx.ErrClosed
	default:
		return nil, fmt.Errorf("%w: tunnel: %s", knx.ErrConnectionLost, state)
	}
	drain(c.featCh)
	req := &knxnetip.TunnellingFeature{Type: t, Channel: ch, Seq: seq, Feature: f, Value: value}
	if c.tr.stream() {
		if err := c.write(dataEP, req); err != nil {
			return nil, err
		}
		c.advance(gen)
	} else if err := c.exchange(ctx, gen, ch, seq, dataEP, req, func(err error) error { return err }); err != nil {
		return nil, err
	}
	timer := time.NewTimer(c.o.confirmTimeout)
	defer timer.Stop()
	for {
		select {
		case r := <-c.featCh:
			if r.Type != knxnetip.TunnellingFeatureResponseType || r.Feature != f {
				continue
			}
			if r.ReturnCode != 0 {
				return nil, &FeatureError{Feature: f, ReturnCode: r.ReturnCode}
			}
			return r, nil
		case <-timer.C:
			return nil, fmt.Errorf("%w: tunnel: no TUNNELLING_FEATURE_RESPONSE for feature 0x%02X", knx.ErrTimeout, uint8(f))
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.closing:
			return nil, knx.ErrClosed
		}
	}
}
