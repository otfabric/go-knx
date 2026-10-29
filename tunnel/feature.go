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
// (TUNNELLING_FEATURE_GET, tunnelling v2) and returns its value.
func (c *Conn) FeatureGet(ctx context.Context, f knxnetip.FeatureID) ([]byte, error) {
	r, err := c.feature(ctx, knxnetip.TunnellingFeatureGetType, f, nil)
	if err != nil {
		return nil, err
	}
	return r.Value, nil
}

// FeatureSet writes an interface feature of the server
// (TUNNELLING_FEATURE_SET, tunnelling v2).
func (c *Conn) FeatureSet(ctx context.Context, f knxnetip.FeatureID, value []byte) error {
	_, err := c.feature(ctx, knxnetip.TunnellingFeatureSetType, f, value)
	return err
}

func (c *Conn) feature(ctx context.Context, t knxnetip.ServiceType, f knxnetip.FeatureID, value []byte) (*knxnetip.TunnellingFeature, error) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	c.mu.Lock()
	state, ch, seq, dataEP := c.state, c.channel, c.txSeq, c.dataEP
	c.mu.Unlock()
	if state != knx.StateConnected {
		return nil, fmt.Errorf("%w: tunnel: %s", knx.ErrConnectionLost, state)
	}
	drain(c.featCh)
	drain(c.ackCh)
	req := &knxnetip.TunnellingFeature{Type: t, Channel: ch, Seq: seq, Feature: f, Value: value}
	if err := c.write(dataEP, req); err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.txSeq++
	c.mu.Unlock()
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
		case <-c.ackCh:
			// The UDP acknowledgement of the request; the response follows.
		case <-timer.C:
			return nil, fmt.Errorf("%w: tunnel: no TUNNELLING_FEATURE_RESPONSE for feature 0x%02X", knx.ErrTimeout, uint8(f))
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.closing:
			return nil, knx.ErrClosed
		}
	}
}
