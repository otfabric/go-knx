// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/otfabric/go-knx/server"
	"github.com/otfabric/go-knx/tunnel"
)

// BenchmarkConcurrentClients measures the telegrams per second the server
// handles from 8 tunnelling clients writing at once, each telegram
// confirmed to its sender and delivered to the 7 others.
func BenchmarkConcurrentClients(b *testing.B) {
	const clients = 8
	s, _ := start(b, server.WithTunnelAddresses(addrs(clients)...), server.WithQueueSize(4096))
	conns := make([]*tunnel.Conn, clients)
	rctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var rwg sync.WaitGroup
	for i := range conns {
		conns[i] = dialTunnel(b, s, tunnel.WithQueueSize(1<<16))
		rwg.Add(1)
		go func(c *tunnel.Conn) { // drain the deliveries
			defer rwg.Done()
			for {
				if _, err := c.Receive(rctx); err != nil {
					return
				}
			}
		}(conns[i])
	}
	var next atomic.Int64
	b.ResetTimer()
	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Add(1)
		go func(c *tunnel.Conn) {
			defer wg.Done()
			for next.Add(1) <= int64(b.N) {
				if err := c.Send(context.Background(), write(ga, 1)); err != nil {
					b.Error(err)
					return
				}
			}
		}(c)
	}
	wg.Wait()
	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "telegrams/s")
	cancel()
	for _, c := range conns {
		c.Close()
	}
	rwg.Wait()
}
