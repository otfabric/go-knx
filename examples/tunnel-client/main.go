// SPDX-License-Identifier: MIT

// Command tunnel-client connects to a KNXnet/IP interface or router,
// switches a group object and prints the group telegrams it sees.
//
//	go run ./examples/tunnel-client -gateway 192.168.1.10 -group 1/2/3
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"syscall"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/client"
	"github.com/otfabric/go-knx/tunnel"
)

func main() {
	gateway := flag.String("gateway", "", "KNXnet/IP server, host[:port]")
	group := flag.String("group", "1/2/3", "group address to switch on")
	nat := flag.Bool("nat", false, "route back endpoints (behind NAT)")
	flag.Parse()
	if *gateway == "" {
		log.Fatal("-gateway is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	c, err := client.DialTunnel(ctx, *gateway, []tunnel.Option{tunnel.WithNAT(*nat), tunnel.WithReconnect(time.Second, 30*time.Second)})
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	if err := c.GroupWrite(ctx, knx.MustParseGroupAddress(*group), true); err != nil {
		log.Fatal(err)
	}
	sub := c.Subscribe(64)
	for {
		select {
		case <-ctx.Done():
			return
		case t, ok := <-sub.C():
			if !ok {
				return
			}
			fmt.Printf("%s %s -> %s %s % X\n", t.Time.Format("15:04:05.000"), t.Source, t.Group, t.Service, t.Value.Data)
		}
	}
}
