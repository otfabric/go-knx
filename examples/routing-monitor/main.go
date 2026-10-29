// SPDX-License-Identifier: MIT

// Command routing-monitor prints the routing indications on the KNXnet/IP
// multicast group. It sends nothing.
//
//	go run ./examples/routing-monitor -interface eth0
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"syscall"

	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/routing"
)

func main() {
	iface := flag.String("interface", "", "network interface")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var opts []routing.Option
	if *iface != "" {
		opts = append(opts, routing.WithInterface(*iface))
	}
	r, err := routing.Listen(ctx, opts...)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()
	for {
		f, err := r.Receive(ctx)
		if err != nil {
			return
		}
		if ld, ok := f.(*cemi.LData); ok {
			fmt.Println(ld)
		}
	}
}
