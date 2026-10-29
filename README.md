# go-knx

[![CI](https://github.com/otfabric/go-knx/actions/workflows/ci.yml/badge.svg)](https://github.com/otfabric/go-knx/actions/workflows/ci.yml)
[![Interop](https://github.com/otfabric/go-knx/actions/workflows/interop.yml/badge.svg)](https://github.com/otfabric/go-knx/actions/workflows/interop.yml)
[![codecov](https://codecov.io/gh/otfabric/go-knx/graph/badge.svg)](https://codecov.io/gh/otfabric/go-knx)
[![Go Reference](https://pkg.go.dev/badge/github.com/otfabric/go-knx.svg)](https://pkg.go.dev/github.com/otfabric/go-knx)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A native Go implementation of KNX over KNXnet/IP: frames, cEMI, datapoint
types, discovery, a tunnelling client, routing, group communication and a
KNXnet/IP server with virtual devices. Pure Go, no cgo, no dependencies;
it runs on embedded Linux (ARM, ARM64) as well as servers, macOS and
Windows.

go-knx is part of [OT Fabric](https://otfabric.io). Its command-line tool
is [knxctl](https://github.com/otfabric/knxctl); its interoperability
tests against independent stacks live in
[knx-interop](https://github.com/otfabric/knx-interop).

> KNX is a registered trademark of KNX Association cvba. go-knx is an
> independent implementation, not affiliated with or endorsed by KNX
> Association, and **not KNX certified** ([CONFORMANCE](docs/standards/CONFORMANCE.md)).

## Features

| Area | Status |
|---|---|
| Individual and group addresses (3-level, 2-level, free), strict and reversible parsing | ✅ |
| KNXnet/IP frames: header, HPAI, DIB (all standard types), CRI/CRD, core, device management, tunnelling, routing and secure service bodies | ✅ encode/decode, fuzzed |
| cEMI: L_Data.req/.ind/.con, L_Busmon, L_Raw, M_PropRead/Write/Info, M_FuncProp*, M_Reset; additional info; standard and extended frames | ✅ |
| TPCI and APCI (all application services named; group values with small values) | ✅ |
| Datapoint types: 1–14, 16–22, 26, 29, 232, 242, 251 (209 subtypes), ranges, units, text format/parse | ✅ |
| Discovery: multicast and directed search, extended search with parameters, description | ✅ |
| Tunnelling client over UDP (sequence handling, ACK and retransmission, L_Data.con, heartbeat, NAT, reconnect) and TCP (tunnelling v2), tunnelling v2 address request and feature services | ✅ |
| Device management client (`devmgmt`: M_PropRead/M_PropWrite of interface object properties) | ✅ |
| Busmonitor tunnelling (L_Busmon.ind; TP1 frame encode/decode with check octet) | ✅ |
| Routing: indications, ROUTING_BUSY flow control, rate limit, echo suppression | ✅ |
| Group communication: write, read (first or all responses), respond, subscriptions, callbacks | ✅ |
| KNXnet/IP server: discovery, description, tunnelling over UDP and TCP (multiple clients, channel limits, feature services), busmonitor, device management (device, router and KNXnet/IP parameter objects), routing, virtual group objects with flags | ✅ |
| KNX IP Secure, KNX Data Secure | ⏳ frames only; see [status](docs/IMPLEMENTATION-STATUS.md) |
| KNX TP/RF media, ETS project import, KNX IoT | ❌ out of scope |

Interoperability, verified both ways against Calimero 3.0-M1, knxd 0.14.73,
xknx 4.0.0 and KNXUltimate 6.3.1: [INTEROPERABILITY.md](INTEROPERABILITY.md).

## Install

```bash
go get github.com/otfabric/go-knx
```

Go 1.23 or later.

## Quick start

### Group communication through a KNXnet/IP interface

```go
c, err := client.DialTunnel(ctx, "192.168.1.10", nil)
if err != nil {
	return err
}
defer c.Close()

// Switch on (DPT 1.001).
err = c.GroupWrite(ctx, knx.MustParseGroupAddress("1/2/3"), true)

// Write a temperature (DPT 9.001).
err = c.GroupWrite(ctx, knx.MustParseGroupAddress("1/2/4"), 21.5, client.WithDPT("9.001"))

// Read a value: no response is guaranteed, the read times out (knx.ErrTimeout).
r, err := c.GroupRead(ctx, knx.MustParseGroupAddress("1/2/5"), client.WithDPT("9.001"))
fmt.Println(r.Source, r.Decoded)

// Watch group telegrams.
sub := c.Subscribe(64, knx.MustParseGroupAddress("1/2/3"))
for t := range sub.C() {
	fmt.Println(t.Source, t.Group, t.Service, t.Value.Data)
}
```

Behind NAT (Docker port mappings) use `tunnel.WithNAT(true)`; to reconnect
after a lost connection `tunnel.WithReconnect(time.Second, 30*time.Second)`.

### Routing

```go
c, err := client.ListenRouting(ctx, []routing.Option{routing.WithInterface("eth0")},
	client.WithSource(knx.MustParseIndividualAddress("1.1.250")))
```

### Discovery

```go
servers, err := discovery.Search(ctx, discovery.WithTimeout(3*time.Second))
for _, s := range servers {
	d := s.Device()
	fmt.Println(s.Endpoint(), d.Name, d.Address)
}
dibs, err := discovery.Describe(ctx, "192.168.1.10")
```

### A KNXnet/IP server with virtual devices

```go
s, _ := server.New(server.WithName("simulator"),
	server.WithTunnelAddresses(knx.MustParseIndividualAddress("1.1.10"), knx.MustParseIndividualAddress("1.1.11")))
dev := device.New("living room", knx.MustParseIndividualAddress("1.1.1"))
light, _ := device.NewGroupObject("light", "1.001", "CRWU", "1/2/3")
temp, _ := device.NewGroupObject("temperature", "9.001", "CRT", "1/2/4")
_ = temp.Set(21.5)
dev.Add(light, temp)
s.AddDevice(dev)
err := s.Serve(ctx) // until ctx is done
```

KNXnet/IP clients (ETS-style tools, Home Assistant through xknx, Calimero,
knxd) connect to it as to an IP interface; the virtual devices store
written values and answer reads according to their flags. It is a
KNXnet/IP server with an application-level device model, not an emulation
of a KNX TP line.

### Datapoint types

```go
t := dpt.MustLookup("9.001")
b, _ := t.Encode(21.5)    // 0C 33
v, _ := t.Decode(b)       // 21.5
fmt.Println(t.Format(v))  // 21.5 °C
```

More in [examples/](examples) and the package documentation.

## Packages

| Package | Purpose |
|---|---|
| `knx` | Addresses, priorities, errors, Logger, Metrics, State |
| `knxnetip` | KNXnet/IP frames |
| `cemi` | cEMI frames |
| `apdu` | TPCI and APCI |
| `dpt` | Datapoint types |
| `discovery` | Search and description |
| `tunnel` | Tunnelling client (UDP, TCP, busmonitor, feature services) |
| `devmgmt` | Device management client (interface object properties) |
| `routing` | Routing |
| `client` | Group communication over a tunnel or routing |
| `server` | KNXnet/IP server |
| `device` | Virtual devices and group objects |

Design: [ARCHITECTURE.md](ARCHITECTURE.md). Errors: [ERRORS.md](ERRORS.md).
Observability: [OBSERVABILITY.md](OBSERVABILITY.md). Tests:
[TESTING.md](TESTING.md).

## Security

KNXnet/IP without KNX IP Secure has no authentication and no encryption:
anyone on the network can read and send telegrams. Isolate KNX IP networks.
See [SECURITY.md](SECURITY.md) for the threat model and the status of KNX
Secure.

## Standards and licensing

What is implemented from which part of the standard:
[docs/standards/SPECIFICATIONS.md](docs/standards/SPECIFICATIONS.md).
Specification access and licensing:
[docs/standards/LICENSING.md](docs/standards/LICENSING.md).
Status and roadmap: [docs/IMPLEMENTATION-STATUS.md](docs/IMPLEMENTATION-STATUS.md).

## License

MIT, see [LICENSE](LICENSE).
