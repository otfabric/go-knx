# Interoperability

go-knx is tested against independent KNX implementations in two places:

1. **The knx-interop matrix** ([otfabric/knx-interop](https://github.com/otfabric/knx-interop),
   docs/INTEROPERABILITY.md) with go-knx's own adapter (`make
   interop-matrix`): every client against every server and every routing
   peer against every other, inside one Docker network, including
   multicast discovery and routing, 12 DPT vectors, a negative suite,
   KNX Secure, remote management, the sim suite (cB-Sigma knx-sim's
   gateway and router with fault switches and flow control frames) and an
   offline check of ETS keyring import. go-knx takes part through `interop/node`, a command built
   from this repository's sources that implements knx-interop's container
   contract on the library; knx-interop holds third-party stacks only and
   does not depend on go-knx.
2. **This repository's `interop/` suite** (`make interop-images interop`):
   go-knx used as a library from the host, against the knx-interop images,
   through published UDP ports with route back (NAT) endpoints.

## Results (2026-11-07, knx-interop v0.9.2)

`make interop-matrix` on arm64: 609 pass, 13 known differences of other
stacks, 110 unsupported, 0 fail; of the results with go-knx in a role, 456
pass, 2 known differences (Calimero tools' Data Secure through a tunnel,
which needs a surrogate) and 34 unsupported. `make interop` (host-based): 72
of 72 pass. Since knx-interop v0.9.2, knxd runs its TCP tunnelling server
(`tcptunsrv`, configured in knxd's config file), and go-knx's TCP client
passes against it.

| Peer (version) | go-knx as client | go-knx as server | Routing with go-knx |
|---|---|---|---|
| Calimero server 3.0-M1 | discovery, description, connect, confirmed write, read, inbound telegrams, 12 DPT vectors: pass | — | — |
| Calimero tools 3.0-M1 | — | discovery, description, connect, write, read, 12 DPT vectors: pass (also through NAT) | both directions: pass |
| knxd 0.14.73 | discovery, description, connect, confirmed write, read (answered by xknx through knxd), inbound telegrams, 12 DPT vectors: pass; over TCP: connect, confirmed write seen by xknx, inbound write, read answered by xknx: pass | connect, write, read, 12 DPT vectors: pass (also through NAT) | both directions: pass |
| xknx 4.1.1 | observer and responder in every scenario | discovery, description, connect, write, read, 12 DPT vectors: pass (also through NAT) | both directions: pass |
| KNXUltimate 6.3.2 | — | discovery, description, connect, write, read, 12 DPT vectors: pass | both directions: pass |
| cB-Sigma knx v0.2.0 | — (client only) | discovery, description, connect, write, read, 12 DPT vectors, TCP write and read, busmonitor: pass (also through NAT, `interop/`); secure session with bound address, secure write and read, Data Secure write: pass | both directions, plain and secure (with Data Secure): pass |
| cB-Sigma knx-sim v0.2.0 | gateway: write and read over UDP and TCP, repeated indication delivered once, unacknowledged request reported, secure write and read, Data Secure both ways, replayed and tampered wrappers discarded, SESSION_STATUS close ends the session, idle secure session kept past 60 s; router: ROUTING_BUSY wait honoured (answer 518 ms after a 500 ms wait), answers go on after ROUTING_LOST_MESSAGE — all pass | — (no client) | — |
| knx-interop probe | — | 24 of 24 negative checks pass | — |

ETS keyrings (knx-interop files suite, offline): go-knx reads the test
profile's keyring and the same profile written by knx-sim, with the same
interfaces, devices, backbone and Data Secure keys as cB-Sigma knx reads,
and refuses a wrong password.

The matrix, the known differences of the other stacks and the reports
filed upstream are in knx-interop's docs/INTEROPERABILITY.md.

## KNX Secure (2026-10-30)

First verified by hand, now automated (re-run 2026-11-06 with knx-interop
v0.9.0 and xknx 4.1.1: the same results): knx-interop's `secure` suite
(container contract 1.3 since v0.4.0: also secure sessions over UDP, the
servers' secure routing and Calimero tools' Data Secure through go-knx as
the surrogate; 0 failures)
and this repository's `interop/secure_test.go` (xknx, Calimero tools and
cB-Sigma knx against go-knx's secure server, go-knx's secure client against Calimero's
secure server, with the knx-interop test profile).

The table below is the record of the 2026-11-06 run, against knx-interop
v0.9.0. The current pin is knx-interop v0.9.2 (Makefile); the `secure`
suite is part of the matrix run against it on 2026-11-07
([Results](#results-2026-11-07-knx-interop-v092): 0 fail), which did not
record the secure scenarios separately.

| Scenario | xknx 4.1.1 | Calimero 3.0-M1 |
|---|---|---|
| Secure tunnelling: peer client → go-knx server (session, device authentication verified by the client, write, read) | pass | tools: pass |
| Secure tunnelling: go-knx client → peer server (session, device authentication, user bound address, write, read; wrong password and plain connection refused) | — (no server) | server: pass |
| Secure device management: go-knx → peer server (user 1, property read) | — | server: pass; other users refused with E_CONNECTION_TYPE, as go-knx does |
| Secure routing, both directions, with timer synchronisation | pass | tools: pass (Calimero synchronises with go-knx's timer) |
| Data Secure group write, go-knx → peer (keyring written by go-knx) | pass | tools: pass (decrypted) |
| Data Secure group write, peer → go-knx | pass | tools: pass through go-knx as the surrogate (S-A_Sync, group object diagnostics with go-knx's tool key, go-knx sends the secured telegram) |
| Secure sessions over UDP: peer client → go-knx server, go-knx client → peer server (also device management) | — (xknx: TCP only) | tools and server: pass |
| Secure routing of the go-knx server: in from the peer, out to the peer through a tunnel | pass | tools → server: pass (Calimero synchronises with the server's timer) |
| Keyring written by go-knx loaded by the peer | pass (signature verified) | pass |

## Remote device management and tool access (2026-10-30)

Automated in knx-interop's `management` suite (container contract 1.4,
since v0.6.0): the remote property services of a server's device, through
a tunnel; with tool access, secured with the device's tool key.

| Scenario | Calimero 3.0-M1 | xknx 4.1.1 |
|---|---|---|
| Peer tool → go-knx's device: property read, read in a transport connection, write | tools: pass | read and write in a connection: pass (no connectionless management) |
| Peer tool → go-knx's device with tool access (S-A_Sync, S-A_Data): read, read in a connection, write | tools: pass | — (no tool key access) |
| Plain access refused by go-knx's secured device | tools: pass | pass |
| go-knx tool → peer's device: property read, read in a connection, write | server: pass | — (no server) |
| go-knx tool → peer's device with tool access | — (Calimero server has no tool key access) | — |

go-knx's tool access as a tool therefore has no third-party device to run
against: it is verified against go-knx's own device only, which Calimero
tools does verify as a device.

Calimero tools needs its tunnel address (`-k`) for tool access: it computes
the MAC over the source it sends, 0.0.0 otherwise, and a device refuses the
frames once the tunnelling server has replaced that source. Calimero's
device information tool also works with tool access, up to its A/D
converter read, which the server does not answer.

Passing these shows that go-knx and those stacks agree with each other;
it does not show conformance to the KNX specification.

## Recorded traffic (2026-11-08)

Traffic of physical devices recorded by others, replayed
([testdata/captures/README.md](testdata/captures/README.md)); class B
evidence, not a live test.

| Recording | Devices | What passes |
|---|---|---|
| knx-datasets (KNX TP1 of a house, 2020) | the installation's devices, models not documented (device descriptors 0013, 0021, 0701, 07B0) | 1 150 094 TP1 frames decode and encode again byte for byte (6 414 repetitions included) and equal the dataset authors' decode in every row; `client.Device.DescriptorRead` against 145 recorded answers; `mgmt.Responder` answers the recorded device descriptor reads as the devices did and ends idle connections as 75 devices did |
| Wireshark issue 14825 (KNXnet/IP, 2018) | ABB IP-Router IPR/S, ABB IPS/S2.1 (named by their DEVICE_INFO; firmware unknown) | every frame Wireshark decodes, go-knx decodes and encodes again byte for byte, but 26 malformed negative cases of the test client; the devices' identities equal Wireshark's; discovery finds the router from its recorded extended search response; 1 008 of 1 063 connection management requests replayed on a go-knx server are answered as the router did (the rest classified) |
| Wireshark test captures | synthetic or of unknown origin | SECURE_WRAPPER, TIMER_NOTIFY and S-A_Data opened with Wireshark's published test keys as Wireshark does |

Three go-knx defects were found this way and fixed in v0.10.0 (RELEASE.md).

## Running

```bash
make interop-images   # build the Calimero and knxd images from knx-interop INTEROP_REF (Docker)
make interop          # the host-based suite; writes bin/interop-report.json
make interop-matrix   # knx-interop's matrix with go-knx's node; writes bin/interop-matrix.{json,md}
```

`KNX_INTEROP_IMAGE_<ADAPTER>` overrides an image (for example
`KNX_INTEROP_IMAGE_XKNX=ghcr.io/otfabric/knx-interop-xknx:dev`), and
`KNX_INTEROP_ADAPTERS=calimero-server,xknx` runs those peers only.

The Self-interop workflow, run by hand, runs a commit against the latest
published go-knx (`ghcr.io/otfabric/knx-interop-otfabric:latest`, from
knx-interop's `own/go-knx`), as a server and a client of the host-based
tests, plain and secure (`KNX_INTEROP_OTFABRIC_IMAGE`; without it the
`otfabric` peer never runs). It finds a change on the wire that breaks an
earlier release. A pass is not independent verification: it is go-knx on
both sides, and its results are not in the tables above.
