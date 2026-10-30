# Interoperability

go-knx is tested against independent KNX implementations in two places:

1. **The knx-interop matrix** ([otfabric/knx-interop](https://github.com/otfabric/knx-interop),
   docs/INTEROPERABILITY.md): every client against every server and every
   routing peer against every other, inside one Docker network, including
   multicast discovery and routing, 12 DPT vectors and a negative suite.
   go-knx takes part through knxctl.
2. **This repository's `interop/` suite** (`make interop-images interop`):
   go-knx used as a library from the host, against the knx-interop images,
   through published UDP ports with route back (NAT) endpoints.

## Results (2026-10-29)

| Peer (version) | go-knx as client | go-knx as server | Routing with go-knx |
|---|---|---|---|
| Calimero server 3.0-M1 | discovery, description, connect, confirmed write, read, inbound telegrams, 12 DPT vectors: pass | — | — |
| Calimero tools 3.0-M1 | — | discovery, description, connect, write, read, 12 DPT vectors: pass (also through NAT) | both directions: pass |
| knxd 0.14.73 | discovery, description, connect, confirmed write, read (answered by xknx through knxd), inbound telegrams, 12 DPT vectors: pass | connect, write, read, 12 DPT vectors: pass (also through NAT) | both directions: pass |
| xknx 4.0.0 | observer and responder in every scenario | discovery, description, connect, write, read, 12 DPT vectors: pass (also through NAT) | both directions: pass |
| KNXUltimate 6.3.1 | — | discovery, connect, write, read, 12 DPT vectors: pass; description: known difference of KNXUltimate | both directions: pass |
| knx-interop probe | — | 23 of 23 negative checks pass | — |

The matrix, the known differences of the other stacks and the reports
filed upstream are in knx-interop's docs/INTEROPERABILITY.md.

## KNX Secure (2026-10-30)

First verified by hand, now automated: knx-interop's `secure` suite
(container contract 1.2, all secure scenarios of the matrix, 0 failures)
and this repository's `interop/secure_test.go` (xknx and Calimero tools
against go-knx's secure server, go-knx's secure client against Calimero's
secure server, with the knx-interop test profile).

| Scenario | xknx 4.0.0 | Calimero 3.0-M1 |
|---|---|---|
| Secure tunnelling: peer client → go-knx server (session, device authentication verified by the client, write, read) | pass | tools: pass |
| Secure tunnelling: go-knx client → peer server (session, device authentication, user bound address, write, read; wrong password and plain connection refused) | — (no server) | server: pass |
| Secure device management: go-knx → peer server (user 1, property read) | — | server: pass; other users refused with E_CONNECTION_TYPE, as go-knx does |
| Secure routing, both directions, with timer synchronisation | pass | tools: pass (Calimero synchronises with go-knx's timer) |
| Data Secure group write, go-knx → peer (keyring written by go-knx) | pass | tools: pass (decrypted) |
| Data Secure group write, peer → go-knx | pass | **not working**: Calimero tools refuse to send without a "surrogate" with go-knx's keyring and, with an ETS keyring, first ask a device for its sequence number (S-A_Sync), which go-knx does not answer |
| Keyring written by go-knx loaded by the peer | pass (signature verified) | pass |

Passing these shows that go-knx and those stacks agree with each other;
it does not show conformance to the KNX specification.

## Running

```bash
make interop-images   # build the Calimero and knxd images from knx-interop v0.3.0 (Docker)
make interop                                    # writes bin/interop-report.json
```

`KNX_INTEROP_IMAGE_<ADAPTER>` overrides an image (for example
`KNX_INTEROP_IMAGE_XKNX=ghcr.io/otfabric/knx-interop-xknx:dev`).
