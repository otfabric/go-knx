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

Not covered yet: KNXnet/IP over TCP, tunnelling v2 feature services,
busmonitor, device management, KNX IP Secure, KNX Data Secure (not
implemented in go-knx). The matrix, the known differences of the other
stacks and the reports filed upstream are in knx-interop's
docs/INTEROPERABILITY.md.

## Running

```bash
make interop-images INTEROP_REF=feat/adapters   # build the adapter images (Docker)
make interop                                    # writes bin/interop-report.json
```

`KNX_INTEROP_IMAGE_<ADAPTER>` overrides an image (for example
`KNX_INTEROP_IMAGE_XKNX=ghcr.io/otfabric/knx-interop-xknx:dev`).
