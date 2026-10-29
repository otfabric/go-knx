# Testing go-knx

| Layer | Where | Run with |
|---|---|---|
| Unit tests (codecs, state machines, server, client, devices) | `*_test.go` in every package | `make test` |
| Golden frames | `knxnetip/testdata/frames.json` (45 frames built from the frame structures, not copied from a specification or capture) | `make test` |
| DPT reference vectors | `dpt/testdata/xknx_vectors.json` (computed with xknx 4.0.0; known differences in `dpt/xknx_test.go`) | `make test` |
| Fuzz tests | `FuzzXxx` in knxnetip, cemi, apdu, dpt and the root package | `make fuzz FUZZTIME=30s` |
| End-to-end over loopback sockets | `e2e/` | `make e2e` |
| Multicast (discovery, routing) | tests gated on a working multicast loopback; `KNX_REQUIRE_MULTICAST=1` turns the skip into a failure (Linux CI) | `make test-multicast` |
| Interoperability | `interop/` (build tag `interop`), knx-interop matrix | `make interop` |
| Benchmarks | `bench_test.go` files, server benchmarks | `make bench` |

## Coverage

`make coverage-check` measures every library package with `-coverpkg`
(excluding examples, e2e, interop and the test helpers internal/fakeknx and
internal/leak) and fails below 85 %. The codec packages are expected to
stay at or above 90 %. At the time of writing: total 97.7 %; root,
knxnetip, cemi, apdu 100 %; dpt 99 %; tunnel 96 %; server 96 %; client
99 %; device 99 %; discovery 92 %; routing 97 %.

## Helpers

- `internal/fakeknx`: a scriptable fake KNXnet/IP peer over a loopback UDP
  socket, used to drive the client through failure paths (lost ACKs,
  refused connections, server-initiated disconnects).
- `internal/leak`: checks that a test leaves no goroutines behind.

## Benchmarks (Apple M1, loopback, Go 1.27)

| Benchmark | Result |
|---|---|
| Client GroupWrite round trip (ACK + L_Data.con) | about 15 000 per second |
| Server, 8 tunnelling clients writing concurrently, each telegram acknowledged, confirmed and delivered to 7 clients | about 6 700 telegrams per second |

These are measurements, not guarantees: a real TP line carries about 50
telegrams per second.
