# Testing go-knx

| Layer | Where | Run with |
|---|---|---|
| Unit tests (codecs, state machines, server, client, devices) | `*_test.go` in every package | `make test` |
| Recorded traffic | `testdata/captures` (README there): a KNX TP1 installation (knx-datasets, 1 150 094 frames), the live KNXnet/IP sessions of an ABB IP-Router IPR/S and IPS/S2.1 (Wireshark issue 14825, 46 059 frames with Wireshark's test captures), Wireshark's KNX test captures; decoded and encoded again byte for byte, compared with Wireshark 4.6.9 and the dataset authors' decode; replayed through `mgmt.Responder`, `client.Device`, discovery and the server; read by `internal/capture` | `make test`; `make captures-verify` (SHA256SUMS); `make captures-extended` (every TP1 frame against the CSV exports, fetched); `make captures-generate` (manifest, needs tshark) |
| Golden frames | `knxnetip/testdata/frames.json` (45 frames built from the frame structures, not copied from a specification or capture) | `make test` |
| DPT reference vectors | `dpt/testdata/xknx_vectors.json` (computed with xknx 4.0.0; known differences in `dpt/xknx_test.go`) | `make test` |
| Fuzz tests | `FuzzXxx` in knxnetip, cemi, apdu, dpt and the root package (codecs); secure (session and wrapper frames), datasecure (S-A_Data, sync, tool access), keyring (parse), mgmt (responder, property description), server (UDP datagrams and TCP stream) and tunnel (client receive path) | `make fuzz FUZZTIME=30s` |
| End-to-end over loopback sockets | `e2e/` | `make e2e` |
| Hostile peers | `e2e/hostile_test.go`: noise, CONNECT floods, sequence replay, spoofed channel frames, stalled and lying TCP peers, forged and replayed secure frames, a garbage-answering server for the client, discovery against garbage | `make e2e` |
| Deterministic chaos | `e2e/chaos_test.go`: a seeded UDP proxy that drops, duplicates, reorders and delays datagrams; writes are delivered at most once, and the client reconnects after a black hole | `make e2e` |
| Multicast (discovery, routing) | tests gated on a working multicast loopback; `KNX_REQUIRE_MULTICAST=1` turns the skip into a failure (Linux CI) | `make test-multicast` |
| Interoperability | `interop/` (build tag `interop`); knx-interop's matrix with `interop/node` | `make interop`, `make interop-matrix` |
| Benchmarks | `bench_test.go` files, server benchmarks | `make bench` |

## Coverage

`make coverage-check` measures every library package with `-coverpkg`
(excluding examples, e2e, interop and the test helpers internal/fakeknx,
internal/leak and internal/capture) and fails below 90 %. The codec packages are expected to
stay at or above 90 %. At the time of writing: total 97.7 %; root,
knxnetip, cemi, apdu 100 %; dpt 99 %; tunnel 96 %; server 96 %; client
99 %; device 99 %; discovery 92 %; routing 97 %.

`make coverage-pkg-check` adds a floor of 85 % per package (`COVER_PKG_MIN`),
from the same profile; the Linux CI job runs it. `internal/mcast` is the
package closest to it: what is left there are failures of socket options that
loopback cannot provoke.

## Extended tier

`.github/workflows/extended.yml` runs every night: every fuzz target for five
minutes, `make captures-extended` (every recorded TP1 frame against the
dataset authors' CSV exports, downloaded and checked against their SHA256)
and the whole suite five times with the race detector and
`KNX_REQUIRE_MULTICAST=1`. A crasher is uploaded as an artifact; commit it to
`<package>/testdata/fuzz/<Target>/` with the fix. `interop.yml` runs weekly.

## Helpers

- `internal/fakeknx`: a scriptable fake KNXnet/IP peer over a loopback UDP
  socket, used to drive the client through failure paths (lost ACKs,
  refused connections, server-initiated disconnects).
- `internal/capture`: reads the recorded traffic of `testdata/captures`
  (pcap, pcapng, gzip, K12 text; TP1 frames and KNXnet/IP over UDP and
  reassembled TCP), counts what go-knx decodes and holds the manifest and
  the oracle comparisons.
- `internal/leak`: checks that no goroutine outlives the code under test by
  comparing goroutine stacks, so a failure names the goroutine. `leak.Check`
  covers one test; `leak.VerifyNoLeaks` in `TestMain` covers every test of
  the packages that start goroutines (client, discovery, routing, server,
  tunnel) and of the e2e suite.

## Benchmarks (Apple M1, loopback, Go 1.27)

| Benchmark | Result |
|---|---|
| Client GroupWrite round trip (ACK + L_Data.con) | about 15 000 per second |
| Server, 8 tunnelling clients writing concurrently, each telegram acknowledged, confirmed and delivered to 7 clients | about 6 700 telegrams per second |

These are measurements, not guarantees: a real TP line carries about 50
telegrams per second.
