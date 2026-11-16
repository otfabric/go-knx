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
| Lifecycle contracts | `lifecycle_test.go` in tunnel, routing, client and server ([matrix](#lifecycle-contract-matrix)) | `make test` |
| Allocation budgets | `knxnetip/budget_test.go`, `keyring/budget_test.go` ([below](#allocation-budgets)) | `make test` |

## Coverage

`make coverage-check` measures every library package with `-coverpkg`
(excluding examples, e2e, interop and the test helpers internal/fakeknx,
internal/leak and internal/capture) and fails below 90 %. The codec packages are expected to
stay at or above 90 %. At v0.11.1 (2026-11-15, macOS with multicast): total
96.3 %; root, knxnetip, cemi, apdu 100 %; dpt 99 %; device 99 %; tunnel
96 %; server 94 %; client 93 %; discovery 93 %; routing 92 %.

`make coverage-pkg-check` adds a floor of 85 % per package (`COVER_PKG_MIN`),
from the same profile; the Linux CI job runs it. `internal/mcast` is the
package closest to it: what is left there are failures of socket options that
loopback cannot provoke.

## Extended tier

`.github/workflows/extended.yml` runs every night: every fuzz target for five
minutes, `make captures-extended` (every recorded TP1 frame against the
dataset authors' CSV exports, downloaded and checked against their SHA256),
the whole suite on a 32-bit architecture (`GOARCH=386 go test -count=1 ./...`,
without the race detector, which 386 does not have) and the whole suite five
times with the race detector and `KNX_REQUIRE_MULTICAST=1`. A failing fuzz
input is uploaded as an artifact; commit it to
`<package>/testdata/fuzz/<Target>/` with the fix. `interop.yml` runs weekly.

## Lifecycle contract matrix

The contract tests of otfabric/engineering `standards/lifecycle.md`, for the
types that hold a socket or a goroutine: `tunnel.Conn` (T), `routing.Conn`
(R), `client.Client` (C), `client.Device` (D) and `server.Server` (S).
`devmgmt.Conn` is a thin wrapper of T. The tests are in the package of the
type unless a package is named.

| Row | Scenario | Tests | Not applicable, or not covered |
|---|---|---|---|
| L1 | Close twice | T `TestCloseSendsDisconnect`; R `TestClose`; C `TestClose`; D `TestDeviceCloseConcurrently`; S `TestLifecycle` (never started), `TestCloseConcurrently` (started) | — |
| L2 | Two goroutines call Close | T, R, C, S `TestCloseConcurrently`; D `TestDeviceCloseConcurrently` | S: a second concurrent `Close` returns at once, before the first has finished (LIMITATIONS.md); the test waits for all of them |
| L3 | Close during a blocked read | T `TestCloseConcurrently`, `TestCloseDuringSend`, `TestReceiveDrainsAfterClose`; R `TestCloseConcurrently`, `TestClose`; C `TestCloseConcurrently`, `TestReadEndsWithClient`; D `TestDeviceRequestEndsWithClose` | S: n/a, no blocking read |
| L4 | Close during a write | T `TestSendTurnEndsWithContextAndClose`, `TestCloseDuringSend`, `TestTCPWriteBounded`, `TestSecureCloseServerNotReading`; R `TestSendTurnEndsWithContextAndClose`, `TestRoutingBusy`; S `TestCloseDisconnectsClients`, `TestRoutingBusyPausesServer` | C, D: n/a, they write through the link |
| L5 | Close during the handshake | T: `Dial` gives no handle before it is connected, its context ends it: `TestDialContextCanceled`, `TestSecureDialContextEnds`; R: `TestSecureListenContextEnds`; S `TestLifecycle` (Start after Close), `TestStartCloseRaceSecureRouting` | C, D: n/a, no handshake |
| L6 | Cancel a pending request | T `TestSendContextEndsBeforeAck`, `TestContextCancel`; R `TestSendTurnPassedOn`; C `TestGroupReadCancelLeavesNothing`; D `TestDeviceRequestAfterCancel`, `TestDeviceCancelIsNotTimeout` | S: n/a, no requests of its own |
| L7 | Response after the request ended | T `TestLateAndDuplicateAcks`, `TestSendConfirmMissing`, `TestSendContextEndsBeforeAck`; C `TestGroupReadCancelLeavesNothing`; D `TestDeviceRequestAfterCancel` | devmgmt: not covered: a confirmation that arrives after its request timed out is taken by the next read of the same property (cEMI carries no correlation; LIMITATIONS.md) |
| L8 | Response after a reconnection | T `TestAckOfEarlierConnection`, `TestUnacknowledgedRequestOfEarlierConnection`, `TestReconnect`; e2e `TestReconnectAfterServerRestart`, `TestHostileReconnectSameEndpoint`, `TestChaosBlackhole` | R, C, D, S: n/a, no reconnection. T: an acknowledgement of the earlier connection that arrives after the first request of the new one was written, with the same channel and sequence number, cannot be told apart on the wire |
| L9 | A callback calls a public method | C `TestCallbackCallsClient`; S `TestTapCallsServer` | T: n/a, `WithStateHandler` forbids calling the Conn. R, D: n/a, no callbacks |
| L10 | A callback calls Close | C `TestCallbackClosesClient`; S `TestTapClosesServer` (from another goroutine: `Close` returns after the callback) | a callback that calls `Close` itself waits for its own goroutine (API.md, "Callbacks") |
| L11 | Slow callback | C `TestSubscribe` (a full subscription drops and counts); S `TestClientNotAcking`, `TestConcurrentClients` (one sender per connection) | callbacks run on the reader and must not block: no isolation is promised |
| L12 | Queue at capacity | T `TestQueueFull`; R `TestReceiveErrorsAndQueue`, `TestLostMessageAndEventOverflow`; C `TestSubscribe`, `TestGroupReadAllMaxResponses`, `TestAnswersBounded`, `TestAnswersBoundedByOption`; S `TestQueueFull`, `TestChannelsExhausted`, `TestDeviceManagementLimit`, `TestTCPLimitPlain`; discovery `TestSearchMaxResults` | the 16 responses of a pending read and the 32 frames of a `Device` drop without a counter |
| L13 | Concurrent sessions | S `TestConcurrentClients`, `TestSecureTunnelSourceBound`, `TestSecureSessionUDPSpoofedRequests`; e2e `TestHostileSpoofedChannelFrames`, `TestHostileSequence` | T, R, C, D: n/a, one session |
| L14 | Failure during construction | T `TestDialFailureReleasesSocket`, `TestSecureDialContextEnds`, `TestDialErrors`, `TestDialRefused`, `TestDialTimeout`, `TestHandshakeErrors`; R `TestSecureListenContextEnds`, `TestListenErrors`; S `TestStartFailureReleasesSockets`, `TestOptionsAndStartErrors`, `TestStartAddressNotAvailable` | C, D: n/a, `New` and `Device` open nothing |
| L15 | Shutdown(ctx) | — | n/a: no type has a graceful shutdown; `Server.Serve(ctx)` closes when its context ends (`TestLifecycle`) |
| L16 | Close racing a reconnection | T `TestCloseWhileReconnecting`, `TestCloseReleasesChannelOfReconnection` | a CONNECT_RESPONSE more than 1 s after `Close` began finds the socket closed: the server keeps that channel until its heartbeat timeout |

The tests of construction failures and of `Close` count the open file
descriptors of the process before and after, next to the goroutine check of
`internal/leak`.

## Determinism

The lifecycle tests and the tests of timers wait for events, not for time
to pass: a frame the fake peer received, a metrics callback, a value on a
channel, a context that reports when a call starts to wait on it. A bound
of 2 s only ends a wait that would otherwise hang, and its failure message
names what did not happen. Where time itself is the subject and no socket
is involved, the clock is that of `testing/synctest`: the routing timer of
package `secure`, the pauses of `internal/backoff`, and the accept and read
loops of the server, of `routing.Conn` and of `internal/udp`, which take an
injected accept or read function.

Still waiting real time: tests of the rate and of ROUTING_BUSY pauses with
real sockets (lower bounds on elapsed time), the authentication and session
timeouts of the server (`server/limits_test.go`), `mgmt.Responder`, which
reads the wall clock, the chaos suite, and the polling helper `eventually`
of the older tests.

## Allocation budgets

A fuzz run does not show that a decoder allocates within bounds, so tests
measure it (`runtime.MemStats.TotalAlloc` per call): `knxnetip.ReadFrame`
with a total length of 1025, 32767, 32768 and 65535 octets (refused after
the header, within 1 KiB), `knxnetip.Parse` of the longest frame,
`knxnetip.ParseDIBs` of as many blocks as a frame holds, and
`keyring.Parse` one step over each of its limits (size, depth, elements)
and far over them. The limits and their tests are listed in
[SECURITY.md](SECURITY.md#resource-limits).

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
- `internal/backoff` and `internal/guard` are library packages with their
  own tests: the pauses of retrying loops and the reconnect jitter, and the
  call of application callbacks.

## Benchmarks (Apple M1, loopback, Go 1.27.4, 2026-11-15)

| Benchmark | Result |
|---|---|
| `BenchmarkGroupWrite` (client): GroupWrite round trip (ACK + L_Data.con) | about 16 000 per second |
| `BenchmarkConcurrentClients` (server): 8 tunnelling clients writing concurrently, each telegram acknowledged, confirmed and delivered to 7 clients | about 7 000 telegrams per second |

Measured with
`go test -run '^$' -bench 'GroupWrite|ConcurrentClients' -benchtime=2s ./client ./server`
(16 400 to 16 700 writes per second and 7 000 to 7 500 telegrams per second
in three runs). These are measurements, not guarantees: a real TP line
carries about 50 telegrams per second.

## When CI runs

| Event | Workflow | What runs |
|---|---|---|
| Pull request | `pr.yml` | `docs.yml` (docsync, otfabric-policy) always; `ci.yml`, `interop.yml` unless every changed file is documentation; then `OT Fabric Required Checks` |
| Push to a branch | none | nothing; dispatch `ci.yml`, `interop.yml` to test a branch without a pull request |
| Push to `main` | `docs.yml` | the light checks; the merged commit was tested as the pull request's merge commit |
| Schedule | `extended.yml`, `interop.yml` | the scheduled runs, on `main` |
| Release | `release.yml` | the release workflow tests the release commit again |

Documentation means an added or modified `*.md` file outside `.github/`, `testdata/` and `vendor/`, other than `AGENTS.md` and `CLAUDE.md`. A deleted or renamed document, or any other file, runs everything. `OT Fabric Required Checks` fails unless every job that applies succeeded; its summary lists them.
