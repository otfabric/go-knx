# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `go-knx`, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Email **security@otfabric.io**, or open a private advisory on GitHub (the [Security](https://github.com/otfabric/go-knx/security) tab → **Advisories** → **Report a vulnerability**), with a description, steps to reproduce (ideally a minimal program or the datagrams), the affected version(s) and the impact you see.

We will acknowledge your report within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Older releases | No |

## Threat model

KNX controls lighting, blinds, heating, ventilation, access and alarms.
A KNXnet/IP network is part of a building's control system.

| Asset | Threat | What go-knx does | What it cannot do |
|---|---|---|---|
| The building's devices | Unauthorised telegrams (switch off heating, open blinds, trigger scenes) | Sends only what the application asks; never scans, probes or retransmits on its own beyond the protocol's one repetition | Prevent telegrams from others: plain KNXnet/IP has no authentication |
| Confidentiality of states | Eavesdropping on group values (presence, alarms) | — | Plain KNXnet/IP is not encrypted |
| The host running go-knx | Malformed or hostile datagrams | Strict decoding (no panics, fuzzed), bounded frame size (1024 octets), bounded queues, bounded connections, deadlines on every wait, rate-limited routing | — |
| A go-knx server | Resource exhaustion by many clients | Connection limit (one per tunnelling address), per-connection bounded queue, heartbeat timeout (120 s), refusal with the standard status codes; on a secure server, sessions and TCP connections that do not authenticate within 10 s end, and a new one replaces the oldest that has not authenticated when all are taken | Rate limiting per source address (not implemented) |
| The KNX IP network | Telegram storms or loops through routing | Routing indications are rate limited (50/s by default); telegrams with hop count 0 are not routed; the server never re-routes indications received from multicast; routing.Conn never forwards | Loops created by other routers |

## KNXnet/IP security limitations

- **KNXnet/IP (tunnelling, routing, discovery) has no security of its own.**
  Any host that can reach UDP port 3671 or the multicast group 224.0.23.12
  can read and send telegrams.
- A tunnelling connection is identified by a channel number and the
  client's control and data endpoints (address and port): the server
  ignores frames of the channel from any other endpoint, including other
  sockets on the client's host. A host on the same network that forges
  the source address and port can still spoof datagrams of a connected
  client.
- NAT mode (route back endpoints) makes the server answer to the source
  address of each datagram, which is spoofable.

## KNX IP Secure and KNX Data Secure

Implemented from public sources (xknx's MIT implementation and the KNX
keyring article; the KNX application notes 158/159 were not available) and
verified for interoperability with xknx 4.1.1, Calimero 3.0-M1 and cB-Sigma
knx v0.2.0 (and its simulator knx-sim's secure-session faults) — **not**
verified for conformance, and not certified
([SPECIFICATIONS](docs/standards/SPECIFICATIONS.md#knx-secure-sources)).

| Feature | Covered | Not covered |
|---|---|---|
| Secure tunnelling (`tunnel.WithSecure`, `server.WithSecure`) | X25519 session over TCP or UDP (`tunnel.WithUDP`), user authentication, device authentication (client verifies when given the code), SECURE_WRAPPER with replay protection, keep alive, close; server binds users to tunnelling addresses, device management for user 1 only, ends sessions that do not authenticate within `server.WithSecureAuthTimeout` (10 s; frames before authentication do not extend a session, and when all sessions or TCP connections are taken a new one replaces the oldest that has not authenticated), drops a tunnel's telegrams whose source is not its own address (negative L_Data.con), ends sessions idle for the session timeout (60 s, `server.WithSecureSessionTimeout`; the client sends a keep alive after 30 s idle, `tunnel.WithSessionKeepAlive`) | secure device management by remote tools beyond property access |
| Secure routing (`routing.WithSecure`, `server.WithSecureRouting`) | backbone key, timer synchronisation as keeper or follower (answers are collected for the whole synchronisation window and the newest is used; no frame is accepted before the window has passed, and a context that ends inside it leaves the timer unsynchronised), latency tolerance, each frame accepted once within it (at most 4096 remembered; more are dropped until older ones expire); plain routing frames dropped | a timer value kept across restarts: a router that hears no time keeper starts its own timer (see below) |
| Data Secure (`datasecure`, `client.WithDataSecure`) | S-A_Data with authentication and confidentiality (or authentication only) for group communication, per sender sequence numbers; S-A_Sync request and response; answering S-A_Sync and group object diagnostics with the device's tool key (the surrogate a tool such as Calimero uses to send secured group telegrams) | asking group peers by S-A_Sync automatically |
| Data Secure tool access (`client.Device`, `client.WithToolKey`, `server.WithToolKey`, `mgmt.Responder`) | remote device management secured with the device's tool key: S-A_Sync, then S-A_Data with tool access, connectionless and in transport connections, as tool and as device; a secured device ignores plain management | device-to-device link keys (P2P key table), secure commissioning with the factory key (FDSK), setting the security mode by function property |
| Keyrings (`keyring`) | signature check, decryption, lookups, writing test keyrings; input bounded (4 MiB, nesting depth 64, 262144 elements) before the signature is checked | — |

Behaviour that matters for security:

- A client configured for security never falls back to a plain
  connection: a failed handshake is an error (`knx.ErrSecurity`).
- A secure server refuses plain connection requests (E_CONNECTION_TYPE);
  search and description stay plain, as the standard requires.
- Frames that fail authentication, replay an old sequence number or carry
  an outdated routing timer are dropped and counted
  (`Metrics.OnDecodeError` / `OnDropped`), never delivered. A secure
  session refuses frames carrying its own serial number; the two ends of
  a session must use different KNX serial numbers.
- The timer synchronisation of secure routing always takes its whole
  window (about 3.3 s at the default latency), and routing frames are
  accepted only after it. `routing.Listen` whose context ends inside the
  window returns the context's error and no `Conn`; a server runs the
  synchronisation until the window has passed or `Close`, whatever becomes
  of the context `Start` was called with.
- A secure router that hears no time keeper during its synchronisation
  window becomes time keeper with its own timer, which counts from 0 when
  the process starts. Until the timer of another router or of an accepted
  frame raises it, it accepts every authentic routing frame whose timer
  value is above its own, whenever that frame was sealed. What a router
  refuses as outdated therefore depends on a synchronisation with a time
  keeper that runs: start a router while the other routers of its backbone
  are up.
- A Data Secure table remembers the last sequence number of each sender
  only while it runs. Persist `Table.Senders()` and
  `Table.ToolSequences()` together with `Table.Sequence()`, and restore
  them (`datasecure.NewTable`, `Table.SetToolSequence`), or a recorded
  telegram is accepted again after a restart.
- A client with Data Secure drops plain telegrams to secured groups.
- The secure session's frames are sealed with AES-128-CCM; the key
  agreement is X25519 (`crypto/ecdh`); comparisons of MACs are constant
  time.
- As a surrogate, a client sends a group telegram for a tool only after
  the tool authenticated with the client's own tool key (S-A_Sync, then a
  tool access S-A_Data). The tool key is the tool's credential: any
  sender that has it may synchronise, and its tool access sequence
  numbers are tracked apart from the group senders'. An S-A_Sync_Req lets its own sequence number be used once only when that number is above the last tool access frame of the sender. The layout of the group object diagnostics request comes
  from observing Calimero, not from the specification.
- A device with a tool key (`server.WithToolKey`) answers no plain
  management request; with a tool key, `client.Device` never falls back
  to plain access, and answers that fail authentication or replay an old
  sequence number are dropped.
- Without a tool key, remote management of a secure server's own
  individual address (property read and write over L_Data) stays plain
  for every tunnelling user: `server.WithSecure` protects the KNXnet/IP
  connections, `server.WithToolKey` the device.
- The tunnelling client bounds every TCP write by the request timeout and
  drops stray datagrams during the KNX IP Secure handshake over UDP. The
  handshake ends with the connect timeout or with the context of `Dial`,
  whichever is first.
- A client with Data Secure sends its answers to individually addressed
  requests (S-A_Sync_Res, the answer to a tool request) from one goroutine,
  through a queue of 16 (`client.WithMaxPendingAnswers`): an answer that
  finds the queue full is dropped and logged at debug level, and each send
  gets 5 s.
- A `Send` of `routing.Conn` or `tunnel.Conn` (and a tunnelling feature
  call) that waits for its turn behind another returns when its context
  ends or the connection closes.
- A Data Secure table starts its sending sequence number at the
  milliseconds since 2018-01-05 when none is given; persist
  `Table.Sequence()` if the clock may go backwards.

## Recommendations

- Put KNX IP traffic on its own VLAN or physical network; never expose UDP
  3671 to the internet. Reach installations remotely through a VPN.
- Allow only the hosts that need it to reach KNXnet/IP interfaces (host
  firewall, switch ACLs); block multicast 224.0.23.12 from other segments.
- Prefer discovery and passive monitoring for diagnostics; send telegrams
  only to installations you are responsible for.
- Where devices support it, use KNX IP Secure and Data Secure.
- Run go-knx servers with the fewest tunnelling addresses you need.

## Credential handling

Keys and passwords are never logged and never appear in error messages
(errors name users and addresses only). The key types (`secure.Key`,
`datasecure.Key`, `keyring.Key`), `secure.Credentials` and the keyring's
`Backbone`, `Interface` and `Device` print as `(redacted)` with `%v`,
`%s`, `%x`, `%q` and `%#v`, and log so with `log/slog`; `%d` and
`encoding/json` still give the octets of a key. The library takes derived keys
(`secure.Key`) or passwords and derives them once (PBKDF2-HMAC-SHA256,
65536 iterations); it keeps them in memory for the life of the connection.
knxctl reads secrets from environment variables or the keyring by default
(`KNXCTL_KEYRING_PASSWORD`, `KNXCTL_USER_PASSWORD`, ...); command-line
flags exist for tests and should be avoided on shared hosts.

## Resource limits

What a peer can make go-knx hold or do is bounded. The limits, where they
are enforced and the test of each:

| Limit | Value | Set by | Enforced | Test |
|---|---|---|---|---|
| KNXnet/IP frame | 1024 octets (`knxnetip.MaxFrameLen`) | — | `knxnetip.Parse`, `Marshal`; `ReadFrame` refuses a longer total length after the header, before it reads or allocates the body | knxnetip `TestReadFrameAllocationBudget`, `TestParseAllocationBudget`, `TestReadFrame`, `TestAppendTooLong` |
| Description blocks of a frame | what a frame holds (509 of two octets) | — | `knxnetip.ParseDIBs`: allocation per block of the input, none by a declared length | knxnetip `TestParseDIBsAllocationBudget` |
| Keyring document | 4 MiB, 64 levels, 262144 elements | — | `keyring.Parse`, `Load`, `LoadFile`, before the signature is checked | keyring `TestParseAllocationBudgetAtLimits`, `TestLimits`, `TestMalformed` |
| Inbound queue of a tunnel | 256 frames | `tunnel.WithQueueSize` | newer frames are acknowledged and dropped (`queue_full`) | tunnel `TestQueueFull` |
| Inbound queue of a routing `Conn` | 256 frames | `routing.WithQueueSize` | newer frames are dropped (`queue_full`) | routing `TestReceiveErrorsAndQueue` |
| Routing events | 16 | — | an event that does not fit is dropped | routing `TestLostMessageAndEventOverflow` |
| Own indications remembered to recognise their echo | 1024, for 2 s | — | `routing.Conn` with `WithLoopback` | routing `TestEchoSuppression` |
| Routing indications sent | 50 per second, no bursts | `routing.WithRate`, `server.WithRoutingRate` | `Send` waits its turn; the server queues | routing `TestRateLimit`, server `TestRoutingOutbound` |
| Secure routing frames remembered | 4096 within the latency tolerance | — | `secure.RoutingTimer.Accept` refuses further ones until older ones expire | secure `TestRoutingTimerAcceptBounded` |
| Tunnelling connections of a server | one per tunnelling address, 255 channels | `server.WithTunnelAddresses` | E_NO_MORE_CONNECTIONS | server `TestConnectRefusals`, `TestChannelsExhausted` |
| Device management connections of a server | 4 | — | E_NO_MORE_CONNECTIONS | server `TestDeviceManagementLimit` |
| TCP connections and UDP secure sessions of a server | tunnelling addresses + 4, each | — | a further connection is closed; on a secure server it replaces the oldest that has not authenticated | server `TestTCPLimitPlain`, `TestSecureTCPUnauthenticated`, `TestSecureSessionUDPSpoofedRequests` |
| Time to authenticate a secure session | 10 s | `server.WithSecureAuthTimeout` | the session or TCP connection ends | server `TestSecureSessionUDPUnauthenticatedKeepAlive`, `TestSecureTCPUnauthenticated` |
| Send queue of a server's connection, routing send queue | 128 frames | `server.WithQueueSize` | a frame that does not fit is dropped (`queue_full`, `routing_rate`) | server `TestQueueFull`, `TestRoutingOutbound` |
| Telegrams of a subscription | the buffer given to `Subscribe` | the caller | dropped and counted (`Subscription.Dropped`) | client `TestSubscribe` |
| Responses of `GroupReadAll` | 1000 | `client.WithMaxResponses` | it returns when it has them | client `TestGroupReadAllMaxResponses` |
| Answers of a client with Data Secure waiting for the link | 16 (`client.DefaultMaxPendingAnswers`), sent by one goroutine, 5 s each | `client.WithMaxPendingAnswers`, 1 to 65536 | an answer that does not fit is dropped (debug log) | client `TestAnswersBounded`, `TestAnswersBoundedByOption`, `TestAnswersEndWithClose` |
| Pause of the routing sender after a ROUTING_BUSY | the frame's wait time (up to 65.535 s) plus 0 … N × 50 ms | `routing.WithMaxBusyPause`, `server.WithRoutingMaxBusyPause` (a ceiling; none by default) | `internal/flowctl`, for `routing.Conn` and the server's routing sender | internal/flowctl `TestMaxPause`, routing `TestMaxBusyPause`, server `TestRoutingMaxBusyPause` |
| Property data of `Device.PropertyWrite` | 250 octets | — | refused before sending | client `TestPropertyWriteTooLong` |
| Servers of `discovery.Search` | 256 | `discovery.WithMaxResults` | it returns when it has them | discovery `TestSearchMaxResults` |
| Pause after an accept or read error of a socket | 5 ms, doubling to 1 s while errors follow each other | — | the server's accept and read loops, `routing.Conn`, the tunnelling client and discovery | server `TestAcceptLoopPausesAfterErrors`, `TestReadLoopPausesAfterErrors`, routing `TestReadLoopPausesAfterErrors`, internal/udp `TestReadPausesAfterDatagramErrors` |
| Wait between reconnection attempts of a tunnel | a random time in the upper half of a backoff from 1 s to 30 s | `tunnel.WithReconnect` | the supervisor of a `tunnel.Conn` | tunnel `TestReconnectWaitsAreJittered`, internal/backoff `TestJitter` |

Two more queues are bounded and drop without a counter: the frames of a
managed device waiting for a `client.Device` (32) and the responses
waiting for a pending group read (16). The rate of datagrams per source
address is not limited.

## Known limitations

- Routing write deadlines are 1 s: a blocked multicast send drops the
  telegram rather than stalling the server.
- The server takes the frames of a tunnelling connection over UDP from the
  client's control or data endpoint only, address and port. A host that
  forges both can still send datagrams in the client's name, as said above.
