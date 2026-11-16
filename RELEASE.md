# go-knx Releases

Releases are made with the Release workflow (Actions → Release → bump):
it computes the version, tags it and publishes this file's section of
that version as the release notes. Add the section, headed exactly
`## vX.Y.Z` and closed by a line `---`, before running it.

## v0.14.0

**Date:** 2026-11-16
**Previous release:** v0.13.0

## Summary

Deadlines and redaction, the remaining calls. A deadline in `tunnel.Conn.Receive`, `routing.Conn.Receive`, `discovery.Search` and `discovery.Describe` gives an error matching `knx.ErrTimeout` and `context.DeadlineExceeded`, as in the other calls of `tunnel`, `routing`, `client` and `devmgmt`. A `*secure.RoutingTimer` prints a summary without its key.

## Changes

### Breaking

- An expired deadline of `tunnel.Conn.Receive`, `routing.Conn.Receive`, `discovery.Search` and `discovery.Describe` gives an error matching `knx.ErrTimeout` and `context.DeadlineExceeded` (it was the context's error itself, `context.DeadlineExceeded`, which did not match `knx.ErrTimeout`). The message is `knx: timeout: tunnel: context deadline exceeded`, with `routing` and `discovery` likewise. A cancelled context still gives `context.Canceled` only, and `tunnel.Conn.Receive` still returns a frame already queued whatever the state of the context. The errors of `devmgmt.Conn.PropRead` and `PropWrite` at a deadline, which read the tunnel with `Receive`, are unchanged, their message too. Who notices: code that compares the error with `==` (`err == context.DeadlineExceeded`), that tells a deadline from a timeout of the library by `knx.ErrTimeout` (a `Describe` that got no answer within its own timeout matches `knx.ErrTimeout` alone), or that reads the message. Restore path: `errors.Is(err, context.DeadlineExceeded)` tells the deadline, tested before `knx.ErrTimeout`; `errors.Is(err, context.Canceled)` a cancellation.

### Added

- `String` and `Format` on `*secure.RoutingTimer`.

### Changed

- `*secure.RoutingTimer` prints a summary with the verbs of `fmt` that call a method of the value, `%#v` and `%d` too: `secure.RoutingTimer{Serial: 00FA:01020304, Latency: 1s, Key: (redacted)}`; nil prints `<nil>`. It printed its unexported fields: the backbone key, the start time, a function address and the lock. `log/slog`'s text handler writes the summary; `encoding/json` writes `{}`, and `%p` and `%T` print, as before. `Authenticated` and `TimeKeeper` report its state.

### Documentation

- API.md and ERRORS.md: `tunnel.Conn.Receive`, `routing.Conn.Receive`, `discovery.Search` and `Describe` among the calls that match `knx.ErrTimeout` and `context.DeadlineExceeded` at a deadline. API.md and SECURITY.md: the summary of `*secure.RoutingTimer`. LIMITATIONS.md: the entry on expired deadlines removed; the routing timer no longer among what the redaction does not cover. TESTING.md: the discovery deadline rows that wait real time. Doc comments of the four calls. docs/api regenerated.

### Tests

- The deadline of `tunnel.Conn.Receive`, `routing.Conn.Receive`, `discovery.Search` and `Describe`: passed before the call, passing while it waits, cancelled before and while it waits; for the tunnel, frames already queued returned with an ended context. `devmgmt.Conn.PropRead` and `PropWrite` whose deadline passes while they wait for the confirmation, with the message, and cancelled. Every verb of `fmt`, `encoding/json` and `log/slog` of a `*secure.RoutingTimer`, and a nil one.

---

## v0.13.0

**Date:** 2026-11-16
**Previous release:** v0.12.0

## Summary

Deadlines, redaction and flow control. A deadline in `tunnel.Dial`, `tunnel.Conn.FeatureGet` and `FeatureSet`, `routing.Listen` and `routing.Conn.Send` gives an error matching `knx.ErrTimeout` and `context.DeadlineExceeded`, as in the other calls since v0.12.0. The key types print `(redacted)` with the verbs of `fmt`, `%d` included, and marshal to `"(redacted)"` in JSON; so do the keys and passwords of `secure.Credentials` and the keyring entries; a Data Secure table and a secure session print a summary without keys. `devmgmt` discards the confirmations queued before each request. New: a ceiling on the busy counter of the routing flow control, none by default.

## Changes

### Breaking

- An expired deadline of `tunnel.Dial`, `tunnel.Conn.FeatureGet`, `FeatureSet`, `routing.Listen` and `routing.Conn.Send` gives an error matching `knx.ErrTimeout` and `context.DeadlineExceeded` (it was the context's error, or one wrapping it, matching `context.DeadlineExceeded` only); so do `client.DialTunnel`, `client.ListenRouting`, and `client.GroupWrite` and `GroupRespond` over routing, which return these errors. A `routing.Conn.Send` whose deadline had passed when it came to the write returned the error of the write (`i/o timeout`, matching neither) and now matches both; it sends nothing, as before. The message starts with `knx: timeout:`. Who notices: code that compares the error with `==` (`err == context.DeadlineExceeded`), or that reads the message. Restore path: `errors.Is(err, context.DeadlineExceeded)`; a cancelled context still gives an error matching `context.Canceled` only.
- The key types `secure.Key`, `datasecure.Key` and `keyring.Key` print `(redacted)` with the verbs of `fmt` that call a method of the value: `%d`, `%o`, `%b`, `%c` and the others print it too (they printed the octets; `%v`, `%s`, `%x`, `%X`, `%q` and `%#v` print as in v0.12.0; `%p` and `%w` outside `fmt.Errorf` call none, LIMITATIONS.md). `encoding/json` writes a key as the string `"(redacted)"` (it wrote an array of 16 numbers), also inside `secure.Credentials`, `keyring.Backbone`, `keyring.Device` and `keyring.Keyring`; reading that JSON back into a key fails. `secure.Credentials`, `keyring.Backbone`, `keyring.Interface` and `keyring.Device` print with every verb of `fmt` as with `%v`, their keys and passwords `(redacted)` (`%d` printed their fields, the passwords of `Interface` and `Device` included). `encoding/json` writes the passwords of `keyring.Interface` and `keyring.Device` as `"(redacted)"`, an empty one as `""`, and their other fields as before; so inside a `keyring.Keyring`; read back, such a password is the text `(redacted)`. A struct of the caller's own that embeds a key type or one of these structs (rather than having it as a named field) takes its `Format` (and its `MarshalJSON`, where it has one), which print and write the embedded value only, also when the struct has a `String` method of its own. `*datasecure.Table` and `*secure.Session` print a summary without keys, `%#v` and `%d` too (they printed their fields, the keys included). Who notices: code that marshals a keyring, credentials or another value holding a key or password to JSON on purpose, or that prints one with `%d`. Restore path: marshal the fields it needs, for a key `k[:]` (base64) or `[16]byte(k)` (the array of numbers as before); for the passwords a type of its own with the same fields (`type plain keyring.Interface`, then `json.Marshal(plain(itf))`) or the `Password` field itself; a struct that embeds one of them names the field instead; print `k[:]`.
- `devmgmt.Conn.PropRead` and `PropWrite` discard the frames queued on the tunnel before they send their request, so a confirmation that arrived after an earlier request timed out is no longer taken for the answer (they returned it when it was for the same object, instance, property and start). A confirmation that arrives after the request was sent is still taken: cEMI device management carries no correlation. Who notices: an application that reads a property again after a read timed out, which now gets the answer to its new request; and one that reads other frames of the connection with `Tunnel().Receive` and leaves them queued across a `PropRead` or `PropWrite` (the call discarded those that were ahead of its answer before too, but now also when the call fails before sending). Restore path: none by option; read those frames with `Tunnel().Receive` before the call.

### Added

- `routing.WithMaxBusyCount(n)` and `server.WithRoutingMaxBusyCount(n)`: a ceiling on the busy counter N of the routing flow control, which sets the random extension of the pause after a ROUTING_BUSY (up to N × 50 ms), the reduced rate after it (a gap N + 1 times the normal one) and how long that lasts (N × 100 ms). 0, the default, leaves N unbounded, so the rate a deployment sees is unchanged; a negative value is `knx.ErrInvalidOption`.
- `Format` and `MarshalJSON` on `secure.Key`, `datasecure.Key`, `keyring.Key`, `keyring.Interface` and `keyring.Device`; `Format` on `secure.Credentials` and `keyring.Backbone`; `String` and `Format` on `*datasecure.Table` and `*secure.Session`.

### Documentation

- API.md: the calls that match `knx.ErrTimeout` and `context.DeadlineExceeded` at a deadline, the busy counter bound, what the key types and the table and session print. LIMITATIONS.md: the calls that return the context's error alone (`Receive`, `discovery`), the devmgmt confirmation that arrives after the next request, what the redaction does not cover. ERRORS.md: the `knx.ErrTimeout` row. SECURITY.md: the redaction, the busy counter limit with its option and tests. ARCHITECTURE.md and docs/IMPLEMENTATION-STATUS.md: the busy counter ceiling, deadlines, the devmgmt discard. TESTING.md: matrix row L7 for devmgmt. docs/api regenerated.

### Tests

- A late devmgmt confirmation followed by the next read of the same property; the busy counter ceiling in `internal/flowctl` (none, below, at, one over, far over, 1, negative, `MaxInt`) and through `routing.Conn` and the server, with and without the option; every `fmt` verb, `encoding/json` and `log/slog` of the key types, of the credentials and keyring entries with keys and passwords, of the values holding them and of a table and a session, and the verbs of v0.12.0 printing as before; the JSON fields of `keyring.Interface` and `keyring.Device` (with passwords, one empty, none; inside a `keyring.Keyring`) and the restore path through a type with the same fields; the deadline of `FeatureGet` and `FeatureSet` in each wait, of `tunnel.Dial` (CONNECT_RESPONSE, a dialer, the secure handshake over TCP and UDP; cancelled; the connect timeout), of `routing.Conn.Send` (the write, the pause, the turn; cancelled) and of `routing.Listen` with `WithSecure`.

---

## v0.12.0

**Date:** 2026-11-16
**Previous release:** v0.11.1

## Summary

Close, deadlines and ownership as the documents state them. After `Close` every call returns `knx.ErrClosed`, and a `client.Device` request that waits when the device or its client closes ends with it; a deadline in `client.GroupRead` and `tunnel.Conn.Send` gives an error matching `knx.ErrTimeout` and `context.DeadlineExceeded`; every consumer of a delivered telegram gets its own copy; keys and credentials print and log redacted. New: `tunnel.WithDialer`, `client.Client.DeviceWithToolKey`, `client.WithMaxPendingAnswers`, and a ceiling for the pause after a ROUTING_BUSY. `tunnel.Conn.Close` during a reconnection disconnects the channel the server opens for it.

## Changes

### Breaking

- After `Close`, `routing.Conn.Send` returns an error matching `knx.ErrClosed` and sends nothing (it returned the error of the closed socket). `server.Server.Send`, `GroupWrite` and `Transmit` return an error matching `knx.ErrClosed` and reach neither the `Subscribe` callbacks nor the virtual devices; `Transmit` leaves the group object as it was (they returned nil and distributed the telegram). `tunnel.Conn.FeatureGet` and `FeatureSet` return an error matching `knx.ErrClosed` (it matched `knx.ErrConnectionLost`). Who notices: an application that calls these after `Close`, in particular one that relied on `Server.Send` distributing to the taps and devices of a closed server. Restore path: none by option; call them before `Close`, or ignore `knx.ErrClosed` where a call after `Close` is expected.
- A `client.Device` request after `Device.Close` or `Client.Close` returns an error matching `knx.ErrClosed` and sends nothing (it went to the link and ended at its deadline). A request that waits for its answer or its turn when the device or the client closes returns at once with that error; `Device.Close` no longer waits for the request's deadline, and still ends the transport connection. Who notices: an application that closes a `Device` while a request runs and expected the request to complete. Restore path: let the request return before `Close`.
- An expired deadline of `client.GroupRead` gives an error matching `knx.ErrTimeout` and `context.DeadlineExceeded` (it matched `knx.ErrTimeout` only), also while its request waits for the link. `tunnel.Conn.Send` at a deadline, in any of its waits, gives an error matching both (it returned the context's error). Who notices: code that compares the error with `==` instead of `errors.Is`, or that tells a deadline from a timeout of the library by `knx.ErrTimeout`. Restore path: `errors.Is(err, context.DeadlineExceeded)` tells the deadline; a cancelled context still gives `context.Canceled` only.
- Each subscription, `OnTelegram` callback and read of a `client.Client` gets its own copy of a delivered `Telegram` (`Frame` and `Value.Data`); each `server.Server.Subscribe` callback gets its own copy of the frame, so what it changes no longer reaches the clients and devices. `cemi.NewGroupFrame` and `NewIndividualFrame` copy the TPDU. Who notices: code that changed a telegram in one consumer so that another sees it, a tap that edited the frame before the server distributed it, or a caller that changed the slice given to `NewGroupFrame` after the call. Restore path: none by option; share changes through the application's own state, and send a changed frame with `Server.Send`. Measured cost, this machine: `NewGroupFrame` one allocation more (8 octets); a telegram to one subscription none; to a subscription, a callback and a read 7 allocations, 168 octets; a server telegram 2 allocations, 72 octets per `Subscribe` callback; a `GroupWrite` through a tunnel 73 instead of 72 allocations.
- The key types `secure.Key`, `datasecure.Key` and `keyring.Key`, `secure.Credentials` and `keyring.Backbone`, `Interface` and `Device` print `(redacted)` for their keys and passwords with `%v`, `%s`, `%x`, `%q` and `%#v`, and log so with `log/slog`. Who notices: code that printed a key with `%x` or `%v` to show or store it. Restore path: `hex.EncodeToString(k[:])` or `fmt.Sprintf("%x", k[:])`.
- `tunnel.Conn.Close` during a reconnection waits up to 1 s (no longer than the rest of the connect timeout) for the CONNECT_RESPONSE in flight and sends a DISCONNECT_REQUEST for the channel it opened; the supervisor ends before `Close` decides whether to disconnect. Who notices: an application that closes a reconnecting tunnel whose server answers late: `Close` returns up to 1 s later. Restore path: call `Close` from another goroutine where it must not wait.

### Added

- `tunnel.WithDialer(func(ctx, network, address) (net.Conn, error))` supplies the TCP connection of a tunnel (`WithTCP`, or `WithSecure` without `WithUDP`), and with it of `devmgmt.Dial` and `client.DialTunnel`: the dialer gets "tcp4", the server's address and a context bounded by the connect timeout. Its error fails `Dial`, wrapped; a connection returned with an error is closed; no connection is `knx.ErrInvalidOption`, as are a UDP tunnel and `WithLocalAddr` with it. nil keeps the `net.Dialer`.
- `client.Client.DeviceWithToolKey(addr, key, opts...)` returns the `Device` secured with the tool key and the error when its Data Secure table cannot be made (`datasecure.NewTable` refuses a system clock before 2018-01-05); on an error it returns no `Device` and leaves an earlier `Device` of the address in place. A `Device` made with `client.WithToolKey` in that case returns the error from every request and sends nothing.
- `client.DefaultMaxPendingAnswers` (16) and `client.WithMaxPendingAnswers(n)`, 1 to 65536: the queue of the answers of a client with Data Secure to individually addressed requests. A value outside the range keeps the default.
- `routing.WithMaxBusyPause(d)` and `server.WithRoutingMaxBusyPause(d)`: a ceiling for the pause after a ROUTING_BUSY, the wait time and the random extension together, measured from the busy frame that starts or extends the pause. 0, the default, keeps the pause the frame asks for; a negative value is `knx.ErrInvalidOption`. The busy counter and the reduced rate after the pause are not changed.
- `String`, `GoString` and `LogValue` on `secure.Key`, `secure.Credentials`, `datasecure.Key`, `keyring.Key`, `keyring.Backbone`, `keyring.Interface` and `keyring.Device`; `LogValue` on `keyring.Keyring` (the project and the number of entries).

### Documentation

- LIMITATIONS.md: which calls match which sentinel at a deadline, the late devmgmt confirmation, `WithDialer` and the UDP socket, what the redaction covers (`%d` and `encoding/json` of a key still give its octets). ERRORS.md: the calls that return `knx.ErrClosed`, the deadlines that match `knx.ErrTimeout`. API.md: bounds of the answer queue and the busy pause, the deadline rule, ownership of delivered telegrams, `DeviceWithToolKey`, the redaction. ARCHITECTURE.md: `Close` during a reconnection, the busy pause ceiling, copies per consumer. SECURITY.md: the redaction, the two limits with their options and tests. TESTING.md: matrix rows L3 (D), L12 and L16 covered. docs/IMPLEMENTATION-STATUS.md: the busy pause ceiling and `Close` during a reconnection.

### Tests

- One test per type that every call after `Close` matches `knx.ErrClosed` and has no side effect, and that a `Device` request waiting at `Close` ends with it; deadline tests of `GroupRead` and of each wait of `tunnel.Conn.Send`; aliasing tests of the client's consumers, the server's taps and `NewGroupFrame`; `WithDialer` with a fault-injecting connection and every refusal; a tool key table that cannot be made; the answer queue at sizes from 1 to 65536 and out of range; the busy pause ceiling at, below and above its value; `Close` during a reconnection whose CONNECT_RESPONSE comes late; the redaction in `fmt` and `log/slog`. Benchmarks of `NewGroupFrame`, the client's delivery and the server's taps.

---

## v0.11.1

**Date:** 2026-11-15
**Previous release:** v0.11.0

## Summary

Lifecycle and timing of the tunnelling client, the routing connection, the group client and the server. Sends take turns that end with the caller's context; a tunnelling request keeps its sequence number until it is acknowledged; feature requests are acknowledged and repeated; the KNX IP Secure handshake follows the context of `Dial`; the timer synchronisation of secure routing always takes its whole window; reconnection waits are jittered; the loops that accept and read pause after an error; application callbacks that do not return normally are logged. No exported identifier is added, removed or changed.

## Changes

### Changed

- Secure routing: a timer synchronisation counts only when its whole window has passed. `routing.Listen` with `WithSecure` (and `client.ListenRouting`) returns the context's error and no `Conn` when its context ends inside the window, and closes its socket. `secure.RoutingTimer.Synchronize` then leaves the timer unsynchronised: `Authenticated` reports false, `Accept` refuses every frame, the router is not time keeper and no periodic notify is scheduled; a later `Synchronize` starts a new window. A server runs the synchronisation for its whole window whatever becomes of the context `Start` was called with; `Close` ends it.
- `routing.Conn.Send`, `tunnel.Conn.Send`, `FeatureGet` and `FeatureSet` take turns, and a call that waits for its turn returns when its context ends (the context's error) or the `Conn` closes (`knx.ErrClosed`). A turn that is free is taken as before.
- A client with `WithDataSecure` sends its answers to individually addressed requests (S-A_Sync_Res, the answer to a tool request) from one goroutine, in order, through a queue of 16. An answer that finds the queue full is dropped and logged at debug level; each send gets 5 s.
- `tunnel.Dial` with `WithSecure`: the KNX IP Secure handshake ends with the connect timeout or with the context of `Dial`, whichever is first. When the context ends first, by its deadline or by cancellation, `Dial` returns the context's error.
- `tunnel.WithReconnect`: each reconnection attempt waits a random time between half the backoff and the backoff (the backoff still starts at the minimum and doubles to the maximum), so that clients which lost the same server do not come back together.
- The server's accept and read loops, the reader of `routing.Conn`, and the UDP reads of the tunnelling client and of discovery pause after an error other than a closed socket: 5 ms, twice as long after each further error up to 1 s, 5 ms again after a success. `Close` ends a pause. The error is logged at debug level by the server and by `routing.Conn`.
- `client.Client.OnTelegram`, `server.Server.Subscribe` and the `OnChange` handler of a virtual device in a server: a callback that does not return normally is stopped where the library called it and logged at error level with its stack; the reader or the server goes on. The comments say what a callback may call and that it calls `Close` from another goroutine.
- `secure.RoutingTimer.Stop` waits for a notify the timer is sending, so `Close` of a `routing.Conn` or a server returns after it. `Stop` must not be called from the send function.

### Fixed

- `tunnel.Conn.Send` whose context ended between its TUNNELLING_REQUEST and the TUNNELLING_ACK returned without consuming the sequence number, although the server may have taken the frame; the next telegram then went out under the same number, which a server takes for a repetition. The request now stays outstanding: it is not repeated, and the next `Send` or feature call first waits for its acknowledgement, for what is left of the request timeout, before it sends under the next number. Without the acknowledgement the connection is lost (`knx.ErrConnectionLost`), as for a request that is not acknowledged twice.
- `tunnel.Conn.FeatureGet` and `FeatureSet` over UDP wrote the request once and advanced the sequence number at once. They now wait for the TUNNELLING_ACK, repeat the request once and consume the sequence number when it is acknowledged, like `Send`; a feature request that is not acknowledged twice loses the connection.
- A secure tunnel's keep alive timer was started again by the SESSION_STATUS that closes the session; it now stays stopped after `Close`.
- `server.Start` that refuses routing on a port other than the group's left the TCP listener it had opened; it now closes it.
- `server.Start` published the routing timer outside the server's lock; a `Close` that ran during `Start` could leave the timer running. The timer is now published with the sockets. `secure.RoutingTimer.Synchronize` read the time keeper state without the timer's lock.
- `dpt` 242.600 (xyY): `Encode` took a NaN in x, y or the brightness and encoded an unspecified value; it now returns `knx.ErrInvalidValue`, as the other float types do.

### Documentation

- SECURITY.md: a table of the resource limits with the test of each; what a secure router does when it hears no time keeper; the server's endpoint check as the code has it. OBSERVABILITY.md: every reason of `Metrics.OnDropped` (17, compared with the code by `TestDropReasonsDocumented`) and the log entry of a callback. LIMITATIONS.md: what calls return after `Close`, which sentinels an expired deadline matches, shared telegrams, no dialer option. ARCHITECTURE.md, API.md and ERRORS.md: waits, `Close`, callbacks and the sequence counter as the code has them. TESTING.md: the lifecycle contract matrix (L1–L16), how the tests wait, the allocation budgets, the command of the benchmarks. CONFORMANCE.md, OTFABRIC-CONVENTIONS.md and the comment of `internal/pbkdf2` no longer state superseded versions and gates.

### Tests

- Lifecycle contract tests for `tunnel.Conn`, `routing.Conn`, `client.Client`, `client.Device` and `server.Server`: concurrent `Close`, cancelled requests, acknowledgements of an earlier connection, callbacks that call the library or end it, construction failures with a count of the open descriptors.
- Allocation budgets for `knxnetip.ReadFrame`, `Parse`, `ParseDIBs` and `keyring.Parse` at their limits.
- The routing timer, the pauses of the loops and the reconnect jitter are tested on the clock of `testing/synctest`; several tests wait for an event where they slept.

### CI

- The nightly tier runs the tests with `GOARCH=386`. The release workflow builds, vets and tests otfabric/knxctl against the candidate before the tag is created.

---

## v0.11.0

**Date:** 2026-11-14
**Previous release:** v0.10.0

## Summary

Tighter state handling in KNX IP Secure, KNX Data Secure and the server: tool access sequence numbers, the receive replay state across restarts, secure session direction, secure routing repeats and timer synchronisation, the server's session and channel capacity, the tunnelling client's TCP writes and keyring input bounds.

## Changes

### Added

- `datasecure.Table.Senders`, `Table.ToolSequences` and `Table.SetToolSequence`: read and restore the last valid sequence number of each group sender and tool access peer. Persist them with `Table.Sequence` and restore them after a restart, or a recorded telegram is accepted again.
- `server.WithSecureAuthTimeout` and `server.DefaultSecureAuthTimeout` (10 s): a KNX IP Secure session or TCP connection of a secure server must authenticate within it.
- `Metrics.OnDropped` reasons `source_address` and `session_replaced`.

### Changed

- A secure server ends sessions and TCP connections that do not authenticate in time; frames before authentication no longer keep them open, and when all are taken a new one replaces the oldest that has not authenticated. The capacity check comes before the key agreement.
- On a secure server, a tunnel's telegrams carry only its own individual address as source; others are dropped with a negative L_Data.con.
- Secure routing timer synchronisation collects answers for the whole synchronisation window and uses the newest timer value; `routing.Listen` with `WithSecure` therefore takes the whole window (about 3.3 s at the default latency), and frames are accepted only after it. `secure.RoutingTimer.Next` returns strictly increasing values.
- The tunnelling client bounds every TCP write (plain and KNX IP Secure) by the request timeout: a server that stops reading ends the connection (`knx.ErrConnectionLost`) instead of blocking `Send`, the heartbeat and `Close`, and `Send` honours its context during the write. `Close` bounds its own writes by 1 s.
- `keyring.Load`, `LoadFile` and `Parse` refuse documents over 4 MiB, nested deeper than 64 levels or with more than 262144 elements as `knx.ErrMalformed` before the signature is checked; duplicate attributes, mismatched end tags and a latency outside 0..65535 ms are refused too. `LoadFile` reads through `Load`.
- `datasecure.AddSender` only raises a known sender's sequence number.
- Replies the server cannot encode are logged at debug level.
- The server's DISCONNECT_REQUEST for a connection opened in a UDP secure session is sent inside the session; the routing timer synchronisation runs under the server's WaitGroup, so `Close` waits for it.

### Fixed

- `datasecure.Table`: an S-A_Sync_Req whose sequence number is not above the sender's last tool access frame let that number be used again, so a repeated sync request with its tool access frame was answered (client surrogate, `mgmt.Responder`, the server's own device with `WithToolKey`). The sync request now opens its sequence number only when it is new.
- `secure.Session.Unwrap` accepted a SECURE_WRAPPER sealed by the session itself; it is now refused. The tunnelling client never picks the go-knx server's default serial number.
- Secure routing accepted the same SECURE_WRAPPER again within the latency tolerance; each is now accepted once.
- Secure routing timer synchronisation took the first matching answer, even an older one.
- The server replaced a live connection when all 255 channels were in use; such a request is now refused with E_NO_MORE_CONNECTIONS.
- An extended search answered a repeated DIB type once per repetition; each type is answered once. With more than 62 tunnelling addresses, TUNNELLING_INFO lists the first 62 slots and KNX_ADDRESSES the first 126 addresses, so the blocks encode.
- KNX IP Secure over UDP: the client drops unparsable or unexpected datagrams during the handshake instead of aborting it; the handshake timeout still applies.

### Documentation

- SECURITY.md, ARCHITECTURE.md, API.md, ERRORS.md, LIMITATIONS.md and OBSERVABILITY.md describe the new bounds, the persisted replay state, and that remote management of a secure server's own device stays plain without `WithToolKey`.

---

## v0.10.0

**Date:** 2026-11-08
**Previous release:** v0.9.0

## Summary

go-knx is validated against recorded traffic of physical devices: five weeks of a KNX TP1 house installation (1 150 094 frames, knx-datasets) and the live KNXnet/IP sessions of an ABB IP-Router IPR/S and an ABB IPS/S2.1 with a test client (Wireshark issue 14825), with Wireshark's KNX test captures. Every frame is decoded and encoded again byte for byte, compared with Wireshark 4.6.9 and with the dataset authors' own decode, and the management, client, discovery and server code is replayed against the recorded devices. Three defects the recordings show are fixed: discovery missed the ABB router, a repeated TP1 frame did not encode back, and the server's own device ended an idle transport connection without telling the peer.

## Changes

### Fixed

- `knxnetip.ParseDIBs` (and every search and description response): one optional block of a known type with another layout made the whole response fail to decode, so `discovery` did not see the device. An ABB IP-Router IPR/S sends a TUNNELLING_INFO block without the maximum APDU length and an 11-octet SECURED_SERVICE_FAMILIES block in its extended search responses (91 recorded; Wireshark marks both blocks malformed). Such an optional block is now kept as `knxnetip.UnknownDIB`, octets as sent, when the DEVICE_INFO block decodes; a malformed DEVICE_INFO or SUPP_SVC_FAMILIES block, or one in a response without DEVICE_INFO, still refuses the response.
- `cemi.TP1Frame` always wrote the "not repeated" bit: a repeated frame (control field 0x90, 0x9C) decoded by `cemi.ParseTP1` did not encode back to its octets, and the server's busmonitor connections saw a repeated L_Data.ind (from routing) as a first transmission. `TP1Frame` now takes the repeat flag from an L_Data.ind that reports a repeated frame; requests are first transmissions as before. 6 414 repeated frames recorded on the TP1 line now encode back.
- `mgmt.Responder` (the server's own device) ended a transport connection idle for 6 s silently. `Repeat` now returns a T_Disconnect to the peer, as 75 devices of the recorded TP1 line do 5 to 13 s after a T_Connect that no data follows. The server sends it once a second, as it sends repetitions.

### Added

- `testdata/captures`: the recordings, byte-identical, with SHA256SUMS, a manifest (provenance, evidence class, go-knx's and the oracles' counts) and a README. `make captures-verify` (in CI), `captures-fetch`, `captures-extended` (nightly: every TP1 frame against the CSV exports) and `captures-generate`.
- Capture tests in `cemi`, `knxnetip`, `discovery`, `secure`, `datasecure`, `mgmt`, `client`, `server` and `internal/capture`; fuzz seeds from the recordings for `cemi.ParseTP1`, `apdu.Parse` and `knxnetip.Parse`. `FuzzParseTP1` now requires a byte-exact round trip, repeat flag included.

### Documentation

- testdata/captures/README.md: sources, terms, evidence classes, comparison rules, results and the classified differences (unsupported memory and ADC services, link-layer repetitions acknowledged again, cEMI transport layer messages and remote diagnosis kept unknown, the router's configuration in the server replay).
- INTEROPERABILITY.md, LIMITATIONS.md, TESTING.md, docs/IMPLEMENTATION-STATUS.md and README describe the recorded-traffic evidence and its limits. No device was tested live.

---

## v0.9.0

**Date:** 2026-11-07
**Previous release:** v0.8.2

## Summary

The server's own device now repeats an answer in a transport connection that the peer misses, as the KNX transport layer does: Calimero tools lost one now and then and timed out. The interop suite pins knx-interop v0.9.2, in which knxd runs its TCP tunnelling server, and tests go-knx's TCP client against knxd.

## Changes

### Added

- `mgmt.Responder.Repeat`: the frames a responder must send again at a time: an answer in a transport connection not acknowledged within 3 s. The server calls it once a second.

### Changed

- The interop suite pins the knx-interop v0.9.2 images (xknx, KNXUltimate and cB-Sigma knx by digest; Calimero and knxd built from the tag), and `make interop-images`, `make interop-matrix` and the Interop workflow default to that tag.
- `interop/`: `TestGoKNXClientTCPKnxd` runs go-knx's TCP tunnel against knxd's TCP tunnelling server: connect, a confirmed write seen by xknx, a write of xknx received, a read answered by xknx.

### Fixed

- `mgmt.Responder` (the server's own device): an answer in a transport connection was sent once. When the peer missed it, the responder answered the peer's next request with the same sequence number, which the peer took for a repetition, and the peer timed out. The responder now repeats an answer that is not acknowledged within 3 s, or that the peer refuses with T_NAK, at most three times, then ends the connection, as the KNX transport layer does. Calimero tools 3.0-M1 misses an answer that closely follows the T_Ack now and then: the Interop workflow failed on Calimero tools' tool access read in a transport connection ("timeout waiting for data response"). In 40 runs of that read against a server that made Calimero miss answers more often, 6 failed without the repetition and none with it.

### Documentation

- INTEROPERABILITY.md: results of knx-interop v0.9.2. Matrix: 609 pass, 13 known differences of other stacks, 110 unsupported, 0 fail; with go-knx in a role, 456 pass (446 before), 2 known differences, 34 unsupported. `make interop`: 72 of 72 pass. go-knx's TCP client passes against knxd's TCP server in both the matrix and `interop/`.
- README and docs/IMPLEMENTATION-STATUS.md name knx-interop v0.9.2.

---

## v0.8.2

**Date:** 2026-11-07
**Previous release:** v0.8.1

## Summary

Documentation only: the package comments of `server` and `datasecure` (shown on pkg.go.dev) described the first releases. The code is unchanged.

## Changes

### Documentation

- `server`: the package comment said busmonitor, device management connections, KNXnet/IP over TCP, tunnelling feature services and KNX IP Secure were not implemented. It now lists what the server does: tunnelling over UDP and TCP, busmonitor, feature services, local and remote device management (with tool access), routing flow control, KNX IP Secure tunnelling and routing. Only raw tunnelling is refused.
- `datasecure`: the package comment said S-A_Sync and tool keys were not implemented. It now says point to point security with a tool key is implemented, and that device-to-device link keys and FDSK are not.

---

## v0.8.1

**Date:** 2026-11-07
**Previous release:** v0.8.0

## Summary

The interop suite pins knx-interop v0.9.1 (contract 1.6) and tests go-knx against a fifth independent implementation, cB-Sigma knx with its simulator knx-sim. The library is unchanged.

## Changes

### Changed

- The interop suite pins the knx-interop v0.9.1 images (xknx 4.1.1, KNXUltimate 6.3.2, cB-Sigma knx v0.2.0 by digest; Calimero and knxd built from the tag), and `make interop-images` and `make interop-matrix` default to that tag.
- cB-Sigma knx is a client of go-knx's server in `interop/` (plain and over TCP, busmonitor, KNX IP Secure, Data Secure).
- `interop/node` implements the contract 1.6 `keyring` operation, so the matrix's offline keyring checks include go-knx.

### Fixed

- `TestChaosExactlyOnce` failed now and then in CI ("write 28 without chaos: … reconnecting"): its clean-path writes started while datagrams delayed by the chaos proxy (up to 4 x its 15 ms delay) were still in flight. One of them can be a DISCONNECT_REQUEST of the channel number the server gave the reconnected client again, which the client rightly obeys. The test now waits for them to land. No library change.

### Documentation

- INTEROPERABILITY.md: results of knx-interop v0.9.0 (v0.9.1 changes only the cbsigma capabilities document; `make interop` re-run against the v0.9.1 images). go-knx against cB-Sigma knx-sim's fault switches (replayed and tampered secure wrappers, a session closed by the gateway, an idle session past 60 s, repeated indications, missing acknowledgements) and its router's ROUTING_BUSY and ROUTING_LOST_MESSAGE: all pass. LIMITATIONS.md: the routing client's flow control is now checked against a third-party router.
- README, SECURITY.md, CONTRIBUTING.md, docs/IMPLEMENTATION-STATUS.md and docs/standards/SPECIFICATIONS.md name the current peers and versions, and the upstream reports from the knx-interop sim suite.

---

## v0.8.0

**Date:** 2026-11-06
**Previous release:** v0.7.0

## Summary

Gaps found by comparing go-knx with xknx 4.1.1 (otfabric/knx-interop#19): routing flow control, TCP frame resynchronisation, a foreign-channel DISCONNECT_REQUEST, KNX IP Secure session timers, PropertyDescription and 30 more datapoint types.

**Upgrade notes:** `mgmt.Description.Type` is now `mgmt.PDT` (was `uint8`), and `Description` has an `Object` field: code that assigns a typed `uint8` to `Type` needs a conversion. A go-knx server now ends KNX IP Secure sessions idle for 60 s (was the 120 s connection alive time; `server.WithSecureSessionTimeout`). Routing senders are paced at the configured rate instead of in bursts, so a burst of indications now takes rate-limited time.

## Changes

### Added

- `client.Device.PropertyDescription` (A_PropertyDescription_Read), connectionless, connected and with the tool key. `mgmt.PDT` with the property datatypes, `Size` and `String`; `mgmt.ParseDescription`, `mgmt.DescriptionReadTPDU`, `Description.Data`, `TPDU`, `ReadLevel`, `WriteLevel`.
- Datapoint types 5.100, 15.000, 20.107, 21.002, 21.100-21.106, 21.601, 21.1000, 21.1001, 21.1010, 21.1200, 21.1201, 22.100, 22.101, 22.103, 22.1000, 22.1010, 27.001, 217.001, 222.100, 222.101, 234.001, 234.002, 275.100, 275.101, with the values `AccessData`, `OnOffInfo`, `Version` and `RoomSetpoints`. The new encodings decode to the same values in xknx 4.1.1.
- `server.WithSecureSessionTimeout` (default 60 s, `DefaultSecureSessionTimeout`) and `tunnel.WithSessionKeepAlive` (default 30 s, `DefaultSessionKeepAlive`).

### Changed

- The tunnel client sends its KNX IP Secure keep alive after 30 s idle (was a fixed 45 s).
- The server queues its outgoing routing indications (bounded by `WithQueueSize`) and paces them, instead of dropping what exceeded the rate; a full queue is still counted as `OnDropped("routing_rate")`.

### Fixed

- Routing flow control (Routing, ROUTING_BUSY): the client only waited out the last busy frame's wait time and could send 50 indications back to back; the server ignored ROUTING_BUSY. Both now count busy frames (more than 10 ms apart, the first included), wait the wait time plus a random 0..N x 50 ms, slow down afterwards and keep a minimum gap of 1/rate between indications.
- The server closed a TCP connection, and the client a KNX IP Secure tunnel over TCP, on one frame whose body did not parse, although its valid header framed it. Such a frame is now dropped and the connection kept.
- The server freed a TCP connection's slot of its connection limit only after closing the socket, so a client that saw the close could still be refused for a moment (`TestHostileTCP` failed now and then in CI). The slot is now freed first.
- The tunnel client ignored a DISCONNECT_REQUEST for another channel; it now answers E_CONNECTION_ID and keeps the tunnel.
- The server expired idle KNX IP Secure sessions after the 120 s tunnelling alive time instead of the 60 s session timeout.

### Documentation

- `tunnel.Conn.Send` and ERRORS.md: a frame lost with the tunnel is not resent after a reconnect; the caller decides whether to repeat it.

---

## v0.7.0

**Date:** 2026-11-05
**Previous release:** v0.6.0

## Summary

Bounds for every call that waits for a peer or collects its answers. Found while hardening knxctl, which had to work around them. API.md has a new Bounds section.

**Upgrade notes:** `GroupReadAll` and `Search` now stop at a limit (1000 responses, 256 servers): raise it with `WithMaxResponses` or `WithMaxResults`. devmgmt calls without a context deadline now end after 3 s.

## Changes

### Added

- `client.WithMaxResponses`, `client.DefaultMaxResponses`, `discovery.WithMaxResults`, `discovery.DefaultMaxResults`, `devmgmt.DefaultTimeout`, `client.MaxPropertyData`.

### Fixed

- `discovery.Search` kept every distinct answer, so a flood of SEARCH_RESPONSEs grew memory for the whole timeout. It now returns once it has `DefaultMaxResults` servers (`WithMaxResults`).
- `client.GroupReadAll` kept every response. It now returns once it has `DefaultMaxResponses` (`WithMaxResponses`).
- devmgmt `PropRead`/`PropWrite` waited as long as the context lived. A server that acknowledged the request and never confirmed it blocked a caller without a deadline for ever. They now end after `DefaultTimeout` with `knx.ErrTimeout`.
- `client.Device` reported a cancelled context as `knx.ErrTimeout` ("no answer"). It now returns an error matching `context.Canceled`. An expired deadline still matches `knx.ErrTimeout` and now also `context.DeadlineExceeded`.
- `tunnel.Conn.Send` (and devmgmt, client over a tunnel): a frame too long for a KNXnet/IP datagram, or too long once wrapped by KNX IP Secure, was counted as a failed write. The connection was torn down (or reconnected) and the caller got `knx.ErrConnectionLost`. It now returns `knx.ErrInvalidValue`, sends nothing and keeps the connection.
- `client.Device.PropertyWrite` refuses data over `MaxPropertyData` (250 octets) before sending.

---

## v0.6.0

**Date:** 2026-11-04
**Previous release:** v0.5.2

## Summary

Static analysis (gosec, opengrep) at low/low is clean: every finding was fixed in the code, none was recorded as accepted. The work found defects where lengths and counters wrapped, and new hostile-peer, chaos and fuzz tests found a server defect on reconnects and a spoofing gap. Go 1.26 is now the minimum version.

**Upgrade notes:** Go 1.26 or later. No API signatures changed. See Changed for the stricter behaviour of the server and client.

## Changes

### Fixed

- `server`: a repeated CONNECT_REQUEST from the same endpoints (a client reconnecting from its socket, e.g. `tunnel.WithReconnect`) got its old channel with stale sequence counters. The client's first telegram was then acknowledged as a repetition and dropped, and the server's next request was ignored. The connection now restarts at sequence 0 and keeps its channel and individual address. Frames still queued for the old connection are dropped.
- `server`: frames of a channel (TUNNELLING_REQUEST/ACK, CONNECTIONSTATE_REQUEST, DISCONNECT_REQUEST) were accepted from any port of the client's IP address. They are now accepted only from the connection's recorded control or data endpoint, address and port.
- `discovery`, `tunnel` (Windows): a datagram larger than the receive buffer (WSAEMSGSIZE), or an ICMP port unreachable reported on the next read (WSAECONNRESET), ended `Search`, `Describe` or a secure tunnel's handshake with an error. It is now dropped and reading continues until the deadline. Found by the new hostile tests on the Windows runner.
- `tunnel`: `Send` could return a bare "use of closed network connection" error. It now returns an error matching `knx.ErrClosed` or `knx.ErrConnectionLost`, with the cause wrapped.
- `knxnetip`: structure lengths that do not fit their length octet (a DIB, CRI, CRD or SRP of 256 octets or more) wrapped modulo 256, and the wrapped frame decoded as different structures. `Marshal` and `Append` now return `ErrInvalidValue`. `AppendTo` and `AppendHeader` write the length 0, which every decoder refuses.
- `knxnetip`: `AppendHeader` wrapped a total length above 65535, for example to 6.
- `secure`: the routing timer wrapped at 48 bits. A TIMER_NOTIFY at 2^48−1 set it back to a few milliseconds, after which peers refused every frame. It now saturates.
- `secure`: the TIMER_NOTIFY message tag, which the time keeper's answer must echo, and the notify delay came from math/rand. They now come from crypto/rand.
- `secure`: `Open` refuses a wrapper longer than `knxnetip.MaxFrameLen`. Before, the length in the first CCM block wrapped.
- `mgmt`: the maximum element count of a property description is 12 bits on the wire and was masked, so 4096 was described as 0. It now saturates at 4095.
- `internal/mcast` (macOS, BSD): a multicast TTL of 256 or more wrapped to 0. It is refused (the public options already limit it to 1..255).
- `datasecure`: `NewTable` with the system clock before the sequence epoch (2018-01-05) now gives a clear error.
- `interop/node`: `--object`, `--pid`, `--start` and `--count` out of range were truncated (`--pid 300` read PID 44). They are refused.

### Changed

- Go 1.26 minimum (CI on 1.26 and 1.27), `go fix` applied.
- Tests: fuzz targets for secure, datasecure, keyring, mgmt, the server (UDP datagrams and TCP stream) and the tunnel client. New e2e suites for hostile peers and deterministic chaos. See TESTING.md.
- knx-interop v0.7.1 images (same contract 1.4), shared workflows v3.3.1.

---

## v0.5.2

**Date:** 2026-10-31
**Previous release:** v0.5.1

### Changed

- Policy 1.2: build output in `bin/` and `release/`, a per-package coverage floor, and more tests and CI. No change in behaviour.

---

## v0.5.1

**Date:** 2026-10-31
**Previous release:** v0.5.0

## Summary

`server` with an ephemeral port and TCP starts on Windows.

**Upgrade notes:** none.

## Changes

### Fixed

- `server`: with port 0 and TCP the server could fail with "no port free for UDP and TCP" on Windows, where ephemeral UDP ports can fall in a range reserved for TCP. It now takes the TCP port first.

---

## v0.5.0

**Date:** 2026-10-30
**Previous release:** v0.4.2

## Summary

Remote device management over the KNX network, and KNX Data Secure point
to point with tool access: a tool reads and writes a device's properties
secured with the device's tool key, and go-knx's server is such a device.
Implemented from public descriptions and xknx (MIT), verified for
interoperability with Calimero tools and xknx, not for conformance.

## Added

- `mgmt`: the remote property services (A_PropertyValue_Read, _Write,
  _Response; A_PropertyDescription_Read and _Response;
  A_DeviceDescriptor_Read type 0) and `mgmt.Responder`, the device side:
  connectionless and in one transport connection at a time (T_Connect,
  numbered data with T_ACK, repetitions, T_Disconnect), secured with
  `Security` (the device's tool key): only S-A_Sync and S-A_Data with tool
  access are answered.
- `client.Device`: remote management of one device through the client's
  link (`PropertyRead`, `PropertyElements`, `PropertyWrite`,
  `DescriptorRead`); `client.Connected()` for a transport connection
  (acknowledgements, repetitions, reconnect after the device's idle
  timeout); `client.WithToolKey`, or the tool key in the client's Data
  Secure table, secures it (S-A_Sync, then S-A_Data with tool access).
- `datasecure.Table`, tool side: `SyncRequest`, `OpenSyncResponse`,
  `SealToolRequest`, `OpenToolResponse`, `ToolKey`; device side
  `RespondTPCI` (the S-A_Sync_Res numbered in a transport connection).
- `server`: the server's own device answers remote device management at
  its individual address (the device, router and KNXnet/IP parameter
  objects, with property descriptions); `server.WithToolKey` secures it
  and adds a security object (type 17, security mode on). The friendly
  name is writable, locally (M_PropWrite) and remotely.
- `interop/node`: container contract 1.4 (`remote-property`, `server
  --tool-access`).

## Changes

- Tool access is authenticated by the tool key alone: any tool that has
  it may synchronise with a device, and tool access sequence numbers are
  kept per peer apart from the group senders (before, an S-A_Sync_Req from
  a sender missing from the table was refused).
- The interop suite pins knx-interop v0.6.0 (contract 1.4).

## Interoperability

knx-interop v0.6.0 matrix with go-knx's node: 448 pass, 7 known
differences, 0 fail.

- Calimero tools 3.0-M1 → go-knx's device: property read (connectionless
  and in a connection), write, description, device information, plain and
  with tool access; plain access to the secured device is refused.
- xknx 4.0.0 → go-knx's device: read and write in a transport connection.
- go-knx → Calimero server 3.0-M1's device: read (connectionless and in a
  connection) and write. Calimero server has no tool key access, so the
  secured tool side of go-knx is verified against go-knx only.
- Calimero tools computes the Data Secure MAC over the source address it
  sends (0.0.0 unless given its address with `-k`), which a tunnelling
  server replaces; go-knx sets the tunnel address.

---

## v0.4.2

**Date:** 2026-10-30
**Previous release:** v0.4.1

## Changes

- go-knx now owns its interop adapter: `interop/node` implements the
  knx-interop container contract 1.3 on the library itself (server and
  client roles, KNX IP Secure, Data Secure, the surrogate role, secure
  routing). knx-interop v0.5.0 tests third-party stacks only and takes a
  system under test as an external adapter.
- `make interop-matrix` runs the knx-interop v0.5.0 matrix with go-knx's
  node as an external adapter (gate: go-knx); the Interop workflow runs it
  and publishes the report.
- The interop suite pins knx-interop v0.5.0.

---

## v0.4.1

**Date:** 2026-10-30
**Previous release:** v0.4.0

## Changes

- The interop suite pins knx-interop v0.4.0 (container contract 1.3: secure
  sessions over UDP, the servers' secure routing, Calimero tools' Data
  Secure through go-knx as the surrogate; full matrix 423 pass, 0 fail).
- server: with listen port 0 and TCP on, the server now finds a port free
  for both UDP and TCP; before, TCP was disabled (with a warning) when the
  ephemeral UDP port was taken for TCP.
- README badges as in the sibling libraries.

---

## v0.4.0

**Date:** 2026-10-30
**Previous release:** v0.3.1

## Summary

The KNX Secure gaps of v0.3.0 closed: S-A_Sync and the surrogate role,
so that Calimero tools can send Data Secure telegrams to go-knx; secure
sessions over UDP; secure routing in the server.

## Added

- `datasecure`: S-A_Sync request and response (`SyncRequest`,
  `OpenSyncRequest`, `SyncResponse`, `OpenSyncResponse`), verified against
  the Application Layer Annex C examples (as reproduced by xknx's open
  work) and a Calimero capture; tool keys in the table (`SetToolKey`,
  `Respond`, `OpenTool`, `SealTool`); `keyring.DataSecure` loads the
  devices' tool keys.
- `client`: with Data Secure, the client answers S-A_Sync and group object
  diagnostics addressed to it as the surrogate of a secured group: it
  sends the group telegram for the tool and delivers it to its own
  subscribers too.
- `tunnel.WithUDP`: KNX IP Secure sessions over UDP; `server.WithSecure`
  serves them (sessions bound to the client's address, idle sessions end).
- `server.WithSecureRouting`: the server's routing with the backbone key
  (timer synchronisation, plain routing frames dropped, Security in the
  secured services DIB).
- `apdu`: A_FunctionPropertyExt_Command/_StateRead/_StateResponse.

## Interoperability

Verified by hand: Calimero tools → go-knx Data Secure through the
surrogate over secure routing; secure sessions over UDP with Calimero
tools and Calimero server (also device management); the server's secure
routing with xknx and Calimero tools. Automated in knx-interop's next
contract version.

---

## v0.3.1

**Date:** 2026-10-30
**Previous release:** v0.3.0

## Changes

- The interop suite pins knx-interop v0.3.0 (container contract 1.2) and
  tests KNX Secure with its public test profile: xknx and Calimero tools
  open secure sessions to go-knx's secure server (bound user addresses,
  write, read, Data Secure decrypted with the profile key, device
  management as user 1), and go-knx's secure client works against
  Calimero's secure server (write seen and Data Secure decrypted by xknx,
  device management, plain connection refused). No library changes.

---

## v0.3.0

**Date:** 2026-10-30
**Previous release:** v0.2.1

## Summary

KNX IP Secure and KNX Data Secure, implemented from public sources (xknx's
MIT implementation and the KNX keyring article; the application notes
were not available) and verified for interoperability with xknx 4.0.0 and
Calimero 3.0-M1. This is not a claim of conformance or certification.

## Added

- `secure`: key derivations, AES-CCM sealing of SECURE_WRAPPER, session
  handshake (X25519, SESSION_RESPONSE and SESSION_AUTHENTICATE MACs),
  sessions with replay protection, TIMER_NOTIFY and the secure routing
  timer (time keeper and follower).
- `tunnel.WithSecure`: secure tunnelling over TCP, with keep alive and
  verification of the server's device authentication code.
- `server.WithSecure`: a secure KNXnet/IP server — secure sessions, users
  bound to tunnelling addresses, device management for user 1, plain
  connections refused, Security family and secured services DIB.
- `routing.WithSecure`: secure routing with the backbone key.
- `datasecure`: S-A_Data for group communication and the security tables;
  `client.WithDataSecure` and `Telegram.Secure`.
- `keyring`: ETS keyrings — signature check, decryption, lookups,
  credentials, Data Secure tables, writing test keyrings.

## Not included

- Data Secure S-A_Sync and point to point security; secure sessions over
  UDP; secure routing in the server.

## Interoperability

Verified by hand (INTEROPERABILITY.md): secure tunnelling with xknx and
Calimero tools as clients and Calimero server as server, secure device
management with Calimero, secure routing both ways with xknx and
Calimero tools, Data Secure both ways with xknx and from go-knx to
Calimero tools. Calimero tools cannot yet send Data Secure telegrams to
go-knx (they need S-A_Sync).

---

## v0.2.1

**Date:** 2026-10-29
**Previous release:** v0.2.0

## Changes

- The interop suite pins knx-interop v0.2.0 (container contract 1.1) and
  tests more of the server against independent clients: xknx and Calimero
  tools over TCP (write, read), Calimero tools' device management (serial
  number) and busmonitor (a telegram of the server, decoded from the TP1
  frame). No library changes.

---

## v0.2.0

**Date:** 2026-10-29
**Previous release:** v0.1.1

## Summary

KNXnet/IP over TCP, tunnelling feature services, device management and
busmonitor, in the client and in the server.

## Additions

- **TCP** (KNXnet/IP core v2): `tunnel.WithTCP()`; the server accepts TCP
  on its port (`server.WithTCP`, default on) and announces core v2 and
  tunnelling v2. No TUNNELLING_ACKs over TCP; connections end with their
  TCP connection.
- **Tunnelling feature services** (v2): `Conn.FeatureGet`,
  `Conn.FeatureSet`; the server answers supported and active EMI type,
  device descriptor, bus connection status, manufacturer code, individual
  address, maximum APDU length and the info service switch.
- **Device management**: package `devmgmt` (`PropRead`, `PropElements`,
  `PropWrite`, `PropertyError`), `tunnel.WithDeviceManagement`; the server
  answers M_PropRead.req for its device, router and KNXnet/IP parameter
  objects, including the interface object list tools address objects by.
- **Busmonitor**: `tunnel.WithLayer(knxnetip.TunnelBusmonitor)` receives
  L_Busmon.ind; `cemi.TP1Frame` and `cemi.ParseTP1` (fuzzed) encode and
  decode TP1 standard frames with the check octet. The server sends
  L_Busmon.ind to busmonitor connections; busmonitor and link layer
  tunnelling exclude each other unless `server.WithConcurrentBusmonitor`.

## Fixes

- **Search request parameter types** of SEARCH_REQUEST_EXTENDED were one
  too high (`knxnetip.SRPProgrammingMode` was 0x02 and so on). They are now
  0x00 invalid, 0x01 programming mode, 0x02 MAC address, 0x03 service,
  0x04 request DIBs, as Calimero and xknx define them. Found because xknx's
  describe, once the server announced core v2, sends an extended search
  with "request DIBs" (0x04), which the server took for "select by
  service" and did not answer.
- Feature frames of the server consume the client's receive sequence
  number (found with the new feature services).

## Verification

go-knx's interop suite against knx-interop v0.1.0 images: TCP tunnel and
feature services, device management (UDP, TCP) against calimero-server
3.0-M1; busmonitor against knxd 0.14.73 (TP1 frames and check octets of
knxd decoded). By hand: Calimero tools over TCP, `get --local` and
`monitor` against the go-knx server.

---

## v0.1.1

**Date:** 2026-10-29
**Previous release:** v0.1.0

## Changes

- The interop suite pins knx-interop v0.1.0: the xknx and KNXUltimate
  images by digest from GHCR; the Calimero and knxd images (GPL binaries,
  never published) built from the v0.1.0 tag. No library changes.

---

## v0.1.0

**Date:** 2026-10-29
**Previous release:** none

## Summary

The first release: KNX addresses, KNXnet/IP frames, cEMI, TPCI/APCI and
209 datapoint subtypes; discovery; a tunnelling client over UDP with
retransmission, heartbeats, NAT and reconnection; routing; group
communication; and a KNXnet/IP server with virtual devices.
Interoperability verified both ways against Calimero 3.0-M1 and knxd
0.14.73, and against xknx 4.0.0 and KNXUltimate 6.3.1 as clients and
routing peers, in the knx-interop matrix and this repository's interop
suite (amd64 and arm64). Coverage 97.7 %.

Fixes found by the interoperability tests: route back data endpoints for
NAT clients, a default routing source address (routers drop 0.0.0), ACK
status handling, write deadlines on multicast sends, ordering of
disconnect metrics and responses.

## Not included

KNXnet/IP over TCP, tunnelling feature services, device management
connections, busmonitor, KNX IP Secure, KNX Data Secure.

---
