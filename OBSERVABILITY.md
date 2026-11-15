# Observability

## Logging

Every networking type takes a `knx.Logger` (`WithLogger`). Logging is
silent by default. Adapters: `knx.NewStdLogger(*log.Logger)`,
`knx.NewSlogLogger(slog.Handler)` (structured; implements `FieldLogger` and
`ContextLogger`). Logged events: connection state changes (info),
repetitions, drops and ignored frames, replies that cannot be encoded,
read and accept errors of a socket, answers a client with Data Secure
could not queue (debug), lost connections and full queues (warn), and an
application callback that did not return normally (error, see below).
Telegram contents are logged at debug level only.

## Application callbacks

`client.Client.OnTelegram`, `server.Server.Subscribe` and the `OnChange`
handler of a virtual device in a server run on a goroutine of the library,
with none of its locks held. A callback that does not return normally is
stopped where the library called it and logged at error level, as
`<callback> did not return normally: <value>` followed by the stack of the
goroutine (`client.OnTelegram`, `server.Subscribe`, `device.Device.Handle`);
the reader or the server goes on as if it had returned. The callbacks of
`knx.Logger`, `knx.Metrics` and `tunnel.WithStateHandler` are called as
they are.

## Metrics

`knx.Metrics` (embed `knx.NopMetrics`) is called synchronously on the
protocol path:

| Callback | When |
|---|---|
| `OnConnect(remote, channel)` | a tunnelling connection is established (client) or accepted (server) |
| `OnDisconnect(remote, channel, err)` | it ends; `err` nil on a normal close |
| `OnFrameSent(remote, service, size)` / `OnFrameReceived` | every KNXnet/IP frame |
| `OnDecodeError(remote, err)` | a datagram or cEMI frame that did not decode |
| `OnRetransmit(remote, channel)` | a tunnelling request repeated for a missing ACK |
| `OnDropped(remote, reason)` | a frame or telegram that decoded and was not delivered; the reasons are listed below |

## Drop reasons

The `reason` of `OnDropped` is one of these constant strings
(`TestDropReasonsDocumented` compares this table with the code):

| Reason | Reported by | When |
|---|---|---|
| `queue_full` | tunnel, routing, server | the inbound queue of a `tunnel.Conn` or `routing.Conn`, or the send queue of a server's connection, is full |
| `duplicate` | tunnel, server | a request repeated with the previous sequence number: acknowledged again, not delivered |
| `sequence` | tunnel, server | a request with a sequence number that is neither the expected nor the previous one |
| `foreign_source` | tunnel | a datagram from another address than the server's |
| `unknown_channel` | server | a tunnelling or device configuration request for a channel that does not exist, or from another endpoint than its client's |
| `routing_rate` | server | the routing send queue is full: the rate or a ROUTING_BUSY holds it |
| `source_address` | server | a secure tunnel's telegram with another source than the tunnel's address |
| `session_replaced` | server | a secure session or TCP connection that had not authenticated, replaced when all were taken |
| `session` | server, routing | a SECURE_WRAPPER of a session the server does not have, or from another address than the session's; in secure routing, a wrapper with a session identifier |
| `session_started` | server | a second SESSION_REQUEST on a TCP connection that has a session |
| `no_session` | server | a SECURE_WRAPPER on a TCP connection without a session |
| `no_security` | server | a SESSION_REQUEST to a server without secure tunnelling, or a routing SECURE_WRAPPER to one without secure routing |
| `unsecured` | server, routing | a plain frame where only secured ones are taken: on a TCP connection of a secure server, or a routing frame with secure routing |
| `authentication` | server, routing | a TIMER_NOTIFY whose MAC does not verify |
| `timer` | server, routing | a routing SECURE_WRAPPER whose timer value is outdated, that was accepted before, or that does not fit the remembered frames |
| `timer_unsynchronised` | server, routing | a routing SECURE_WRAPPER before the timer synchronisation has ended |
| `unexpected` | server | a routing SECURE_WRAPPER that carries another frame than a routing one |

## State

`tunnel.WithStateHandler(func(knx.State, error))` reports connecting,
connected, reconnecting and closed; `Conn.State()`, `Conn.Done()` and
`Conn.Err()` expose the same. `server.Server.Connections()` lists the open
tunnelling connections with their last heartbeat; `Server.Subscribe` taps
every telegram on the virtual network.
