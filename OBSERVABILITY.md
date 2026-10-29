# Observability

## Logging

Every networking type takes a `knx.Logger` (`WithLogger`). Logging is
silent by default. Adapters: `knx.NewStdLogger(*log.Logger)`,
`knx.NewSlogLogger(slog.Handler)` (structured; implements `FieldLogger` and
`ContextLogger`). Logged events: connection state changes (info),
repetitions, drops and ignored frames (debug), lost connections and full
queues (warn). Telegram contents are logged at debug level only.

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
| `OnDropped(remote, reason)` | a telegram dropped: `queue_full`, `duplicate`, `sequence`, `foreign_source`, `unknown_channel`, `routing_rate` |

## State

`tunnel.WithStateHandler(func(knx.State, error))` reports connecting,
connected, reconnecting and closed; `Conn.State()`, `Conn.Done()` and
`Conn.Err()` expose the same. `server.Server.Connections()` lists the open
tunnelling connections with their last heartbeat; `Server.Subscribe` taps
every telegram on the virtual network.
