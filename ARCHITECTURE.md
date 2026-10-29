# go-knx architecture

## Layers

```
            application
   ┌────────────┴─────────────┐
   │ client (group read/write,│   server (KNXnet/IP server)
   │ respond, subscriptions)  │      │           │
   └──────┬───────────┬───────┘      │        device (group objects, flags)
       tunnel      routing        discovery responder, tunnelling channels,
   (UDP client)  (multicast)      routing, virtual network
          │           │              │
          └─────┬─────┴──────────────┘
           knxnetip (frames)   discovery (search/describe)
                │
              cemi (L_Data, M_Prop...)
                │
              apdu (TPCI/APCI)          dpt (datapoint types)
                │
               knx (addresses, errors, Logger, Metrics, State)
```

- **Codecs** (`knxnetip`, `cemi`, `apdu`, `dpt`) are pure functions over
  byte slices: no I/O, no goroutines, no global state except the DPT
  registry (built at init, read-only). They decode strictly, never panic,
  and the KNXnet/IP encoder refuses to produce a frame its own decoder
  would reject.
- `knxnetip` keeps cEMI frames as octets and `cemi` keeps the TPDU as
  octets, so that each layer can be used and tested alone and unknown
  content passes through unchanged.
- **Transports** (`tunnel`, `routing`) move cEMI frames. Both implement
  `client.Link` (Send, Receive, Close).
- **Application** (`client`) turns group telegrams into calls and events;
  it does not know whether it runs over a tunnel or routing.
- **Server** (`server`, `device`) is the other side: a KNXnet/IP server
  with a virtual network behind it.

## Concurrency and resource ownership

| Type | Goroutines | Ends on |
|---|---|---|
| `tunnel.Conn` | reader, heartbeat, supervisor (reconnect) | `Close`, or a lost connection without reconnect |
| `routing.Conn` | reader | `Close` |
| `client.Client` | reader of its link | `Close` (closes the link) or link failure |
| `server.Server` | reader per socket, janitor, one sender per tunnelling connection (bounded by the number of tunnelling addresses) | `Close` |

Every queue is bounded (inbound telegrams, per-connection sends,
subscriptions); when one is full the telegram is dropped and
`Metrics.OnDropped` is called. Every wait has a deadline or a context.
`Close` is idempotent and returns after all goroutines have ended (tested
with `internal/leak`).

## Tunnelling client state machine

```
disconnected ──Dial──▶ connecting ──CONNECT_RESPONSE E_NO_ERROR──▶ connected
connecting ──refusal / no response in 10 s──▶ closed (Dial returns the error)
connected ──Send: request, wait 1 s for TUNNELLING_ACK, repeat once──▶ connected
connected ──second ACK missing / heartbeat failed 3× / server DISCONNECT_REQUEST──▶ lost
lost ──WithReconnect──▶ reconnecting ──backoff 1 s … 30 s──▶ connected (new channel, counters reset)
lost ──otherwise──▶ closed (Err() matches knx.ErrConnectionLost)
any ──Close──▶ DISCONNECT_REQUEST (wait ≤ 1 s) ──▶ closed
```

Receiving: a TUNNELLING_REQUEST with the expected sequence number is
acknowledged and delivered; the previous number (a repetition whose ACK
was lost) is acknowledged and dropped; any other is dropped without ACK.
Sending allows one unacknowledged request at a time; an L_Data.req also
waits for its L_Data.con (3 s) unless `WithConfirm(false)`.

## Server

- One UDP socket on port 3671 (unicast and, when discovery or routing is
  on, the multicast group). Search requests, description requests and
  connection management are answered from it.
- Each tunnelling connection holds one of the configured tunnelling
  addresses; the number of addresses is the connection limit.
- A client's L_Data.req is acknowledged, confirmed to it (L_Data.con) and
  distributed as L_Data.ind to the other clients, the virtual devices and,
  with routing, the multicast group. Devices' responses are distributed the
  same way. Indications received from the multicast group reach clients
  and devices but are never routed back.
- Connections without a heartbeat for 120 s are closed; a client that does
  not acknowledge a request twice is disconnected.
- NAT: a client that sends route back HPAIs gets route back endpoints in
  the CONNECT_RESPONSE, and answers go to the datagrams' sources.

## Decisions

- **Group reads return the first response** (`GroupRead`) or every response
  in a window (`GroupReadAll`). No response is guaranteed; several devices
  may answer; a late answer to an earlier read is indistinguishable from an
  answer to a new one (the protocol carries no correlation).
- **DPT 9 encoding** chooses the smallest exponent and rounds the mantissa
  half away from zero; xknx rounds half to even, which differs only for
  exact ties (documented in `dpt/xknx_test.go`). The largest encodable
  value is 670 433.28: 0x7FFF means "invalid data".
- **Standard and extended frames**: an L_Data whose NPDU exceeds 15 octets
  must be an extended frame, on encode and on decode.
- **Routing safety**: 50 indications per second by default, ROUTING_BUSY
  respected, hop count 0 never routed.
