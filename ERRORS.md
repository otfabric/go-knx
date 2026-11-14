# Errors

Every error matches one of the sentinels of the root package with
`errors.Is`; most are wrapped with detail.

| Sentinel | Meaning | Typical source |
|---|---|---|
| `knx.ErrInvalidAddress` | An address out of range or in no accepted presentation | `ParseGroupAddress`, `ParseIndividualAddress` |
| `knx.ErrMalformed` | A frame that cannot be decoded | every decoder |
| `knx.ErrUnsupported` | A service, protocol version, datapoint type or feature not implemented | decoders, `dpt.Lookup`, `apdu.ParseGroupValue` |
| `knx.ErrInvalidOption` | An option or argument a function cannot be called with | constructors, `dpt.ParseID` |
| `knx.ErrInvalidValue` | A value outside its type's range, data of the wrong size, a frame that would not encode to a valid one | `dpt.Type.Encode/Decode`, encoders |
| `knx.ErrClosed` | The connection, client or server was closed | every type with Close |
| `knx.ErrTimeout` | No answer in time: CONNECT_RESPONSE, DESCRIPTION_RESPONSE, group read | tunnel, discovery, client |
| `knx.ErrConnectionLost` | The tunnel is gone: no ACK twice, heartbeat failed, server disconnected; over TCP, a write the server does not take within the request timeout | tunnel |
| `knx.ErrRejected` | The peer refused with a KNXnet/IP status code | tunnel (CONNECT_RESPONSE, TUNNELLING_ACK) |
| `knx.ErrBusy` | A limit: E_NO_MORE_CONNECTIONS, E_NO_MORE_UNIQUE_CONNECTIONS, a full queue | tunnel |
| `knx.ErrNotConfirmed` | The L_Data.con reported an error or did not arrive | tunnel.Send |
| `knx.ErrSecurity` | A KNX IP Secure or KNX Data Secure failure: a tag that does not verify, a replayed sequence number, a missing key, an exhausted sending sequence. Secure connections never fall back to plain ones | secure, datasecure, keyring |
| `keyring.ErrSignature` | A keyring file whose signature does not verify: the password is wrong or the file was modified. Nothing of the file is used. Matches `knx.ErrSecurity` | `keyring.Parse`, `keyring.Load`, `keyring.LoadFile` |
| `knx.ErrMalformed` (keyring) | A keyring over 4 MiB, nested deeper than 64 levels, with more than 262144 elements, duplicate attributes, mismatched end tags or a latency outside 0..65535 ms; refused before the signature is checked, nothing of the file is used | `keyring.Parse`, `keyring.Load`, `keyring.LoadFile` |

No operation is retried implicitly. `ErrConnectionLost` or
`ErrNotConfirmed` from `tunnel.Conn.Send` leaves open whether the frame
reached the bus; after a reconnect (`tunnel.WithReconnect`) it is not
resent on the new channel. Repeat it only where that is safe.

`*knxnetip.StatusError` carries the service and the status code
(`knxnetip.StatusOf(err)`); it matches `ErrRejected`, and `ErrBusy` for the
connection-exhaustion codes. Three more error types carry the detail of
a refusal and match `ErrRejected`:

- `*tunnel.FeatureError`: a TUNNELLING_FEATURE_RESPONSE with a return
  code other than E_NO_ERROR (the feature and the return code).
- `*mgmt.PropertyError`: a negative A_PropertyValue_Response or
  A_PropertyDescription_Response (the device, object and property).
- `*devmgmt.PropertyError`: a negative cEMI device management
  confirmation (the object type, property and cEMI error code).

`dpt.ErrFloat16Invalid` is DPT 9's "invalid
data" value 0x7FFF.
