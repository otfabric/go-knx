# Limitations

What go-knx does not do, or does with restrictions. Feature status:
[docs/IMPLEMENTATION-STATUS.md](docs/IMPLEMENTATION-STATUS.md). Evidence:
[INTEROPERABILITY.md](INTEROPERABILITY.md).

## Certification and conformance

- **Nothing here is certified**: go-knx is not KNX certified and claims no
  conformance to the KNX standard
  ([docs/standards/CONFORMANCE.md](docs/standards/CONFORMANCE.md)).
- KNX IP Secure and KNX Data Secure are implemented from public sources and
  verified against xknx and Calimero; conformance to AN158/AN159 is not
  established.
- Passing the interop suites shows that go-knx and those stacks agree with
  each other, not that any of them conforms.
- No physical KNX IP interface or router has been tested.

## Not implemented

- KNX TP and RF media (TP1 frames are handled for busmonitor only), ETS
  project import, KNX IoT.
- Device-to-device link keys and secure commissioning (FDSK).
- Remote device management: no memory, restart or ADC services.

## Restrictions

- **Tool access as a tool** is verified against go-knx's own device only: no
  third-party device with tool access was available.
- **Secure device management** uses user 1 (the management user) only.
- **Virtual devices** are application layer only.
- **Server properties**: the friendly name is writable; the other properties
  of the device management connection are read only.
- **Standard frames** carry an NPDU of at most 15 octets, enforced on encode
  and decode.

Decisions where public sources leave a choice (rounding ties, timer start,
NAT endpoints) are listed under "Deviations and decisions" in
[docs/IMPLEMENTATION-STATUS.md](docs/IMPLEMENTATION-STATUS.md).
