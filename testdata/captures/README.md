# Recorded KNX traffic

Captures recorded by others, committed byte-identical, and what go-knx
makes of them. Two transports are kept apart throughout:

- **KNX TP1**: frames of a twisted-pair line, as the bus carries them
  (control field to check octet). go-knx decodes them with
  `cemi.ParseTP1` and encodes them with `cemi.TP1Frame`, as for
  busmonitor; it has no TP1 interface of its own.
- **KNXnet/IP**: frames over UDP and TCP (tunnelling, routing, device
  management, KNX IP Secure), and the cEMI frames they carry.

This is recorded traffic, replayed: not a test against a live device, and
not a conformance claim.

## Sources and terms

| Directory | Source | Revision | Terms (as stated) |
|---|---|---|---|
| `knx-datasets/` | [vgraveto/knx-datasets](https://github.com/vgraveto/knx-datasets), also IEEE DataPort DOI 10.21227/16a5-m134 | commit `c649ad65ea64276572905781d860a5b0a374e7fc` | MIT licence |
| `wireshark/` | Wireshark test captures (`test/captures`) | commit `0bb30bc152617526072bd82e62781f3978169f02` | Distributed with Wireshark; no licence statement for the captures |
| `wireshark-14825/` | Attachments of [Wireshark issue 14825](https://gitlab.com/wireshark/wireshark/-/issues/14825) (2018, "Replace KNXIP dissector") | the nine text files attached individually, byte-identical to `KnxipCaptures.zip` (SHA256 `af1f268c…ad5ab`) | No licence statement |

[manifest.json](manifest.json) records for every file its original name
and URL, size, SHA256, format, evidence class and basis, privacy notes,
go-knx's counts and the independent decoder's counts; it also lists the
files of the sources that are not committed, and why. The files are
byte-identical to their sources, checked by [SHA256SUMS](SHA256SUMS)
(`make captures-verify`, in CI). The knx-datasets CSV exports (89-91 MB
each, the authors' own decode) are not committed: [CACHED](CACHED) lists
them with their SHA256, `make captures-fetch` downloads them into the
git-ignored `cache/`, and `make captures-extended` (nightly) compares every
TP1 frame with them.

## Names

`<client>_<device>_<operation>.<ext>`, lower case, words joined by
hyphens, original extension.

| File | Original name | Class |
|---|---|:-:|
| `knx-datasets/unknown_residential-tp1_all-knx.pcapng` | `Dataset/Original/all_KNX.pcapng` | B |
| `knx-datasets/attack-tool_residential-tp1_line-scan.pcapng` | `Dataset/LS/all_KNX_LS.pcapng` | B |
| `knx-datasets/attack-tool_residential-tp1_device-info.pcapng` | `Dataset/DI/all_KNX_DI.pcapng` | B |
| `wireshark-14825/test-tool_abb-ipr-s_00-setup.txt` … `_08-systembroadcast.txt` | `00_Setup.txt` … `08_SystemBroadcast.txt` | B |
| `wireshark/wireshark-test_synthetic_knxip-datasec.pcap` | `knxip_DataSec.pcap` | C |
| `wireshark/wireshark-test_synthetic_knxip-securewrapper.pcap` | `knxip_SecureWrapper.pcap` | C |
| `wireshark/wireshark-test_synthetic_knxip-timernotify.pcap` | `knxip_TimerNotify.pcap` | C |
| `wireshark/wireshark-test_synthetic_knxip-coverage.pcap.gz` | `knxip_coverage.pcap.gz` | E |
| `wireshark/wireshark-test_synthetic_knxip-decrypt-coverage.pcap.gz` | `knxip_decrypt_coverage.pcap.gz` | E |
| `wireshark/wireshark-test_synthetic_cemi-coverage.pcap.gz` | `cemi_coverage.pcap.gz` | E |

## Evidence classes

A verified physical-device traffic · B credibly documented physical-device
traffic · C recorded traffic, hardware origin unknown · D simulated or
software testbed · E standards-derived or generated. Only A and B support a
statement about real devices; nothing here is class A.

- **knx-datasets (B)**: the README documents a KNX TP1 installation in a
  single-family house (lighting, blinds, heating, alarm, a touch panel),
  recorded without interruption from 2020-03-07 to 2020-04-13, 379 875
  frames. It names neither the capture interface nor any device model. The
  line scan (LS) and device info (DI) sets add attack frames from
  individual address 1.1.102, run on the real installation, and the
  devices' answers, merged into the normal recording with shifted time
  stamps. The device descriptors the devices answer (mask versions 0013,
  0021, 0701 and 07B0) are in the traffic; no model.
- **wireshark-14825 (B)**: Ethernet traffic between a test client
  (192.168.0.100, not identified) and KNXnet/IP devices, recorded in 2018;
  Wireshark's test suite calls them "realistic (live captured) KNX/IP
  telegram sequences". The devices name themselves in their DEVICE_INFO
  blocks: **ABB IP-Router IPR/S** (MAC 00:0c:de:02:80:8e, serial
  0002:81FDFF50, at 192.168.0.10 and later 192.168.0.11) and **ABB
  IPS/S2.1** (MAC 00:0c:de:9e:50:54, serial 0002:549EFF50, at
  192.168.0.222); 00:0c:de is ABB's IEEE OUI. No firmware version is in the
  traffic. The client sends deliberately malformed frames
  (conformance-style negative cases).
- **wireshark (C, E)**: Wireshark's own test captures. Three hold one
  telegram each, origin not stated (C); the three coverage files are
  synthetic by Wireshark's own description (E). Their keys are Wireshark's
  published test keys (`kip.key_1` 00 01 … 0F, and `test/keys/knx_keyring.xml`
  B0 … BF).

## Capture format

- **knx-datasets**: pcapng written by gopacket. The interface declares link
  type 0 (DLT_NULL), but every packet is a whole TP1 frame (control field,
  source, destination, address type / hop count / length, TPDU, check
  octet) without a loopback header; tshark therefore shows a bogus
  "Null/Loopback" family. `internal/capture` reads link type 0 as TP1
  (`capture.TPLinkType`) and nothing else as TP1. All 1 150 094 frames
  are standard frames with a correct check octet; the acknowledgement
  character is not recorded.
- **wireshark-14825**: K12 text files (Ethernet); the file holds no date,
  time stamps are times of day.
- **wireshark**: pcap, three gzip-compressed.

## What the tests do

| Test | What |
|---|---|
| `internal/capture` `TestCorpus` | Every capture: SHA256; go-knx's decode and re-encode counts equal the manifest; TP1 services equal the dataset authors' CSV decode; KNXnet/IP service and cEMI message codes equal Wireshark 4.6.9's but for the classified differences below |
| `internal/capture` `TestCorpusCSV` (extended) | Every TP1 frame against its CSV row: octets, check octet, source, destination, service, value (1 150 094 rows) |
| `cemi` `TestCaptureTP1` | Every TP1 frame decodes and encodes again byte for byte, repetitions included; cEMI round trip |
| `knxnetip` `TestCaptureFrames`, `TestCaptureDeviceIdentity` | Every KNXnet/IP frame decodes and encodes again byte for byte (TCP also through `ReadFrame`); the devices' identities equal Wireshark's |
| `discovery` `TestCaptureExtendedSearchABB` | An extended search answered with the ABB router's recorded response finds the router |
| `secure`, `datasecure` `TestCapture*` | SECURE_WRAPPER, TIMER_NOTIFY and S-A_Data opened with the published test keys, with the results Wireshark reports; the placeholder MACs fail |
| `mgmt` `TestCaptureResponderReplay`, `TestCaptureConnectionTimeout` | The requests the management tool sent the house's devices, sent to `mgmt.Responder`; answers compared with the devices' |
| `client` `TestCaptureDescriptorRead`, `TestCaptureGroupTelegrams` | `client.Device.DescriptorRead` against the devices' recorded answers (145 reads); the five weeks of group telegrams through the client |
| `server` `TestCaptureConnectionManagement` | The client's 1 063 connection management requests to the ABB router, replayed on a go-knx server; statuses compared |

Fuzz seeds from the recordings are in `cemi/testdata/fuzz/FuzzParseTP1`,
`apdu/testdata/fuzz/FuzzParse` and `knxnetip/testdata/fuzz/FuzzParse`.

## Comparison rules

- **TP1**: frames are compared octet for octet. Time stamps are not
  compared (the LS and DI sets shifted them). Hop counts of answers are not
  compared in the management replay: line couplers change them (requests
  arrive with 5, many answers with 6).
- **Management replay** (`mgmt`): requests are grouped with their
  link-layer repetitions (repeat flag clear, same octets); the device's
  frames up to the client's next request are its answers. The line scan
  also addressed 1.1.102, the address the tool used itself; the
  installation's own 1.1.102 answered. Those frames cannot be told apart
  by address and are skipped.
- **Server replay** (`server`): each recorded client endpoint is a socket
  of its own, and the HPAIs of a request name it; channels are mapped from
  the router's to go-knx's. Where the recording shows the router's state
  change without a request (restart after M_Reset.req, 120 s alive time,
  a channel number assigned again), the replay ends go-knx's connections
  in its place. Answers are compared by service and status.
- **Wireshark counts**: frames inside ICMP error messages are not counted.

## Results

| | TP1 | KNXnet/IP |
|---|---:|---:|
| Frames | 1 150 094 | 46 059 |
| Decoded | 1 150 094 | 46 026 |
| Re-encoded byte for byte | 1 150 094 | 46 026 (all decoded) |
| cEMI frames decoded / re-encoded | 1 150 094 (as L_Data.ind) | 19 625 of 19 640 / all decoded |

TP1 services (all three sets): A_GroupValue_Write 1 139 613,
A_GroupValue_Response 9, A_GroupValue_Read 3, T_Connect 1 383,
T_Disconnect 582, T_ACK 4 252, A_DeviceDescriptor_Read 506 and _Response
146, A_Memory_Read 2 160 and _Response 540, A_ADC_Read 720 and _Response
180; equal to the authors' CSV decode in every row.

### Production defects found and fixed

| Defect | Evidence | Regression test |
|---|---|---|
| `cemi.TP1Frame` always wrote "not repeated": a repeated frame (control 0x90, 0x9C) decoded by `ParseTP1` did not encode back, and the server's busmonitor showed a repeated L_Data.ind as an original | 6 414 repeated frames in the three TP1 sets (10 in normal operation) | `cemi` `TestTP1RepeatedFrameRoundTrip`, `TestCaptureTP1` |
| `knxnetip.ParseDIBs` refused a whole description or search response for one malformed optional block: go-knx's discovery did not see the ABB IP-Router IPR/S, whose TUNNELLING_INFO (22 octets, no maximum APDU length) and SECURED_SERVICE_FAMILIES (11 octets) blocks have another layout | 91 SEARCH_RESPONSE_EXTENDED frames of the router (over UDP and TCP); Wireshark marks both blocks malformed too | `knxnetip` `TestRecordedMalformedOptionalDIB`, `TestCaptureDeviceIdentity`; `discovery` `TestCaptureExtendedSearchABB` |
| `mgmt.Responder` ended an idle transport connection silently; the devices send T_Disconnect when their connection timeout expires | 75 devices of the line scan disconnect 5 to 13 s after an idle T_Connect | `mgmt` `TestCaptureConnectionTimeout` |

### Classified differences

| Where | Difference | Class |
|---|---|---|
| mgmt replay, DI | A_Memory_Read (2 160 with repetitions) and A_ADC_Read: the Responder acknowledges and does not answer (720 exchanges) | unsupported feature |
| mgmt replay, LS and DI | The devices answered a request and its link-layer repetitions once; the Responder acknowledges each repetition of a T_Data_Connected again, as the transport layer does for a repeated sequence number (120 exchanges) | implementation-specific: the devices' TP1 data link layer drops the repetitions; the Responder has no data link layer |
| mgmt timeout | Six devices disconnected 5.0 to 6.0 s after the first T_Connect; the Responder after 6 s | legitimate variation (timer granularity) |
| server replay | 47 of 1 063 answers differ (8 more follow from them), all where the router's configuration or state is not the replay server's: tunnelling addresses rewritten by the client (E_NO_MORE_UNIQUE_CONNECTIONS, established), KNX IP Secure set up (E_CONNECTION_TYPE), connections over TCP or secure sessions the replay does not see (E_NO_MORE_CONNECTIONS), bus disconnected (E_KNX_CONNECTION) | vendor/configuration difference; evidence incomplete beyond the first |
| server replay | The router restarts on M_Reset.req; go-knx's virtual server does not (9 resets) | implementation-specific (documented decision) |
| KNXnet/IP decode | 33 frames go-knx refuses: 26 negative cases of the test client (wrong header length or version, total length beyond the datagram, short HPAI, CRI length, TIMER_NOTIFY and SESSION_REQUEST lengths, a 65 535-octet SECURE_WRAPPER over TCP); Wireshark marks them malformed or short as well | legitimate (malformed input) |
| KNXnet/IP decode | 7 synthetic SECURE_WRAPPERs of 0 to 5 encrypted octets (Wireshark coverage): go-knx requires a whole KNXnet/IP frame (6 octets) inside | legitimate variation (synthetic E) |
| cEMI decode | 14 synthetic L_Data.ind with the standard frame type and an NPDU of 16 to 248 octets (Wireshark cEMI coverage): go-knx refuses a standard frame over 15 octets | legitimate variation (synthetic E) |
| cEMI decode | One M_PropRead.req of 4 octets from the test client | malformed input |
| cEMI | Transport layer message codes 0x41, 0x89, 0x4A, 0x94 (T_Data_Connected.req/.ind, T_Data_Individual.req/.ind; 5 880 frames, nearly all the ABB devices' local management, and the Data Secure telegram of `knxip_DataSec.pcap`) decode as `cemi.Unknown` and re-encode byte for byte | unsupported feature |
| KNXnet/IP | Remote diagnosis and configuration (0x0740-0x0744, 137 frames) decode as `knxnetip.Unknown` | unsupported feature |
| Wireshark counts | TCP port 2152 is dissected as GTP; streams whose start Wireshark missed show as "Continuation Data"; UDP port 3672 is not dissected as KNXnet/IP (counts pinned in `internal/capture/corpus_test.go`) | oracle limitation |
| TP1 group values | The dataset documents no datapoint types; values are compared as octets only, not decoded with a DPT | evidence incomplete |

## Privacy

- knx-datasets: addresses, group values and their times of a family home;
  no names, keys or credentials. The CSV exports (not committed) add room
  names from the ETS project.
- wireshark-14825: private IPv4 addresses, the devices' MAC addresses and
  KNX serial numbers. The KNX IP Secure traffic (07) is encrypted with keys
  that are not published; nothing secret is in clear.
- wireshark: Wireshark's published test keys only.

## Further captures searched

None of the recordings we found adds a further identified KNXnet/IP gateway
or interface: GitHub repository and code search ("knx pcap", "knxnetip
capture", "knx dataset") found only knx-datasets; the ICS-Pcaps collection
has no KNX capture. The knx-datasets message-injection (MI) and
invalid-context (IC) sets are not committed (manifest `skipped`): they
merge frames the authors generated into the normal recording and add no
service.
