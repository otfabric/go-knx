# Specification access and licensing

Research date: 2026-10-29. Not legal advice. Every statement has a
source; "unresolved" means no evidence was found either way. Quotes from
support.knx.org and iso.org come from search-engine excerpts (those sites
refused automated fetching) and should be re-checked in a browser.

## Access to the KNX specifications

- A **free public set** exists: the MyKNX shop lists "the public version
  (3.0.0) of the KNX Specifications" at €0.00; members get the latest
  version (v3.0.3, v3.0.4) — <https://my.knx.org/en/shop/knx-specifications>.
- v3.0.4 was released on 22 August 2025 for KNX members —
  <https://knx.org/news/knx-launches-knx-standard-version-304>. v3.0 was
  announced to be downloadable by anyone after the IPR review —
  <https://knx.org/news/knx-standard-v30-bringing-internet-things-knx-specifications>.
- Members additionally receive the "full set" including Application Notes —
  <https://support.knx.org/hc/en-us/articles/360000040999-KNX-Specifications>.
- KNXnet/IP is also the international standard **ISO 22510:2019** (EN ISO
  22510:2020), which replaced the withdrawn EN 13321-2. KNX as a whole is
  ISO/IEC 14543-3-1 to -7 (2006/2007), which predate KNX Secure and KNX IoT.

## What the repository may contain

| Material | Allowed here? | Basis |
|---|---|---|
| Specification PDFs or text | **No** | The download carries "All rights reserved" and no published redistribution licence (unresolved: the MyKNX download terms) |
| Code written from the specification | Yes | Normal practice for this open standard; independent open-source stacks do it publicly (xknx, MIT; Calimero, GPL-2.0 with Classpath exception; OpenKNX, GPL-3.0) |
| Constants, frame layouts, DPT encodings re-typed in our own structure | Yes | Facts of the protocol, written in our own tables |
| Frames captured from or built against independent implementations | Yes | Our own test data |
| Example frames or test vectors copied from the specification or application notes | **Avoided** | No statement found allowing or forbidding it (unresolved); tests use our own frames |
| ETS project XSD (`KNX-Project-Scheme-*.xsd`) | **No** | Ships inside ETS / the Manufacturer Tool; no licence found |
| ETS keyring format description | Referenced, not copied | KNX support article "Keyring File Format" |
| Third-party sample files (for example xknx test keyrings) | Only with attribution and a compatible licence | Not used yet |

## Membership, certification, trademark

| Activity | Needs KNX membership? | Source |
|---|---|---|
| Reading and implementing the public specification | No | Free MyKNX account |
| Publishing an open-source implementation | No rule found (unresolved); KNX Association itself funded an open-source KNX IoT stack | <https://knx.org/news/knx-iot-part-7-open-source-knx-iot-stack> |
| Official conformance testing and certification | **Yes** (accredited test labs; the "Interested Party" class cannot certify) | <https://support.knx.org/hc/en-us/articles/360000038460>, <https://knx.org/manufacturers-hub/become-knx-member> |
| The EITT interoperability test tool | **Yes** ("can only be licensed by KNX members and KNX accredited test labs") | <https://knx.org/knx-fr/newsroom/fr/news/EITT-40-is-now-available> |
| A manufacturer code | **Yes** (assigned to a member, for a commercial product) | <https://support.knx.org/hc/en-us/sections/115000749885-Manufacturer-Code> |
| The KNX logo on products or publications | Products: member plus trademark and IPR licences; publications: written permission for non-members | <https://support.knx.org/hc/en-us/articles/4692536334866-Use-of-KNX-logo-on-unregistered-products>, <https://support.knx.org/hc/en-us/articles/4741645555730-Use-of-KNX-logo-on-publications> |

go-knx therefore:

- uses the word KNX descriptively and no KNX logo;
- claims no certification and no conformance (CONFORMANCE.md);
- uses no manufacturer code of its own: the server's serial number starts
  with 0x00FA as a placeholder and products must set their own
  (`server.WithSerial`);
- carries the notice: *KNX is a registered trademark of KNX Association
  cvba. go-knx is an independent implementation, not affiliated with or
  endorsed by KNX Association.*

## ETS files

- The project file format (namespace `http://knx.org/xml/project/20` for
  ETS 5.7, later numbers for ETS 6) has a published scheme description
  that "may change without any prior notice"; the XSD is not separately
  published. go-knx does not read project files yet; a future reader would
  be written from observed files, without vendoring the XSD.
- The keyring format (namespace `http://knx.org/xml/keyring/1`, PBKDF2-
  HMAC-SHA256, salt "1.keyring.ets.knx.org") is described in a KNX support
  article — <https://support.knx.org/hc/en-us/articles/18968368409874-Keyring-File-Format>.

## Unresolved, to settle before the secure work

1. The terms shown on the MyKNX download of the public set.
2. Whether Application Notes 158 (Data Secure) and 159 (IP Secure) are in
   the public v3.0.0 set or members-only. **This decides whether KNX IP
   Secure and Data Secure can be implemented from authoritative sources
   without membership.**
3. The licence of the ETS project XSD and its description.
4. A written KNX Association position on open-source implementations and
   the word mark (support@knx.org).
5. Membership and test-lab fees (not published).
