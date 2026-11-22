# wireshark-remoteid

A Wireshark / tshark dissector for **ASTM F3411 Open Drone ID** (drone Remote ID)
broadcast over Bluetooth and Wi-Fi.

It decodes the Open Drone ID messages, Basic ID, Location/Vector, Self ID,
Authentication, System and Operator ID, and the Message Pack that carries
several of them behind one header, into a readable protocol tree: ID type and
UAS ID, aircraft position, operator location, operating area, timestamps and
accuracy codes.

The field layout follows the `opendroneid-core-c` reference and the Rust
[`remoteid`](https://crates.io/crates/remoteid) crate byte for byte. Decoding
is verified against `remoteid`'s own encoder: every message in the bundled
sample capture round-trips to the exact values the encoder produced (320/320).

This is a **receive / decode only** tool. There is no transmit path anywhere in
this repository, and the sample capture is synthetic bench data written to a
file, never broadcast.

## What it dissects

| Message | Fields |
|---|---|
| **Basic ID** | ID type, UA (aircraft) type, UAS ID (serial / registration / UUID / session) |
| **Location / Vector** | status, height type, track direction, horizontal and vertical speed, latitude, longitude, barometric / geodetic altitude, height, horizontal / vertical / baro / speed / timestamp accuracy codes, timestamp |
| **Authentication** | auth type, page number, last-page index, length, timestamp, auth data (page 0 header + data; pages 1-15 data) |
| **Self ID** | description type, free text |
| **System** | operator location type, classification, operator latitude / longitude, area count, area radius, area ceiling / floor, EU category and class, operator geodetic altitude, timestamp |
| **Operator ID** | operator ID type, operator ID string |
| **Message Pack** | single-message size, count, then each framed message |

"Unknown" sentinel values (the encodings the standard reserves for *not sent*,
such as direction 361, speed 255, altitude 0, timestamp 0xFFFF) are shown as
`(unknown)` rather than as a raw number.

## Install

The dissector is a single Lua file. Copy `opendroneid.lua` into your Wireshark
personal plugins folder:

| OS | Folder |
|---|---|
| Windows | `%APPDATA%\Wireshark\plugins\` |
| macOS | `~/.local/lib/wireshark/plugins/` or `~/.config/wireshark/plugins/` |
| Linux | `~/.local/lib/wireshark/plugins/` |

The exact path is shown in Wireshark under **Help -> About Wireshark ->
Folders -> Personal Lua Plugins** (double-click the row to open it). Create the
`plugins` folder if it does not exist, then restart Wireshark, or press
**Ctrl+Shift+L** (Analyze -> Reload Lua Plugins).

For tshark, the same personal plugins folder is picked up automatically, or
point at the file directly:

```
tshark -X lua_script:opendroneid.lua -r test/remoteid-sample.pcap
```

Requires Wireshark 3.x or 4.x with Lua enabled (the default in official
builds).

## Try it

The repository ships a sample capture at
[`test/remoteid-sample.pcap`](test/remoteid-sample.pcap): 320 Bluetooth LE
advertising packets (link type 251, `LINKTYPE_BLUETOOTH_LE_LL`) carrying a
clean baseline of four honest drones, each cycling Basic ID, Location, System
and Operator ID messages.

```
tshark -X lua_script:opendroneid.lua -r test/remoteid-sample.pcap -V
```

A Basic ID dissects like this:

```
ASTM Remote ID (Bluetooth LE service data)
    Application Code: 0x0d
    Message Counter: 0
    Open Drone ID Message: Basic ID (15819HNEST0000)
        0000 .... = Message Type: Basic ID (0)
        .... 0010 = Protocol Version: 2
        0001 .... = ID Type: Serial Number (ANSI/CTA-2063-A) (1)
        .... 0010 = UA Type: Helicopter or Multirotor (2)
        UAS ID: 15819HNEST0000
```

A one-line-per-packet summary:

```
tshark -X lua_script:opendroneid.lua -r test/remoteid-sample.pcap
```

The decoded reference for the same capture (one JSON record per message, as
produced by the generator) is in
[`test/remoteid-sample.jsonl`](test/remoteid-sample.jsonl), so you can diff the
dissector's output against known-good values.

## How the sample capture was made

The capture was generated with
[`remoteid-scenario`](https://crates.io/crates/remoteid-scenario), a data-only
test-vector generator that builds spec-compliant Remote ID streams with
`remoteid`'s own encoders and writes them to a file (it never opens a radio):

```
cargo install remoteid-scenario
remoteid-scenario clean --count 4 --format pcap --out test/remoteid-sample.pcap
```

## Capturing real Remote ID traffic

- **Bluetooth** (legacy advertising, BT4, and extended advertising, BT5): the
  Remote ID data is an AD structure of type Service Data (0x16) with the ASTM
  16-bit UUID `0xFFFA`, followed by application code `0x0D`, a message counter
  and the message or message pack. Capture with an HCI sniffer (`btmon`, a
  nRF Sniffer, Ellisys, etc.); the dissector registers on the `0xFFFA` service
  UUID, so it attaches automatically.
- **Wi-Fi Beacon** (EN 4709-002): the Remote ID data is a vendor-specific
  element (tag 221) with the ASD-STAN OUI `FA:0B:BC`, OUI type `0x0D`, a
  counter and a message pack. Capture in monitor mode. The dissector finds this
  element with a post-dissector (it looks for the `FA:0B:BC:0D` signature after
  a tag-221 element) and decodes the pack that follows.

For any other framing, or if auto-attach does not fire on your capture, select
a packet, right-click the Remote ID payload, choose **Decode As...** and pick
**opendroneid**; the dissector expects the payload to start at the application
code byte (`0x0D`).

## Scope and status

Fully implemented and verified against the reference encoder: all six single
message types and the message pack, over Bluetooth LE service data and the
Wi-Fi Beacon vendor element.

Deferred:

- **Wi-Fi NAN** (Neighbor Awareness Networking) action-frame framing. The
  Bluetooth and Wi-Fi Beacon transports cover the common captures; NAN is
  less commonly captured and is left for a follow-up. The underlying message
  dissection already handles NAN payloads once they are located, so adding NAN
  is a matter of the transport hook.

## Related projects

Part of a family of honest, receive-only drone Remote ID tooling:

- [`remoteid`](https://crates.io/crates/remoteid): ASTM F3411 / ASD-STAN Remote
  ID decode, trust verdicts and DJI DroneID, `no_std`.
- [`remoteid-scenario`](https://crates.io/crates/remoteid-scenario): data-only
  Remote ID test-vector generator (flood / spoof / clean streams to a file).
- [`remoteid-sentinel`](https://crates.io/crates/remoteid-sentinel): Remote ID
  flood / spoof field detection, the one real drone in a flood of fakes.
- [`uas-cot`](https://crates.io/crates/uas-cot): Remote ID to TAK
  Cursor-on-Target.

## License

Licensed under either of

- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.
