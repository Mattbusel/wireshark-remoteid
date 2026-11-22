# Sample capture

- `remoteid-sample.pcap`: 320 Bluetooth LE advertising packets (link type 251,
  `LINKTYPE_BLUETOOTH_LE_LL`) carrying ASTM F3411 Open Drone ID service data. A
  clean baseline of four honest drones, each cycling Basic ID, Location, System
  and Operator ID.
- `remoteid-sample.jsonl`: the same stream decoded, one JSON record per
  message, straight from the generator. Use it as the expected-output reference
  when checking the dissector.

Both files come from one deterministic run of
[`remoteid-scenario`](https://crates.io/crates/remoteid-scenario):

```
remoteid-scenario clean --count 4 --format pcap  --out remoteid-sample.pcap
remoteid-scenario clean --count 4 --format jsonl --out remoteid-sample.jsonl
```

The generator is data-only: it builds the frames with the `remoteid` crate's
own encoders and writes them to a file. It never opens a radio and there is no
transmit path.

## Check the dissector against the reference

```
tshark -X lua_script:../opendroneid.lua -r remoteid-sample.pcap \
  -T fields \
  -e opendroneid.basic_id.uas_id \
  -e opendroneid.location.lat \
  -e opendroneid.location.lon \
  -e opendroneid.system.op_lat \
  -e opendroneid.operator_id.id
```

The emitted UAS IDs, positions and operator IDs match the `message` fields in
`remoteid-sample.jsonl`.
