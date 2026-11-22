# YankiProtocol

YankiProtocol is the standalone Arduino library for the MeshForest compact
binary mesh protocol. It packages the protocol codec, AES-128-CMAC
authentication, replay window, duplicate suppression, managed-flood relay, and
gateway ACK logic as a reusable ESP8266 library.

This repository is the protocol-owned half of the MeshForest split (decision
D18). The application repository consumes it as a pinned git submodule at
`firmware/lib/yanki-protocol`.

## Protocol v1 summary

- **Topology:** managed flooding with no routing state. Every node is both a
  sensor and a relay; each valid new packet is rebroadcast once, bounded by a
  duplicate cache, TTL, and random backoff.
- **Packet size:** 60-byte total packet cap — 8-byte header, up to 48-byte
  payload, and a 4-byte MIC. All multi-byte fields are little-endian.
- **Authentication:** AES-128-CMAC (RFC 4493) over header + payload, truncated
  to a 32-bit MIC. One 128-bit network PSK per deployment. Authentication only;
  v1 does not encrypt payloads.
- **Replay protection:** per-source 16-bit message counters with a 64-entry
  modular acceptance window and bounded duplicate caches. Replay state is
  RAM-only.
- **Alert delivery:** the gateway floods an authenticated ALERT_ACK naming
  `(src, msg_id)`. The source retransmits an alert at +3/+8/+20 s (four
  transmissions total) until acknowledged. Reports are fire-and-forget.
- **Bounded behavior:** retry counts, queues, relay slots, duplicate caches,
  and gateway memory are all fixed-size. No unbounded allocation in the packet
  path.

The authoritative wire format and semantics are in
[docs/protocol-spec.md](docs/protocol-spec.md). Protocol decisions are recorded
in [docs/decision-log.md](docs/decision-log.md).

## Status

**Bench prototype.** This is not field-tested, not certified fire detection, and
not production-ready. Radio interoperability, range, and reliability have not
been verified for this library build. The protocol design has been exercised on
the bench in an earlier wire format and against a Python reference model; the
current little-endian codec still needs over-the-air re-verification. Those
results do not establish field performance.

## Installation

### Arduino library

Copy or clone this repository into your Arduino libraries directory, or install
it as a `.zip` library. The library is ESP8266-only and includes
`YankiProtocol.h`.

### Git submodule

From the application repository:

```sh
git submodule add <repository-url> firmware/lib/yanki-protocol
```

Then include the library from your sketch with `#include <YankiProtocol.h>`.

## API usage

```cpp
#include <YankiProtocol.h>

void setup() {
  Serial.begin(115200);

  // Validate the C++ codec and MIC against the reference vectors.
  Proto::goldenVectorsSelfTest(Serial);

  uint8_t payload[5];
  Proto::buildReport(payload, Proto::SF_DHT_PRESENT | Proto::SF_DHT_VALID,
                     2150, 4200);  // 21.50 C, 42.00 %RH

  uint8_t packet[Proto::MAX_PACKET_LEN];
  uint8_t len = 0;
  bool ok = Proto::encode(DEMO_PSK, DEMO_NET_ID, 0x02, 0x0101,
                          Proto::T_REPORT, payload, sizeof(payload),
                          packet, &len);
  if (!ok) return;

  Proto::Packet decoded;
  int8_t result = Proto::decode(packet, len, DEMO_PSK, DEMO_NET_ID, false,
                                &decoded);
  if (result == Proto::R_OK) {
    Serial.printf("type=%u src=%02X msg_id=%04X len=%u\n",
                  decoded.type, decoded.src, decoded.msg_id, decoded.plen);
  }
}
```

Use the `Proto` namespace. The main entry points are `Proto::encode`,
`Proto::decode`, the payload builders (`buildReport`, `buildAlert`, `buildAck`,
`buildStatus`), `Proto::ReceiveState`, and `Proto::Node`. `Proto::Node` provides
the receive path, relay scheduling, alert retries, and gateway ACK behavior;
your sketch drains its TX queue with `popTx()` and transmits each packet.

`DEMO_PSK` and `DEMO_NET_ID` in `YankiConfig.h` are public demo placeholders.
Replace them with a fresh random key and a deployment-specific network ID. The
golden vectors depend on the demo values, so changing them invalidates the
self-test vectors.

## Running the Python tests

From the repository root:

```sh
python tools/proto/protocol.py
python tools/proto/simulate.py
```

`protocol.py` runs the codec, AES-CMAC, replay-window, and protocol unit checks.
`simulate.py` runs the discrete-event flood/retry scenarios. Both should pass
(50 checks and 9 scenarios respectively).

## Version

1.0.0

## Limitations

- **No encryption.** v1 provides authentication and replay protection only.
  Sensor readings are not confidential. Encryption is a future version with a
  protocol version bump.
- **Key provisioning and rotation are not solved.** The network uses one shared
  PSK; there is no over-the-air key distribution or rotation mechanism. A
  captured node reveals the key and enables forgery until every node is
  reflashed.
- **Replay windows are RAM-only.** Freshness protection is best-effort and
  resets on reboot.
- **No anti-jamming or denial-of-service resistance.** The protocol does not
  claim to survive a deliberate radio jammer.
- **Not field-tested.** Range, interference, antenna behavior, power
  consumption, and fire-detection accuracy remain unverified.

Known demo-build omissions specified in protocol-spec §16.1 are also not
implemented in the demo firmware: CCA before TX, the `PKTLEN` hardware length
filter, report jitter, alert-retry jitter, duty-cycle budget enforcement, the
gateway per-node freshness table, `msg_id` persistence across reboots, a
per-deployment sync word, and PSK provisioning/key storage. The demo build uses
fixed cadence, literal +3/+8/+20 s retries, and a committed placeholder key.
These mechanisms must be implemented before any deployment claim.

See [docs/protocol-spec.md](docs/protocol-spec.md) for the full specification and
[docs/decision-log.md](docs/decision-log.md) for the protocol decision record.

## License

MIT. See [LICENSE](LICENSE).
