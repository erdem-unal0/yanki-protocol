# MeshForest protocol virtual test suite (Python reference model)

Host-side executable specification of `docs/protocol-spec.md` v1 (decision
D13: virtual testing before any MCU firmware). Stdlib-only Python; runs on
Python 3.14 on the dev machine (no g++ present, no external server needed).

## Files

| File | Role |
|---|---|
| `aes_cmac.py` | AES-128 (FIPS-197) + AES-CMAC (RFC 4493). Self-checks at import against the FIPS-197 Appendix C.1 known answer and RFC 4493 examples 1–3 (empty / one full block / 40-byte message → exercises both the K1 complete-block and K2 padded CMAC paths). |
| `protocol.py` | Packet codec (§4), payloads (§5), msg_id persistence (§6), receive pipeline with replay window + dedup cache (§7), node model: relay/backoff/retries/gateway-ACK/priority queues/duty budget (§8–§12). Run unit tests: `python tools/proto/protocol.py` |
| `simulate.py` | Discrete-event flood simulator with uniform per-link loss, half-duplex radios, pairwise collision corruption, seeded RNG. Scenario battery per protocol-spec §15.2: `python tools/proto/simulate.py` (exit code 0 = pass) |

## Scenario battery (`simulate.py`)

| # | Scenario | Assertion |
|---|---|---|
| s1 | Codec/pipeline unit tests | 50 checks: round-trips, payload lengths, validation order (length→net→version→MIC), MIC bit-flip rejection, MIC-less in production vs debug, replay window edges + wrap, dedup TTLs, relay eligibility/TTL, msg_id persistence across reboots, gateway-only ACK authority, forged-ACK drop, level-TEST never sirens |
| s2 | Mesh delivery vs loss | 6-node random geometric mesh × 4 loss levels × 20 trials; ≥ 100% delivery required at ≤ 30% loss |
| s3 | Duplicate suppression | ≤ 1 relay per node per (src, msg_id) for alert and ACK floods separately |
| s4 | ACK cancellation | source retry state cleared by gateway ACK |
| s5 | Partition | source stops after exactly 4 TX; no storm; gateway never receives across a full cut |
| s6 | Reboot mid-flood | 10/10 delivered with a relay rebooting mid-flood @ 30% loss; TX bounded |
| s7 | Simultaneous alerters | both alerts delivered; siren fires once per unique alert |
| s8 | Duty budget | 60 s bench cadence, 6 h: worst node TX time < 1% of an hour (legal limit is 10% at 433 MHz) |
| s9 | 8-hop chain @ 15%/link | informational worst case, no pass threshold |

## Model simplifications (documented, not hidden)

- No radio CCA modeling (collisions still occur via overlapping transmissions).
- Loss is per-link, uniform, memoryless; real links are bursty.
- Delivery happens at end of transmission; no capture-effect or RSSI range model.
- Python timing is virtual; no ESP8266/CC1101 real-world timing, FIFO, or SPI behavior.
- **This suite does not prove radio interoperability, security, low-power
  behavior, or fire detection.** It validates protocol logic only. The
  firmware C++ implementation must later pass the same golden vectors
  produced from this model (cross-validation).

## Last run

2026-11-22 — all scenarios passed (test log kept in the MeshForest application
repository). Regenerated the
firmware golden vectors after decision D16 corrected the packet-header byte
order to little-endian; the vectors above are the current reference set.