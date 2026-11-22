# YANKI Protocol — Specification v1

**YANKI** — *Yerel Ağlarda Noktalararası Katmanlı İletişim* (Turkish) /
*Layered Inter-Node Communication in Local Networks* (English).

This document defines the custom wireless communication protocol used by the
forest-fire detection mesh. It is the **authoritative reference for protocol
behavior**. The working project specification (in the MeshForest application
repository) remains the authority for project requirements; `decision-log.md`
records why protocol decisions were made.

- **Status:** Approved v1 baseline (design approved by the project owner on 2026-10-20).
- **Implementation:** Demo build implemented (2026-10-24); first over-the-air
  exchange confirmed 2026-11-06 (test log kept in the MeshForest application
  repository). Known demo-build
  omissions are listed in §16.1. This document must stay consistent with the
  firmware; deviations are defects.
- **Maturity:** Experimental prototype protocol. It does **not** make the system
  a reliable or certified fire detector.
- **Labels:** Facts are marked VERIFIED (checked against cited sources),
  UNVERIFIED (still requires checking), or ESTIMATE (must be measured).
  Radio-dependent parameters are UNVERIFIED until bench-tested.

Normative language: MUST (required), SHOULD (recommended), MAY (optional).
All protocol timings and limits are named constants (see §14, Parameter registry)
and MUST be configurable rather than hard-coded literals scattered in code.

---

## 1. Design goals and non-goals

### 1.1 Goals (v1)

1. Carry fire **ALERT** messages from any node to the gateway across multiple
   hops, with bounded, *observable* delivery (end-to-end gateway acknowledgement).
2. Carry periodic sensor reports and node health so the gateway can display
   freshness and status honestly (silence is "unknown", never "all clear").
3. Survive packet loss, node reboot, radio failure, and network partitions
   without unbounded retransmission, forwarding loops, or retry storms.
4. Fit small packets within CC1101 FIFO limits and keep per-node airtime far
   below legal duty-cycle limits.
5. Authenticate every packet (AES-CMAC) and reject replays within a bounded
   window.
6. Be implementable and testable on ESP8266 + CC1101 with continuous receive.

### 1.2 Non-goals (v1) — explicitly out of scope

- **Encryption/confidentiality.** Payloads are non-sensitive; a reserved flag
  bit and version path exist for adding AES-CTR/CCM* later (§17).
- **Time synchronization.** No wall-clock timestamps on nodes; the gateway
  owns time and stamps receipts. Nodes report uptime only.
- **Duty-cycled listening / sleep scheduling.** v1 nodes keep the radio in
  continuous RX (an approved decision). All listen/retry timings are
  parameterized so a duty-cycled mode can be added later without a packet
  format change.
- **Node-to-node sessions, remote configuration.** All v1 traffic is
  node→gateway or gateway→network broadcast. The CONFIG message type is
  reserved but undefined (§5.6).
- **Anti-jamming.** An attacker can always deny radio service; documented as a
  limitation, not mitigated at protocol level.
- **Guaranteed delivery.** The protocol provides *bounded delivery effort* plus
  *observable confirmation* (ACK), never a guarantee (§13, §16).

### 1.3 Assumed deployment

Single-digit to ~10 nodes, one gateway, sparse static topology, low traffic
(one report per node per few minutes, alerts rare). Scaling beyond ~10–15
nodes or sub-minute reporting should trigger a routing redesign review
(collection-tree class protocols; see decision log D3).

---

## 2. Verified constraints this protocol is built on

| Constraint | Value | Source |
|---|---|---|
| CC1101 FIFO size | 64 B TX / 64 B RX; packets >64 B need mid-packet FIFO streaming (avoided) | TI CC1101 datasheet SWRS061 §10.5; TI DN500 |
| Max packet with CRC auto-flush (variable-length mode) | 63 B payload, −2 B if RSSI/LQI status bytes appended → ~61 B practical ceiling | SWRS061 §15.3.3 |
| Hardware features used | CRC16 (noise integrity only), whitening, configurable 16-bit sync word, max-length filtering via PKTLEN, RSSI/LQI status append | SWRS061 §15 |
| ESP8266 deep sleep | ~20 µA chip current but wake = full reboot; GPIO interrupts cannot wake it → a sleeping node cannot receive | Espressif Low-Power Solutions; ESP8266 RTOS SDK sleep docs |
| ESP8266 light sleep | ~0.4 mA, GPIO wake supported — the future path for duty cycling (via CC1101 GDO0) | same |
| ESP8266 RAM | 98 KB DRAM, ~40–50 KB free heap for a minimal sketch → protocol state is not the binding constraint | arduino-esp8266 docs & issues |
| Crypto hardware | None on ESP8266 or CC1101 → software AES-128; latency UNVERIFIED, must be benchmarked | datasheets |
| Türkiye SRD duty limits (general-purpose, TS EN 300 220 referenced) | 433.05–434.79 MHz: 10 mW e.r.p., ≤10% duty; 868.0–868.6 MHz: 25 mW e.r.p., ≤1% duty or LBT+AFA | BTK FTM Teknik Ölçütler (see §18) |
| Regulatory status | Band **CONFIRMED 433 MHz** (module marking + vendor page); general-purpose SRD rules selected — alarm-specific bands deliberately not used (decision D10). Still open: e.r.p. incl. antenna gain, occupied-BW mask (TS EN 300 220), channel choice | BTK technical criteria row 15a: 10 mW e.r.p., ≤10% duty |

---

## 3. Network architecture

### 3.1 Roles

- **NODE** — senses, originates SENSOR_REPORT / ALERT / NODE_STATUS, and relays
  (forwards) all eligible packets. Every node is both sensor and relay.
- **GATEWAY** — the sink: receives, dedups, and acts on reports/alerts; the
  sole originator of ALERT_ACK. It also relays. v1 assumes exactly one
  gateway. Hardware concept (decision D11): the same NodeMCU + CC1101
  platform as the nodes plus an OLED display and a speaker module, at a
  mains + UPS-backed lookout station; exact parts open (docs/hardware.md).
  The protocol itself is platform-agnostic.

### 3.2 Addressing

- Node ID: 8 bits.
  - `0x00` = broadcast (all nodes process).
  - `0x01` = gateway (fixed in v1).
  - `0x02–0xFE` = sensor nodes.
  - `0xFF` = reserved (must not be assigned; avoids confusion with the
    CC1101 optional second broadcast address).
- IDs are assigned at build time in a documented configuration table and
  provisioned per device. Uniqueness within a deployment is a provisioning
  responsibility. (Small-network assumption; dynamic assignment is a v2+
  candidate.)
- All v1 messages use `dst = 0x00`. The `dst` field exists for future unicast
  (e.g., gateway→node CONFIG) and must still be honored: nodes process packets
  with `dst == 0x00` or `dst == own_id`.

### 3.3 Network identification

- **NET_ID:** 16-bit per-deployment value carried in every packet. Receivers
  MUST drop packets with a foreign NET_ID before any state change.
- **CC1101 sync word:** programmed per-deployment to a random 16-bit value that
  is not preamble-like (not `0xAAAA`/`0x5555` patterns) and not the TI default
  `0xD391`, so foreign deployments are rejected at radio level before packet
  processing. Both NET_ID and sync word are per-deployment constants.
- Hardware address filtering (ADR_CHK) is OFF in v1 (all traffic is broadcast);
  `NET_ID` + sync word perform network discrimination.

### 3.4 Provisioning summary (per device, at build/provision time)

| Item | Value |
|---|---|
| NODE_ID | unique in deployment (nodes) or `0x01` (gateway) |
| NET_ID | same 16-bit value across the deployment |
| sync word | same per-deployment 16-bit value |
| network key (PSK) | same 16-byte AES-128 key across the deployment |

Secrets MUST NOT be committed to version control (§11.1).

---

## 4. Packet format

### 4.1 On-air structure

```
[preamble 4 B] [sync word 2 B]      ← generated by CC1101, never in FIFO
[length 1 B]                         ← radio variable-length mode
[FIFO region: header + payload + MIC] ← "packet" below
[CRC16 2 B]                          ← appended/checked by CC1101 (noise only)
[RSSI+LQI 2 B]                       ← radio-appended status, RX side only
```

- The radio is configured for **variable-length mode**, CRC **ON**,
  appended status **ON**, preamble 4 bytes. With the selected library
  (RadioLib, decision D12): CRC auto-flush is **OFF** by default (CRC is
  checked in software from the appended status bytes — bring-up MUST verify
  that bad-CRC packets are actually rejected), and whitening is **OFF** by
  default; whitening may be enabled but MUST match on every node
  (network-wide). RadioLib's default sync word `0x12AD` MUST be replaced
  with the per-deployment value (§3.3).
- `PKTLEN` (hardware max length) = 60 → oversize packets are discarded by the
  radio before the MCU parses anything (RadioLib: `variablePacketLengthMode(60)`).
  RadioLib's `startTransmit` is interrupt-driven only for packets < 64 bytes;
  our ≤60-byte FIFO region stays inside that regime (longer packets block
  with documented limitations — see RadioLib discussion #1138).

### 4.2 FIFO region layout (the "packet")

All multi-byte fields are **little-endian**. No raw C structs over the air;
fields are encoded/decoded explicitly.

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 4 bits | `ver` | protocol version; v1 = `1`. Unknown → drop. |
| 0 | 4 bits | `ttl` | remaining hops (1–15); set by originator, decremented by each relay. |
| 1 | 4 bits | `type` | message type (§5). |
| 1 | 4 bits | `flags` | bit 0 (0x01) = MIC present. Bits 1–3 reserved, MUST be 0 in v1; receivers MUST ignore unknown flag bits. |
| 2–3 | 2 B | `net_id` | deployment network ID (u16 LE). |
| 4 | 1 B | `dst` | `0x00` broadcast in v1; otherwise target node ID. |
| 5 | 1 B | `src` | originator node ID (never the forwarder — the forwarder is implicit "everyone in range"). |
| 6–7 | 2 B | `msg_id` | per-source monotonic counter (u16 LE), unique per message within the source's counter cycle (§6). |
| 8..8+n−1 | 0–48 B | payload | type-specific (§5). |
| 8+n..11+n | 4 B | MIC | first 4 bytes of AES-CMAC over bytes 0..(8+n−1) (§11). |

**Sizes:** total FIFO region length `L = 8 + n + 4` (with MIC), where
`n` ≤ 48. Therefore `12 ≤ L ≤ 60`. The radio length byte value = `L`.

**Header + MIC overhead = 12 bytes; payload ceiling = 48 bytes.**
This implements the project's 50–60 B budget as a *total packet* cap with a
large safety margin under the 61–63 B hardware ceiling (§2).

### 4.3 Validation order (normative — receivers MUST apply in this order)

1. (Hardware) CRC16 pass, length ≤ PKTLEN, else packet already discarded.
2. Software length check: `12 ≤ L ≤ 60` when MIC flag set (production builds
   MUST reject `flags.MIC = 0` packets; bench/debug builds may accept them —
   §11.4).
3. Cheap header filters, no state changes: NET_ID match, version match.
4. **MIC verification** (over bytes 0..L−5, compare against bytes L−4..L−1).
   A failed MIC MUST NOT touch any protocol state.
5. Stateful checks (only after MIC passes): replay window + duplicate cache
   (§7.2).
6. Dispatch: process if `dst == 0x00` or `dst == own_id`; evaluate relay
   eligibility (§8).

Malformed/failed packets are silently dropped and counted; v1 never sends
error messages in response to bad input (no error-channel amplification).

---

## 5. Message types and payloads

Type field values (4 bits). Types not listed are reserved: v1 relays them
(flooding is content-agnostic) but MUST NOT act on them.

### 5.1 SENSOR_REPORT (type 0x1) — payload 5 B

Periodic sensor snapshot. Payload:

| Byte(s) | Field | Encoding |
|---|---|---|
| 0 | sensor flags | bit 0 `mq2_present`; bit 1 `mq2_active` (comparator indicating); bit 2 `mq2_valid` (warmed up / trusted by firmware); bit 3 `dht22_present`; bit 4 `dht22_valid` (last read OK); bit 5 `flame_present`; bit 6 `flame_active`; bit 7 reserved (0) |
| 1–2 | temperature | i16 LE, °C × 10 (e.g. 254 = 25.4 °C); missing = `0x7FFF` |
| 3–4 | humidity | u16 LE, %RH × 10 (e.g. 456 = 45.6 %); missing = `0xFFFF` |

Presence bits declare what the node carries; validity bits declare whether the
value is currently trustworthy. A missing/invalid value MUST NOT be silently
converted to zero anywhere in the system.

### 5.2 ALERT (type 0x2) — payload 7 B

Raised by node firmware when its (out-of-protocol) alert policy triggers.

| Byte(s) | Field | Encoding |
|---|---|---|
| 0 | alert flags | bit 0 `mq2_trigger`; bit 1 `flame_trigger`; bit 2 `temp_trigger`; bit 3 `multi_sensor` (≥2 indicators); bits 4–7 reserved (0) |
| 1 | level | `0` = test/drill — the gateway MUST never sound the siren for level 0; `1` = warning; `2` = critical; others reserved |
| 2–6 | sensor snapshot | identical layout to SENSOR_REPORT payload |

The alert *policy* (thresholds, persistence, hysteresis, fusion) is firmware
scope and must be calibrated with real data; the protocol only carries the
outcome plus evidence.

### 5.3 ALERT_ACK (type 0x3) — payload 3 B, gateway-originated only

| Byte(s) | Field | Encoding |
|---|---|---|
| 0 | acked_src | node ID of the alert's originator |
| 1–2 | acked_msg_id | the alert's `msg_id` (u16 LE) |

Semantics in §9.3. Only the gateway (`src = 0x01`) may originate ALERT_ACK;
nodes MUST silently drop ALERT_ACK claimed to originate from anyone else.

### 5.4 NODE_STATUS (type 0x4) — payload 5 B

Event-driven health message: sent once at boot (with `booted` set), and on
fault state changes (sensor fault, low battery transition). Optional periodic
re-send is a configurable parameter (default: off).

| Byte(s) | Field | Encoding |
|---|---|---|
| 0 | status flags | bit 0 `booted` (first message of this boot); bit 1 `low_battery` (only if battery monitoring exists — hardware UNVERIFIED); bit 2 `sensor_fault` (any sensor failed self-check); bits 3–7 reserved (0) |
| 1–2 | uptime | u16 LE, minutes since boot; wraps at 65536 (~45.5 days), receivers treat wrap as continuity |
| 3 | reset reason | `0` power-on/normal, `1` hardware watchdog, `2` exception/panic, `3` software restart, `4` deep-sleep wake (unused in v1), `0xFF` unknown; firmware maps ESP8266 reset reasons into this table and documents the mapping |
| 4 | boot count | u8 persistent counter, wraps at 256; diagnostic aid |

### 5.5 ALERT_CLEAR (type 0x5) — reserved

Defined as a type to prevent ad-hoc reuse. Semantics MUST NOT be implemented
until an alert-clearing policy is designed, tested, and approved (working spec:
"CLEAR only after a reliable clearing policy is defined"). v1 gateways: display
only; v1 nodes: never originate.

### 5.6 PING (0x6), CONFIG (0x7) — reserved

PING is a future diagnostic echo. CONFIG is future authenticated remote
configuration: it MUST NOT be implemented until its security review
(including replay of stale configuration) is done. Types 0x8–0xF reserved.

---

## 6. Message identifiers (`msg_id`)

- 16-bit, incremented by 1 for **every message a node originates** (all types
  share one sequence).
- **Monotonic across reboots** via a persistence scheme (EEPROM/flash emulation):
  - At boot: read persisted base `P`; set counter = `P + 128` (mod 65536);
    persist the new base immediately.
  - Every 128 increments during runtime: persist current counter again.
  - Invariant: a power loss can lose at most 127 counter values; the next
    boot resumes strictly above every value ever used. Worst-case ~2–3 flash
    commits/day → decades of wear even pessimistically (100k erase cycles).
    The ESP8266 EEPROM-emulation wear-leveling behavior MUST be verified at
    implementation and the wear math re-checked.
  - First-ever boot: base 0 → counter starts at 128.
- **Wrap** at 65536 → continues from 0; receivers compare modularly (§7.2).
- Rationale (decision log D7): avoids an epoch byte in every header and keeps
  replay windows valid across reboots.

---

## 7. Receiving: duplicate suppression and replay protection

### 7.1 Layers

Duplicate/replay control is intentionally layered and bounded:

1. Radio CRC + hardware length filter (§4).
2. MIC gate (§11) — unauthenticated packets never reach state.
3. **Per-source acceptance window** (replay window).
4. **Duplicate cache** keyed `(src, msg_id)` (flood suppression).
5. Gateway-level alert memory (siren dedup, §12).

### 7.2 Per-source state (nodes and gateway)

Bounded LRU table, `NEIGHBOR_TABLE_SLOTS = 16` entries: `src`,
`last_id` (16-bit), `last_seen`. Algorithm on a MIC-valid packet from `S`
with `msg_id = M`:

- No entry for `S` → accept; create entry with `last_id = M`.
  (Fresh-source acceptance after table eviction/reboot — documented exposure.)
- Else `d = (M − last_id) mod 65536`:
  - `1 ≤ d ≤ REPLAY_WINDOW (=64)` → accept; set `last_id = M`; gaps are
    counted for diagnostics only (v1 has no gap recovery).
  - `d == 0`, or `65536 − 64 ≤ d ≤ 65535` → recently-seen range: check the
    duplicate cache;
    hit → drop (duplicate); miss → accept as late/out-of-order without moving
    `last_id` backward.
  - Otherwise (older than the window or more than 64 ahead) → drop and count.
    The "too new" rejection bounds counter-inflation abuse (a technique
    described in the IEEE 802.15.4 security literature).

### 7.3 Duplicate cache

Bounded LRU, `DEDUP_CACHE_SLOTS = 24` entries: `(src, msg_id)`, insert-time,
expiry per type at insertion: **ALERT entries 2 s** (so each source retry may
re-flood — §9.2), **all other types 300 s**. A cache hit means: do not
process, do not relay. A node also MUST NOT relay a packet whose `src` equals
its own ID.

### 7.4 Honest properties (documented, accepted)

- State is per-receiver RAM: after a receiver reboots, recent packets can be
  replayed to it once more (bounded by TTL and cache; the MIC does not expire).
- A source whose table entry was evicted is accepted fresh.
- This is *windowed freshness*, not cryptographic expiry. It is proportionate
  to the threat (alerts are authenticated; replays at worst re-trigger a
  siren the gateway already dedups).

---

## 8. Forwarding (managed flooding) — the routing rules

There is no routing table. The entire routing is one rule:

> On receiving a valid, non-duplicate, in-window packet with `ttl = T`:
> process it if addressed to me or broadcast; **and if `T ≥ 2`, schedule a
> retransmission of the same packet with `ttl = T − 1` after a random backoff
> of `U(RELAY_BACKOFF_MIN_MS, RELAY_BACKOFF_MAX_MS)` (default 30–150 ms).**
> Before the retransmission fires, an `ALERT_ACK` matching the packet's
> `(src, msg_id)` cancels it.

Details (normative):

- **Relay eligibility is content-agnostic:** any type relays (including
  reserved types), so future types propagate through old relays. Exceptions:
  never relay own `src`; never relay a duplicate; ALERT relays are cancelled
  by a matching ACK; an ALERT_ACK is itself relayed (it must flood back to the
  alert source) but is never cancelled by anything.
- The relay MUST re-verify the MIC of the received packet before
  retransmitting (it did — §4.3), decrement TTL, and **recompute the MIC**
  over the modified header (the network key is symmetric; relays are trusted
  participants — §11.3).
- **Pending-relay list:** bounded (8 slots). If full, evict a pending
  report/status relay first (alerts are never evicted); if every slot holds an
  alert, slot 0 is overwritten. No insertion age is tracked — something is
  always dropped, so growth stays bounded.
- **Loop-freedom:** any loop re-presents a `(src, msg_id)` already in the
  duplicate cache → suppressed; TTL bounds everything even if caches were
  empty. No other loop-prevention mechanism exists or is needed.
- **No route repair exists or is needed:** after reboot or partition, the
  next flood is the repair.

---

## 9. Delivery semantics

### 9.1 SENSOR_REPORT / NODE_STATUS — fire-and-forget

Sent at cadence `REPORT_INTERVAL_MS` (default 300000) with per-node jitter
`±REPORT_JITTER_MS` (default 15000; deterministic component from node ID plus
random component). No ACK, no retry. Reliability comes from cadence plus
flooding redundancy plus the gateway's staleness display (§12.2). Alert
traffic never waits behind report traffic (§10.2).

### 9.2 ALERT — source behavior (bounded retries)

1. Originator sends ALERT with fresh `msg_id`, `ttl = TTL_INIT_ALERT` (8).
2. If a matching ALERT_ACK is heard → done (mark confirmed).
3. Otherwise retransmit the **same** `(src, msg_id)` — a fresh bounded flood
   with TTL reset to the initial value — at `+3 s`, `+8 s`, `+20 s`
   (`ALERT_RETRY_DELAYS_MS`). After the 4th transmission, stop and mark the
   alert **unconfirmed** locally (diagnostic counter only).
4. Retransmission is the identical message; relays re-flood it because ALERT
   cache entries expire after 2 s (§7.3).
5. While the sensor condition persists, the node's alert policy may raise a
   *new* alert with a new `msg_id` — the number of such alerts is bounded by
   the alert policy (firmware scope), not by the protocol.

Bounds: 4 transmissions per alert, exponential jittered spacing, TTL ≤ 8 →
retry storms are structurally impossible (§13).

### 9.3 ALERT_ACK — gateway behavior

1. On a valid, new ALERT: act on it (§12.1), then broadcast ALERT_ACK after
   `U(200, 400) ms` (`ACK_DELAY_*`) — deliberately after the relay wave
   (30–150 ms) to reduce collisions.
2. **Re-ACK:** if the same `(src, msg_id)` is received again ≥
   `GATEWAY_REACK_MIN_INTERVAL_MS` (2000) after the last ACK for it, the
   gateway re-ACKs (so a source that lost the first ACK still confirms).
3. Gateway alert memory (`GATEWAY_ALERT_MEMORY_MS`, default 600000, RAM table
   bounded at 64 IDs, LRU) dedups siren/display actions. After eviction or
   gateway reboot, a re-received old alert can re-trigger the siren —
   documented, accepted (bounded by relay-side caches).
4. ALERT_ACK floods with `ttl = 8` and cancels pending ALERT relays and
   source retries on its way (§8). Only `src = 0x01` ACKs are valid (§5.3).

### 9.4 What "delivery" means here

- **Confirmed:** the source heard an authenticated ACK naming its alert.
- **Delivered-but-unconfirmed:** the gateway has the alert but the source
  never heard the ACK (possible with asymmetric loss). The gateway display
  and the source's local state are allowed to disagree; the gateway is
  authoritative for the alarm.
- The protocol provides bounded effort + observable confirmation, never a
  guarantee. "Unconfirmed" MUST be displayed as unknown, not as failed.

---

## 10. Radio access and airtime

### 10.1 Channel access

- **No TDMA in v1.** Non-persistent CSMA-style: before every transmission,
  sample RSSI (CCA); if the channel is busy, wait a random backoff
  (`CCA_BACKOFF_MIN/MAX_MS`, default 20–120 ms) and retry, at most
  `CCA_ATTEMPTS` (4) times. Then: reports/status are dropped until their next
  cycle; alerts are re-queued once at the back of the priority queue.
- Hidden-node collisions cannot be fully prevented by CCA (two transmitters
  that cannot hear each other). Mitigation is flooding redundancy; documented
  limitation.
- All TX times are additionally randomized by design (report jitter, relay
  backoff, retry jitter) to break synchronization.

### 10.2 Priority

Two TX queues: **P0** = ALERT, ALERT_ACK; **P1** = SENSOR_REPORT, NODE_STATUS.
P0 always dequeues first. An in-flight transmission is never preempted.
Queue slots: 4 per priority (bounded RAM).

### 10.3 Duty-cycle budget (regulatory compliance mechanism)

- Each node counts its own on-air TX time (preamble through CRC) in a sliding
  1-hour window.
- `DUTY_LIMIT_MS_PER_HOUR` default = **360000 (10%)** — the legal limit for
  general-purpose SRDs at 433.05–434.79 MHz (BTK row 15a; band confirmed,
  decision D10). Deployments wanting an engineering margin may configure
  lower (e.g., 36000 = 1%); the firmware mechanism is unchanged.
- Non-alert (P1) traffic is deferred when the window total reaches
  `DUTY_SOFT_FRACTION (0.5) × limit`; **all** traffic, including alerts, is
  deferred at `1.0 × limit` until the window recovers. Legal compliance is
  enforced in firmware, not assumed.
- Duty-cycle versus LBT+AFA compliance choice is deferred until the band and
  module are verified (UNVERIFIED — §16).

### 10.4 Airtime (measured at the implemented rate)

The implemented data rate is **4.8 kbps** (RadioLib default; decision D17),
not the 38.4 kBaud originally proposed. Measured on the bench 2026-11-06: a
17-byte SENSOR_REPORT occupies **≈ 43 ms** on air (preamble through CRC).
Scaling with payload length, a 19-byte ALERT ≈ 47 ms and a 15-byte ACK ≈ 40 ms.

At the 300 s report cadence that is 12 reports/h × 43 ms ≈ **0.52 s/h per node
≈ 0.014 %** of an hour — three orders of magnitude below the 10 % limit
(§10.3). A worst-case alert event (4 source transmissions plus relay and ACK
floods) stays in the low single-digit seconds per node, i.e. well under 0.1 %
of an hour, but the exact figure MUST be read from the airtime counter rather
than estimated.

38.4 kBaud would cut all of the above by ~8× and is a v1.1 tuning candidate
(decision D17); it is **not** current behavior.

---

## 11. Security

### 11.1 Key model and provisioning

- One **128-bit network PSK** per deployment (AES-128 key). All nodes and the
  gateway share it. Provisioned at build/flash time via a secrets mechanism
  that MUST NOT be committed to version control (e.g., a git-ignored config
  header, optional serial provisioning mode). Never logged.
- Rotation = reflash/reprovision all devices (v1 has no over-the-air rekey).
- **Documented limitation:** any captured node reveals the PSK; the attacker
  can then forge any message, including ACKs (which suppress alert floods —
  ACK forgery is the highest-value attack; the MIC is the defense, and it
  fails only on key compromise). Per-node keys with gateway-mediated
  distribution are a v2 candidate (§17).
- ESP8266 has no secure key storage; a physical attacker with flash access
  can extract the key. Accepted for a prototype; documented.

### 11.2 Message authentication

- **AES-128-CMAC** (RFC 4493 / NIST SP 800-38B — established, reviewed;
  no custom cryptography) over the entire FIFO region bytes `0 .. L−5`
  (header + payload).
- **MIC = first 4 bytes (32 bits)** of the CMAC, appended. 32-bit truncation
  gives a ~2⁻³² per-packet forgery chance for an online attacker — acceptable
  for the prototype; 8-byte MIC is a drop-in parameter if risk rises.
- Verification happens before any state update (§4.3). Comparison SHOULD be
  constant-time.
- The radio's CRC16 is **noise integrity only** and is never described as
  authentication (project rule).

### 11.3 Trust model

- All relays share the symmetric key: a relay can technically forge or alter
  any message. v1 accepts this (the threat model is outsiders without the
  key). Insiders/compromised nodes are out of scope for v1 and documented.
- Encryption is absent: anyone with a CC1101 and this spec can read sensor
  data. Accepted (§1.2); flag bit reserved for a future MIC-with-encryption
  mode via version bump.

### 11.4 Replay protection

Per-source windowed freshness (§7.2) + duplicate cache + gateway alert memory.
Properties and exposures are documented in §7.4. This is not a cryptographic
expiry; there is no time-based validity.

### 11.5 Bench/debug mode

A compile-time DEBUG flag may allow sending/receiving MIC-less packets
(`flags.MIC = 0`). Production builds MUST reject MIC-less packets and MUST
NOT be deployed with the debug flag enabled.

### 11.6 Performance

Software AES-CMAC cost on the 80 MHz ESP8266 is an ESTIMATE (~sub-millisecond
per packet for 1–2 AES blocks + CMAC finalization). It MUST be benchmarked
during bring-up; if it exceeds a few ms per packet, the design is revisited
(decision log).

---

## 12. Node and gateway behavior summaries

### 12.1 Node boot sequence

1. Init peripherals, radio (verify CC1101 part/version registers; radio init
   failure MUST be visible in logs/status — not a silent "working" node), sensors.
2. Load `msg_id` base (§6), increment boot count, persist.
3. Send NODE_STATUS with `booted` + reset reason.
4. Enter continuous RX; run scheduler (report timer with jitter, alert policy,
   retry timers, airtime budget, watchdog).

### 12.2 Gateway behavior

- Maintain a per-node freshness table: last report time, last alert, uptime,
  boot count, sensor flags. Silence beyond `2 × REPORT_INTERVAL + jitter` is
  displayed as **stale/unknown**, never as "no fire" (project rule: silence
  may mean dead node, bad link, or sleeping node — here, always ambiguous).
- On a new ALERT: dedup by `(src, msg_id)`; act once per unique alert (level 0
  MUST NOT trigger the siren — test/drill); display source, level, evidence
  snapshot, receipt time, and age. Then ACK per §9.3.
- Gateway UI muting/acknowledgement is a gateway application feature, out of
  protocol scope.

---

## 13. Failure modes and recovery

| Failure | Protocol behavior | Bound |
|---|---|---|
| Packet corrupted | Radio CRC drop | — |
| Packet lost end-to-end (report) | Next cadence covers it | ≤ one report period |
| Packet lost (alert) | ≤ 3 retries + redundant flood paths | 4 TX total, ~20 s |
| Duplicate flood copies | Duplicate cache + TTL + ACK suppression + gateway memory | 1 relay per node per ID per window |
| Forwarding loop | Cache hit suppresses; TTL | structurally impossible to sustain |
| Retry storm | 4-TX cap, exponential spacing, airtime budget | structurally impossible |
| Node reboot | msg_id continuity preserved; NODE_STATUS(booted); caches lost → at most a few TTL-bounded duplicate relays | bounded by TTL |
| Gateway down | Sources retry then mark unconfirmed; reports continue; no state corruption; recovery = next message | 4 TX per alert |
| Network partition | Same as gateway-down on the source side; healing needs no protocol action | — |
| ALERT_ACK lost | Re-ACK on re-received copies (≥2 s apart); source may show unconfirmed while gateway is authoritative | §9.4 |
| Receiver table evicted / rebooted | Fresh-source acceptance; single replay exposure | §7.4 |
| Counter wrap | Modular window comparison | §7.2 |
| RX FIFO overflow | Counted, flushed, logged; RX path never blocks or allocates | — |
| Airtime budget exhausted | P1 deferred at 50%, everything at 100% until window recovers | §10.3 |
| PSK compromised | Full forgery possible incl. ACK suppression; rotation = reflash | §11.1 |
| Jamming | Not mitigated; gateway displays silence as unknown | §1.2 |

---

## 14. Configuration parameter registry

All parameters are named constants (recommended home: the firmware's
`project_config.h`), documented, and overridable. "Change scope" defines what
must stay consistent for interoperability:

- **per-node free** — behavioral tuning; changing it on one node cannot break
  interop (only that node's behavior changes).
- **per-deployment** — must match across one deployment; may differ between
  deployments (e.g., two separate installations).
- **network-wide** — changing it requires re-provisioning/migrating all
  nodes; mismatches break interoperability silently or visibly.

| Constant | Default | Unit / range | Change scope | Notes |
|---|---|---|---|---|
| `PROTO_VERSION` | 1 | 4 bits | network-wide | version bump = migration (§17) |
| `NET_ID` | per deployment | u16 | per-deployment | — |
| `NODE_ID` | build-assigned | 0x02–0xFE (gateway 0x01) | per-deployment unique | §3.2 |
| `RF_SYNC_WORD` | per deployment | u16, not preamble-like | per-deployment | radio register |
| `MAX_PACKET_LEN` | 60 | B, ≤ 63 hard cap | network-wide | §4.2 |
| `REPORT_INTERVAL_MS` | 300000 | ms | per-node free | — |
| `REPORT_JITTER_MS` | 15000 | ms | per-node free | — |
| `ALERT_RETRY_DELAYS_MS` | {3000, 8000, 20000} | ms list | per-node free | length ≤ 3 (4 TX total cap is normative) |
| `TTL_INIT_ALERT` / `_ACK` | 8 | 1–15 | per-node free | must cover deployment diameter |
| `TTL_INIT_REPORT` / `_STATUS` | 4 | 1–15 | per-node free | — |
| `RELAY_BACKOFF_MIN_MS` / `MAX_MS` | 30 / 150 | ms | per-node free | — |
| `DEDUP_CACHE_SLOTS` | 24 | entries | per-node free | RAM-bounded |
| `DEDUP_TTL_ALERT_MS` | 2000 | ms | per-node free | must exceed relay backoff span |
| `DEDUP_TTL_DEFAULT_MS` | 300000 | ms | per-node free | — |
| `REPLAY_WINDOW` | 64 | IDs | per-node free | §7.2 |
| `NEIGHBOR_TABLE_SLOTS` | 16 | entries | per-node free | — |
| `PENDING_RELAY_SLOTS` | 8 | entries | per-node free | §8 |
| `TX_QUEUE_SLOTS_P0` / `_P1` | 4 / 4 | entries | per-node free | §10.2 |
| `CCA_ENABLED` / `CCA_ATTEMPTS` | true / 4 | — | per-node free | §10.1 |
| `CCA_BACKOFF_MIN_MS` / `MAX_MS` | 20 / 120 | ms | per-node free | — |
| `ACK_DELAY_MIN_MS` / `MAX_MS` | 200 / 400 | ms | gateway | §9.3 |
| `GATEWAY_ALERT_MEMORY_MS` | 600000 | ms | gateway | RAM, 64 IDs LRU |
| `GATEWAY_REACK_MIN_INTERVAL_MS` | 2000 | ms | gateway | — |
| `MSG_ID_PERSIST_BLOCK` | 128 | IDs | per-node free | §6 |
| `DUTY_LIMIT_MS_PER_HOUR` | 360000 (10%) | ms/h | per-deployment | legal parameter; 433 MHz row 15a confirmed (D10); lower it for extra margin |
| `DUTY_SOFT_FRACTION` | 0.5 | fraction | per-node free | — |
| `MIC_LEN` | 4 | B | network-wide | §11.2 |
| Radio: `RF_DATA_RATE`, `RF_DEVIATION`, `RF_BW`, `RF_FREQ`, `RF_POWER`, `RF_PREAMBLE`, whitening/CRC/append-status | 434.0 MHz, **4.8 kbps** (implemented), **25 kHz deviation** (D15), 135 kHz RX BW, **0 dBm**, sync `0x12AD` (demo only) | — | network-wide | Implemented values live in `firmware/shared/config.h` (single source of radio configuration). 38.4 kBaud is a v1.1 candidate (D17), not current behavior. Still open: occupied-BW mask check, e.r.p. incl. antenna gain, channel choice (§16). Note: 250 kBaud (540 kHz BW) is not usable at 433 MHz (row 15b: >250 kHz → 1 mW). |

Any constant marked per-node free or per-deployment MAY be changed without a
protocol version bump. Anything affecting packet layout, crypto, or semantics
requires a version bump and a decision-log entry.

---

## 15. Testing requirements and acceptance criteria

Testing is staged; host-side tests come first. Results are recorded with
date, tool versions, and pass/fail evidence. Nothing is called "verified"
until measured.

### 15.1 Packet codec unit tests (host-side, before any radio work)

- Round-trip encode/decode of every v1 type; golden vectors committed.
- Boundaries: L = 12 and L = 60; payload 0 B (type reserved semantics);
  every field at min/max.
- Malformed: truncated, oversize (radio + software layers), length < 12,
  bad version, foreign NET_ID, unknown flag bits (must be ignored, not
  crashed on), MIC bit-flips (must fail), MIC-less packets in production mode
  (must fail) and debug mode (must pass).
- Counter cases: replays, late/out-of-order IDs inside the window, IDs outside
  the window, wrap-around comparisons, fresh-source acceptance.
- **Acceptance:** all listed cases pass; the parser never reads past the
  buffer; no dynamic allocation in RX paths.

### 15.2 Flood simulator (host-side)

- Topologies: chain (8 hops), star, ring, random; uniform link loss 0–50%;
  node reboots; partitions; two nodes alerting simultaneously; gateway outage.
- Assertions: alerts delivered in ≥ 99% of trials on connected topologies at
  ≤ 30% loss; duplicates relayed = 0 after cache hit; per-node TX per alert
  event ≤ 6 (flood + retries seen by a relay); ACK cancels pending relays;
  no infinite forwarding; duty counter respects limits.
- **Acceptance:** all assertions pass across seeded scenario battery;
  scenario battery committed to the repository.

### 15.3 Bench (once firmware exists)

- Pin and record the RadioLib version (decision D12) before anything else.
- Verify with RadioLib that bad-CRC packets are actually rejected (CRC
  auto-flush is off by default; CRC is checked from appended status bytes).
- Two nodes: PER vs distance/PDU measurement table at each candidate data
  rate; RSSI/LQI logs.
- Measured AES-CMAC latency (send path) — target < 5 ms worst case at 80 MHz.
- Measured on-air TX time vs airtime-counter accounting (calibrate the duty
  budget implementation).
- Measured current per firmware state (feeds the power budget work).
- **Acceptance:** measured numbers replace every ESTIMATE in this document.

### 15.4 Regulatory (before any outdoor transmission at final power)

- Verify module band marking; confirm applicable BTK band row and duty limit;
  resolve whether fire-alarm use implies alarm-specific band rules; verify
  e.r.p. including antenna gain. Record in the decision log.

---

## 16. Limitations and unresolved items (honest list)

1. **CONFIRMED:** CC1101 module band = 433 MHz; general-purpose SRD rules
   selected (decision D10). **Still UNVERIFIED:** exact legal TX power
   (e.r.p. incl. antenna gain), occupied bandwidth vs TS EN 300 220 masks,
   channel choice, and all remaining radio parameters (§14) until bench tests.
2. **DECIDED:** alarm-specific band rules are not used (D10); regulatory
   re-verification of the final configuration against current BTK texts
   remains mandatory before deployment.
3. No confidentiality; no protection against insider/compromised-key attack;
   no anti-jamming; best-effort replay windows (RAM-only state).
4. Single point of failure: one gateway; its loss = no ACKs and no display
   (nodes keep bounded-retrying; nothing storms).
5. Continuous RX power draw until a duty-cycled mode is designed (v2 path via
   light sleep + CC1101 WOR exists and needs no packet-format change).
6. Alert *content* correctness (thresholds, false positives/negatives) is
   entirely outside the protocol and remains unproven until calibrated field
   tests exist.
7. No delivery guarantee — bounded effort + observable confirmation only.
8. v1 assumes ≤ ~10 nodes; beyond that, revisit routing (decision log D3).

### 16.1 Known demo-build omissions (firmware vs this specification)

The demo firmware (2026-10-24) implements the codec, MIC, replay window,
dedup cache, managed flooding, alert retries, gateway ACK, TX priority queues
and gateway-only ACK authority. The mechanisms below are **specified but not
implemented in the demo build**. They are listed here so that no reader
mistakes this specification for a description of current firmware behavior.
Each MUST be implemented before any deployment claim is made.

| Mechanism | Spec | Demo firmware status |
|---|---|---|
| CCA (channel-clear assessment) before TX | §10.1 | not implemented — transmission is immediate |
| `PKTLEN` hardware length filter | §4.1 | not implemented — software length check only (safe bound, but no radio-level filter) |
| Report jitter `±REPORT_JITTER_MS` | §9.1 | not implemented — fixed cadence |
| Jitter on alert retries | §9.2 | not implemented — literal +3/+8/+20 s |
| Duty-cycle budget enforcement | §10.3 | not implemented |
| Gateway per-node freshness table | §12.2 | not implemented — last alert/report only |
| `msg_id` persistence across reboots | §6 | not implemented — counter restarts at 128 |
| Per-deployment sync word | §3.3 | demo uses RadioLib default `0x12AD` |
| PSK provisioning / key storage | §11.1 | demo key is a committed placeholder, never a real key |

Because this document is published as an implementable protocol, this table is
part of the specification, not a disclaimer bolted onto it.

---

## 17. Versioning and evolution

- `ver` = 1. Receivers MUST drop unknown versions (count them); no error
  replies in v1.
- Migrating to v2 (small network) = reflash all nodes; v1/v2 cannot coexist on
  one NET_ID (deliberate: no dual-stack complexity in a prototype).
- Reserved mechanisms ready for v2, each requiring a decision-log entry and a
  security review before implementation: encryption (AES-CTR/CCM* using the
  reserved flag bit + `(src, msg_id)` nonce material), per-node keys,
  ALERT_CLEAR policy, PING diagnostics, CONFIG (authenticated), duty-cycled
  listening, time synchronization, collection-tree routing if scale demands.
- Deprecated/retired concepts must never be reintroduced silently
  (e.g., "hashed broadcasts", "MULTICAST WHISPER" — retired 2026-10-20, see
  decision log).

---

## 18. References

- TI CC1101 datasheet (SWRS061): https://www.ti.com/lit/ds/symlink/cc1101.pdf —
  FIFO/length/CRC/address filtering/currents/sensitivity/WOR.
- TI DN500, Packet Transmission Basics (SWRA109): https://www.ti.com/lit/swra109 —
  64-byte FIFO guidance.
- Espressif, ESP8266 Low-Power Solutions:
  https://documentation.espressif.com/9b-esp8266-low_power_solutions__en.pdf
- ESP8266 RTOS SDK sleep modes:
  https://docs.espressif.com/projects/esp8266-rtos-sdk/en/latest/api-reference/system/sleep_modes.html
- arduino-esp8266 core docs (memory, EEPROM, LowPowerDemo):
  https://arduino-esp8266.readthedocs.io/en/latest/ ;
  https://github.com/esp8266/Arduino/blob/master/libraries/esp8266/examples/LowPowerDemo/README.md
- BTK — FTM Regulation & Technical Criteria (current regime):
  https://www.btk.gov.tr/en/radio-devices-and-systems-exempt-from-frequency-allocation ;
  technical criteria:
  https://www.btk.gov.tr/uploads/pages/ftm-teknik-olcutler-ek-5.pdf
- KET Regulation (2012, superseded, historical):
  https://resmigazete.gov.tr/eskiler/2012/09/20120911-24.htm
- RFC 4493, The AES-CMAC Algorithm: https://www.rfc-editor.org/rfc/rfc4493.html
- NIST SP 800-38B (CMAC): https://csrc.nist.gov/publications/detail/sp/800-38b/final
- Gnawali et al., CTP (ACM TOSN 2013): https://dl.acm.org/doi/10.1145/2529988 —
  collection-tree comparison point.
- Xiao et al., MAC security in IEEE 802.15.4 (EURASIP JWCN 2006):
  https://doi.org/10.1155/2006/93830 — replay-counter attack literature.
- WSN routing survey (flooding/gossiping): https://pmc.ncbi.nlm.nih.gov/articles/PMC3260592/
- RadioLib (CC1101 library, decision D12) — wiki default configuration:
  https://github.com/jgromes/RadioLib/wiki/Default-configuration ;
  CC1101 API: https://jgromes.github.io/RadioLib/class_c_c1101.html ;
  long-packet limitations: https://github.com/jgromes/RadioLib/discussions/1138 ;
  length-byte/address-filtering fix: https://github.com/jgromes/RadioLib/issues/1482

END OF PROTOCOL SPECIFICATION v1
