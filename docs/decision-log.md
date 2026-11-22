# YankiProtocol Decision Log

This repository owns the protocol decisions for the YankiProtocol library. The
entries below are a scoped extract of the MeshForest project's single historical
decision log; protocol decisions are authoritative here.

**Note:** Protocol decisions are authoritative here. Hardware/power/gateway
decisions (D1, D10, D11, D14, D18) remain in the MeshForest application
repository's decision log; this file is a scoped extract of the project's single
historical log.

Status legend: **APPROVED** (owner confirmed), **RETIRED** (concept dropped),
**OPEN** (unresolved — not a decision yet).

---

### D2. Radio listening model: continuous RX; all nodes relay; no deep sleep in v1
**Status:** APPROVED

- **Problem:** The MAC, alert latency, and forwarding feasibility all depend
  on whether nodes listen continuously or sleep.
- **Decision:** Nodes keep the CC1101 in continuous receive; every node is
  sensor **and** relay. No deep sleep in v1 (ESP8266 deep sleep cannot be
  woken by the radio and would break sensing continuity).
- **Alternatives:** ESP8266 light sleep + CC1101 wake-on-radio (lower power,
  but long preambles multiply airtime and complicate the driver); deep sleep
  with scheduled windows (sleeping nodes cannot forward; high complexity).
- **Rationale:** Simplest correct protocol first; MQ-2 heater likely dominates
  the power budget; the protocol keeps all timings parameterized so a
  duty-cycled mode can be added later without a packet-format change.
- **Consequences:** Idle power ~15–20 mA radio + MCU; acceptable until real
  power measurements exist. Duty-cycled listening remains a documented v2
  candidate (protocol-spec §17).

### D3. Routing: managed flooding (no routing state)
**Status:** APPROVED

- **Problem:** Multi-hop forwarding across ≤ ~10 nodes with reboots,
  brownouts, and partitions.
- **Decision:** Managed flooding: each node rebroadcasts every valid new
  packet once (duplicate cache + TTL + random backoff); gateway ACK
  suppresses further copies. No routing tables, no beacons, no link-state.
- **Alternatives:** collection-tree protocol (CTP-class: ETX link
  estimation, adaptive beacons, datapath validation — efficient at scale but
  a much larger test/repair surface); DSR-style route discovery; hybrid
  flood+tree; alerts-only networking (rejected: gateway needs node
  health/freshness).
- **Rationale:** At single-digit node counts and a report every few minutes,
  flooding costs ~0.001–0.03% duty (orders below legal limits), needs zero
  repair logic after reboot/partition, and maximizes alert-path robustness —
  the project's priority. Flooding's O(N) airtime is the accepted trade-off.
- **Consequences:** Scaling beyond ~10–15 nodes or sub-minute reporting must
  trigger a routing redesign review. Loop-freedom comes from
  dedup+TTL, not from route state.

### D4. Alert delivery: end-to-end gateway ACK with bounded retries
**Status:** APPROVED

- **Problem:** "Reliable" alert delivery needs a defined, observable meaning.
- **Decision:** Only the gateway confirms delivery, by flooding an
  authenticated ALERT_ACK naming (src, msg_id). The source retransmits the
  same alert at +3/+8/+20 s (4 transmissions total) until it hears the ACK,
  then stops. Relays cancel pending ALERT relays upon hearing the matching
  ACK. Reports stay fire-and-forget (cadence + gateway staleness display).
- **Alternatives:** hop-by-hop ACKs (faster local retry but no end-to-end
  proof, per-neighbor timers); blind K-repetition (cannot distinguish
  delivered from lost, storm-prone); persistent re-alerting (kept as an
  alert-policy option in firmware, not a protocol mechanism).
- **Rationale:** True end-to-end confirmation with no reverse-routing state;
  the ACK doubles as flood suppression; every counter is bounded (no storms
  during partitions — a project requirement).
- **Consequences:** "Unconfirmed" ≠ "undelivered" (asymmetric loss); the
  gateway display is authoritative for alarms (protocol-spec §9.4). ACK
  forgery = alert suppression → ACKs are authenticated like everything else.

### D5. Security v1: AES-CMAC authentication + windowed replay protection; no encryption
**Status:** APPROVED

- **Problem:** A fire alert drives a siren; forged alerts/replayed alerts are
  real nuisance/safety risks. No hardware crypto on ESP8266 or CC1101.
- **Decision:** One 128-bit network PSK; AES-128-CMAC (RFC 4493 —
  established, reviewed; no custom cryptography) over header+payload with a
  32-bit MIC; per-source 16-bit counters with a modular acceptance window
  (64) and bounded duplicate caches. No encryption in v1.
- **Alternatives:** defer all crypto with reserved fields (faster bring-up,
  forgeable pilot); full AEAD (overkill for non-sensitive data, more
  nonce/complexity surface); no crypto ever (indefensible given the siren).
- **Rationale:** Auth-only blocks outsider spoofing/replay at +4 B/packet
  and modest CPU; sensor data is not confidential; encryption can be added
  later via a reserved flag bit and version bump.
- **Consequences / documented limits:** captured node = key compromise =
  full forgery possible (rotation = reflash); replay windows are RAM-only,
  best-effort freshness; no anti-jamming. See protocol-spec §11.

### D6. Packet budget: total packet ≤ 60 B (48 B payload ceiling); little-endian
**Status:** APPROVED (part of v1 design)

- **Problem:** The project's "~50–60 B application message" target had to be
  reconciled with the verified CC1101 limits (64 B FIFO; 61–63 B usable with
  CRC auto-flush + status bytes; >64 B needs mid-packet FIFO streaming that
  simple libraries don't support).
- **Decision:** The 50–60 B target is interpreted as a **total packet** cap:
  60 B FIFO region = 8 B header + ≤48 B payload + 4 B MIC. Hardware PKTLEN =
  60. Little-endian throughout.
- **Alternatives:** 50–60 B payload on top of header+MIC (65–75 B total →
  risky FIFO streaming, library-dependent); fixed-length mode.
- **Rationale:** Stays inside the FIFO with margin, works with any sane
  CC1101 library, and leaves 2–3× headroom over actual v1 messages
  (15–19 B total).
- **Consequences:** If a future message ever needs >48 B payload, that is a
  design review, not a silent extension.

### D7. Message identifiers: 16-bit per-source counters, persisted monotonic across reboots
**Status:** APPROVED (part of v1 design)

- **Problem:** Dedup, replay windows, and ACK matching all key on
  (src, msg_id); reboot must not make IDs ambiguous.
- **Decision:** One 16-bit counter per node for all originated messages.
  Persisted in blocks: at boot resume at (persisted + 128); persist again
  every 128 increments. Wrap at 65536 handled by modular window comparison.
- **Alternatives:** epoch byte in every header (costs a byte, needs its own
  persistence); random message IDs (breaks windowing); 32-bit counter
  (wastes 2 B in every packet forever).
- **Rationale:** Block persistence makes IDs strictly monotonic across
  reboots (≤127 values ever lost on power cut; resume is provably above all
  used IDs) at ~2–3 flash commits/day — decades of wear headroom.
- **Consequences:** ESP8266 EEPROM-emulation wear-leveling must be verified
  at implementation; wear math re-checked then.

### D8. Default parameter set + configurability requirement
**Status:** APPROVED (owner accepted defaults, requested configurability)

- **Decision:** Defaults recorded in protocol-spec §14 (report 300 s ±15 s
  jitter; alert retries +3/+8/+20 s; TTL 8 for ALERT/ACK and 4 for
  REPORT/STATUS; 38.4 kBaud GFSK as the *proposal*; build-time node IDs;
  duty limit default 1% pending band verification).
  **Superseded in part:** the 1 % duty default was replaced by D10
  (360000 ms/h = 10 %) once the 433 MHz band was confirmed, and the
  38.4 kBaud proposal was replaced by D17 (the implemented rate is 4.8 kbps).
- **Configurability rule:** every protocol constant is a named, documented,
  overridable parameter; §14 defines the change scope of each
  (per-node free / per-deployment / network-wide). Packet-layout, crypto, or
  semantic changes require a version bump and a decision-log entry.
- **Consequences:** radio parameters (band, rate, power, sync word…) remain
  **UNVERIFIED** until the physical module is identified and bench-tested;
  the 38.4 kBaud figure is a starting hypothesis, not a fact.

### D9. "Hashed broadcasts" and "MULTICAST WHISPER" retired
**Status:** RETIRED (owner, 2026-10-20)

- **Problem:** Two concept names appeared in early discussions and the
  working spec with no defined semantics; the spec forbids implementing
  behavior based on names alone.
- **Decision:** Retired. Per the owner: they were an early, HTTP-method-like
  concept sketch; do not use or keep them. The approved managed-flood +
  AES-CMAC + dedup design supersedes them.
- **Consequences:** Working spec references updated; the names must not be
  reintroduced silently.

---

### D12. CC1101 Arduino library: RadioLib selected
**Status:** VALIDATED (bench-proven 2026-11-06; RadioLib 7.8.1 pinned per D14)

- **Verified (RadioLib wiki/API/source, 2026-10-20):** CC1101 supported with
  434 MHz default (matches our band); explicit ESP8266 support (examples use
  `ICACHE_RAM_ATTR` for ESP8266/ESP32); pin model CS + GDO0 (+ optional
  GDO2/RST); variable-length packet mode; `startTransmit` is
  **interrupt-driven for packets < 64 bytes** — our ≤60-byte FIFO region
  stays inside this clean regime — and blocks up to 255 bytes with documented
  limitations (discussion #1138); configurable sync word (default `0x12AD`,
  must be replaced per-deployment per protocol-spec §3.3); CC1101-native CRC16
  enabled (hardware-fixed config), appended status ON → `getRSSI()`/`getLQI()`
  available; whitening default OFF; the length-byte-with-address-filtering
  pitfall (issue #1482) was fixed in #1483 (April 2025) — evidence of active
  maintenance on exactly the subtle CC1101 quirks this project cares about.
- **Alternatives:** ELECHOUSE-style wrappers — simpler but with less
  documented register-level control and packet-length behavior; rejected on
  maintenance and documentation quality.
- **Consequences:** firmware keeps a radio-driver wrapper so protocol code
  stays library-agnostic; RadioLib version must be pinned and recorded at the
  first bench run. With RadioLib defaults, CRC auto-flush is OFF (CRC checked
  via appended status in software) — bring-up must verify bad-CRC packets are
  actually rejected.

### D13. Virtual testing first; Python reference model + flood simulator
**Status:** APPROVED (owner, 2026-10-20, session 2: "virtual testing is more
appropriate now")

- **Decision:** No MCU firmware yet. Host-side testing comes first: a Python
  reference model of the protocol (packet codec + AES-CMAC validated against
  the official RFC 4493 test vectors) and a discrete-event flood simulator
  implement protocol-spec §15.1/§15.2. Later, the ESP8266 C++ firmware must
  pass the same golden vectors (cross-validation between reference model and
  firmware).
- **Toolchain facts (dev machine, 2026-10-20):** Python 3.14 available; g++
  absent → Python chosen; no external server required. The owner's offered
  local server is not connected to the agent environment (no MCP resources
  registered) and is not needed for these tests — they run locally in
  seconds.
- **Report cadence note:** 300 s default stands; for rapid bench testing a
  shorter profile (e.g., 60 s) is recommended — already a config constant
  (`REPORT_INTERVAL_MS`), no spec change needed.
- **Results (2026-10-20):** suite built and passing — see
  `docs/test-log.md` (50 unit checks + 9 simulator scenarios, including a
  real retry-scheduler off-by-one the tests caught before it could become a
  firmware bug).

---

### D15. CC1101 frequency deviation widened 5 kHz → 25 kHz
**Status:** ADOPTED under D14 bench authority (measurement-driven necessity;
owner informed 2026-11-06; single reversible config constant)

- **Problem:** with RadioLib 7.8.1 defaults (4.8 kbps, 5 kHz deviation),
  4-byte test pings arrived ~72% clean, but 17-byte protocol packets only
  ever arrived with CRC errors (or died mid-packet). Two ±10 ppm crystals at
  434 MHz can sit ~8.7 kHz apart — wider than the deviation itself, so
  demodulation was marginal and longer packets lost.
- **Decision:** `RF_FREQ_DEV_KHZ 25.0` in `firmware/shared/config.h` (the
  single radio-configuration source), applied identically in demo_node,
  demo_gateway, 03_ping_tx, 03_ping_rx. Measured result: 18/18 reports
  received clean, LQI ≈ 12 (was ≈ 60 at 5 kHz), zero CRC failures.
- **Alternatives:** keep 5 kHz (measured failing); CC1101 AFC (not exposed
  by RadioLib); narrower RX bandwidth (unneeded — bench RSSI ≈ −36 dBm,
  Carson ≈ 55 kHz ≪ the 135 kHz default RX BW).
- **Consequences:** interop requirement — all boards must use the same
  deviation (protocol-spec §14 class of parameter); occupied bandwidth grows
  to ≈ 55 kHz, still trivially inside the SRD allocation with the same
  10 mW e.r.p. limit (D10). Power consumption unchanged.

---

### D16. Packet header byte order corrected to little-endian (code changed, not the spec)
**Status:** APPROVED (owner, 2026-11-22) — code corrected; bench re-verification pending

- **Problem:** `protocol-spec.md` §4.2 and D6 both state "all multi-byte
  fields little-endian", but `net_id` (bytes 2–3) and `msg_id` (bytes 6–7)
  were encoded **big-endian** in both `tools/proto/protocol.py` and
  `firmware/shared/protocol.h`. Payload fields were correctly little-endian,
  so the packet carried two byte orders — the same bug class that already
  produced a defect in the ACK/status payloads (test-log 2026-10-24).
- **Decision:** The **code** changes to match the spec, not the reverse. One
  invariant ("every multi-byte field is little-endian") is worth more than
  the hex-dump readability of a big-endian header, especially because the
  protocol is about to be published as an implementable specification.
- **Alternatives:** amend the spec to "header BE, payload LE" (zero reflash,
  but permanently splits the rule and invites third-party interop bugs).
- **Changes:** 4 lines in `protocol.h` (`encode`/`decode`), 3 in
  `protocol.py` (`encode`/`decode` + one hand-built test fixture that
  hard-coded the old order); `golden_vectors.h` regenerated with
  `tools/proto/make_vectors.py`.
- **Verified:** Python suite 50/50 checks; simulator 9/9 scenarios; all seven
  sketches compile for `esp8266:esp8266:nodemcuv2` (including the two bring-up
  sketches that had not compiled since the D15 deviation edit).
- **NOT yet verified:** both boards must be reflashed with the new codec and
  the over-the-air exchange re-run. Until then the bench result of 2026-11-06
  describes the **old** wire format. No deployment exists, so no version bump
  is required.

### D17. v1 runs 4.8 kbps; 38.4 kBaud deferred to v1.1
**Status:** APPROVED (owner, 2026-11-22)

- **Problem:** The spec's airtime budget (§10.4) assumed a 38.4 kBaud GFSK
  proposal (5.8 ms per 19-byte ALERT), but the firmware never sets a bit rate
  and therefore runs RadioLib's 4.8 kbps default. The measured 43 ms per
  17-byte report (2026-11-06) is the 4.8 kbps figure.
- **Decision:** Document 4.8 kbps as the implemented v1 rate; treat 38.4 kBaud
  as a v1.1 tuning task. At the 300 s cadence the measured duty is ~0.014 %,
  far below the 10 % limit, so there is no compliance pressure to change it.
- **Why it is not simply "obviously better" to raise the rate:** with the
  D15 deviation of 25 kHz, the modulation index is h = 2Δf/R ≈ 10.4 at
  4.8 kbps versus ≈ 1.3 at 38.4 kbps. The current operating point is
  inefficient (wide bandwidth for the data rate, so lower sensitivity than
  achievable) and it only exists because the deviation was widened to beat a
  crystal offset. Rate and deviation must be re-optimised together, with PER
  measurements, not changed independently.
- **Consequences:** §10.4 and §14 now carry measured 4.8 kbps figures; any
  future rate change is a network-wide parameter change requiring re-bench.

---

## Open protocol items

The following protocol/radio/security/packet/ACK/duty/byte-order/reflash items
are copied from the source log's "Open items" section. Hardware/power items
live in the MeshForest application repository.

- **[RESOLVED by D10]** Module band = 433 MHz; general SRD rules (10 mW
  e.r.p., ≤10% duty). Still open within it: e.r.p. verification incl. antenna
  gain, occupied-bandwidth mask check (TS EN 300 220), channel selection.
- **[RESOLVED by D14]** Library = RadioLib **7.8.1, pinned** and bench-proven
  (D12 status is now VALIDATED).
- **[OPEN — action, D16]** Both boards must be reflashed with the little-endian
  codec and the over-the-air exchange re-run. The 18/18 clean-reception result
  of 2026-11-06 describes the previous wire format and must not be quoted as
  evidence for the current firmware until that test is repeated.
- **[OPEN]** Source-node ACK reception: the gateway schedules its ACK 200–400 ms
  after receipt (protocol-spec §9.3), but the transmitting node's radio is
  still in its own TX/standby blind window at that moment, so the source node
  never hears the ACK (observed 0/18, 2026-11-06). Candidate fix: extend or
  randomize the gateway ACK delay into 150–350 ms *after the node's blind
  window closes*; if adopted it needs a protocol-spec §9.3 note (the Python
  model does not simulate TX blind windows). Demo is unaffected — siren/OLED
  fire on receipt.
