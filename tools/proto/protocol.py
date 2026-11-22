"""MeshForest protocol v1 reference model (host-side).

Executable specification of docs/protocol-spec.md for host-side testing
(decision D13). The ESP8266 firmware must eventually pass the same golden
vectors produced from this model.

Implements: packet format (§4), message payloads (§5), msg_id persistence
(§6), receive pipeline with replay window + dedup cache (§7), managed-flood
forwarding (§8), alert retries + gateway ACK (§9), TX priority + duty budget
(§10). Time and randomness are injected so the simulator drives everything
deterministically.

Run unit tests:  python tools/proto/protocol.py
"""

import hmac
import random
import struct
from collections import OrderedDict, deque, defaultdict

from aes_cmac import aes128_cmac

# ---- constants (names match protocol-spec §14 parameter registry) ----------
PROTO_VERSION = 1
MAX_PACKET_LEN = 60          # FIFO-region cap == radio length-byte value
HEADER_LEN = 8
MIC_LEN = 4
FLAG_MIC = 0x01
BROADCAST = 0x00
GATEWAY_ID = 0x01
RESERVED_ID = 0xFF

T_RESERVED, T_REPORT, T_ALERT, T_ACK, T_STATUS = 0, 1, 2, 3, 4
T_ALERT_CLEAR, T_PING, T_CONFIG = 5, 6, 7          # reserved types: relay only
TTL_INIT = {T_REPORT: 4, T_ALERT: 8, T_ACK: 8, T_STATUS: 4,
            T_ALERT_CLEAR: 8, T_PING: 8, T_CONFIG: 8}
PAYLOAD_LEN = {T_REPORT: 5, T_ALERT: 7, T_ACK: 3, T_STATUS: 5}
PRIO_ALERT = 0                                     # queue class P0
PRIO_OTHER = 1                                     # queue class P1
P0_TYPES = (T_ALERT, T_ACK)

REPLAY_WINDOW = 64
NEIGHBOR_SLOTS = 16
DEDUP_SLOTS = 24
DEDUP_TTL_ALERT_S = 2.0
DEDUP_TTL_DEFAULT_S = 300.0

RELAY_BACKOFF_MIN_S = 0.030
RELAY_BACKOFF_MAX_S = 0.150
PENDING_RELAY_SLOTS = 8
QUEUE_SLOTS_P0 = 4
QUEUE_SLOTS_P1 = 4

ALERT_RETRY_DELAYS_S = (3.0, 8.0, 20.0)            # after the initial TX
ACK_DELAY_MIN_S = 0.200
ACK_DELAY_MAX_S = 0.400
GATEWAY_ALERT_MEMORY_S = 600.0
GATEWAY_REACK_MIN_S = 2.0
ALERT_MEMORY_SLOTS = 64

MSG_ID_PERSIST_BLOCK = 128
DUTY_LIMIT_MS_PER_H = 360000.0                     # 10% @ 433 MHz (D10)
DUTY_SOFT_FRACTION = 0.5

AIRTIME_BAUD = 38400.0                             # proposal, parameterized
PREAMBLE_BYTES, SYNC_BYTES, LEN_BYTES, CRC_BYTES = 4, 2, 1, 2

TEMP_MISSING = 0x7FFF                              # temp ×10, i16
HUM_MISSING = 0xFFFF                               # RH ×10, u16

# sensor flags (SENSOR_REPORT byte 0)
SF_MQ2_PRESENT, SF_MQ2_ACTIVE, SF_MQ2_VALID = 0x01, 0x02, 0x04
SF_DHT_PRESENT, SF_DHT_VALID = 0x08, 0x10
SF_FLAME_PRESENT, SF_FLAME_ACTIVE = 0x20, 0x40
# alert flags (ALERT byte 0)
AF_MQ2, AF_FLAME, AF_TEMP, AF_MULTI = 0x01, 0x02, 0x04, 0x08
# node status flags
NF_BOOTED, NF_LOW_BATT, NF_SENSOR_FAULT = 0x01, 0x02, 0x04
# alert levels
LEVEL_TEST, LEVEL_WARNING, LEVEL_CRITICAL = 0, 1, 2


class Reject(Exception):
    """Packet rejected in the receive pipeline (reason == drop counter)."""
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def airtime_ms(pkt_len):
    """On-air TX time in ms for a FIFO region of pkt_len bytes (§10.4)."""
    on_air = PREAMBLE_BYTES + SYNC_BYTES + LEN_BYTES + pkt_len + CRC_BYTES
    return on_air * 8.0 / AIRTIME_BAUD * 1000.0


def compute_mic(key, body):
    return aes128_cmac(key, body)[:MIC_LEN]


def encode(key, net_id, src, msg_id, ptype, payload=b"", ttl=None,
           dst=BROADCAST, with_mic=True):
    """Build a FIFO-region packet. Returns bytes (length byte excluded)."""
    if ptype in PAYLOAD_LEN and len(payload) != PAYLOAD_LEN[ptype]:
        raise ValueError("payload length mismatch for type %d" % ptype)
    if ttl is None:
        ttl = TTL_INIT.get(ptype, 4)
    flags = FLAG_MIC if with_mic else 0x00
    hdr = bytes([(PROTO_VERSION << 4) | (ttl & 0x0F),
                 (ptype << 4) | flags,
                 net_id & 0xFF, (net_id >> 8) & 0xFF,   # little-endian (§4.2)
                 dst, src,
                 msg_id & 0xFF, (msg_id >> 8) & 0xFF])
    body = hdr + payload
    total = len(body) + (MIC_LEN if with_mic else 0)
    if total > MAX_PACKET_LEN:
        raise ValueError("packet too long: %d" % total)
    return body + compute_mic(key, body) if with_mic else body


def decode(data, key, net_id, allow_no_mic=False):
    """Validate + parse per protocol-spec §4.3 order. Raises Reject."""
    ln = len(data)
    if ln < HEADER_LEN:
        raise Reject("length_short")          # cannot even parse the header
    if ln > MAX_PACKET_LEN:
        raise Reject("length_long")
    ptype, flags = data[1] >> 4, data[1] & 0x0F
    if flags & FLAG_MIC and ln < HEADER_LEN + MIC_LEN:
        raise Reject("length_short")          # §4.2: 12 <= L <= 60 with MIC
    ver, ttl = data[0] >> 4, data[0] & 0x0F
    net = data[2] | (data[3] << 8)          # little-endian (§4.2)
    dst, src = data[4], data[5]
    mid = data[6] | (data[7] << 8)          # little-endian (§4.2)
    if net != net_id:
        raise Reject("net_id")
    if ver != PROTO_VERSION:
        raise Reject("version")
    if flags & FLAG_MIC:
        body, m = data[:ln - MIC_LEN], data[ln - MIC_LEN:]
        if not hmac.compare_digest(compute_mic(key, body), m):
            raise Reject("mic")
        payload = data[HEADER_LEN:ln - MIC_LEN]
    else:
        if not allow_no_mic:                   # §11.5 production rule
            raise Reject("mic_flag")
        payload = data[HEADER_LEN:]
    if ptype in PAYLOAD_LEN and len(payload) != PAYLOAD_LEN[ptype]:
        raise Reject("payload_len")
    return {"ver": ver, "ttl": ttl, "type": ptype, "flags": flags,
            "net_id": net, "dst": dst, "src": src, "msg_id": mid,
            "payload": payload}


# ---- payload builders/parsers (protocol-spec §5) ---------------------------

def report_payload(sflags, temp=TEMP_MISSING, hum=HUM_MISSING):
    return struct.pack("<BhH", sflags, temp, hum)


def parse_report(p):
    sflags = p[0]
    temp, hum = struct.unpack("<hH", p[1:5])
    return {"flags": sflags, "temp_c01": temp, "hum_01": hum}


def alert_payload(aflags, level, snapshot=report_payload(0)):
    return struct.pack("<BB", aflags, level) + snapshot


def parse_alert(p):
    return {"flags": p[0], "level": p[1], "snapshot": parse_report(p[2:7])}


def ack_payload(acked_src, acked_mid):
    return struct.pack("<BH", acked_src, acked_mid)


def parse_ack(p):
    s, m = struct.unpack("<BH", p)
    return {"acked_src": s, "acked_mid": m}


def status_payload(sflags, uptime_min, reset_reason, boot_count):
    return struct.pack("<BHBB", sflags, uptime_min, reset_reason, boot_count)


def parse_status(p):
    sflags, up, rr, bc = struct.unpack("<BHBB", p)
    return {"flags": sflags, "uptime_min": up, "reset_reason": rr,
            "boot_count": bc}


# ---- receive-side state (protocol-spec §7) --------------------------------

class ReceiveState:
    """Per-source replay window + duplicate cache. RAM-only by design."""

    def __init__(self):
        self.last = OrderedDict()      # src -> last_id (LRU-bounded)
        self.seen = OrderedDict()       # (src, mid) -> expiry time

    def _cache_hit(self, key, now):
        exp = self.seen.get(key)
        if exp is None:
            return False
        if exp <= now:                  # expired -> treat as miss
            del self.seen[key]
            return False
        self.seen.move_to_end(key)
        return True

    def _cache_add(self, key, ptype, now):
        ttl = DEDUP_TTL_ALERT_S if ptype == T_ALERT else DEDUP_TTL_DEFAULT_S
        self.seen[key] = now + ttl
        self.seen.move_to_end(key)
        while len(self.seen) > DEDUP_SLOTS:
            self.seen.popitem(last=False)

    def accept(self, src, mid, ptype, now):
        """Returns (ok, reason). reason is a drop-counter name on failure."""
        key = (src, mid)
        if src not in self.last:
            self.last[src] = mid
            if len(self.last) > NEIGHBOR_SLOTS:
                self.last.popitem(last=False)
            self._cache_add(key, ptype, now)
            return True, "new_source"
        d = (mid - self.last[src]) % 65536
        if 1 <= d <= REPLAY_WINDOW:                    # new, within window
            self.last[src] = mid
            self._cache_add(key, ptype, now)
            return True, "new"
        if d == 0 or d >= 65536 - REPLAY_WINDOW:       # recently-seen range
            if self._cache_hit(key, now):
                return False, "duplicate"
            self._cache_add(key, ptype, now)           # late / out of order
            return True, "late"                        # no backward advance
        return False, "out_of_window"                  # too old or too new


# ---- node model (protocol-spec §8-§12) -------------------------------------

class Node:
    def __init__(self, nid, key, net_id, rng, world, is_gateway=False,
                 allow_no_mic=False):
        assert nid != RESERVED_ID
        self.id = nid
        self.key = key
        self.net_id = net_id
        self.rng = rng
        self.world = world
        self.is_gateway = is_gateway
        self.allow_no_mic = allow_no_mic      # bench/debug builds only
        self.stats = defaultdict(int)
        self.rstate = ReceiveState()
        # msg_id persistence (§6)
        self.persisted = 0
        self.ctr = 0
        self.since_persist = 0
        self._boot_reset_counter()
        # TX machinery
        self.queues = ([], [])                # p0, p1: [due, pkt, prio]
        self.busy_until = 0.0
        self.airtime = deque()                # (time_s, ms)
        self.pending_relays = []              # [due, pkt, prio, cancel_key]
        self.alert_retries = {}               # (src, mid) -> [due, attempt, pkt]
        self.confirmed = set()                # alerts ACKed (seen at source)
        # gateway state (§9.3, §12.2)
        self.gw_alerts = OrderedDict()        # (src, mid) -> last_ack_time
        self.gw_ack_due = []                  # [due, (src, mid)]
        self.siren_count = 0
        self.reports_seen = {}                # src -> last report time

    # -- lifecycle --------------------------------------------------------
    def _boot_reset_counter(self):
        self.ctr = (self.persisted + MSG_ID_PERSIST_BLOCK) % 65536
        self.persisted = self.ctr             # immediate persist at boot (§6)
        self.since_persist = 0

    def reboot(self, now):
        """Lose all RAM protocol state; counter stays monotonic (§6)."""
        self.rstate = ReceiveState()
        self.queues = ([], [])
        self.busy_until = 0.0
        self.pending_relays = []
        self.alert_retries = {}
        if self.is_gateway:
            self.gw_alerts = OrderedDict()
            self.gw_ack_due = []
            self.reports_seen = {}
        self.stats["reboots"] += 1
        self._boot_reset_counter()

    # -- originating -------------------------------------------------------
    def next_msg_id(self):
        mid = self.ctr
        self.ctr = (self.ctr + 1) % 65536
        self.since_persist += 1
        if self.since_persist >= MSG_ID_PERSIST_BLOCK:
            self.persisted = self.ctr
            self.since_persist = 0
        return mid

    def originate(self, ptype, payload, now, with_mic=True):
        mid = self.next_msg_id()
        pkt = encode(self.key, self.net_id, self.id, mid, ptype,
                      payload=payload, with_mic=with_mic)
        prio = PRIO_ALERT if ptype in P0_TYPES else PRIO_OTHER
        self.enqueue_tx(now, pkt, prio)
        self.stats["orig_%d" % ptype] += 1
        return mid

    def originate_alert(self, now, aflags=AF_MQ2, level=LEVEL_CRITICAL,
                        snapshot=None):
        snapshot = snapshot if snapshot is not None else report_payload(
            SF_MQ2_PRESENT | SF_MQ2_ACTIVE | SF_MQ2_VALID |
            SF_DHT_PRESENT | SF_DHT_VALID | SF_FLAME_PRESENT | SF_FLAME_ACTIVE,
            423, 301)
        payload = alert_payload(aflags, level, snapshot)
        mid = self.originate(T_ALERT, payload, now)
        # retry state: [absolute due time, attempt index, payload bytes]
        self.alert_retries[(self.id, mid)] = [now + ALERT_RETRY_DELAYS_S[0],
                                              1, payload]
        return mid

    def originate_report(self, now, sflags=0x7F, temp=423, hum=301):
        return self.originate(T_REPORT, report_payload(sflags, temp, hum),
                              now)

    def originate_status(self, now, sflags=NF_BOOTED, uptime_min=0,
                         reset_reason=0):
        return self.originate(T_STATUS, status_payload(sflags, uptime_min,
                                                       reset_reason,
                                                       self.stats["reboots"]),
                               now)

    # -- TX path (§10) ------------------------------------------------------
    def enqueue_tx(self, now, pkt, prio):
        q = self.queues[prio]
        limit = QUEUE_SLOTS_P0 if prio == PRIO_ALERT else QUEUE_SLOTS_P1
        if len(q) >= limit:
            q.pop(0)                          # bounded: drop oldest in class
            self.stats["queue_drop_p%d" % prio] += 1
        q.append([now, pkt, prio])

    def _duty_window_ms(self, now):
        while self.airtime and self.airtime[0][0] <= now - 3600.0:
            self.airtime.popleft()
        return sum(ms for _, ms in self.airtime)

    def _try_transmit(self, now):
        for prio in (PRIO_ALERT, PRIO_OTHER):          # P0 preempts P1
            q = self.queues[prio]
            while q and now >= self.busy_until:
                due, pkt, p = q[0]
                if due > now:
                    break
                q.pop(0)
                window = self._duty_window_ms(now)
                if window >= DUTY_LIMIT_MS_PER_H:
                    self.enqueue_tx(now + 1.0, pkt, p)  # defer, bounded
                    self.stats["duty_defer"] += 1
                    break
                if p == PRIO_OTHER and \
                        window >= DUTY_SOFT_FRACTION * DUTY_LIMIT_MS_PER_H:
                    self.stats["duty_drop_p1"] += 1     # report dropped
                    continue
                ams = airtime_ms(len(pkt))
                self.airtime.append((now, ams))
                self.busy_until = now + ams / 1000.0
                self.stats["tx"] += 1
                self.stats["tx_type_%d" % decode(pkt, self.key,
                                                self.net_id,
                                                self.allow_no_mic)["type"]] += 1
                self.world.send(self, pkt, now)

    def earliest_due(self):
        """Earliest time at which this node has queued work (for the
        simulator's wake scheduling); None if idle."""
        times = [e[0] for q in self.queues for e in q]
        times += [e[0] for e in self.pending_relays]
        times += [st[0] for st in self.alert_retries.values()]
        if self.is_gateway:
            times += [d for d, _ in self.gw_ack_due]
        return min(times) if times else None

    def tick(self, now):
        # fire due relay retransmissions
        still = []
        for entry in self.pending_relays:
            due, pkt, prio, key = entry
            if due <= now:
                if key is not None and key in self.confirmed:
                    self.stats["relay_cancel_ack"] += 1
                    continue
                self.stats["relay_tx"] += 1
                rtype = decode(pkt, self.key, self.net_id,
                               self.allow_no_mic)["type"]
                self.stats["relay_tx_type_%d" % rtype] += 1
                self.enqueue_tx(now, pkt, prio)
            else:
                still.append(entry)
        self.pending_relays = still
        # fire due alert retries (source side, §9.2): identical packet bytes,
        # fresh flood, at +3/+8/+20 s after the initial transmission.
        for key, st in list(self.alert_retries.items()):
            if key in self.confirmed:
                del self.alert_retries[key]
                continue
            if st[0] > now:
                continue
            self.enqueue_tx(now, encode(self.key, self.net_id, key[0],
                                       key[1], T_ALERT, payload=st[2]),
                            PRIO_ALERT)
            self.stats["alert_retry_tx"] += 1
            if st[1] < len(ALERT_RETRY_DELAYS_S):          # a retry remains
                st[0] = now + (ALERT_RETRY_DELAYS_S[st[1]] -
                               ALERT_RETRY_DELAYS_S[st[1] - 1])
                st[1] += 1
            else:                                           # fired the +20 s one
                del self.alert_retries[key]
                self.stats["alert_unconfirmed"] += 1
        # gateway ACK scheduling (§9.3)
        if self.is_gateway:
            still = []
            for due, key in self.gw_ack_due:
                if due <= now:
                    self.originate(T_ACK, ack_payload(*key), now)
                    self.gw_alerts[key] = now
                    self.stats["ack_tx"] += 1
                else:
                    still.append((due, key))
            self.gw_ack_due = still
        self._try_transmit(now)

    # -- RX path (§4.3, §7, §8, §9, §12) ------------------------------------
    def receive(self, data, now):
        try:
            m = decode(data, self.key, self.net_id, self.allow_no_mic)
        except Reject as r:
            self.stats["drop_" + r.reason] += 1
            return
        ok, reason = self.rstate.accept(m["src"], m["msg_id"], m["type"], now)
        if not ok:
            self.stats["drop_" + reason] += 1
            return
        self.stats["rx_ok"] += 1
        self.stats["rx_type_%d" % m["type"]] += 1
        if m["dst"] not in (BROADCAST, self.id):
            self._maybe_relay(m, data, now)
            return
        if m["type"] == T_ACK:
            if m["src"] != GATEWAY_ID:
                self.stats["drop_ack_forger"] += 1     # §5.3
            else:
                ack = parse_ack(m["payload"])
                key = (ack["acked_src"], ack["acked_mid"])
                self._cancel_alert_work(key)
        elif self.is_gateway:
            self._gateway_process(m, now)
        self._maybe_relay(m, data, now)

    def _gateway_process(self, m, now):
        if m["type"] == T_ALERT:
            key = (m["src"], m["msg_id"])
            if key not in self.gw_alerts:
                if len(self.gw_alerts) >= ALERT_MEMORY_SLOTS:
                    self.gw_alerts.popitem(last=False)   # bounded RAM (§9.3)
                self.gw_alerts[key] = now
                if parse_alert(m["payload"])["level"] != LEVEL_TEST:
                    self.siren_count += 1
                self.stats["siren_events"] += 1
                self.gw_ack_due.append(
                    [now + self.rng.uniform(ACK_DELAY_MIN_S,
                                            ACK_DELAY_MAX_S), key])
            elif now - self.gw_alerts[key] >= GATEWAY_REACK_MIN_S:
                self.gw_alerts[key] = now
                self.gw_ack_due.append(
                    [now + self.rng.uniform(ACK_DELAY_MIN_S,
                                            ACK_DELAY_MAX_S), key])
        elif m["type"] == T_REPORT:
            self.reports_seen[m["src"]] = now

    def _cancel_alert_work(self, key):
        self.confirmed.add(key)
        self.pending_relays = [e for e in self.pending_relays
                               if e[3] != key]
        self.alert_retries.pop(key, None)

    def _maybe_relay(self, m, data, now):
        if m["src"] == self.id:
            return                                        # never relay own
        if m["ttl"] < 2:
            self.stats["ttl_end"] += 1
            return
        pkt = encode(self.key, self.net_id, m["src"], m["msg_id"], m["type"],
                     payload=m["payload"], ttl=m["ttl"] - 1, dst=m["dst"],
                     with_mic=bool(m["flags"] & FLAG_MIC))
        prio = PRIO_ALERT if m["type"] in P0_TYPES else PRIO_OTHER
        due = now + self.rng.uniform(RELAY_BACKOFF_MIN_S,
                                     RELAY_BACKOFF_MAX_S)
        key = (m["src"], m["msg_id"]) if m["type"] == T_ALERT else None
        if len(self.pending_relays) >= PENDING_RELAY_SLOTS:
            # bounded: drop oldest non-alert relay, else oldest alert relay
            drop_idx = next((i for i, e in enumerate(self.pending_relays)
                             if e[3] is None), 0)
            self.pending_relays.pop(drop_idx)
            self.stats["relay_slot_drop"] += 1
        self.pending_relays.append([due, pkt, prio, key])
        self.stats["relay_scheduled"] += 1


# ---------------------------------------------------------------------------
# Unit tests (protocol-spec §15.1). Run: python tools/proto/protocol.py
# ---------------------------------------------------------------------------

def _unit_tests():
    key = bytes(range(16))
    net = 0x1234
    rng = random.Random(1)
    n_tests = [0]

    def check(cond, name):
        n_tests[0] += 1
        assert cond, "UNIT TEST FAILED: %s" % name

    # --- payload round-trips -------------------------------------------------
    rp = report_payload(SF_MQ2_PRESENT | SF_MQ2_ACTIVE | SF_MQ2_VALID |
                        SF_DHT_PRESENT | SF_FLAME_PRESENT, 254, 456)
    check(len(rp) == 5 and parse_report(rp)["temp_c01"] == 254, "report payload")
    rp_missing = report_payload(SF_MQ2_PRESENT, TEMP_MISSING, HUM_MISSING)
    check(parse_report(rp_missing)["temp_c01"] == TEMP_MISSING, "missing temp")
    al = alert_payload(AF_MULTI, LEVEL_WARNING, rp)
    check(len(al) == 7 and parse_alert(al)["level"] == LEVEL_WARNING, "alert payload")
    ak = ack_payload(0x07, 0xBEEF)
    check(parse_ack(ak) == {"acked_src": 7, "acked_mid": 0xBEEF}, "ack payload")
    st = status_payload(NF_BOOTED | NF_SENSOR_FAULT, 1234, 2, 9)
    ps = parse_status(st)
    check(len(st) == 5 and ps["uptime_min"] == 1234 and ps["reset_reason"] == 2
          and ps["boot_count"] == 9, "status payload")

    # --- packet sizes (§4.2) --------------------------------------------------
    def build(ptype, payload, mid=0x0102, src=0x07, ttl=None):
        return encode(key, net, src, mid, ptype, payload=payload, ttl=ttl)
    check(len(build(T_REPORT, rp)) == 17, "report packet len 17")
    check(len(build(T_ALERT, al)) == 19, "alert packet len 19")
    check(len(build(T_ACK, ak)) == 15, "ack packet len 15")
    check(len(build(T_STATUS, st)) == 17, "status packet len 17")
    big = bytes(49)
    try:
        encode(key, net, 7, 1, T_REPORT, payload=big)
        check(False, "oversize payload rejected")
    except ValueError:
        check(True, "oversize payload rejected")
    # reserved type with unknown payload length: relay-eligible, len must fit
    rsv = encode(key, net, 7, 1, T_PING, payload=bytes(3), ttl=8)
    check(len(rsv) == 15, "reserved type packet encodes")

    # --- validation order (§4.3) ---------------------------------------------
    pkt = build(T_ALERT, al)
    m = decode(pkt, key, net)
    check(m["ttl"] == 8 and m["type"] == T_ALERT and m["src"] == 7
          and m["msg_id"] == 0x0102 and m["net_id"] == net, "decode fields")
    # MIC flip
    bad = bytearray(pkt); bad[-1] ^= 0xFF
    try:
        decode(bytes(bad), key, net); check(False, "mic flip rejected")
    except Reject as r:
        check(r.reason == "mic", "mic flip rejected")
    # foreign net_id
    try:
        decode(pkt, key, net + 1); check(False, "foreign net rejected")
    except Reject as r:
        check(r.reason == "net_id", "foreign net rejected")
    # bad version
    bad = bytearray(pkt); bad[0] = (2 << 4) | (bad[0] & 0x0F)
    try:
        decode(bytes(bad), key, net); check(False, "bad version rejected")
    except Reject as r:
        check(r.reason == "version", "bad version rejected")
    # truncated
    try:
        decode(pkt[:11], key, net); check(False, "truncated rejected")
    except Reject as r:
        check(r.reason == "length_short", "truncated rejected")
    # oversize FIFO region
    try:
        decode(bytes(61), key, net); check(False, "oversize rejected")
    except Reject as r:
        check(r.reason == "length_long", "oversize rejected")
    # wrong payload length for known type: hand-build a *correctly signed*
    # but structurally wrong packet (the decoder checks this after the MIC)
    hdr = bytes([(PROTO_VERSION << 4) | 8, (T_ACK << 4) | FLAG_MIC,
                 net & 0xFF, (net >> 8) & 0xFF, 0, 7, 0, 1])
    body = hdr + bytes(2)
    bad = body + compute_mic(key, body)
    try:
        decode(bad, key, net); check(False, "ack payload len enforced")
    except Reject as r:
        check(r.reason == "payload_len", "ack payload len enforced")
    # MIC-less packets: rejected in production, accepted in debug mode
    raw_nom = encode(key, net, 7, 1, T_ACK, payload=ak, with_mic=False)
    try:
        decode(raw_nom, key, net); check(False, "mic-less rejected in prod")
    except Reject as r:
        check(r.reason == "mic_flag", "mic-less rejected in prod")
    m = decode(raw_nom, key, net, allow_no_mic=True)
    check(m["flags"] == 0, "mic-less accepted in debug")

    # --- replay window + dedup (§7.2) ----------------------------------------
    rs = ReceiveState()
    t = 100.0
    check(rs.accept(7, 100, T_REPORT, t)[0], "fresh source accepted")
    check(rs.accept(7, 101, T_REPORT, t + 1)[0], "in-order accepted")
    check(not rs.accept(7, 100, T_REPORT, t + 2)[0], "duplicate rejected")
    check(rs.accept(7, 164, T_REPORT, t + 3)[0], "gap within window accepted")
    check(not rs.accept(7, 229, T_REPORT, t + 4)[0],
          "beyond window (too new, d=65) rejected")
    check(rs.accept(7, 110, T_REPORT, t + 5)[0], "late within window accepted")
    check(not rs.accept(7, 110, T_REPORT, t + 6)[0], "late duplicate rejected")
    check(rs.last[7] == 164, "late does not move window backward")
    check(not rs.accept(7, 40, T_REPORT, t + 7)[0],
          "older than window (d=65412) rejected")
    # wrap-around arithmetic
    rs2 = ReceiveState()
    rs2.accept(9, 65530, T_REPORT, t)
    check(rs2.accept(9, 3, T_REPORT, t + 1)[0], "wrap forward accepted")
    check(rs2.accept(9, 65528, T_REPORT, t + 2)[0], "wrap backward late accepted")
    check(not rs2.accept(9, 65528, T_REPORT, t + 3)[0], "wrap duplicate rejected")
    # alert dedup TTL allows the +3 s source retry to re-flood (§7.3)
    rs3 = ReceiveState()
    rs3.accept(5, 900, T_ALERT, 0.0)
    check(not rs3.accept(5, 900, T_ALERT, 1.0)[0], "alert dup within TTL")
    check(rs3.accept(5, 900, T_ALERT, 2.5)[0], "alert retry after TTL re-floods")
    # neighbor table bound
    rs4 = ReceiveState()
    for s in range(NEIGHBOR_SLOTS + 4):
        rs4.accept(20 + s, 1, T_REPORT, t + s)
    check(len(rs4.last) <= NEIGHBOR_SLOTS, "neighbor table bounded")
    check(rs4.accept(20, 2, T_REPORT, t + 99)[0], "evicted source re-accepted")

    # --- relay eligibility (§8) ------------------------------------------------
    class _W:
        def __init__(self): self.sent = []
        def send(self, node, pkt, now): self.sent.append(pkt)
    nd = Node(0x07, key, net, random.Random(2), _W())
    nd.receive(build(T_ALERT, al, src=0x02), now=0.0)
    check(len(nd.pending_relays) == 1, "alert relay scheduled (ttl 8)")
    check(nd.pending_relays[0][1][0] >> 4 == 1, "relay packet version ok")
    check((nd.pending_relays[0][1][0] & 0x0F) == 7, "relay decrements TTL")
    nd2 = Node(0x07, key, net, random.Random(2), _W())
    nd2.receive(build(T_ALERT, al, src=0x02, ttl=1), now=0.0)
    check(len(nd2.pending_relays) == 0 and nd2.stats["ttl_end"] == 1,
          "ttl 1 not relayed")
    nd3 = Node(0x07, key, net, random.Random(2), _W())
    nd3.receive(build(T_ALERT, al, src=0x07), now=0.0)
    check(len(nd3.pending_relays) == 0, "own src never relayed")

    # --- msg_id persistence across reboots (§6) ---------------------------------
    ndp = Node(0x07, key, net, rng, _W())
    first = ndp.ctr
    used_max = first
    for _ in range(130):
        used_max = max(used_max, ndp.next_msg_id())
    ndp.reboot(0.0)
    check(ndp.ctr > used_max, "counter resumes above all used IDs after reboot")
    ndp2 = Node(0x07, key, net, rng, _W())
    ndp2.reboot(0.0); ndp2.reboot(0.0); ndp2.reboot(0.0)
    check(ndp2.ctr >= 3 * MSG_ID_PERSIST_BLOCK, "repeated reboots stay monotonic")

    # --- gateway-only ACK authority (§5.3) ---------------------------------------
    class _WG(_W):
        def send(self, node, pkt, now):
            self.sent.append((node.id, pkt))
    w = _WG()
    gw = Node(GATEWAY_ID, key, net, random.Random(3), w, is_gateway=True)
    gw.receive(build(T_ALERT, al, src=0x05, mid=0x0AA0), now=0.0)
    check(gw.siren_count == 1, "new alert triggers siren event")
    check(len(gw.gw_ack_due) == 1, "gateway schedules ACK")
    gw.tick(1.0)   # fires ACK + alert relay (radio briefly busy)
    gw.tick(2.0)   # radio free again: queued ACK transmits
    acks = [p for _, p in w.sent if decode(p, key, net)["type"] == T_ACK]
    check(len(acks) >= 1, "gateway sent ACK")
    check(decode(acks[0], key, net)["src"] == GATEWAY_ID, "ACK from gateway id")
    check(parse_ack(decode(acks[0], key, net)["payload"]) ==
          {"acked_src": 5, "acked_mid": 0x0AA0}, "ACK names alert")
    # forged ACK from non-gateway is dropped by nodes
    ndf = Node(0x07, key, net, random.Random(2), _W())
    forged = encode(key, net, 0x09, 0x0001, T_ACK, payload=ack_payload(7, 9))
    ndf.receive(forged, 0.0)
    check(ndf.stats["drop_ack_forger"] == 1, "forged ACK dropped")
    # level TEST must never siren (§5.2)
    gw2 = Node(GATEWAY_ID, key, net, random.Random(3), _W(), is_gateway=True)
    gw2.receive(build(T_ALERT, alert_payload(AF_MQ2, LEVEL_TEST), src=0x05),
                now=0.0)
    check(gw2.siren_count == 0, "level TEST does not siren")

    print("protocol.py unit tests: %d checks passed" % n_tests[0])
    return n_tests[0]


if __name__ == "__main__":
    _unit_tests()
