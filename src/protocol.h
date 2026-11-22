#pragma once
/*
 * protocol.h — MeshForest protocol v1, C++ port of the validated Python
 * reference model (tools/proto/protocol.py). Header-only so both demo
 * sketches share one implementation (working spec §9: protocol module).
 *
 * Implements: packet codec + validation order (spec §4), replay window +
 * dedup cache (§7), managed-flood relay with backoff (§8), alert retries +
 * gateway ACK (§9), TX priority queues (§10).
 *
 * DEMO BUILD simplification (documented): the msg_id counter is NOT
 * persisted to flash (spec §6); reboots restart it at 128. Acceptable for
 * the bench demo; must be implemented before any deployment.
 */

#include "aes_cmac.h"
#include <Arduino.h>
#include <stddef.h>

namespace Proto {

enum MsgType : uint8_t { T_RESERVED = 0, T_REPORT = 1, T_ALERT = 2, T_ACK = 3,
                         T_STATUS = 4 };
const uint8_t PROTO_VERSION = 1;
const uint8_t MAX_PACKET_LEN = 60;
const uint8_t HEADER_LEN = 8;
const uint8_t MIC_LEN = 4;
const uint8_t FLAG_MIC = 0x01;
const uint8_t BROADCAST = 0x00;
const uint8_t GATEWAY_ID = 0x01;
const uint8_t P0_TYPES = (1u << T_ALERT) | (1u << T_ACK);
const uint8_t PAYLOAD_LEN[8] = {0, 5, 7, 3, 5, 0, 0, 0};
const uint8_t TTL_INIT[8] = {4, 4, 8, 8, 4, 8, 8, 8};

const uint16_t REPLAY_WINDOW = 64;
const uint8_t NEIGHBOR_SLOTS = 16;
const uint8_t DEDUP_SLOTS = 24;
const uint32_t DEDUP_TTL_ALERT_MS = 2000;
const uint32_t DEDUP_TTL_DEFAULT_MS = 300000UL;
const uint32_t RELAY_BACKOFF_MIN_MS = 30;
const uint32_t RELAY_BACKOFF_MAX_MS = 150;
const uint8_t PENDING_RELAY_SLOTS = 8;
const uint8_t QUEUE_SLOTS = 4;  // per priority class
const uint32_t ALERT_RETRY_DELAYS_MS[3] = {3000, 8000, 20000};
const uint32_t ACK_DELAY_MIN_MS = 200;
const uint32_t ACK_DELAY_MAX_MS = 400;
const uint32_t GW_REACK_MIN_MS = 2000;
const uint8_t GW_MEMORY_SLOTS = 64;

enum SensorFlag : uint8_t {
  SF_MQ2_PRESENT = 0x01, SF_MQ2_ACTIVE = 0x02, SF_MQ2_VALID = 0x04,
  SF_DHT_PRESENT = 0x08, SF_DHT_VALID = 0x10,
  SF_FLAME_PRESENT = 0x20, SF_FLAME_ACTIVE = 0x40 };
enum AlertFlag : uint8_t { AF_MQ2 = 0x01, AF_FLAME = 0x02, AF_TEMP = 0x04,
                          AF_MULTI = 0x08 };
enum StatusFlag : uint8_t { NF_BOOTED = 0x01, NF_LOW_BATT = 0x02,
                           NF_SENSOR_FAULT = 0x04 };
enum AlertLevel : uint8_t { LEVEL_TEST = 0, LEVEL_WARNING = 1,
                           LEVEL_CRITICAL = 2 };
const int16_t TEMP_MISSING = 0x7FFF;
const uint16_t HUM_MISSING = 0xFFFF;

enum Reject : int8_t { R_OK = 0, R_LEN_SHORT = -1, R_LEN_LONG = -2, R_NET = -3,
                       R_VER = -4, R_MIC = -5, R_MIC_FLAG = -6, R_PLEN = -7 };

struct Packet {
  uint8_t ver, ttl, type, flags, dst, src;
  uint16_t msg_id;
  uint8_t payload[48];
  uint8_t plen;
};

// ---- codec ----------------------------------------------------------------

static inline void computeMic(const uint8_t* key, const uint8_t* body,
                               size_t len, uint8_t* out4) {
  uint8_t tag[16];
  aes128Cmac(key, body, len, tag);
  memcpy(out4, tag, MIC_LEN);
}

static bool encode(const uint8_t* key, uint16_t net, uint8_t src, uint16_t mid,
                   uint8_t type, const uint8_t* payload, uint8_t plen,
                   uint8_t* out, uint8_t* outLen, uint8_t ttl = 0,
                   uint8_t dst = BROADCAST, bool withMic = true) {
  uint8_t t = type & 0x0F;
  if (t < 8 && PAYLOAD_LEN[t] != 0 && plen != PAYLOAD_LEN[t]) return false;
  if (ttl == 0) ttl = TTL_INIT[t];
  uint8_t total = HEADER_LEN + plen + (withMic ? MIC_LEN : 0);
  if (total > MAX_PACKET_LEN) return false;
  out[0] = (uint8_t)((PROTO_VERSION << 4) | (ttl & 0x0F));
  out[1] = (uint8_t)((type << 4) | (withMic ? FLAG_MIC : 0));
  out[2] = (uint8_t)(net & 0xFF);  // little-endian (spec §4.2)
  out[3] = (uint8_t)(net >> 8);
  out[4] = dst;
  out[5] = src;
  out[6] = (uint8_t)(mid & 0xFF);  // little-endian (spec §4.2)
  out[7] = (uint8_t)(mid >> 8);
  if (plen) memcpy(out + HEADER_LEN, payload, plen);
  if (withMic) {
    uint8_t m[MIC_LEN];
    computeMic(key, out, total - MIC_LEN, m);
    memcpy(out + total - MIC_LEN, m, MIC_LEN);
  }
  *outLen = total;
  return true;
}

static int8_t decode(const uint8_t* data, uint8_t len, const uint8_t* key,
                     uint16_t net, bool allowNoMic, Packet* out) {
  if (len < HEADER_LEN) return R_LEN_SHORT;
  if (len > MAX_PACKET_LEN) return R_LEN_LONG;
  uint8_t flags = data[1] & 0x0F;
  if ((flags & FLAG_MIC) && len < HEADER_LEN + MIC_LEN) return R_LEN_SHORT;
  Packet p;
  p.ver = data[0] >> 4;
  p.ttl = data[0] & 0x0F;
  p.type = data[1] >> 4;
  p.flags = flags;
  uint16_t pkt_net = (uint16_t)data[2] | ((uint16_t)data[3] << 8);  // LE
  if (pkt_net != net) return R_NET;
  if (p.ver != PROTO_VERSION) return R_VER;
  p.dst = data[4];
  p.src = data[5];
  p.msg_id = (uint16_t)data[6] | ((uint16_t)data[7] << 8);  // LE
  if (flags & FLAG_MIC) {
    uint8_t m[MIC_LEN];
    computeMic(key, data, len - MIC_LEN, m);
    uint8_t diff = 0;
    for (uint8_t i = 0; i < MIC_LEN; i++)
      diff |= (uint8_t)(m[i] ^ data[len - MIC_LEN + i]);
    if (diff) return R_MIC;
    p.plen = len - HEADER_LEN - MIC_LEN;
  } else {
    if (!allowNoMic) return R_MIC_FLAG;
    p.plen = len - HEADER_LEN;
  }
  if (p.plen > 48) return R_PLEN;
  if (p.plen) memcpy(p.payload, data + HEADER_LEN, p.plen);
  if (p.type < 8 && PAYLOAD_LEN[p.type] != 0 && p.plen != PAYLOAD_LEN[p.type])
    return R_PLEN;
  *out = p;
  return R_OK;
}

// ---- payload helpers (spec §5) ---------------------------------------------

static inline void buildReport(uint8_t* p5, uint8_t sflags, int16_t temp,
                               uint16_t hum) {
  p5[0] = sflags;
  p5[1] = (uint8_t)temp;
  p5[2] = (uint8_t)(temp >> 8);
  p5[3] = (uint8_t)hum;
  p5[4] = (uint8_t)(hum >> 8);
}
static inline void buildAlert(uint8_t* p7, uint8_t aflags, uint8_t level,
                              const uint8_t* snap5) {
  p7[0] = aflags;
  p7[1] = level;
  memcpy(p7 + 2, snap5, 5);
}
static inline void buildAck(uint8_t* p3, uint8_t asrc, uint16_t amid) {
  p3[0] = asrc;
  p3[1] = amid & 0xFF;   // little-endian (spec §5.3)
  p3[2] = amid >> 8;
}
static inline void buildStatus(uint8_t* p5, uint8_t sflags, uint16_t uptimeMin,
                               uint8_t resetReason, uint8_t bootCount) {
  p5[0] = sflags;
  p5[1] = uptimeMin & 0xFF;  // little-endian (spec §5.4)
  p5[2] = uptimeMin >> 8;
  p5[3] = resetReason;
  p5[4] = bootCount;
}

// ---- receive-side state (spec §7) -------------------------------------------

class ReceiveState {
 public:
  bool accept(uint8_t src, uint16_t mid, uint8_t type, uint32_t now) {
    // duplicate cache check for the recently-seen range (below)
    int nb = findNb(src);
    if (nb < 0) {  // fresh source
      nb = allocNb(src);
      nbr_[nb].last_id = mid;
      nbr_[nb].touch = now;
      cacheAdd(src, mid, type, now);
      return true;
    }
    uint16_t d = (uint16_t)(mid - nbr_[nb].last_id);
    if (d >= 1 && d <= REPLAY_WINDOW) {          // new, within window
      nbr_[nb].last_id = mid;
      nbr_[nb].touch = now;
      cacheAdd(src, mid, type, now);
      return true;
    }
    if (d == 0 || d >= (uint16_t)(65536 - REPLAY_WINDOW)) {
      if (cacheHit(src, mid, now)) return false;  // duplicate
      cacheAdd(src, mid, type, now);              // late/out-of-order
      return true;                                // no backward advance
    }
    return false;                                  // out of window
  }

 private:
  struct Nb { uint8_t src; uint16_t last_id; uint32_t touch; bool used; };
  struct Dd { uint8_t src; uint16_t mid; uint32_t expiry; uint32_t seq;
              bool used; };
  Nb nbr_[NEIGHBOR_SLOTS];
  Dd dd_[DEDUP_SLOTS];
  uint32_t seq_ = 0;

  int findNb(uint8_t src) {
    for (uint8_t i = 0; i < NEIGHBOR_SLOTS; i++)
      if (nbr_[i].used && nbr_[i].src == src) return i;
    return -1;
  }
  uint8_t allocNb(uint8_t src) {
    uint8_t victim = 0;
    for (uint8_t i = 0; i < NEIGHBOR_SLOTS; i++) {
      if (!nbr_[i].used) { victim = i; break; }
      if (nbr_[i].touch < nbr_[victim].touch) victim = i;
    }
    nbr_[victim].used = true;
    nbr_[victim].src = src;
    return victim;
  }
  bool cacheHit(uint8_t src, uint16_t mid, uint32_t now) {
    for (uint8_t i = 0; i < DEDUP_SLOTS; i++) {
      if (dd_[i].used && dd_[i].src == src && dd_[i].mid == mid) {
        if (dd_[i].expiry <= now) { dd_[i].used = false; return false; }
        dd_[i].seq = ++seq_;                       // LRU touch
        return true;
      }
    }
    return false;
  }
  void cacheAdd(uint8_t src, uint16_t mid, uint8_t type, uint32_t now) {
    uint32_t ttl = (type == T_ALERT) ? DEDUP_TTL_ALERT_MS : DEDUP_TTL_DEFAULT_MS;
    // refresh or allocate
    for (uint8_t i = 0; i < DEDUP_SLOTS; i++) {
      if (dd_[i].used && dd_[i].src == src && dd_[i].mid == mid) {
        dd_[i].expiry = now + ttl;
        dd_[i].seq = ++seq_;
        return;
      }
    }
    uint8_t victim = 0;                            // evict oldest seq
    for (uint8_t i = 0; i < DEDUP_SLOTS; i++) {
      if (!dd_[i].used) { victim = i; break; }
      if (dd_[i].seq < dd_[victim].seq) victim = i;
    }
    dd_[victim].used = true;
    dd_[victim].src = src;
    dd_[victim].mid = mid;
    dd_[victim].expiry = now + ttl;
    dd_[victim].seq = ++seq_;
  }
};

// implemented in golden_vectors.h (included by the sketches after this file)
bool goldenVectorsSelfTest(Print& log);

// ---- node protocol machine (spec §8-§12) ------------------------------------

struct NodeStats {
  uint16_t rx_ok = 0, tx = 0, relay_tx = 0, retry_tx = 0, unconfirmed = 0;
  uint16_t drop_len = 0, drop_net = 0, drop_ver = 0, drop_mic = 0;
  uint16_t drop_dup = 0, drop_window = 0, drop_forger = 0;
};

class Node {
 public:
  Node(uint8_t id, const uint8_t* key, uint16_t net, bool gateway)
      : id_(id), key_(key), net_(net), gateway_(gateway) {
    // demo build: counter starts at 128 (production persists, spec §6)
    ctr_ = 128;
  }

  uint8_t id() const { return id_; }
  const NodeStats& stats() const { return stats_; }

  // ---- last-received info for the gateway display (demo) -------------------
  struct AlertInfo { bool valid = false; uint8_t src, level, aflags;
                     int16_t temp; uint16_t hum; uint16_t mid; };
  struct ReportInfo { bool valid = false; uint8_t src; int16_t temp;
                      uint16_t hum; };
  const AlertInfo& lastAlert() const { return alert_; }
  const ReportInfo& lastReport() const { return report_; }
  uint32_t sirenEvents() const { return siren_events_; }

  // ---- self-test: official crypto vectors + Python golden vectors ---------
  bool selfTest(Print& log) {
    if (!aesCmacSelfTest(&log)) return false;
    if (!goldenVectorsSelfTest(log)) return false;
    return true;
  }

  // ---- originating ----------------------------------------------------------
  uint16_t originate(uint8_t type, const uint8_t* payload, uint8_t plen,
                     uint32_t now) {
    uint16_t mid = nextMsgId();
    uint8_t buf[MAX_PACKET_LEN], len;
    if (!encode(key_, net_, id_, mid, type, payload, plen, buf, &len)) return 0;
    enqueue(now, buf, len, isP0(type));
    return mid;
  }

  void originateReport(uint32_t now, uint8_t sflags, int16_t temp,
                        uint16_t hum) {
    uint8_t p[5];
    buildReport(p, sflags, temp, hum);
    originate(T_REPORT, p, 5, now);
  }

  uint16_t originateAlert(uint32_t now, uint8_t aflags, uint8_t level,
                          uint8_t sflags, int16_t temp, uint16_t hum) {
    uint8_t snap[5], p[7];
    buildReport(snap, sflags, temp, hum);
    buildAlert(p, aflags, level, snap);
    uint16_t mid = originate(T_ALERT, p, 7, now);
    if (mid == 0) return 0;
    // retry state: identical packet bytes re-flood at +3/+8/+20 s (§9.2);
    // encode() is deterministic, so re-encoding with the same fields yields
    // byte-identical output — verified by the golden-vector self-test.
    uint8_t pkt[MAX_PACKET_LEN], len;
    if (!encode(key_, net_, id_, mid, T_ALERT, p, 7, pkt, &len)) return mid;
    for (uint8_t i = 0; i < MAX_RETRIES; i++) {
      if (!retry_[i].used) {
        retry_[i].used = true;
        retry_[i].mid = mid;
        retry_[i].attempt = 1;
        retry_[i].due = now + ALERT_RETRY_DELAYS_MS[0];
        retry_[i].len = len;
        memcpy(retry_[i].pkt, pkt, len);
        break;
      }
    }
    return mid;
  }

  void originateStatus(uint32_t now, uint8_t sflags, uint16_t uptimeMin,
                       uint8_t resetReason) {
    uint8_t p[5];
    buildStatus(p, sflags, uptimeMin, resetReason, bootCount_);
    originate(T_STATUS, p, 5, now);
    bootCount_++;
  }

  // ---- receive path (§4.3, §7, §8, §9) ---------------------------------------
  void onReceive(const uint8_t* data, uint8_t len, uint32_t now) {
    Packet m;
    int8_t r = decode(data, len, key_, net_, false, &m);
    if (r != R_OK) {
      switch (r) {
        case R_LEN_SHORT: case R_LEN_LONG: stats_.drop_len++; break;
        case R_NET: stats_.drop_net++; break;
        case R_VER: stats_.drop_ver++; break;
        default: stats_.drop_mic++; break;  // R_MIC / R_MIC_FLAG / R_PLEN
      }
      return;
    }
    if (!rstate_.accept(m.src, m.msg_id, m.type, now)) {
      stats_.drop_dup++;
      return;
    }
    stats_.rx_ok++;
    if (m.dst != BROADCAST && m.dst != id_) {  // not addressed to us
      maybeRelay(m, now);
      return;
    }
    if (m.type == T_ACK) {
      if (m.src != GATEWAY_ID) {
        stats_.drop_forger++;                  // §5.3: only gateway ACKs
      } else {
        uint8_t asrc = m.payload[0];
        uint16_t amid = ((uint16_t)m.payload[2] << 8) | m.payload[1];
        cancelAlertWork(asrc, amid);
      }
    } else if (gateway_) {
      gatewayProcess(m, now);
    }
    maybeRelay(m, now);
  }

  // ---- time-driven work; call every loop ------------------------------------
  void tick(uint32_t now) {
    // fire due relay retransmissions (§8)
    for (uint8_t i = 0; i < PENDING_RELAY_SLOTS; i++) {
      if (!relay_[i].used || relay_[i].due > now) continue;
      if (relay_[i].hasKey && isConfirmed(relay_[i].keySrc, relay_[i].keyMid)) {
        relay_[i].used = false;                 // cancelled by gateway ACK
        continue;
      }
      enqueue(now, relay_[i].pkt, relay_[i].len, relay_[i].prio);
      stats_.relay_tx++;
      relay_[i].used = false;
    }
    // fire due alert retries (§9.2)
    for (uint8_t i = 0; i < MAX_RETRIES; i++) {
      if (!retry_[i].used) continue;
      if (isConfirmed(id_, retry_[i].mid)) { retry_[i].used = false; continue; }
      if (retry_[i].due > now) continue;
      enqueue(now, retry_[i].pkt, retry_[i].len, PRIO_ALERT);
      stats_.retry_tx++;
      if (retry_[i].attempt < 3) {
        retry_[i].due =
            now + (ALERT_RETRY_DELAYS_MS[retry_[i].attempt] -
                   ALERT_RETRY_DELAYS_MS[retry_[i].attempt - 1]);
        retry_[i].attempt++;
      } else {
        retry_[i].used = false;                 // 4 transmissions total
        stats_.unconfirmed++;
      }
    }
    // gateway: send due ACKs (§9.3)
    for (uint8_t i = 0; i < MAX_ACKS; i++) {
      if (!ackDue_[i].used || ackDue_[i].due > now) continue;
      uint8_t p[3];
      buildAck(p, ackDue_[i].src, ackDue_[i].mid);
      originate(T_ACK, p, 3, now);
      ackDue_[i].used = false;
    }
  }

  // ---- TX queue; sketch drains this and transmits ----------------------------
  bool popTx(uint8_t* buf, uint8_t* len) {
    for (uint8_t p = 0; p < 2; p++) {
      for (uint8_t i = 0; i < QUEUE_SLOTS; i++) {
        if (q_[p][i].used) {
          memcpy(buf, q_[p][i].pkt, q_[p][i].len);
          *len = q_[p][i].len;
          q_[p][i].used = false;
          stats_.tx++;
          return true;
        }
      }
    }
    return false;
  }

  bool alertConfirmed(uint16_t mid) const { return isConfirmed(id_, mid); }

 private:
  static const uint8_t MAX_RETRIES = 4;
  static const uint8_t MAX_ACKS = 4;
  enum { PRIO_ALERT = 0, PRIO_OTHER = 1 };

  struct TxItem { bool used = false; uint8_t pkt[MAX_PACKET_LEN];
                  uint8_t len; uint32_t insertion = 0; };
  struct RelayItem { bool used = false; uint32_t due; uint8_t pkt[MAX_PACKET_LEN];
                     uint8_t len; uint8_t prio; uint16_t keySrc;
                     uint16_t keyMid; bool hasKey; };
  struct RetryItem { bool used = false; uint16_t mid; uint32_t due;
                     uint8_t attempt; uint8_t pkt[MAX_PACKET_LEN]; uint8_t len; };
  struct AckItem { bool used = false; uint32_t due; uint8_t src; uint16_t mid; };
  struct GwItem { bool used = false; uint8_t src; uint16_t mid;
                  uint32_t lastAck; };

  uint8_t id_;
  const uint8_t* key_;
  uint16_t net_;
  bool gateway_;
  uint16_t ctr_ = 0;
  uint8_t bootCount_ = 0;
  uint8_t alertPktCache_[MAX_PACKET_LEN];
  uint8_t alertLenCache_ = 0;
  NodeStats stats_;
  ReceiveState rstate_;
  TxItem q_[2][QUEUE_SLOTS];
  RelayItem relay_[PENDING_RELAY_SLOTS];
  RetryItem retry_[MAX_RETRIES];
  AckItem ackDue_[MAX_ACKS];
  GwItem gwMem_[GW_MEMORY_SLOTS];
  struct ConfItem { bool used = false; uint8_t src; uint16_t mid; };
  ConfItem conf_[8];
  uint8_t confNext_ = 0;
  AlertInfo alert_;
  ReportInfo report_;
  uint32_t siren_events_ = 0;

  static bool isP0(uint8_t type) { return type == T_ALERT || type == T_ACK; }

  uint16_t nextMsgId() { return ctr_++; }

  void enqueue(uint32_t now, const uint8_t* pkt, uint8_t len, uint8_t prio) {
    (void)now;
    TxItem* q = q_[prio];
    uint8_t victim = QUEUE_SLOTS;                 // find free slot
    for (uint8_t i = 0; i < QUEUE_SLOTS; i++)
      if (!q[i].used) { victim = i; break; }
    if (victim == QUEUE_SLOTS) {                  // bounded: drop oldest
      victim = 0;
      for (uint8_t i = 1; i < QUEUE_SLOTS; i++)
        if (q[i].insertion < q[victim].insertion) victim = i;
    }
    q[victim].used = true;
    q[victim].len = len;
    q[victim].insertion = ++insertSeq_;
    memcpy(q[victim].pkt, pkt, len);
  }

  void cancelAlertWork(uint8_t src, uint16_t mid) {
    conf_[confNext_].used = true;   // bounded ring (8 entries, demo scale)
    conf_[confNext_].src = src;
    conf_[confNext_].mid = mid;
    confNext_ = (uint8_t)((confNext_ + 1) & 7);
    for (uint8_t i = 0; i < PENDING_RELAY_SLOTS; i++)
      if (relay_[i].used && relay_[i].hasKey &&
          relay_[i].keySrc == src && relay_[i].keyMid == mid)
        relay_[i].used = false;
    for (uint8_t i = 0; i < MAX_RETRIES; i++)
      if (retry_[i].used && retry_[i].mid == mid && src == id_)
        retry_[i].used = false;
  }

  bool isConfirmed(uint8_t src, uint16_t mid) const {
    for (uint8_t i = 0; i < 8; i++)
      if (conf_[i].used && conf_[i].src == src && conf_[i].mid == mid)
        return true;
    return false;
  }

  void maybeRelay(const Packet& m, uint32_t now) {
    if (m.src == id_) return;                     // never relay own
    if (m.ttl < 2) return;
    uint8_t buf[MAX_PACKET_LEN], len;
    if (!encode(key_, net_, m.src, m.msg_id, m.type, m.payload, m.plen,
                buf, &len, m.ttl - 1, m.dst,
                (m.flags & FLAG_MIC) != 0))
      return;
    // find/evict a relay slot (§8: bounded)
    uint8_t victim = PENDING_RELAY_SLOTS;
    for (uint8_t i = 0; i < PENDING_RELAY_SLOTS; i++)
      if (!relay_[i].used) { victim = i; break; }
    if (victim == PENDING_RELAY_SLOTS) {
      victim = 0;
      for (uint8_t i = 1; i < PENDING_RELAY_SLOTS; i++)
        if (!relay_[i].hasKey) { victim = i; break; }  // drop non-alert first
    }
    relay_[victim].used = true;
    relay_[victim].due = now + random(RELAY_BACKOFF_MIN_MS,
                                      RELAY_BACKOFF_MAX_MS + 1);
    relay_[victim].len = len;
    relay_[victim].prio = isP0(m.type) ? PRIO_ALERT : PRIO_OTHER;
    relay_[victim].hasKey = (m.type == T_ALERT);
    relay_[victim].keySrc = m.src;
    relay_[victim].keyMid = m.msg_id;
    memcpy(relay_[victim].pkt, buf, len);
  }

  void gatewayProcess(const Packet& m, uint32_t now) {
    if (m.type == T_ALERT) {
      int slot = -1;
      for (uint8_t i = 0; i < GW_MEMORY_SLOTS; i++)
        if (gwMem_[i].used && gwMem_[i].src == m.src &&
            gwMem_[i].mid == m.msg_id) { slot = i; break; }
      uint8_t level = m.payload[1];
      if (slot < 0) {                             // new alert
        uint8_t victim = 0;
        for (uint8_t i = 0; i < GW_MEMORY_SLOTS; i++) {
          if (!gwMem_[i].used) { victim = i; break; }
          if (gwMem_[i].lastAck < gwMem_[victim].lastAck) victim = i;
        }
        gwMem_[victim].used = true;
        gwMem_[victim].src = m.src;
        gwMem_[victim].mid = m.msg_id;
        if (level != LEVEL_TEST) siren_events_++;
        // record alert details for the display (snapshot = payload[2..6])
        alert_.valid = true;
        alert_.src = m.src;
        alert_.mid = m.msg_id;
        alert_.level = level;
        alert_.aflags = m.payload[0];
        alert_.temp = (int16_t)(((uint16_t)m.payload[4] << 8) | m.payload[3]);
        alert_.hum = ((uint16_t)m.payload[6] << 8) | m.payload[5];
        // §9.3: the re-ACK interval is measured from the ACK's TRANSMIT time,
        // not from packet receipt (the ACK is delayed 200-400 ms).
        gwMem_[victim].lastAck = scheduleAck(m.src, m.msg_id, now);
      } else if (now - gwMem_[slot].lastAck >= GW_REACK_MIN_MS) {
        gwMem_[slot].lastAck = scheduleAck(m.src, m.msg_id, now);  // re-ACK
      }
    } else if (m.type == T_REPORT) {
      report_.valid = true;
      report_.src = m.src;
      report_.temp = (int16_t)(((uint16_t)m.payload[2] << 8) | m.payload[1]);
      report_.hum = ((uint16_t)m.payload[4] << 8) | m.payload[3];
    }
  }

  // Schedules an ACK and returns its due time (0 if no slot was free).
  // Callers use the return value so the §9.3 re-ACK interval is measured
  // from the ACK's transmit time rather than from packet receipt.
  uint32_t scheduleAck(uint8_t src, uint16_t mid, uint32_t now) {
    for (uint8_t i = 0; i < MAX_ACKS; i++) {
      if (!ackDue_[i].used) {
        ackDue_[i].used = true;
        ackDue_[i].src = src;
        ackDue_[i].mid = mid;
        ackDue_[i].due = now + random(ACK_DELAY_MIN_MS, ACK_DELAY_MAX_MS + 1);
        return ackDue_[i].due;
      }
    }
    return 0;
  }
  uint32_t insertSeq_ = 0;
};

}  // namespace Proto
