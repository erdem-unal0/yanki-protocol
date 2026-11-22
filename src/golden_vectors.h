#pragma once
/*
 * golden_vectors.h — cross-validation of the C++ firmware against the
 * Python reference model (decision D13). The vectors below were generated
 * by tools/proto/make_vectors.py (regenerated 2026-11-22 after the header
 * byte order was corrected to little-endian, decision D16).
 * goldenVectorsSelfTest()
 * decodes each one with the demo PSK/net-id, checks the fields, re-encodes
 * it, and requires byte-for-byte identical output — proving the codec, the
 * MIC, and the byte order all match the reference model.
 */

#include "YankiConfig.h"
#include "protocol.h"

namespace Proto {

struct GoldenVector {
  const char* name;
  const char* hex;
  uint8_t type;
  uint8_t src;
  uint16_t msg_id;
  uint8_t len;
};

static const GoldenVector GOLDEN_VECTORS[] = {
    {"alert", "1821464d000200010a0279fe002d017623fcda", 2, 0x02, 0x0100, 19},
    {"report", "1411464d000201017ffe002d01b10e3590", 1, 0x02, 0x0101, 17},
    {"ack", "1831464d0001a1000200019ca7b858", 3, 0x01, 0x00A1, 15},
};
static const uint8_t GOLDEN_VECTOR_COUNT =
    sizeof(GOLDEN_VECTORS) / sizeof(GOLDEN_VECTORS[0]);

static bool hexToBytes(const char* hex, uint8_t* out, uint8_t maxLen,
                       uint8_t* outLen) {
  size_t n = strlen(hex) / 2;
  if (n > maxLen) return false;
  for (size_t i = 0; i < n; i++) {
    char b[3] = {hex[2 * i], hex[2 * i + 1], 0};
    out[i] = (uint8_t)strtoul(b, nullptr, 16);
  }
  *outLen = (uint8_t)n;
  return true;
}

inline bool goldenVectorsSelfTest(Print& log) {
  bool ok = true;
  for (uint8_t v = 0; v < GOLDEN_VECTOR_COUNT; v++) {
    const GoldenVector& gv = GOLDEN_VECTORS[v];
    uint8_t buf[MAX_PACKET_LEN], len;
    if (!hexToBytes(gv.hex, buf, sizeof(buf), &len)) {
      log.printf("[golden] %s: hex parse failed\n", gv.name);
      ok = false;
      continue;
    }
    Packet m;
    if (decode(buf, len, DEMO_PSK, DEMO_NET_ID, false, &m) != R_OK) {
      log.printf("[golden] %s: decode rejected a reference packet!\n", gv.name);
      ok = false;
      continue;
    }
    if (m.type != gv.type || m.src != gv.src || m.msg_id != gv.msg_id) {
      log.printf("[golden] %s: field mismatch (type=%u src=%02X mid=%04X)\n",
                 gv.name, m.type, m.src, m.msg_id);
      ok = false;
      continue;
    }
    uint8_t re[MAX_PACKET_LEN], reLen;
    if (!encode(DEMO_PSK, DEMO_NET_ID, m.src, m.msg_id, m.type, m.payload,
                m.plen, re, &reLen, m.ttl, m.dst, true) ||
        reLen != len || memcmp(re, buf, len) != 0) {
      log.printf("[golden] %s: re-encode mismatch!\n", gv.name);
      ok = false;
      continue;
    }
  }
  if (ok)
    log.println("[golden] 3 reference vectors PASS (codec+MIC byte-exact)");
  return ok;
}

}  // namespace Proto
