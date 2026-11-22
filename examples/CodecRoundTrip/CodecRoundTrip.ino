// CodecRoundTrip — minimal YankiProtocol encode/decode example.
//
// Runs the golden-vector self-test, then encodes and decodes one
// SENSOR_REPORT and one ALERT using the demo PSK and network ID.

#include <YankiProtocol.h>

static void printPacket(const char* label, const Proto::Packet& p) {
  Serial.printf("%s: type=%u src=%02X msg_id=%04X len=%u\n", label, p.type,
                p.src, p.msg_id, p.plen);
}

static void roundTripReport() {
  uint8_t payload[5];
  Proto::buildReport(payload, Proto::SF_DHT_PRESENT | Proto::SF_DHT_VALID,
                     2150, 4200);  // 21.50 C, 42.00 %RH

  uint8_t packet[Proto::MAX_PACKET_LEN];
  uint8_t len = 0;
  if (!Proto::encode(DEMO_PSK, DEMO_NET_ID, 0x02, 0x0101, Proto::T_REPORT,
                     payload, sizeof(payload), packet, &len)) {
    Serial.println("report encode failed");
    return;
  }

  Proto::Packet decoded;
  int8_t r = Proto::decode(packet, len, DEMO_PSK, DEMO_NET_ID, false, &decoded);
  if (r != Proto::R_OK) {
    Serial.printf("report decode failed: %d\n", r);
    return;
  }
  printPacket("report", decoded);
}

static void roundTripAlert() {
  uint8_t snap[5];
  Proto::buildReport(snap, Proto::SF_MQ2_PRESENT | Proto::SF_MQ2_ACTIVE |
                               Proto::SF_MQ2_VALID | Proto::SF_FLAME_PRESENT |
                               Proto::SF_FLAME_ACTIVE,
                     3150, 2800);

  uint8_t payload[7];
  Proto::buildAlert(payload, Proto::AF_MQ2 | Proto::AF_FLAME,
                    Proto::LEVEL_CRITICAL, snap);

  uint8_t packet[Proto::MAX_PACKET_LEN];
  uint8_t len = 0;
  if (!Proto::encode(DEMO_PSK, DEMO_NET_ID, 0x02, 0x0102, Proto::T_ALERT,
                     payload, sizeof(payload), packet, &len)) {
    Serial.println("alert encode failed");
    return;
  }

  Proto::Packet decoded;
  int8_t r = Proto::decode(packet, len, DEMO_PSK, DEMO_NET_ID, false, &decoded);
  if (r != Proto::R_OK) {
    Serial.printf("alert decode failed: %d\n", r);
    return;
  }
  printPacket("alert", decoded);
}

void setup() {
  Serial.begin(115200);
  delay(200);

  bool goldenOk = Proto::goldenVectorsSelfTest(Serial);
  Serial.printf("golden vectors: %s\n", goldenOk ? "PASS" : "FAIL");

  roundTripReport();
  roundTripAlert();
}

void loop() {}
