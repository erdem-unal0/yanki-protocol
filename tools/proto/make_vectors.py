"""Generate golden test vectors from the Python reference model.

These get embedded in the C++ firmware (shared/golden_vectors.h) so every
board verifies its AES/CMAC + packet codec against the reference model at
boot (cross-validation, decision D13).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import protocol as P

# Demo deployment constants (MUST match firmware/shared/config.h)
PSK = b"MFdemoPSKv1_2026"          # demo only — never a real deployment key
NET_ID = 0x4D46                   # 'MF'

snap = P.report_payload(P.SF_MQ2_PRESENT | P.SF_FLAME_PRESENT |
                       P.SF_FLAME_ACTIVE | P.SF_DHT_PRESENT | P.SF_DHT_VALID,
                       254, 301)
alert = P.encode(PSK, NET_ID, 0x02, 0x0100, P.T_ALERT,
                 payload=P.alert_payload(P.AF_FLAME | P.AF_MULTI,
                                        P.LEVEL_CRITICAL, snap))
report = P.encode(PSK, NET_ID, 0x02, 0x0101, P.T_REPORT,
                  payload=P.report_payload(0x7F, 254, 301))
ack = P.encode(PSK, NET_ID, 0x01, 0x00A1, P.T_ACK,
               payload=P.ack_payload(0x02, 0x0100))

print('PSK_HEX    = "%s"' % PSK.hex())
print('ALERT_HEX  = "%s"' % alert.hex())
print('REPORT_HEX = "%s"' % report.hex())
print('ACK_HEX    = "%s"' % ack.hex())

# sanity: decode them back
for name, pkt in (("alert", alert), ("report", report), ("ack", ack)):
    m = P.decode(pkt, PSK, NET_ID)
    print("# sanity %s: type=%d src=0x%02X mid=0x%04X len=%d ok" %
          (name, m["type"], m["src"], m["msg_id"], len(pkt)))
