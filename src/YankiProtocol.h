#pragma once
/*
 * YankiProtocol.h — YankiProtocol 1.0.0
 *
 * Compact authenticated managed-flood mesh protocol for ESP8266.
 * Packet codec, AES-128-CMAC authentication, replay window, duplicate
 * suppression, managed-flood relay, and gateway ACKs.
 *
 * Usage:
 *   #include <YankiProtocol.h>
 *   Proto::Packet p;
 *   Proto::decode(buf, len, DEMO_PSK, DEMO_NET_ID, false, &p);
 *
 * This is the umbrella header. It pulls in the demo deployment identity,
 * AES-CMAC, the protocol codec/state machine, and the golden-vector
 * self-test. Replace DEMO_PSK and DEMO_NET_ID for a real deployment.
 */

#include "YankiConfig.h"
#include "aes_cmac.h"
#include "protocol.h"
#include "golden_vectors.h"
