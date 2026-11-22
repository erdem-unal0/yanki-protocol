#pragma once
/*
 * YankiConfig.h — demo deployment identity for the YankiProtocol library.
 *
 * DEMO ONLY — public placeholder key; real deployments must supply a fresh
 * random key and a deployment-specific net_id. The golden vectors in
 * golden_vectors.h depend on these exact values; changing either one
 * invalidates the cross-validation vectors.
 */

#include <Arduino.h>

static const uint8_t DEMO_PSK[16] = {
    0x4d, 0x46, 0x64, 0x65, 0x6d, 0x6f, 0x50, 0x53,
    0x4b, 0x76, 0x31, 0x5f, 0x32, 0x30, 0x32, 0x36};
#define DEMO_NET_ID 0x4D46  // 'MF'
