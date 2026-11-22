#pragma once
/*
 * aes_cmac.h — AES-128 + AES-CMAC for the MeshForest protocol (v1 spec §11).
 * Header-only C++ port of the validated Python reference implementation
 * (tools/proto/aes_cmac.py). The algorithm is standard FIPS-197 AES-128 and
 * the RFC 4493 / NIST SP 800-38B CMAC construction; no custom cryptography.
 * Node::selfTest() verifies against the official test vectors at boot.
 */

#include <Arduino.h>
#include <string.h>

namespace Proto {

static const uint8_t AES_SBOX[256] PROGMEM = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};
static const uint8_t AES_RCON[10] = {1, 2, 4, 8, 16, 32, 64, 128, 0x1B, 0x36};

static inline uint8_t aesXtime(uint8_t a) {
  uint16_t r = (uint16_t)a << 1;
  if (r & 0x0100) r = (r ^ 0x011B);
  return (uint8_t)r;
}

struct AesCtx {
  uint8_t rk[11][16];
};

static void aes128ExpandKey(const uint8_t* key, AesCtx* ctx) {
  uint8_t w[44][4];
  for (uint8_t i = 0; i < 4; i++)
    memcpy(w[i], key + 4 * i, 4);
  for (uint8_t i = 4; i < 44; i++) {
    uint8_t t[4];
    memcpy(t, w[i - 1], 4);
    if (i % 4 == 0) {
      uint8_t tmp = t[0];              // RotWord
      t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = tmp;
      for (uint8_t j = 0; j < 4; j++)   // SubWord
        t[j] = pgm_read_byte(&AES_SBOX[t[j]]);
      t[0] ^= AES_RCON[i / 4 - 1];
    }
    for (uint8_t j = 0; j < 4; j++)
      w[i][j] = w[i - 4][j] ^ t[j];
  }
  for (uint8_t r = 0; r < 11; r++)
    for (uint8_t j = 0; j < 16; j++)
      ctx->rk[r][j] = w[4 * r + (j >> 2)][j & 3];
}

static void aes128EncryptBlock(const AesCtx* ctx, const uint8_t* in,
                                uint8_t* out) {
  uint8_t s[16];
  memcpy(s, in, 16);
  for (uint8_t i = 0; i < 16; i++) s[i] ^= ctx->rk[0][i];
  for (uint8_t rnd = 1; rnd < 10; rnd++) {
    for (uint8_t i = 0; i < 16; i++) s[i] = pgm_read_byte(&AES_SBOX[s[i]]);
    uint8_t t[16];
    for (uint8_t c = 0; c < 4; c++)           // ShiftRows
      for (uint8_t r = 0; r < 4; r++)
        t[c * 4 + r] = s[((c + r) % 4) * 4 + r];
    memcpy(s, t, 16);
    for (uint8_t c = 0; c < 4; c++) {          // MixColumns
      uint8_t i = c * 4;
      uint8_t a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
      s[i]     = aesXtime(a0) ^ aesXtime(a1) ^ a1 ^ a2 ^ a3;
      s[i + 1] = a0 ^ aesXtime(a1) ^ aesXtime(a2) ^ a2 ^ a3;
      s[i + 2] = a0 ^ a1 ^ aesXtime(a2) ^ aesXtime(a3) ^ a3;
      s[i + 3] = aesXtime(a0) ^ a0 ^ a1 ^ a2 ^ aesXtime(a3);
    }
    for (uint8_t i = 0; i < 16; i++) s[i] ^= ctx->rk[rnd][i];
  }
  for (uint8_t i = 0; i < 16; i++) s[i] = pgm_read_byte(&AES_SBOX[s[i]]);
  uint8_t t[16];
  for (uint8_t c = 0; c < 4; c++)
    for (uint8_t r = 0; r < 4; r++)
      t[c * 4 + r] = s[((c + r) % 4) * 4 + r];
  memcpy(s, t, 16);
  for (uint8_t i = 0; i < 16; i++) out[i] = s[i] ^ ctx->rk[10][i];
}

static void cmacDbl(const uint8_t* in, uint8_t* out) {
  uint8_t carry = 0;
  for (int8_t i = 15; i >= 0; i--) {
    out[i] = (uint8_t)(in[i] << 1) | carry;
    carry = in[i] >> 7;
  }
  if (carry) out[15] ^= 0x87;
}

// Full 16-byte AES-CMAC tag (RFC 4493).
static void aes128Cmac(const uint8_t* key, const uint8_t* msg, size_t len,
                       uint8_t* tag16) {
  AesCtx ctx;
  aes128ExpandKey(key, &ctx);
  uint8_t l[16], k1[16], k2[16];
  uint8_t zero[16] = {0};
  aes128EncryptBlock(&ctx, zero, l);
  cmacDbl(l, k1);
  cmacDbl(k1, k2);
  size_t n = (len + 15) / 16;
  if (n == 0) n = 1;
  uint8_t x[16] = {0};
  for (size_t b = 0; b < n - 1; b++) {
    uint8_t y[16];
    for (uint8_t i = 0; i < 16; i++) y[i] = x[i] ^ msg[b * 16 + i];
    aes128EncryptBlock(&ctx, y, x);
  }
  uint8_t last[16] = {0};
  size_t rem = len - (n - 1) * 16;
  if (rem) memcpy(last, msg + (n - 1) * 16, rem);
  if (rem == 16) {                          // complete final block -> K1
    for (uint8_t i = 0; i < 16; i++) last[i] ^= k1[i];
  } else {                                  // padded final block -> K2
    last[rem] = 0x80;
    for (uint8_t i = 0; i < 16; i++) last[i] ^= k2[i];
  }
  uint8_t y[16];
  for (uint8_t i = 0; i < 16; i++) y[i] = x[i] ^ last[i];
  aes128EncryptBlock(&ctx, y, tag16);
}

static bool aesCmacSelfTest(Print* log = nullptr) {
  // FIPS-197 Appendix C.1 known answer
  AesCtx ctx;
  uint8_t key[16], pt[16], ct[16], out[16];
  for (uint8_t i = 0; i < 16; i++) { key[i] = i; pt[i] = 0x11 * i; }
  aes128ExpandKey(key, &ctx);
  aes128EncryptBlock(&ctx, pt, out);
  static const uint8_t want[16] = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
                                   0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
  if (memcmp(out, want, 16)) {
    if (log) log->println("[crypto] FIPS-197 AES vector FAILED");
    return false;
  }
  // RFC 4493 examples 1-3 (same key)
  const uint8_t* k = (const uint8_t*)
      "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";
  const uint8_t m3[40] = {
      0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
      0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
      0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11};
  aes128Cmac(k, nullptr, 0, out);
  if (memcmp(out, "\xbb\x1d\x69\x29\xe9\x59\x37\x28\x7f\xa3\x7d\x12\x9b\x75\x67\x46", 16)) {
    if (log) log->println("[crypto] RFC4493 ex1 FAILED");
    return false;
  }
  aes128Cmac(k, m3, 16, out);
  if (memcmp(out, "\x07\x0a\x16\xb4\x6b\x4d\x41\x44\xf7\x9b\xdd\x9d\xd0\x4a\x28\x7c", 16)) {
    if (log) log->println("[crypto] RFC4493 ex2 FAILED");
    return false;
  }
  aes128Cmac(k, m3, 40, out);
  if (memcmp(out, "\xdf\xa6\x67\x47\xde\x9a\xe6\x30\x30\xca\x32\x61\x14\x97\xc8\x27", 16)) {
    if (log) log->println("[crypto] RFC4493 ex3 FAILED");
    return false;
  }
  if (log) log->println("[crypto] FIPS-197 + RFC4493 vectors PASS");
  return true;
}

}  // namespace Proto
