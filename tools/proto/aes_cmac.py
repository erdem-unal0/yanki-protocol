"""AES-128 + AES-CMAC reference implementation (MeshForest protocol tests).

Pure-Python AES-128 block encryption and AES-CMAC per RFC 4493 / NIST SP
800-38B. This is the *reference model* for host-side protocol testing
(decision D13). It is NOT firmware code and is not performance-optimized.

Correctness is enforced at import time against:
  * FIPS-197 Appendix C.1 AES-128 known answer (single block), and
  * RFC 4493 examples 1-3 (empty message, one full block, 40-byte message),
    which exercise both the complete-block (K1) and padded (K2) CMAC paths.

No custom cryptography is invented here: the algorithm is exactly the
standard AES-128 (FIPS-197) and CMAC construction (SP 800-38B / RFC 4493);
the official test vectors prove the implementation.
"""

import struct

# Standard AES S-box (FIPS-197).
_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(a):
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def _expand_key(key):
    """AES-128 key schedule -> 11 round keys as flat 16-byte blocks."""
    assert len(key) == 16
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]                      # RotWord
            t = [_SBOX[b] for b in t]              # SubWord
            t[0] ^= _RCON[i // 4 - 1]
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [bytes(b for word in w[4 * r:4 * r + 4] for b in word)
            for r in range(11)]


def aes128_encrypt_block(key, block):
    """Encrypt one 16-byte block with AES-128 (FIPS-197)."""
    rk = _expand_key(key)
    # State is kept column-major: state[c*4 + r] (FIPS-197 layout).
    s = bytearray(block)
    def xor_rk(s, k):
        for i in range(16):
            s[i] ^= k[i]
    def shift_rows(s):
        out = bytearray(16)
        for c in range(4):
            for r in range(4):
                out[c * 4 + r] = s[((c + r) % 4) * 4 + r]
        s[:] = out
    def mix_columns(s):
        for c in range(4):
            i = c * 4
            a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
            s[i]     = _xtime(a0) ^ _xtime(a1) ^ a1 ^ a2 ^ a3
            s[i + 1] = a0 ^ _xtime(a1) ^ _xtime(a2) ^ a2 ^ a3
            s[i + 2] = a0 ^ a1 ^ _xtime(a2) ^ _xtime(a3) ^ a3
            s[i + 3] = _xtime(a0) ^ a0 ^ a1 ^ a2 ^ _xtime(a3)
    xor_rk(s, rk[0])
    for rnd in range(1, 10):
        for i in range(16):
            s[i] = _SBOX[s[i]]
        shift_rows(s)
        mix_columns(s)
        xor_rk(s, rk[rnd])
    for i in range(16):
        s[i] = _SBOX[s[i]]
    shift_rows(s)
    xor_rk(s, rk[10])
    return bytes(s)


def _dbl(block):
    """CMAC subkey doubling (RFC 4493 section 2.3)."""
    out = bytearray(16)
    carry = 0
    for i in range(15, -1, -1):
        out[i] = (block[i] << 1 & 0xFE) | carry
        carry = (block[i] >> 7) & 1
    if carry:
        out[15] ^= 0x87
    return bytes(out)


def aes128_cmac(key, message):
    """AES-CMAC (RFC 4493). Returns the full 16-byte tag."""
    l = aes128_encrypt_block(key, bytes(16))
    k1 = _dbl(l)
    k2 = _dbl(k1)
    n = max(1, (len(message) + 15) // 16)
    complete = len(message) > 0 and len(message) % 16 == 0
    blocks = [message[i * 16:(i + 1) * 16] for i in range(n)]
    if complete:
        last = bytes(a ^ b for a, b in zip(blocks[-1], k1))
    else:
        tail = blocks[-1]
        padded = tail + b"\x80" + bytes(15 - len(tail)) if len(tail) < 16 else tail
        last = bytes(a ^ b for a, b in zip(padded, k2))
    x = bytes(16)
    for blk in blocks[:-1]:
        x = aes128_encrypt_block(key, bytes(a ^ b for a, b in zip(x, blk)))
    return aes128_encrypt_block(key, bytes(a ^ b for a, b in zip(x, last)))


def _self_test():
    # FIPS-197 Appendix C.1 known-answer test.
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = aes128_encrypt_block(key, pt)
    assert ct.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a", ct.hex()
    # RFC 4493 section 4 examples 1-3 (same key).
    k = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    assert aes128_cmac(k, b"").hex() == "bb1d6929e95937287fa37d129b756746"
    m2 = bytes.fromhex("6bc1bee22e409f96e93d7e11739317" "2a")
    assert aes128_cmac(k, m2).hex() == "070a16b46b4d4144f79bdd9dd04a287c"
    m3 = bytes.fromhex(
        "6bc1bee22e409f96e93d7e11739317" "2a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411")
    assert aes128_cmac(k, m3).hex() == "dfa66747de9ae63030ca32611497c827"


_self_test()  # fail loudly, at import, if anything above is wrong
