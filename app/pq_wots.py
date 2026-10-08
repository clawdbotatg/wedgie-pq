# WOTS one-time hash signatures over Poseidon2 on a wedgie. Same scheme as ref/wots.py (read that
# for how it works); the hashing runs in pq_p2.mpy (C). Elements are little-endian uint32 in bytearrays.
import struct
import pq_p2 as p2

P = 0x7f000001
W = 16
DIGITS = 60
CHECK = 3
CHAINS = DIGITS + CHECK
SK, CHAIN, MSG, PK = 1, 2, 3, 4


def _b(elems):
    return bytearray(struct.pack("<%dI" % len(elems), *elems))


def _e(b):
    return list(struct.unpack("<%dI" % (len(b) // 4), b))


def sponge(domain, elems):
    s = bytearray(64)
    s[32:40] = struct.pack("<II", domain, len(elems))
    for i in range(0, len(elems), 8):
        chunk = elems[i:i + 8]
        s[:4 * len(chunk)] = struct.pack("<%dI" % len(chunk), *chunk)
        p2.permute(s)
    return _e(s[:32])


def key_elems(key32):
    return [int.from_bytes(key32[i:i + 4], "big") % P for i in range(0, 32, 4)]


def _secret(k, n, i):
    x = _b(k)
    p2.hash(x, SK, n, i)
    return x


def digits(msg_elems, n):
    d = sponge(MSG, [n] + list(msg_elems))
    bits = 0
    for e in d:
        bits = (bits << 30) | (e & 0x3fffffff)
    out = [(bits >> (240 - 4 * (k + 1))) & 15 for k in range(DIGITS)]
    c = sum(W - 1 - x for x in out)
    return out + [(c >> 8) & 15, (c >> 4) & 15, c & 15]


def public_key(key32, n):
    k = key_elems(key32)
    ends = []
    for i in range(CHAINS):
        x = _secret(k, n, i)
        p2.chain(x, CHAIN, n, i, 0, W - 1)
        ends += _e(x)
    return sponge(PK, [n] + ends)


def sign(key32, n, msg_elems):
    k = key_elems(key32)
    sig = []
    for i, d in enumerate(digits(msg_elems, n)):
        x = _secret(k, n, i)
        p2.chain(x, CHAIN, n, i, 0, d)
        sig.append(_e(x))
    return sig


def recover(sig, n, msg_elems):
    ends = []
    for i, d in enumerate(digits(msg_elems, n)):
        x = _b(sig[i])
        p2.chain(x, CHAIN, n, i, d, W - 1 - d)
        ends += _e(x)
    return sponge(PK, [n] + ends)


def bytes_to_elems(b):
    return [int.from_bytes(b[i:i + 2], "big") for i in range(0, len(b), 2)]
