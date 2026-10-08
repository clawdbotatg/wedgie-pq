"""WOTS one-time hash signatures over Poseidon2 (KoalaBear, width 16).

A hash is 8 field elements (~248 bits). w = 16: each chain is 15 hashes long.
The message digest gives 60 digits (30 bits from each of its 8 elements), plus 3 checksum digits:
63 chains. A signature is 63 x 8 elements = 2016 bytes.

Every hash call puts what it is for (a domain number) and where it is (key, chain, step) in the
other 8 elements of the state, so no two hashes in the whole system share an input."""
from poseidon2 import permute, P

W = 16
DIGITS = 60          # 8 elements x 30 bits / 4 bits
CHECK = 3            # checksum is at most 60 * 15 = 900 < 16^3
CHAINS = DIGITS + CHECK
SK, CHAIN, MSG, PK = 1, 2, 3, 4      # domains


def h(x8, *tweak):
    """One Poseidon2 call: 8 elements in, 8 out, with the tweak in the other half of the state."""
    t = list(tweak) + [0] * (8 - len(tweak))
    return permute(list(x8) + t)[:8]


def sponge(domain, elems):
    """Hash any number of elements to 8 (overwrite sponge, rate 8)."""
    s = [0] * 8 + [domain, len(elems)] + [0] * 6
    for i in range(0, len(elems), 8):
        chunk = elems[i:i + 8]
        s[:len(chunk)] = chunk
        s = permute(s)
    return s[:8]


def key_elems(key32):
    """The chip's 32 bytes for one key, as 8 field elements."""
    return [int.from_bytes(key32[i:i + 4], "big") % P for i in range(0, 32, 4)]


def secrets(key32, n):
    k = key_elems(key32)
    return [h(k, SK, n, i) for i in range(CHAINS)]


def chain(x, n, i, start, steps):
    for j in range(start, start + steps):
        x = h(x, CHAIN, n, i, j)
    return x


def digits(msg_elems, n):
    d = sponge(MSG, [n] + list(msg_elems))
    out = []
    bits = 0
    nb = 0
    for e in d:
        bits = (bits << 30) | (e & ((1 << 30) - 1))
        nb += 30
    for k in range(DIGITS):
        out.append((bits >> (nb - 4 * (k + 1))) & 15)
    c = sum(W - 1 - x for x in out)
    out += [(c >> 8) & 15, (c >> 4) & 15, c & 15]
    return out


def public_key(key32, n):
    ends = [chain(s, n, i, 0, W - 1) for i, s in enumerate(secrets(key32, n))]
    return sponge(PK, [n] + [e for x in ends for e in x])


def sign(key32, n, msg_elems):
    return [chain(s, n, i, 0, d) for i, (s, d) in enumerate(zip(secrets(key32, n), digits(msg_elems, n)))]


def recover(sig, n, msg_elems):
    """The public key a signature points to. It's valid if this equals the stored public key."""
    ends = [chain(x, n, i, d, W - 1 - d) for i, (x, d) in enumerate(zip(sig, digits(msg_elems, n)))]
    return sponge(PK, [n] + [e for x in ends for e in x])


def bytes_to_elems(b):
    """32 bytes (a Safe tx hash) as 16 elements of 16 bits each."""
    return [int.from_bytes(b[i:i + 2], "big") for i in range(0, len(b), 2)]


if __name__ == "__main__":
    import os, time
    key = os.urandom(32)
    n = 7
    msg = bytes_to_elems(os.urandom(32)) + [0] * 8
    t = time.time()
    pk = public_key(key, n)
    sig = sign(key, n, msg)
    assert recover(sig, n, msg) == pk
    bad = list(msg); bad[0] ^= 1
    assert recover(sig, n, bad) != pk
    assert recover(sig, n + 1, msg) != pk
    print("wots: sign + verify ok, wrong message and wrong key number fail (%.1f s in Python)" % (time.time() - t))
