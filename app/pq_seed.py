# The WOTS seed lives in the Trust M and never comes out. Key number n's 32 bytes are
# derive(seed, "wots" + n) (TLS 1.2 PRF, works on V1). A counter that only goes up hands out n, so no
# number signs twice, even if the power drops mid-signature.
import optiga as o

SEED = o.DATA[9]          # 140-byte data object, typed "pre-shared secret", read rule "never"
CTR = o.COUNTERS[3]       # monotonic counter: its value is the last key number spent
LIMIT = 600000            # the counter's threshold (about what it can count)


def ready(c):
    m = c.metadata(SEED)
    return m.get(0xE8) == b"\x21" and m.get(0xD1) == b"\xff"


def setup(c):
    """Make the seed and the counter. Changes chip metadata: see lock() for the permanent part."""
    c.write(SEED, c.random(64), erase=True)        # the seed passes through RAM once, here
    c.set_metadata(SEED, {0xE8: b"\x21", 0xD1: b"\xff", 0xD3: b"\x00"})
    c.set_counter(CTR, 0, LIMIT)


def lock(c):
    """PERMANENT. Lifecycle operational on both: nothing can read, overwrite or re-type the seed, or reset
    the counter, ever again. Until this, any code on the wedgie can undo setup()."""
    c.set_metadata(SEED, {0xC0: b"\x07"})
    c.set_metadata(CTR, {0xC0: b"\x07"})


def key(c, n):
    """Key number n's 32 bytes. Fine for public keys; to sign, take n from spend()."""
    return c.derive(SEED, 32, b"wots" + n.to_bytes(4, "big"), method="prf256")


def spend(c):
    """Use up the next key number before signing with it. Returns (n, key32)."""
    n = c.count(CTR)[0]
    return n, key(c, n)


def last(c):
    return c.counter(CTR)[0]
