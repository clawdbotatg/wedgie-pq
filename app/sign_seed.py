# Signs twice with keys from the seed in the Trust M (pq_seed.py). Each signature covers a 32-byte
# message and the next key's public key, so the keys chain. Prints a JSON line per signature for tools/check_seed.py.
import gc, json, time, optiga
import pq_seed, pq_wots as wots

c = optiga.Chip()
for msg32 in (bytes(range(32)), bytes(range(32, 64))):
    t = time.ticks_ms()
    n, k = pq_seed.spend(c)
    pk = wots.public_key(k, n)
    nxt = wots.public_key(pq_seed.key(c, n + 1), n + 1)
    msg = wots.bytes_to_elems(msg32) + nxt
    sig = wots.sign(k, n, msg)
    k = None
    print(json.dumps({"n": n, "ms": time.ticks_diff(time.ticks_ms(), t), "msg": msg32.hex(), "pk": pk,
                      "next_pk": nxt})[:-1] + ', "sig": [', end="")
    for i, row in enumerate(sig):                       # a row at a time: one big dumps runs out of RAM
        print(("," if i else "") + json.dumps(row), end="")
    print("]}")
    sig = None
    gc.collect()
