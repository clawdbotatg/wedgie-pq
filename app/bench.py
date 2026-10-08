# Times Poseidon2 and a full hash signature on this wedgie, and prints JSON a computer can check
# against ref/wots.py. The key's 32 bytes come from the Trust M's random number generator.
import json, time
import pq_p2 as p2
import pq_wots as wots

s = bytearray(64)
t = time.ticks_ms()
for _ in range(100):
    p2.permute(s)
perm_ms = time.ticks_diff(time.ticks_ms(), t) / 100

try:
    import optiga
    key = bytes(optiga.Chip().random(32))
    src = "trust m"
except Exception:
    import os
    key = os.urandom(32)
    src = "os.urandom (no chip)"

n = 1
msg = wots.bytes_to_elems(bytes(range(32))) + [0] * 8
t = time.ticks_ms()
pk = wots.public_key(key, n)
pk_ms = time.ticks_diff(time.ticks_ms(), t)
t = time.ticks_ms()
sig = wots.sign(key, n, msg)
sign_ms = time.ticks_diff(time.ticks_ms(), t)
t = time.ticks_ms()
ok = wots.recover(sig, n, msg) == pk
verify_ms = time.ticks_diff(time.ticks_ms(), t)
print(json.dumps({"perm_ms": perm_ms, "pk_ms": pk_ms, "sign_ms": sign_ms, "verify_ms": verify_ms,
                  "ok": ok, "key_from": src, "key": key.hex(), "n": n, "pk": pk, "sig": sig}))
