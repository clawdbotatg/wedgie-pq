"""Times SLH-DSA signing on a real wedgie and checks each signature with OpenSSL on this computer.
  uv run --with pyserial python3 tools/bench_slh.py [128f] [128s] [--wedgie-py path/to/wedgie.py]
Press the green button on the wedgie when it asks. The key is random, made here, used once and thrown
away: a test key, never one that owns anything. The module file is removed from the wedgie at the end."""
import importlib.util, json, os, sys
from check_slh import verify, wrap, NAME, SIZE

HERE = os.path.dirname(os.path.abspath(__file__))
MPY = os.path.join(HERE, "..", "mp", "slh", "slh.mpy")
ON_WEDGIE = "/pq_slh.mpy"

BENCH = """
import time, gc, binascii
import pq_slh as S
def _bench(set_, sk_seed, sk_prf, pk_seed, msg, title):
    hp, d, a, k = ((9, 7, 12, 14), (3, 22, 6, 33))[set_]
    st = bytearray(S.size()); root = bytearray(16); r = bytearray(16)
    part = bytearray(max(a + 1, 35 + hp) * 16)
    td = time.ticks_diff; now = time.ticks_ms
    t = now(); S.root(st, set_, sk_seed, pk_seed, root); key_ms = td(now(), t)
    print("K", binascii.hexlify(root).decode())
    t = now(); S.begin(st, set_, sk_seed, sk_prf, pk_seed, root, msg, r); ms = td(now(), t)
    print("S", binascii.hexlify(r).decode())
    fors_ms = 0
    for i in range(k):
        t = now(); n = S.fors(st, i, part); fors_ms += td(now(), t)
        print("S", binascii.hexlify(part[:n]).decode())
    ms += fors_ms
    n = (35 + hp) * 16
    worst = 0
    for i in range(d):
        try:
            _ins(title, "layer %d of %d" % (i + 1, d), (i + 1) / (d + 1))
        except Exception:
            pass
        t = now(); S.layer(st, part); one = td(now(), t); ms += one
        worst = max(worst, one)
        print("S", binascii.hexlify(part[:n]).decode())
    gc.collect()
    print("R", '{"key_ms": %d, "sign_ms": %d, "fors_ms": %d, "layer_ms": %d, "free": %d}' % (key_ms, ms, fors_ms, worst, gc.mem_free()))
"""


def load_wedgie_py(path):
    spec = importlib.util.spec_from_file_location("wedgie", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    args = sys.argv[1:]
    path = os.path.join(HERE, "..", "..", "wedgie-dev", "public", "wedgie.py")
    if "--wedgie-py" in args:
        i = args.index("--wedgie-py")
        path = args[i + 1]
        del args[i:i + 2]
    sets = [{"128s": 0, "128f": 1}[a] for a in args] or [1, 0]
    W = load_wedgie_py(path)

    class A:
        port = id = name = None
    wg = W.pick(A)
    bad = 0
    W.take_over(wg, "Run a signature test", "Testing signatures")
    try:
        wg.put(ON_WEDGIE, open(MPY, "rb").read())
        wg.exec(BENCH)
        for set_ in sets:
            sk_seed, sk_prf, pk_seed, msg = os.urandom(16), os.urandom(16), os.urandom(16), os.urandom(32)
            wg.busy("SLH-DSA " + NAME[set_], "making the key")
            out = wg.exec("_bench(%d, %r, %r, %r, %r, %r)" % (set_, sk_seed, sk_prf, pk_seed, wrap(msg), "SLH-DSA " + NAME[set_]), 1800)
            root, sig, res = None, "", None
            for line in out.splitlines():
                if line.startswith("K "):
                    root = bytes.fromhex(line[2:])
                elif line.startswith("S "):
                    sig += line[2:].strip()
                elif line.startswith("R "):
                    res = json.loads(line[2:])
            sig = bytes.fromhex(sig)
            ok = bool(res) and len(sig) == SIZE[set_] and verify(set_, pk_seed + root, msg, sig)
            bad += not ok
            print("OK  " if ok else "FAIL", NAME[set_], "sig %d bytes" % len(sig), json.dumps(res))
    finally:
        try:
            wg.exec("import os\ntry:\n    os.remove(%r)\nexcept OSError:\n    pass" % ON_WEDGIE)
        except Exception:
            pass
        wg.leave(reset=False)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
