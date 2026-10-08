"""Checks app/sign_seed.py's output: each signature verifies against its public key, and each
signature's next_pk is the public key the next signature uses.  python3 tools/check_seed.py out.json"""
import json, os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ref"))
import wots

sigs = [json.loads(l) for l in open(sys.argv[1]) if l.startswith("{")]
assert sigs, "no signatures in " + sys.argv[1]
for i, s in enumerate(sigs):
    msg = wots.bytes_to_elems(bytes.fromhex(s["msg"])) + s["next_pk"]
    assert wots.recover(s["sig"], s["n"], msg) == s["pk"], "signature %d doesn't verify" % i
    bad = list(msg)
    bad[0] ^= 1
    assert wots.recover(s["sig"], s["n"], bad) != s["pk"], "signature %d verifies a changed message" % i
    if i:
        assert sigs[i - 1]["next_pk"] == s["pk"] and s["n"] == sigs[i - 1]["n"] + 1, "chain broken at %d" % i
    print("key %d: ok, %d ms" % (s["n"], s["ms"]))
print("all ok")
