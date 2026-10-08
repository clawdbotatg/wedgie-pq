"""Poseidon2 over KoalaBear, width 16, matching Plonky3's default_koalabear_poseidon2_16.
Plain Python reference. Constants come from vectors.json (made by tools/vectors from Plonky3)."""
import json, os

P = 0x7f000001
_C = json.load(open(os.path.join(os.path.dirname(__file__), "..", "vectors.json")))
EXT_INIT, EXT_FINAL, INTERNAL = _C["external_initial"], _C["external_final"], _C["internal"]
_INV2 = pow(2, P - 2, P)
# Internal diagonal: s_i -> V_i * s_i + sum(s)
V = [P - 2, 1, 2, _INV2, 3, 4, P - _INV2, P - 3, P - 4,
     pow(_INV2, 8, P), pow(_INV2, 3, P), pow(_INV2, 24, P),
     P - pow(_INV2, 8, P), P - pow(_INV2, 3, P), P - pow(_INV2, 4, P), P - pow(_INV2, 24, P)]


def _mat4(x0, x1, x2, x3):
    return ((2 * x0 + 3 * x1 + x2 + x3) % P, (x0 + 2 * x1 + 3 * x2 + x3) % P,
            (x0 + x1 + 2 * x2 + 3 * x3) % P, (3 * x0 + x1 + x2 + 2 * x3) % P)


def _external(s):
    t = []
    for i in range(0, 16, 4):
        t.extend(_mat4(*s[i:i + 4]))
    sums = [sum(t[k::4]) for k in range(4)]
    return [(t[i] + sums[i % 4]) % P for i in range(16)]


def _internal(s):
    tot = sum(s)
    return [(V[i] * s[i] + tot) % P for i in range(16)]


def permute(state):
    s = _external(list(state))
    for rc in EXT_INIT:
        s = _external([pow((x + c) % P, 3, P) for x, c in zip(s, rc)])
    for c in INTERNAL:
        s[0] = pow((s[0] + c) % P, 3, P)
        s = _internal(s)
    for rc in EXT_FINAL:
        s = _external([pow((x + c) % P, 3, P) for x, c in zip(s, rc)])
    return s


if __name__ == "__main__":
    for t in _C["tests"]:
        assert permute(t["in"]) == t["out"], "mismatch"
    print("poseidon2: %d/%d Plonky3 vectors match" % (len(_C["tests"]), len(_C["tests"])))
