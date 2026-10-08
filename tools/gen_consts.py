"""Writes mp/p2/consts.h: Plonky3's KoalaBear Poseidon2 constants in Montgomery form (R = 2^32)."""
import json, os

ROOT = os.path.join(os.path.dirname(__file__), "..")
c = json.load(open(os.path.join(ROOT, "vectors.json")))
P = c["p"]
R = 1 << 32
inv2 = pow(2, P - 2, P)
V = [P - 2, 1, 2, inv2, 3, 4, P - inv2, P - 3, P - 4, pow(inv2, 8, P), pow(inv2, 3, P), pow(inv2, 24, P),
     P - pow(inv2, 8, P), P - pow(inv2, 3, P), P - pow(inv2, 4, P), P - pow(inv2, 24, P)]
m = lambda x: x * R % P
arr = lambda name, xs: "static const uint32_t %s[%d] = {%s};\n" % (name, len(xs), ", ".join("%du" % m(x) for x in xs))
out = "// Made by tools/gen_consts.py from vectors.json. Don't edit.\n"
out += "#define P_MU_NEG %du\n#define P_R2 %du\n" % ((-pow(P, -1, R)) % R, R * R % P)
out += arr("RC_INIT", [x for r in c["external_initial"] for x in r])
out += arr("RC_FINAL", [x for r in c["external_final"] for x in r])
out += arr("RC_INT", c["internal"])
out += arr("DIAG", V)
open(os.path.join(ROOT, "mp", "p2", "consts.h"), "w").write(out)
