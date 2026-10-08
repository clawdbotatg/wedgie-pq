"""Runs the host build of mp/p2 on Plonky3's vectors: python3 tools/check_c.py /tmp/p2host"""
import json, os, subprocess, sys

c = json.load(open(os.path.join(os.path.dirname(__file__), "..", "vectors.json")))
for t in c["tests"]:
    out = subprocess.run([sys.argv[1]], input=" ".join(map(str, t["in"])), capture_output=True, text=True).stdout
    assert list(map(int, out.split())) == t["out"], "mismatch"
print("C permute: %d/%d Plonky3 vectors match" % (len(c["tests"]), len(c["tests"])))
