"""Checks mp/slh/slh.c on a computer: sign with the C code, verify with OpenSSL (3.5 or newer).
  cc -O2 -DSLH_HOST -o /tmp/slhhost mp/slh/slh.c && python3 tools/check_slh.py /tmp/slhhost
Or check a signature a wedgie made:  python3 tools/check_slh.py --sig <set> <pk hex> <msg hex> <sig hex file>"""
import base64, os, subprocess, sys, tempfile, time

OID = {0: 0x14, 1: 0x15}          # SLH-DSA-SHA2-128s, -128f
SIZE = {0: 7856, 1: 17088}
NAME = {0: "128s", 1: "128f"}


def verify(set_, pk, msg, sig):
    """True if OpenSSL takes sig as SLH-DSA (pure, no context) over msg by public key pk (32 bytes)."""
    der = bytes([0x30, 0x30, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, OID[set_],
                 0x03, 0x21, 0x00]) + pk
    pem = "-----BEGIN PUBLIC KEY-----\n" + base64.encodebytes(der).decode() + "-----END PUBLIC KEY-----\n"
    with tempfile.TemporaryDirectory() as d:
        for name, data in (("pk.pem", pem.encode()), ("msg", msg), ("sig", sig)):
            open(os.path.join(d, name), "wb").write(data)
        r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", d + "/pk.pem", "-in", d + "/msg",
                            "-sigfile", d + "/sig"], capture_output=True, text=True)
    return r.returncode == 0 and "Success" in r.stdout


def wrap(msg):
    """What the signer hashes for a plain message with no context (FIPS 205, slh_sign)."""
    return b"\x00\x00" + msg


if __name__ == "__main__":
    if sys.argv[1] == "--sig":
        set_, pk, msg = int(sys.argv[2]), bytes.fromhex(sys.argv[3]), bytes.fromhex(sys.argv[4])
        sig = bytes.fromhex(open(sys.argv[5]).read().strip())
        ok = len(sig) == SIZE[set_] and verify(set_, pk, msg, sig)
        print("OK" if ok else "FAIL", NAME[set_], len(sig), "bytes")
        sys.exit(0 if ok else 1)
    host, bad = sys.argv[1], 0
    for set_ in (1, 0):
        for msg in (b"", bytes(range(32)), os.urandom(200)):
            sk_seed, sk_prf, pk_seed = os.urandom(16), os.urandom(16), os.urandom(16)
            t = time.time()
            out = subprocess.run([host, str(set_), sk_seed.hex(), sk_prf.hex(), pk_seed.hex(), wrap(msg).hex()],
                                 capture_output=True, text=True, check=True).stdout.split()
            root, sig = bytes.fromhex(out[0]), bytes.fromhex(out[1])
            ok = len(sig) == SIZE[set_] and verify(set_, pk_seed + root, msg, sig)
            flipped = bytearray(sig); flipped[len(sig) // 2] ^= 1
            ok = ok and not verify(set_, pk_seed + root, msg, bytes(flipped))
            bad += not ok
            print("OK  " if ok else "FAIL", NAME[set_], "msg", len(msg), "bytes, sig", len(sig), "bytes, %.2f s" % (time.time() - t))
    sys.exit(1 if bad else 0)
