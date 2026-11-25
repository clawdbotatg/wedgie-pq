"""A Safe whose only owner is the wedgie's SLH-DSA key: make it, fund it, send from it.
  uv run --with pyserial python3 tools/safe_slh.py --chain eth --eth 0.0003 [--to 0x..] [--small]
The key comes from the seed in the wedgie's secure chip (app/pq_seed.py's slot, already set up). The wedgie
shows what it is about to sign and waits for the green button. A gas account (DEPLOY_KEY in wedgie-dev's
.env) deploys, funds the Safe and sends the signed transaction: it pays gas and can't move the Safe's money.
What it made is kept in ~/.wedgie-pq-safe.json, so a second run sends from the same Safe.
--fake: no wedgie, the C signer and a fixed test key (cc -O2 -DSLH_HOST -o /tmp/slhhost mp/slh/slh.c), for a fork.
Needs foundry (cast) and `forge build` in contracts/."""
import argparse, importlib.util, json, os, subprocess, sys
from check_slh import wrap, NAME, SIZE

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(HERE, "..", "..", "wedgie-dev")
MPY = os.path.join(HERE, "..", "mp", "slh", "slh.mpy")
BUILT = os.path.join(HERE, "..", "contracts", "out", "SlhSigner.sol", "SlhSigner.json")
STATE = os.path.expanduser("~/.wedgie-pq-safe.json")
ON_WEDGIE = "/pq_slh.mpy"
FACTORY = "0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67"      # Safe 1.4.1, the same on every chain
SAFE_L2 = "0x29fcB43b46531BcA003ddC8FCB67FFE91900C762"
HANDLER = "0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99"
ZERO = "0x0000000000000000000000000000000000000000"
CHAINS = {"eth": "eth-mainnet", "base": "base-mainnet", "sepolia": "eth-sepolia"}

# On the wedgie. The key's three parts are 48 bytes the secure chip derives from its seed; the seed never leaves it.
CODE = """
import gc, binascii, optiga
import pq_slh as _S
def _parts():
    return optiga.Chip().derive(optiga.DATA[9], 48, b"slh-dsa safe owner 0", method="prf256")
def _pub(set_):
    k = _parts(); st = bytearray(_S.size()); root = bytearray(16)
    _S.root(st, set_, k[:16], k[32:48], root)
    print("K", binascii.hexlify(k[32:48] + root).decode())
def _ask(q, lines):
    import lcd, ui
    print("A", 1 if ui.ask(lcd.LCD(), q, lines, yes="sign", no="no", ms=120000) else 0)
def _sign(set_, msg, title):
    hp, d, a, k = ((9, 7, 12, 14), (3, 22, 6, 33))[set_]
    gc.collect()
    p = _parts(); st = bytearray(_S.size()); root = bytearray(16); r = bytearray(16)
    part = bytearray(max(a + 1, 35 + hp) * 16)
    _S.root(st, set_, p[:16], p[32:48], root)
    _S.begin(st, set_, p[:16], p[16:32], p[32:48], root, msg, r)
    print("S", binascii.hexlify(r).decode())
    for i in range(k):
        n = _S.fors(st, i, part)
        print("S", binascii.hexlify(part[:n]).decode())
    n = (35 + hp) * 16
    for i in range(d):
        _ins(title, "part %d of %d" % (i + 1, d), (i + 1) / (d + 1))
        _S.layer(st, part)
        print("S", binascii.hexlify(part[:n]).decode())
"""


def env():
    e = {}
    for line in open(os.path.join(DEV, ".env")):
        if "=" in line and not line.startswith("#"):
            k, v = line.strip().split("=", 1)
            e[k] = v.strip("'\"")
    return e


class Chain:
    def __init__(self, rpc, key):
        self.rpc, self.key = rpc, key
        self.me = self.run("wallet", "address", "--private-key", key)

    def run(self, *a):
        r = subprocess.run(["cast", *a], capture_output=True, text=True)
        if r.returncode:
            sys.exit("cast %s failed: %s" % (a[0], r.stderr.replace(self.key, "<key>").strip()[-600:]))
        return r.stdout.strip()

    def call(self, to, sig, *a):
        return self.run("call", to, sig, *a, "--rpc-url", self.rpc)

    def send(self, *a):
        """Sends, waits for it, returns the receipt. A transaction that reverted stops everything."""
        r = json.loads(self.run("send", "--rpc-url", self.rpc, "--private-key", self.key, "--json", *a))
        if int(r["status"], 16) != 1:
            sys.exit("reverted: " + r["transactionHash"])
        return r


def fake_signer(set_):
    k = ["000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f", "202122232425262728292a2b2c2d2e2f"]
    go = lambda msg: subprocess.run(["/tmp/slhhost", str(set_), *k, msg.hex()], capture_output=True, text=True, check=True).stdout.split()
    return bytes.fromhex(k[2] + go(b"\0")[0]), lambda msg, q, lines: bytes.fromhex(go(msg)[1])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chain", default="base", choices=list(CHAINS))
    ap.add_argument("--rpc", help="another RPC (a local fork)")
    ap.add_argument("--key", help="the gas account's key (a local fork's); default DEPLOY_KEY")
    ap.add_argument("--eth", default="0.0003", help="how much to put in and send")
    ap.add_argument("--to", help="who gets it (default: back to the gas account)")
    ap.add_argument("--small", action="store_true", help="SHA2-128s: 7.9 KB signature, less gas, minutes to sign")
    ap.add_argument("--fake", action="store_true")
    ap.add_argument("--wedgie-py", default=os.path.join(DEV, "public", "wedgie.py"))
    args = ap.parse_args()
    set_ = 0 if args.small else 1
    e = env()
    ch = Chain(args.rpc or "https://%s.g.alchemy.com/v2/%s" % (CHAINS[args.chain], e["ALCHEMY_API_KEY"]), args.key or e["DEPLOY_KEY"])
    to = args.to or ch.me
    wei = ch.run("to-wei", args.eth)
    chain_id = ch.run("chain-id", "--rpc-url", ch.rpc)
    state = json.load(open(STATE)) if os.path.exists(STATE) and not args.rpc else {}

    wg = W = None
    if args.fake:
        pk, sign = fake_signer(set_)
    else:
        spec = importlib.util.spec_from_file_location("wedgie", args.wedgie_py)
        W = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(W)

        class A:
            port = id = name = None
        wg = W.pick(A)
        W.take_over(wg, "Sign with a post-quantum key", "Post-quantum Safe")

    try:
        if wg:
            wg.put(ON_WEDGIE, open(MPY, "rb").read(), span=(0, 0.1))
            wg.exec(CODE)
            wg.busy("Post-quantum Safe", "making the key")
            pk = bytes.fromhex(wg.exec("_pub(%d)" % set_, 120).split("K ")[1].split()[0])

            def sign(msg, q, lines):
                if "A 1" not in wg.exec("_ask(%r, %r)" % (q, lines), 150):
                    sys.exit("the wedgie said no")
                wg.busy("Signing", "starting")
                out = wg.exec("_sign(%d, %r, 'Signing')" % (set_, msg), 1800)
                return bytes.fromhex("".join(l[2:].strip() for l in out.splitlines() if l.startswith("S ")))
        print("key (PK.seed, PK.root):", pk.hex())

        id_ = "%s:%s:%s" % (chain_id, NAME[set_], pk.hex())
        have = state.get(id_)
        if not have:
            wg and wg.busy("Post-quantum Safe", "making the Safe")
            code = json.load(open(BUILT))["bytecode"]["object"]
            ctor = ch.run("abi-encode", "c(bytes16,bytes16,bool)", "0x" + pk[:16].hex(), "0x" + pk[16:].hex(), "true" if set_ else "false")
            r = ch.send("--create", code + ctor[2:])
            owner = r["contractAddress"]
            print("owner contract:", owner, "gas", int(r["gasUsed"], 16))
            init = ch.run("calldata", "setup(address[],uint256,address,bytes,address,address,uint256,address)",
                          "[%s]" % owner, "1", ZERO, "0x", HANDLER, ZERO, "0", ZERO)
            make = ("createProxyWithNonce(address,bytes,uint256)(address)", SAFE_L2, init, "1")
            safe = ch.call(FACTORY, *make, "--from", ch.me)
            r = ch.send(FACTORY, *make)
            print("Safe:", safe, "gas", int(r["gasUsed"], 16))
            have = state[id_] = {"owner": owner, "safe": safe}
            if not args.rpc:
                json.dump(state, open(STATE, "w"), indent=1)
        owner, safe = have["owner"], have["safe"]
        if int(ch.run("balance", safe, "--rpc-url", ch.rpc)) < int(wei):
            wg and wg.busy("Post-quantum Safe", "putting money in")
            ch.send(safe, "--value", wei)
            print("put %s ETH in the Safe" % args.eth)

        nonce = ch.call(safe, "nonce()(uint256)").split()[0]
        tx = (to, wei, "0x", "0", "0", "0", "0", ZERO, ZERO)
        h = ch.call(safe, "getTransactionHash(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,uint256)(bytes32)", *tx, nonce)
        print("Safe transaction hash:", h)
        sig = sign(wrap(bytes.fromhex(h[2:])), "Send %s ETH?" % args.eth, ["to " + to[:10] + ".." + to[-8:], "from your Safe " + safe[:8] + "..", "post-quantum signature"])
        if len(sig) != SIZE[set_]:
            sys.exit("the signature is %d bytes, not %d" % (len(sig), SIZE[set_]))
        if ch.call(owner, "verify(bytes32,bytes)(bool)", h, "0x" + sig.hex()) != "true":
            sys.exit("the owner contract says the signature is bad")
        # a contract owner's signature: the owner, where its bytes start (65), type 0, then the bytes
        sigs = bytes(12) + bytes.fromhex(owner[2:]) + (65).to_bytes(32, "big") + b"\0" + len(sig).to_bytes(32, "big") + sig
        wg and wg.busy("Post-quantum Safe", "sending")
        before = int(ch.run("balance", to, "--rpc-url", ch.rpc))
        r = ch.send(safe, "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)", *tx, "0x" + sigs.hex())
        print("sent: %s  gas %d  (%s signature, %d bytes)" % (r["transactionHash"], int(r["gasUsed"], 16), NAME[set_], len(sig)))
        if to.lower() != ch.me.lower():
            print("arrived:", int(ch.run("balance", to, "--rpc-url", ch.rpc)) - before, "wei")
    finally:
        if wg:
            try:
                wg.exec("import os\ntry:\n    os.remove(%r)\nexcept OSError:\n    pass" % ON_WEDGIE)
            except Exception:
                pass
            wg.leave(reset=False)


if __name__ == "__main__":
    main()
