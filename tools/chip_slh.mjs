// SLH-DSA signing on a virtual RP2040 (wedgie-dev's tools/rp2040: rp2040js + the real MicroPython build),
// each signature checked with OpenSSL. A dry run before a real board; its times are the virtual chip's.
//   node tools/chip_slh.mjs [128f] [128s]      (wedgie-dev checked out beside this repo)
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
const here = dirname(fileURLToPath(import.meta.url));
const dev = join(here, "..", "..", "wedgie-dev", "tools", "rp2040");
const { host } = await import(join(dev, "chip.mjs"));
const { firmware, image } = await import(join(dev, "image.mjs"));
const bench = readFileSync(join(here, "bench_slh.py"), "utf8").match(/BENCH = """([^]*?)"""/)[1];
const F = firmware();
const h = host({ fs: image(F, null, { "pq_slh.mpy": readFileSync(join(here, "..", "mp", "slh", "slh.mpy")) }, ["main.py"]) });
h.until((b) => b.includes(">>> "), 30000, 20);
h.exec(bench);
const py = (b) => "bytes.fromhex('" + b.toString("hex") + "')";
let bad = 0;
for (const name of process.argv.slice(2).length ? process.argv.slice(2) : ["128f"]) {
  const set = name === "128s" ? 0 : 1;
  const [skSeed, skPrf, pkSeed, msg] = [16, 16, 16, 32].map((n) => randomBytes(n));
  const wall = Date.now();
  const out = h.exec(`_bench(${set}, ${py(skSeed)}, ${py(skPrf)}, ${py(pkSeed)}, ${py(Buffer.concat([Buffer.from([0, 0]), msg]))}, "t")`, 3600000);
  let root = "", sig = "", res = "";
  for (const l of out.split(/\r?\n/)) {
    if (l.startsWith("K ")) root = l.slice(2).trim();
    else if (l.startsWith("S ")) sig += l.slice(2).trim();
    else if (l.startsWith("R ")) res = l.slice(2).trim();
  }
  const d = mkdtempSync(join(tmpdir(), "slh-"));
  writeFileSync(join(d, "sig.hex"), sig);
  let ok = true;
  try {
    execFileSync("python3", [join(here, "check_slh.py"), "--sig", String(set), pkSeed.toString("hex") + root, msg.toString("hex"), join(d, "sig.hex")], { stdio: "pipe" });
  } catch { ok = false; }
  bad += !ok;
  console.log(ok ? "OK  " : "FAIL", name, `sig ${sig.length / 2} bytes`, res, `(${((Date.now() - wall) / 1000).toFixed(0)} s to emulate)`);
}
process.exit(bad ? 1 : 0);
