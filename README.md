# wedgie-pq

Quantum-safe signatures for a Safe, made on a [wedgie](https://wedgie.dev).

P-256 and ECDSA fall to a quantum computer. Hashes don't. So the wedgie signs with **WOTS one-time
hash signatures** built on **Poseidon2** (KoalaBear, the hash Plonky3 STARKs use). Later, a computer
turns the owners' signatures into one STARK proof, and a contract on the Safe checks it.

Idea credit: [Nick Dodson's bunker wallet](https://x.com/iamnickdodson/status/2107988457297514883)
(rotate the key every transaction) and
[Roman Storm](https://x.com/rstormsf/status/2108218447998124488) (a private, post-quantum multisig
needs hash signatures inside a hash-based proof). Background:
[wedgie-dev/docs/RESEARCH-ROTATING-KEY.md](https://github.com/clawdbotatg/wedgie-dev/blob/main/docs/RESEARCH-ROTATING-KEY.md).

Prototype. Not audited. Don't put money on it.

## What's here

| Path | What |
|---|---|
| `tools/vectors` | Rust. Prints Plonky3's Poseidon2 constants and test outputs to `vectors.json`. |
| `ref/poseidon2.py` | Poseidon2 in plain Python. Matches Plonky3. |
| `ref/wots.py` | The hash signature scheme in plain Python. |
| `mp/p2` | Poseidon2 in C, as a MicroPython native module for the RP2040 (2 KB). |
| `app/` | The wedgie side: `pq_wots.py` (the scheme) and `bench.py` (timing test). |

## The scheme

- A hash is 8 field elements (about 248 bits).
- Chains of 15 hashes (w = 16). 60 message digits + 3 checksum digits = 63 chains.
- A signature is 63 x 8 elements = 2016 bytes.
- Each key signs once. Key number `n` is mixed into every hash.
- The key's 32 bytes come from the Trust M. For now: its random generator. Later: `derive` from a
  seed the chip never reveals.

## Check it

```sh
python3 ref/poseidon2.py         # Python matches Plonky3
python3 ref/wots.py              # sign, verify, forgeries fail
cc -O2 -DP2_HOST -o /tmp/p2host mp/p2/host_test.c && python3 tools/check_c.py /tmp/p2host   # C matches Plonky3
```

Build the wedgie module (MicroPython v1.29.0 source, `brew install arm-none-eabi-gcc`):

```sh
cd mp/p2 && uv run --with pyelftools --with ar make MPY_DIR=/path/to/micropython CFLAGS_EXTRA="-Istubs -ffreestanding"
```

`stubs/` stands in for the C library headers brew's bare compiler doesn't have.

## On a real wedgie

RP2040 Pico, firmware 0.3.26, Trust M V1, key from the chip's random generator (2026-10-08).
The signature matched `ref/wots.py` exactly.

| What | Time |
|---|---|
| One Poseidon2 permutation | 0.92 ms |
| Public key (63 chains x 15 hashes) | 1.07 s |
| Sign | 0.55 s |
| Verify | 0.59 s |
| Trust M `derive` from the stored seed (`app/pq_seed.py`) | 1.8 s |
| Trust M counter step | 25 ms |
| Sign with the stored seed, next public key included (`app/sign_seed.py`) | 6.4 s |

## Next

Done: the seed in the Trust M (`app/pq_seed.py`, not locked yet), a counter so no key number is
used twice, checked with `tools/check_seed.py`.

1. A Plonky3 circuit: k of n WOTS signatures over a Merkle root of owners.
2. A contract that checks the STARK and acts as the Safe owner.

MIT
