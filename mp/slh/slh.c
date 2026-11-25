// SLH-DSA signing (FIPS 205), the SHA2-128s and SHA2-128f sets. A MicroPython native module for the
// wedgie (RP2040), and a plain C program on a computer (-DSLH_HOST) to check it.
// One key signs any number of times: no counter, nothing to keep between signatures.
// A signature is made in parts (begin, each FORS tree, then one layer at a time) so the caller never holds
// more than one part in memory (at most 704 bytes) and never sits in one call for minutes.
#ifndef SLH_HOST
#include "py/dynruntime.h"
#else
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#endif

#define N 16            // bytes in a hash
#define WLEN 35         // WOTS chains: 32 message digits + 3 checksum digits (w = 16)

// ---- SHA-256 ----
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};
static const uint32_t IV[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

#define ROR(x, r) (((x) >> (r)) | ((x) << (32 - (r))))

static void compress(uint32_t *h, const uint8_t *p) {
    uint32_t w[16];
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t x;
        if (i < 16) {
            x = ((uint32_t)p[4 * i] << 24) | ((uint32_t)p[4 * i + 1] << 16) | ((uint32_t)p[4 * i + 2] << 8) | p[4 * i + 3];
        } else {
            uint32_t s0 = w[(i + 1) & 15], s1 = w[(i + 14) & 15];
            s0 = ROR(s0, 7) ^ ROR(s0, 18) ^ (s0 >> 3);
            s1 = ROR(s1, 17) ^ ROR(s1, 19) ^ (s1 >> 10);
            x = w[i & 15] + s0 + w[(i + 9) & 15] + s1;
        }
        w[i & 15] = x;
        uint32_t t1 = hh + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + x;
        uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

typedef struct {
    uint32_t h[8];
    uint32_t n;          // bytes taken so far
    uint8_t buf[64];
} sha_t;

static void cpy(uint8_t *d, const uint8_t *s, size_t n) {
    while (n--) {
        *d++ = *s++;
    }
}

static void sha_init(sha_t *s) {
    for (int i = 0; i < 8; i++) {
        s->h[i] = IV[i];
    }
    s->n = 0;
}

static void sha_update(sha_t *s, const uint8_t *p, size_t len) {
    while (len) {
        size_t at = s->n & 63, take = 64 - at;
        if (take > len) {
            take = len;
        }
        cpy(s->buf + at, p, take);
        s->n += take; p += take; len -= take;
        if ((s->n & 63) == 0) {
            compress(s->h, s->buf);
        }
    }
}

// The first `outlen` bytes of the hash (outlen <= 32).
static void sha_final(sha_t *s, uint8_t *out, size_t outlen) {
    uint32_t bits = s->n << 3, hi = s->n >> 29;
    size_t at = s->n & 63;
    s->buf[at++] = 0x80;
    if (at > 56) {
        while (at < 64) {
            s->buf[at++] = 0;
        }
        compress(s->h, s->buf);
        at = 0;
    }
    while (at < 56) {
        s->buf[at++] = 0;
    }
    s->buf[56] = 0; s->buf[57] = 0; s->buf[58] = 0; s->buf[59] = (uint8_t)hi;
    s->buf[60] = (uint8_t)(bits >> 24); s->buf[61] = (uint8_t)(bits >> 16); s->buf[62] = (uint8_t)(bits >> 8); s->buf[63] = (uint8_t)bits;
    compress(s->h, s->buf);
    for (size_t i = 0; i < outlen; i++) {
        out[i] = (uint8_t)(s->h[i >> 2] >> (24 - 8 * (i & 3)));
    }
}

// ---- SLH-DSA ----
// One signature in progress. Lives in a buffer the caller owns.
typedef struct {
    uint32_t seeded[8];          // SHA-256 after PK.seed and 48 zero bytes: where every tweaked hash starts
    uint32_t tree_hi, tree_lo;   // which tree, at the layer being signed
    uint32_t leaf;               // which leaf in it
    uint8_t hp, d, a, k;         // the set: tree height per layer, layers, FORS tree height, FORS trees
    uint8_t layer;               // next layer to sign
    uint8_t sk_seed[N], pk_seed[N];
    uint8_t root[N];             // what the next layer signs
    uint8_t md[25];              // the message digest's FORS part
    sha_t roots;                 // the hash over the FORS roots, as they come
} slh_t;

// An address (FIPS 205 ADRS), in the 22-byte compressed form the SHA2 sets hash.
typedef struct {
    uint32_t tree_hi, tree_lo, w1, w2, w3;
    uint8_t layer, type;
} adrs_t;
enum { WOTS_HASH, WOTS_PK, TREE, FORS_TREE, FORS_ROOTS, WOTS_PRF, FORS_PRF };

static void be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

static void adrs_bytes(const adrs_t *a, uint8_t *p) {
    p[0] = a->layer;
    be32(p + 1, a->tree_hi);
    be32(p + 5, a->tree_lo);
    p[9] = a->type;
    be32(p + 10, a->w1);
    be32(p + 14, a->w2);
    be32(p + 18, a->w3);
}

static void set_type(adrs_t *a, uint8_t type) {
    a->type = type; a->w1 = 0; a->w2 = 0; a->w3 = 0;
}

// F, H and PRF: out = SHA-256(PK.seed || zeros || ADRS || in)[:16], in is 16 or 32 bytes. One block.
static void thash(const slh_t *c, const adrs_t *a, const uint8_t *in, size_t inlen, uint8_t *out) {
    uint8_t blk[64];
    uint32_t h[8];
    adrs_bytes(a, blk);
    cpy(blk + 22, in, inlen);
    size_t at = 22 + inlen;
    blk[at++] = 0x80;
    while (at < 62) {
        blk[at++] = 0;
    }
    uint32_t bits = (64 + 22 + (uint32_t)inlen) * 8;
    blk[62] = (uint8_t)(bits >> 8); blk[63] = (uint8_t)bits;
    for (int i = 0; i < 8; i++) {
        h[i] = c->seeded[i];
    }
    compress(h, blk);
    for (int i = 0; i < N; i++) {
        out[i] = (uint8_t)(h[i >> 2] >> (24 - 8 * (i & 3)));
    }
}

// T_l: the same hash over many values, taken one at a time.
static void tl_begin(const slh_t *c, const adrs_t *a, sha_t *s) {
    uint8_t ab[22];
    for (int i = 0; i < 8; i++) {
        s->h[i] = c->seeded[i];
    }
    s->n = 64;
    adrs_bytes(a, ab);
    sha_update(s, ab, 22);
}

static void chain(const slh_t *c, adrs_t *a, uint8_t *x, uint32_t start, uint32_t steps) {
    for (uint32_t j = start; j < start + steps; j++) {
        a->w3 = j;
        thash(c, a, x, N, x);
    }
}

// The 35 digits of a 16-byte message: 32 nibbles, then the checksum's 3.
static void digits(const uint8_t *m, uint8_t *dg) {
    uint32_t csum = 0;
    for (int i = 0; i < 16; i++) {
        dg[2 * i] = m[i] >> 4;
        dg[2 * i + 1] = m[i] & 15;
        csum += 30 - dg[2 * i] - dg[2 * i + 1];
    }
    dg[32] = (csum >> 8) & 15; dg[33] = (csum >> 4) & 15; dg[34] = csum & 15;
}

static void wots_secret(const slh_t *c, const adrs_t *a, uint32_t i, uint8_t *out) {
    adrs_t sk = *a;
    sk.type = WOTS_PRF; sk.w2 = i; sk.w3 = 0;
    thash(c, &sk, c->sk_seed, N, out);
}

// A leaf of an XMSS tree: the WOTS public key of key pair `kp`.
static void wots_pk(const slh_t *c, adrs_t *a, uint32_t kp, uint8_t *out) {
    sha_t s;
    uint8_t x[N];
    adrs_t pk = *a;
    set_type(&pk, WOTS_PK);
    pk.w1 = kp;
    tl_begin(c, &pk, &s);
    set_type(a, WOTS_HASH);
    a->w1 = kp;
    for (uint32_t i = 0; i < WLEN; i++) {
        wots_secret(c, a, i, x);
        a->w2 = i;
        chain(c, a, x, 0, 15);
        sha_update(&s, x, N);
    }
    sha_final(&s, out, N);
}

// The WOTS signature of `m` by key pair `kp`, into sig (35 x 16 bytes). Also the leaf it belongs to.
static void wots_sign(const slh_t *c, adrs_t *a, uint32_t kp, const uint8_t *m, uint8_t *sig, uint8_t *leaf) {
    sha_t s;
    uint8_t dg[WLEN], x[N];
    adrs_t pk = *a;
    set_type(&pk, WOTS_PK);
    pk.w1 = kp;
    tl_begin(c, &pk, &s);
    digits(m, dg);
    set_type(a, WOTS_HASH);
    a->w1 = kp;
    for (uint32_t i = 0; i < WLEN; i++) {
        wots_secret(c, a, i, x);
        a->w2 = i;
        chain(c, a, x, 0, dg[i]);
        cpy(sig + i * N, x, N);
        chain(c, a, x, dg[i], 15 - dg[i]);
        sha_update(&s, x, N);
    }
    sha_final(&s, leaf, N);
}

// Node i at height z of the XMSS tree at address a.
static void xmss_node(const slh_t *c, adrs_t *a, uint32_t i, uint32_t z, uint8_t *out) {
    if (z == 0) {
        wots_pk(c, a, i, out);
        return;
    }
    uint8_t lr[2 * N];
    xmss_node(c, a, 2 * i, z - 1, lr);
    xmss_node(c, a, 2 * i + 1, z - 1, lr + N);
    set_type(a, TREE);
    a->w2 = z; a->w3 = i;
    thash(c, a, lr, 2 * N, out);
}

static void fors_secret(const slh_t *c, const adrs_t *a, uint32_t idx, uint8_t *out) {
    adrs_t sk = *a;
    sk.type = FORS_PRF; sk.w2 = 0; sk.w3 = idx;
    thash(c, &sk, c->sk_seed, N, out);
}

// Node i at height z across the FORS trees. a is a FORS_TREE address with its key pair set.
static void fors_node(const slh_t *c, adrs_t *a, uint32_t i, uint32_t z, uint8_t *out) {
    if (z == 0) {
        uint8_t sk[N];
        fors_secret(c, a, i, sk);
        a->w2 = 0; a->w3 = i;
        thash(c, a, sk, N, out);
        return;
    }
    uint8_t lr[2 * N];
    fors_node(c, a, 2 * i, z - 1, lr);
    fors_node(c, a, 2 * i + 1, z - 1, lr + N);
    a->w2 = z; a->w3 = i;
    thash(c, a, lr, 2 * N, out);
}

// Up from a node to its tree's root along an authentication path. idx: the node's place at height 0
// (w3 on the way in). kind: TREE or FORS_TREE (already the address's type).
static void climb(const slh_t *c, adrs_t *a, uint32_t idx, uint32_t height, const uint8_t *auth, uint8_t *node) {
    uint8_t lr[2 * N];
    for (uint32_t j = 0; j < height; j++) {
        a->w2 = j + 1;
        a->w3 >>= 1;
        if (((idx >> j) & 1) == 0) {
            cpy(lr, node, N); cpy(lr + N, auth + j * N, N);
        } else {
            cpy(lr, auth + j * N, N); cpy(lr + N, node, N);
        }
        thash(c, a, lr, 2 * N, node);
    }
}

static const uint8_t SETS[2][4] = {
    { 9, 7, 12, 14 },      // 128s: 7 layers of 512 keys, 14 FORS trees of 4096
    { 3, 22, 6, 33 },      // 128f: 22 layers of 8 keys, 33 FORS trees of 64
};

static void set_up(slh_t *c, int set, const uint8_t *sk_seed, const uint8_t *pk_seed) {
    sha_t s;
    uint8_t z[48];
    c->hp = SETS[set][0]; c->d = SETS[set][1]; c->a = SETS[set][2]; c->k = SETS[set][3];
    cpy(c->sk_seed, sk_seed, N);
    cpy(c->pk_seed, pk_seed, N);
    for (int i = 0; i < 48; i++) {
        z[i] = 0;
    }
    sha_init(&s);
    sha_update(&s, pk_seed, N);
    sha_update(&s, z, 48);
    for (int i = 0; i < 8; i++) {
        c->seeded[i] = s.h[i];
    }
}

// The public key's root: the top tree's root.
static void slh_root(slh_t *c, int set, const uint8_t *sk_seed, const uint8_t *pk_seed, uint8_t *out) {
    adrs_t a = { 0 };
    set_up(c, set, sk_seed, pk_seed);
    a.layer = c->d - 1;
    xmss_node(c, &a, 0, c->hp, out);
}

// Start a signature of msg. Writes R (16 bytes) to out. Deterministic (no added randomness).
static void slh_begin(slh_t *c, int set, const uint8_t *sk_seed, const uint8_t *sk_prf, const uint8_t *pk_seed,
    const uint8_t *pk_root, const uint8_t *msg, size_t msglen, uint8_t *out) {
    sha_t s;
    uint8_t pad[64], inner[32], dig[64], ctr[4] = { 0, 0, 0, 0 };
    set_up(c, set, sk_seed, pk_seed);
    // R = HMAC-SHA-256(SK.prf, PK.seed || msg)[:16]
    for (int i = 0; i < 64; i++) {
        pad[i] = (i < N ? sk_prf[i] : 0) ^ 0x36;
    }
    sha_init(&s);
    sha_update(&s, pad, 64);
    sha_update(&s, pk_seed, N);
    sha_update(&s, msg, msglen);
    sha_final(&s, inner, 32);
    for (int i = 0; i < 64; i++) {
        pad[i] ^= 0x36 ^ 0x5c;
    }
    sha_init(&s);
    sha_update(&s, pad, 64);
    sha_update(&s, inner, 32);
    sha_final(&s, out, N);
    // digest = MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || msg))
    sha_init(&s);
    sha_update(&s, out, N);
    sha_update(&s, pk_seed, N);
    sha_update(&s, pk_root, N);
    sha_update(&s, msg, msglen);
    sha_final(&s, inner, 32);
    for (int b = 0; b < 2; b++) {
        ctr[3] = (uint8_t)b;
        sha_init(&s);
        sha_update(&s, out, N);
        sha_update(&s, pk_seed, N);
        sha_update(&s, inner, 32);
        sha_update(&s, ctr, 4);
        sha_final(&s, dig + 32 * b, 32);
    }
    size_t mdlen = (c->k * c->a + 7) / 8;
    size_t tbits = (size_t)c->hp * (c->d - 1), tlen = (tbits + 7) / 8, llen = (c->hp + 7) / 8;
    cpy(c->md, dig, mdlen);
    uint32_t hi = 0, lo = 0;
    for (size_t i = 0; i < tlen; i++) {
        hi = (hi << 8) | (lo >> 24);
        lo = (lo << 8) | dig[mdlen + i];
    }
    if (tbits < 64) {      // keep the low tbits bits (tbits is 54 or 63)
        hi &= (1u << (tbits - 32)) - 1;
    }
    c->tree_hi = hi; c->tree_lo = lo;
    uint32_t leaf = 0;
    for (size_t i = 0; i < llen; i++) {
        leaf = (leaf << 8) | dig[mdlen + tlen + i];
    }
    c->leaf = leaf & ((1u << c->hp) - 1);
    c->layer = 0;
}

// FORS tree i (0..k-1, in order): its secret and path, (a + 1) x 16 bytes, into out. One tree at a time
// so the caller's buffer stays small. After the last, what layer 0 signs is in c->root.
static size_t slh_fors(slh_t *c, uint32_t i, uint8_t *out) {
    adrs_t a = { 0 };
    uint8_t node[N];
    a.tree_hi = c->tree_hi; a.tree_lo = c->tree_lo;
    set_type(&a, FORS_TREE);
    a.w1 = c->leaf;
    if (i == 0) {
        adrs_t pk = a;
        set_type(&pk, FORS_ROOTS);
        pk.w1 = c->leaf;
        tl_begin(c, &pk, &c->roots);
    }
    uint32_t idx = 0;                       // bits i*a .. i*a + a - 1 of md, high bit first
    for (uint32_t b = i * c->a; b < (i + 1) * c->a; b++) {
        idx = (idx << 1) | ((c->md[b >> 3] >> (7 - (b & 7))) & 1);
    }
    fors_secret(c, &a, (i << c->a) + idx, out);
    for (uint32_t j = 0; j < c->a; j++) {
        fors_node(c, &a, (i << (c->a - j)) + ((idx >> j) ^ 1), j, out + (j + 1) * N);
    }
    a.w2 = 0; a.w3 = (i << c->a) + idx;
    thash(c, &a, out, N, node);
    climb(c, &a, idx, c->a, out + N, node);
    sha_update(&c->roots, node, N);
    if (i == (uint32_t)c->k - 1) {
        sha_final(&c->roots, c->root, N);
    }
    return (size_t)(c->a + 1) * N;
}

// One layer of the hypertree: (35 + hp) x 16 bytes into out. Returns how many layers are left.
static int slh_layer(slh_t *c, uint8_t *out) {
    adrs_t a = { 0 };
    uint8_t node[N];
    a.layer = c->layer; a.tree_hi = c->tree_hi; a.tree_lo = c->tree_lo;
    uint8_t *auth = out + WLEN * N;
    for (uint32_t j = 0; j < c->hp; j++) {
        xmss_node(c, &a, (c->leaf >> j) ^ 1, j, auth + j * N);
    }
    wots_sign(c, &a, c->leaf, c->root, out, node);
    set_type(&a, TREE);
    a.w3 = c->leaf;
    climb(c, &a, c->leaf, c->hp, auth, node);
    cpy(c->root, node, N);
    c->leaf = c->tree_lo & ((1u << c->hp) - 1);
    c->tree_lo = (c->tree_lo >> c->hp) | (c->tree_hi << (32 - c->hp));
    c->tree_hi >>= c->hp;
    c->layer++;
    return c->d - c->layer;
}

#ifdef SLH_HOST
// slh_host <set 0|1> <sk_seed> <sk_prf> <pk_seed> <msg>   (hex). Prints the root, then the signature.
#include <stdio.h>
#include <stdlib.h>
static size_t unhex(const char *h, uint8_t *out) {
    size_t n = strlen(h) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
    return n;
}
static void hex(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        printf("%02x", p[i]);
    }
}
int main(int argc, char **argv) {
    if (argc != 6) {
        return 2;
    }
    slh_t c;
    int set = atoi(argv[1]);
    uint8_t sk_seed[64], sk_prf[64], pk_seed[64], root[N], msg[4096], part[4096];
    unhex(argv[2], sk_seed); unhex(argv[3], sk_prf); unhex(argv[4], pk_seed);
    size_t msglen = unhex(argv[5], msg);
    slh_root(&c, set, sk_seed, pk_seed, root);
    hex(root, N); printf("\n");
    slh_begin(&c, set, sk_seed, sk_prf, pk_seed, root, msg, msglen, part);
    hex(part, N);
    for (uint32_t i = 0; i < c.k; i++) {
        hex(part, slh_fors(&c, i, part));
    }
    int left;
    do {
        left = slh_layer(&c, part);
        hex(part, (WLEN + c.hp) * N);
    } while (left);
    printf("\n");
    return 0;
}
#else
static void *buf(mp_obj_t o, size_t min, mp_uint_t flags) {
    mp_buffer_info_t b;
    mp_get_buffer_raise(o, &b, flags);
    if (b.len < min) {
        mp_raise_ValueError(MP_ERROR_TEXT("too short"));
    }
    return b.buf;
}
#define STATE(o) ((slh_t *)buf(o, sizeof(slh_t), MP_BUFFER_RW))

// size(): how big the state buffer must be.
static mp_obj_t py_size(void) {
    return mp_obj_new_int(sizeof(slh_t));
}
static MP_DEFINE_CONST_FUN_OBJ_0(size_obj, py_size);

// root(state, set, sk_seed, pk_seed, out16): the public key's root. set: 0 = 128s, 1 = 128f.
static mp_obj_t py_root(size_t n, const mp_obj_t *a) {
    slh_root(STATE(a[0]), mp_obj_get_int(a[1]) & 1, buf(a[2], N, MP_BUFFER_READ), buf(a[3], N, MP_BUFFER_READ),
        buf(a[4], N, MP_BUFFER_WRITE));
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(root_obj, 5, 5, py_root);

// begin(state, set, sk_seed, sk_prf, pk_seed, pk_root, msg, out16): start a signature; out gets R.
static mp_obj_t py_begin(size_t n, const mp_obj_t *a) {
    mp_buffer_info_t m;
    mp_get_buffer_raise(a[6], &m, MP_BUFFER_READ);
    slh_begin(STATE(a[0]), mp_obj_get_int(a[1]) & 1, buf(a[2], N, MP_BUFFER_READ), buf(a[3], N, MP_BUFFER_READ),
        buf(a[4], N, MP_BUFFER_READ), buf(a[5], N, MP_BUFFER_READ), m.buf, m.len, buf(a[7], N, MP_BUFFER_WRITE));
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(begin_obj, 8, 8, py_begin);

// fors(state, i, out): FORS tree i (0..k-1, in order) into out. Returns its length, (a + 1) x 16.
static mp_obj_t py_fors(mp_obj_t st, mp_obj_t i, mp_obj_t out) {
    slh_t *c = STATE(st);
    uint32_t n = mp_obj_get_int(i);
    if (n >= c->k) {
        mp_raise_ValueError(MP_ERROR_TEXT("done"));
    }
    return mp_obj_new_int(slh_fors(c, n, buf(out, (size_t)(c->a + 1) * N, MP_BUFFER_WRITE)));
}
static MP_DEFINE_CONST_FUN_OBJ_3(fors_obj, py_fors);

// layer(state, out): the next layer into out. Returns how many layers are left.
static mp_obj_t py_layer(mp_obj_t st, mp_obj_t out) {
    slh_t *c = STATE(st);
    if (c->layer >= c->d) {
        mp_raise_ValueError(MP_ERROR_TEXT("done"));
    }
    return mp_obj_new_int(slh_layer(c, buf(out, (size_t)(WLEN + c->hp) * N, MP_BUFFER_WRITE)));
}
static MP_DEFINE_CONST_FUN_OBJ_2(layer_obj, py_layer);

mp_obj_t mpy_init(mp_obj_fun_bc_t *self, size_t n_args, size_t n_kw, mp_obj_t *args) {
    MP_DYNRUNTIME_INIT_ENTRY
    mp_store_global(MP_QSTR_size, MP_OBJ_FROM_PTR(&size_obj));
    mp_store_global(MP_QSTR_root, MP_OBJ_FROM_PTR(&root_obj));
    mp_store_global(MP_QSTR_begin, MP_OBJ_FROM_PTR(&begin_obj));
    mp_store_global(MP_QSTR_fors, MP_OBJ_FROM_PTR(&fors_obj));
    mp_store_global(MP_QSTR_layer, MP_OBJ_FROM_PTR(&layer_obj));
    MP_DYNRUNTIME_INIT_EXIT
}
#endif
