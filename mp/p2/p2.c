// Poseidon2 over KoalaBear (p = 2^31 - 2^24 + 1), width 16, matching Plonky3's
// default_koalabear_poseidon2_16. A MicroPython native module for the wedgie (RP2040).
// Elements cross the boundary as little-endian uint32 in normal form; inside, Montgomery form.
#ifndef P2_HOST
#include "py/dynruntime.h"
#else
#include <stdint.h>
#endif
#include "consts.h"

#define P 0x7f000001u

static inline uint32_t add(uint32_t a, uint32_t b) {
    uint32_t s = a + b;
    return s >= P ? s - P : s;
}

static inline uint32_t sub(uint32_t a, uint32_t b) {
    return a >= b ? a - b : a + P - b;
}

static inline uint32_t mul(uint32_t a, uint32_t b) {
    uint64_t x = (uint64_t)a * b;
    uint32_t t = (uint32_t)x * P_MU_NEG;
    uint32_t r = (uint32_t)((x + (uint64_t)t * P) >> 32);
    return r >= P ? r - P : r;
}

static inline uint32_t cube(uint32_t x) {
    return mul(mul(x, x), x);
}

// The external layer: M4 on each group of four, then add the sum of each column across groups.
static void external(uint32_t *s) {
    for (int i = 0; i < 16; i += 4) {
        uint32_t x0 = s[i], x1 = s[i + 1], x2 = s[i + 2], x3 = s[i + 3];
        uint32_t t01 = add(x0, x1), t23 = add(x2, x3), t0123 = add(t01, t23);
        uint32_t t01123 = add(t0123, x1), t01233 = add(t0123, x3);
        s[i + 3] = add(t01233, add(x0, x0));
        s[i + 1] = add(t01123, add(x2, x2));
        s[i] = add(t01123, t01);
        s[i + 2] = add(t01233, t23);
    }
    for (int k = 0; k < 4; k++) {
        uint32_t c = add(add(s[k], s[k + 4]), add(s[k + 8], s[k + 12]));
        s[k] = add(s[k], c);
        s[k + 4] = add(s[k + 4], c);
        s[k + 8] = add(s[k + 8], c);
        s[k + 12] = add(s[k + 12], c);
    }
}

static void full_round(uint32_t *s, const uint32_t *rc) {
    for (int i = 0; i < 16; i++) {
        s[i] = cube(add(s[i], rc[i]));
    }
    external(s);
}

static void permute(uint32_t *s) {
    for (int i = 0; i < 16; i++) {
        s[i] = mul(s[i], P_R2);
    }
    external(s);
    for (int r = 0; r < 4; r++) {
        full_round(s, RC_INIT + 16 * r);
    }
    for (int r = 0; r < 20; r++) {
        s[0] = cube(add(s[0], RC_INT[r]));
        uint32_t sum = 0;
        for (int i = 0; i < 16; i++) {
            sum = add(sum, s[i]);
        }
        for (int i = 0; i < 16; i++) {
            s[i] = add(mul(s[i], DIAG[i]), sum);
        }
    }
    for (int r = 0; r < 4; r++) {
        full_round(s, RC_FINAL + 16 * r);
    }
    for (int i = 0; i < 16; i++) {
        s[i] = mul(s[i], 1);
    }
}

#ifndef P2_HOST
static uint32_t *words(mp_obj_t o, size_t n) {
    mp_buffer_info_t b;
    mp_get_buffer_raise(o, &b, MP_BUFFER_RW);
    if (b.len != n * 4) {
        mp_raise_ValueError(MP_ERROR_TEXT("wrong length"));
    }
    return (uint32_t *)b.buf;
}

// permute(buf): buf is 64 bytes (16 elements), changed in place.
static mp_obj_t py_permute(mp_obj_t buf) {
    permute(words(buf, 16));
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_1(permute_obj, py_permute);

// hash(x, a, b, c, d): x is 32 bytes (8 elements). x = permute(x || a b c d 0 0 0 0)[:8].
static mp_obj_t py_hash(size_t n_args, const mp_obj_t *args) {
    uint32_t *x = words(args[0], 8);
    uint32_t s[16] = {0};
    for (int i = 0; i < 8; i++) {
        s[i] = x[i];
    }
    for (size_t i = 1; i < n_args; i++) {
        s[7 + i] = mp_obj_get_int(args[i]);
    }
    permute(s);
    for (int i = 0; i < 8; i++) {
        x[i] = s[i];
    }
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(hash_obj, 1, 5, py_hash);

// chain(x, domain, n, i, start, steps): `steps` hashes of x, step j tweaked (domain, n, i, j).
static mp_obj_t py_chain(size_t n_args, const mp_obj_t *args) {
    uint32_t *x = words(args[0], 8);
    uint32_t dom = mp_obj_get_int(args[1]), n = mp_obj_get_int(args[2]), ci = mp_obj_get_int(args[3]);
    int start = mp_obj_get_int(args[4]), steps = mp_obj_get_int(args[5]);
    uint32_t s[16];
    for (int j = start; j < start + steps; j++) {
        for (int i = 0; i < 8; i++) {
            s[i] = x[i];
        }
        s[8] = dom; s[9] = n; s[10] = ci; s[11] = j;
        s[12] = s[13] = s[14] = s[15] = 0;
        permute(s);
        for (int i = 0; i < 8; i++) {
            x[i] = s[i];
        }
    }
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(chain_obj, 6, 6, py_chain);

mp_obj_t mpy_init(mp_obj_fun_bc_t *self, size_t n_args, size_t n_kw, mp_obj_t *args) {
    MP_DYNRUNTIME_INIT_ENTRY
    mp_store_global(MP_QSTR_permute, MP_OBJ_FROM_PTR(&permute_obj));
    mp_store_global(MP_QSTR_hash, MP_OBJ_FROM_PTR(&hash_obj));
    mp_store_global(MP_QSTR_chain, MP_OBJ_FROM_PTR(&chain_obj));
    MP_DYNRUNTIME_INIT_EXIT
}
#endif
