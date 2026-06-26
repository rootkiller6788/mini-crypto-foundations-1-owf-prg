/*
 * blum_blum_shub.c -- Blum-Blum-Shub (BBS) Pseudorandom Generator Implementation
 *
 * L4 Fundamental Theorem: If QRP is hard for Blum integers,
 * then BBS is a secure PRG. (Blum-Blum-Shub, 1986)
 *
 * L5 Algorithm: Key generation, state initialization, LSB extraction,
 * CRT-accelerated generation, and PRG interface wrapping.
 *
 * Construction: x_{i+1} = x_i^2 mod N, output = LSB(x_{i+1}).
 * The LSB is a hardcore predicate for squaring mod Blum integer N.
 *
 * Reference: Blum, Blum, Shub (1986), SIAM J. Computing.
 *            Alexi, Chor, Goldreich, Schnorr (1988) -- LSB hardcore for RSA
 * Courses: MIT 6.875, Stanford CS255, Princeton COS 551
 */
#include "blum_blum_shub.h"
#include "prg_crypto.h"
#include <string.h>
#include <stdlib.h>

/* ================================================================
 * BBS Key Generation (L5)
 * ================================================================ */

/* L5: Generate BBS parameters: find Blum integer N=p*q, pick seed x0 in Z_N^*.
 * The security of BBS rests on the hardness of factoring N.
 * For demo: n_bits selects target Blum integer size (small: 8-32 bits). */
BBSState* bbs_keygen(size_t n_bits) {
    if (n_bits < BBS_MIN_BLUM_BITS || n_bits > BBS_MAX_BLUM_BITS) return NULL;

    /* Find prime range for factors: each factor ~ n_bits/2 bits */
    uint64_t max_factor = (1ULL << (n_bits / 2)) - 1;
    uint64_t min_factor = 1ULL << ((n_bits / 2) - 1);

    BlumInteger bi = blum_integer_generate(min_factor, max_factor);
    if (bi.n == 0) return NULL;

    BBSState* bbs = (BBSState*)calloc(1, sizeof(BBSState));
    if (!bbs) return NULL;

    bbs->blum = bi;
    bbs->n_bits = n_bits;

    /* Pick random seed x0 in [2, N-1] with gcd(x0, N) = 1 */
    bbs->seed = 2 + (prg_test_rand() % (bi.n - 2));
    while (gcd(bbs->seed, bi.n) != 1) {
        bbs->seed = 2 + (prg_test_rand() % (bi.n - 2));
    }
    bbs->state = bbs->seed;
    bbs->iterations = 0;
    bbs->use_crt = 0;

    return bbs;
}

/* L5: Initialize BBS with explicit factors p,q and seed.
 * Validates: p,q are prime and = 3 mod 4; seed is coprime to N. */
int bbs_init(BBSState* bbs, uint64_t p, uint64_t q, uint64_t seed) {
    if (!bbs) return -1;
    if (!is_prime_bruteforce(p) || !is_prime_bruteforce(q)) return -1;
    if (p % 4 != 3 || q % 4 != 3) return -1;
    if (p == q) return -1;

    bbs->blum.p = p;
    bbs->blum.q = q;
    bbs->blum.n = p * q;
    bbs->n_bits = 0;
    uint64_t tmp = bbs->blum.n;
    while (tmp > 0) { bbs->n_bits++; tmp >>= 1; }

    if (seed == 0 || seed >= bbs->blum.n) return -1;
    if (gcd(seed, bbs->blum.n) != 1) return -1;

    bbs->seed = seed;
    bbs->state = seed;
    bbs->iterations = 0;
    bbs->use_crt = 0;
    return 0;
}

BBSState* bbs_clone(const BBSState* src) {
    if (!src) return NULL;
    BBSState* dst = (BBSState*)malloc(sizeof(BBSState));
    if (!dst) return NULL;
    memcpy(dst, src, sizeof(BBSState));
    return dst;
}

void bbs_free(BBSState* bbs) {
    if (!bbs) return;
    memset(bbs, 0, sizeof(BBSState));
    free(bbs);
}

/* ================================================================
 * BBS Bit Generation -- LSB Extraction (L5)
 * ================================================================ */

/* L5: Generate next pseudorandom bit via x_{i+1} = x_i^2 mod N, output LSB.
 * The LSB extraction rate is 1 bit per squaring. For higher throughput,
 * one can extract O(log log N) bits per iteration, but security bounds
 * become more subtle (Alexi et al., 1988).
 *
 * Returns 0 or 1 (the LSB of x_{i+1}), or -1 on error. */
int bbs_next_bit(BBSState* bbs) {
    if (!bbs || bbs->blum.n == 0) return -1;
    if (bbs->state == 0) return -1;

    /* x_{i+1} = x_i^2 mod N */
    bbs->state = mod_mul(bbs->state, bbs->state, bbs->blum.n);
    bbs->iterations++;

    /* LSB: least significant bit */
    return (int)(bbs->state & 1);
}

/* L5: Generate bytes from BBS by iterating bit generation.
 * Each byte requires 8 squarings. */
size_t bbs_generate_bytes(BBSState* bbs, uint8_t* buffer, size_t n_bytes) {
    if (!bbs || !buffer) return 0;

    size_t generated = 0;
    for (size_t i = 0; i < n_bytes; i++) {
        uint8_t byte_val = 0;
        for (int bit = 7; bit >= 0; bit--) {
            int b = bbs_next_bit(bbs);
            if (b < 0) return generated;
            if (b) byte_val |= (uint8_t)(1U << bit);
        }
        buffer[i] = byte_val;
        generated++;
    }
    return generated;
}

/* L5: Generate exactly n_bits, packed into bytes.
 * Final byte is zero-padded if n_bits is not a multiple of 8. */
size_t bbs_generate_bits(BBSState* bbs, uint8_t* buffer, size_t n_bits) {
    if (!bbs || !buffer) return 0;

    size_t n_bytes = (n_bits + 7) / 8;
    memset(buffer, 0, n_bytes);

    size_t bit_count = 0;
    for (size_t byte_idx = 0; byte_idx < n_bytes && bit_count < n_bits; byte_idx++) {
        uint8_t byte_val = 0;
        for (int bit = 7; bit >= 0 && bit_count < n_bits; bit--) {
            int b = bbs_next_bit(bbs);
            if (b < 0) return (bit_count + 7) / 8;
            if (b) byte_val |= (uint8_t)(1U << bit);
            bit_count++;
        }
        buffer[byte_idx] = byte_val;
    }
    return n_bytes;
}

/* ================================================================
 * BBS CRT-Accelerated Generation (L5)
 * ================================================================ */

/* L5: Initialize CRT state for accelerated BBS.
 * CRT splits computation: compute x^2 mod p and x^2 mod q separately,
 * then combine via CRT. This is ~4x faster.
 *
 * Precomputes: x_p = x mod p, x_q = x mod q */
int bbs_crt_init(BBSState* bbs) {
    if (!bbs || bbs->blum.p == 0 || bbs->blum.q == 0) return -1;
    bbs->x_p = bbs->state % bbs->blum.p;
    bbs->x_q = bbs->state % bbs->blum.q;
    bbs->use_crt = 1;
    return 0;
}

/* L5: Generate next bit using CRT acceleration.
 * x_p' = x_p^2 mod p; x_q' = x_q^2 mod q; state = CRT(x_p', x_q') */
int bbs_crt_next_bit(BBSState* bbs) {
    if (!bbs || !bbs->use_crt) return bbs_next_bit(bbs);

    bbs->x_p = mod_mul(bbs->x_p, bbs->x_p, bbs->blum.p);
    bbs->x_q = mod_mul(bbs->x_q, bbs->x_q, bbs->blum.q);

    CRTResult crt = crt_solve(bbs->x_p, bbs->blum.p,
                               bbs->x_q, bbs->blum.q);
    bbs->state = crt.solution;
    bbs->iterations++;

    return (int)(bbs->state & 1);
}

/* L5: Generate bytes with CRT acceleration. */
size_t bbs_crt_generate_bytes(BBSState* bbs, uint8_t* buffer, size_t n_bytes) {
    if (!bbs || !buffer) return 0;
    if (!bbs->use_crt) bbs_crt_init(bbs);

    size_t generated = 0;
    for (size_t i = 0; i < n_bytes; i++) {
        uint8_t byte_val = 0;
        for (int bit = 7; bit >= 0; bit--) {
            int b = bbs_crt_next_bit(bbs);
            if (b < 0) return generated;
            if (b) byte_val |= (uint8_t)(1U << bit);
        }
        buffer[i] = byte_val;
        generated++;
    }
    return generated;
}

/* ================================================================
 * BBS as Generic PRG Interface (L5)
 * ================================================================ */

/* L5: BBS init callback for PRG interface.
 * Validates that seed is coprime to N for security. */
static int bbs_prg_init(PRG* prg, const uint8_t* seed, size_t seed_bytes) {
    BBSState* bbs = (BBSState*)prg->priv;
    if (!bbs) return -1;

    /* Extract 64-bit seed value from bytes (little-endian for simplicity) */
    uint64_t seed_val = 0;
    for (size_t i = 0; i < seed_bytes && i < 8; i++) {
        seed_val |= ((uint64_t)seed[i]) << (i * 8);
    }
    seed_val %= bbs->blum.n;
    if (seed_val == 0) seed_val = 1;
    if (gcd(seed_val, bbs->blum.n) != 1) seed_val = 3;

    bbs->seed = seed_val;
    bbs->state = seed_val;
    bbs->iterations = 0;
    return 0;
}

/* L5: BBS next callback: generate output bytes. */
static int bbs_prg_next(PRG* prg, uint8_t* output, size_t output_bytes) {
    BBSState* bbs = (BBSState*)prg->priv;
    if (!bbs) return -1;
    return (int)bbs_generate_bytes(bbs, output, output_bytes);
}

/* L5: BBS free callback: clean up BBS state. */
static void bbs_prg_free(PRG* prg) {
    BBSState* bbs = (BBSState*)prg->priv;
    if (bbs) bbs_free(bbs);
    prg->priv = NULL;
}

/* L5: Wrap a BBSState as a generic PRG.
 * This demonstrates the abstraction: any PRG can be plugged into
 * the generic PRG framework defined in prg_crypto.h. */
PRG* bbs_to_prg(BBSState* bbs) {
    if (!bbs) return NULL;

    PRG* prg = prg_create(bbs->n_bits, bbs->n_bits * 2); /* stretch factor 2 */
    if (!prg) return NULL;

    prg->priv = bbs;
    prg->init = bbs_prg_init;
    prg->next = bbs_prg_next;
    prg->free_ctx = bbs_prg_free;
    return prg;
}

/* ================================================================
 * BBS Security Analysis (L4)
 * ================================================================ */

/* L4: Verify that Jacobi symbol (a/N) = +1.
 * For a Blum integer N, this means a is either a QR or a pseudo-square.
 * The Quadratic Residuosity Problem (QRP) is exactly the problem of
 * distinguishing QRs from pseudo-squares given only N. */
int jacobi_is_plus_one(uint64_t a, uint64_t n) {
    return (jacobi_symbol(a, n) == 1);
}

/* L4: Check if a is a quadratic residue mod N = p*q (requires factorization).
 * With the factorization, we can test: a is QR mod N iff a is QR mod p AND mod q.
 * This is easy with p,q known, but believed hard without them. */
int is_quadratic_residue(uint64_t a, uint64_t p, uint64_t q) {
    if (p == 0 || q == 0) return 0;
    return qr_test_prime(a, p) && qr_test_prime(a, q);
}

/* L4: Verify BBS state is a quadratic residue.
 * After the first iteration, each x_i is a QR by construction:
 * x_i = (x_{i-1})^2 mod N. So x_i is trivially a QR.
 * But for x_0 (the seed), it may be a QR or pseudo-square.
 * The BBS security proof requires x_0 to be a random QR. */
int bbs_state_is_qr(const BBSState* bbs) {
    if (!bbs || bbs->blum.p == 0) return 0;
    return is_quadratic_residue(bbs->state, bbs->blum.p, bbs->blum.q);
}
