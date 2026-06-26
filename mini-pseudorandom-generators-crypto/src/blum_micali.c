/*
 * blum_micali.c -- Blum-Micali Pseudorandom Generator Implementation
 *
 * L4 Fundamental Theorem: If the Discrete Logarithm Problem (DLP)
 * is hard in Z_p^*, then the Blum-Micali generator is a secure PRG.
 * (Blum & Micali, 1984)
 *
 * L5 Algorithm: Safe prime generation, generator finding, state
 * initialization, iterated exponentiation + MSB extraction.
 *
 * Construction: x_{i+1} = g^{x_i} mod p, output = MSB(x_{i+1}).
 * The MSB of g^x mod p is a hardcore predicate for modular exponentiation.
 *
 * Reference: Blum & Micali (1984), SIAM J. Computing.
 *            Long & Wigderson (1988) -- MSB hardcore for discrete log
 * Courses: MIT 6.875, Stanford CS255, Princeton COS 551
 */
#include "blum_micali.h"
#include "prg_crypto.h"
#include <string.h>
#include <stdlib.h>

/* ================================================================
 * BM Key Generation (L5)
 * ================================================================ */

/* L5: Generate BM parameters: find safe prime p, generator g, random seed.
 * For demo: uses small safe primes (16-32 bits).
 * In practice, p >= 2048 bits is standard for cryptographic security. */
BMState* bm_keygen(size_t p_bits) {
    if (p_bits < BM_MIN_PRIME_BITS || p_bits > BM_MAX_PRIME_BITS) return NULL;

    uint64_t max_p = (1ULL << p_bits) - 1;
    uint64_t min_p = 1ULL << (p_bits - 1);

    uint64_t p = safe_prime_generate(min_p, max_p);
    if (p == 0) return NULL;

    uint64_t g = find_generator_mod_p(p);
    if (g == 0) return NULL;

    BMState* bm = (BMState*)calloc(1, sizeof(BMState));
    if (!bm) return NULL;

    bm->p = p;
    bm->g = g;
    bm->p_bits = p_bits;

    /* Random seed x0 in {1, ..., p-1} */
    bm->seed = 1 + (prg_test_rand() % (p - 1));
    bm->state = bm->seed;
    bm->iterations = 0;

    return bm;
}

/* L5: Initialize BM with explicit prime, generator, and seed.
 * Validates that g generates Z_p^* and seed is in valid range. */
int bm_init(BMState* bm, uint64_t p, uint64_t g, uint64_t seed) {
    if (!bm) return -1;
    if (p <= 1) return -1;
    if (!is_generator_mod_p(g, p)) return -1;
    if (seed == 0 || seed >= p) return -1;

    bm->p = p;
    bm->g = g;
    bm->seed = seed;
    bm->state = seed;
    bm->iterations = 0;

    bm->p_bits = 0;
    uint64_t tmp = p;
    while (tmp > 0) { bm->p_bits++; tmp >>= 1; }

    return 0;
}

BMState* bm_clone(const BMState* src) {
    if (!src) return NULL;
    BMState* dst = (BMState*)malloc(sizeof(BMState));
    if (dst) memcpy(dst, src, sizeof(BMState));
    return dst;
}

void bm_free(BMState* bm) {
    if (!bm) return;
    memset(bm, 0, sizeof(BMState));
    free(bm);
}

/* ================================================================
 * BM Bit Generation -- MSB Extraction (L5)
 * ================================================================ */

/* L5: Generate next pseudorandom bit via x_{i+1} = g^{x_i} mod p.
 * Output the MSB of x_{i+1}.
 *
 * The MSB at position p_bits-1 is the most unpredictable bit
 * because the modular exponentiation f(x)=g^x mod p distributes
 * input bits across the entire output range.
 *
 * Returns 0 or 1 (MSB), or -1 on error. */
int bm_next_bit(BMState* bm) {
    if (!bm || bm->p == 0) return -1;

    /* x_{i+1} = g^{x_i} mod p */
    bm->state = mod_pow(bm->g, bm->state, bm->p);
    bm->iterations++;

    /* MSB: most significant bit of current state */
    uint64_t msb_mask = 1ULL << (bm->p_bits - 1);
    return (bm->state & msb_mask) ? 1 : 0;
}

/* L5: Generate bytes via iterated exponentiation. */
size_t bm_generate_bytes(BMState* bm, uint8_t* buffer, size_t n_bytes) {
    if (!bm || !buffer) return 0;

    size_t generated = 0;
    for (size_t i = 0; i < n_bytes; i++) {
        uint8_t byte_val = 0;
        for (int bit = 7; bit >= 0; bit--) {
            int b = bm_next_bit(bm);
            if (b < 0) return generated;
            if (b) byte_val |= (uint8_t)(1U << bit);
        }
        buffer[i] = byte_val;
        generated++;
    }
    return generated;
}

/* L5: Generate n_bits, packed into byte array (zero-padded final byte). */
size_t bm_generate_bits(BMState* bm, uint8_t* buffer, size_t n_bits) {
    if (!bm || !buffer) return 0;

    size_t n_bytes = (n_bits + 7) / 8;
    memset(buffer, 0, n_bytes);

    size_t bit_count = 0;
    for (size_t i = 0; i < n_bytes && bit_count < n_bits; i++) {
        uint8_t byte_val = 0;
        for (int bit = 7; bit >= 0 && bit_count < n_bits; bit--) {
            int b = bm_next_bit(bm);
            if (b < 0) return (bit_count + 7) / 8;
            if (b) byte_val |= (uint8_t)(1U << bit);
            bit_count++;
        }
        buffer[i] = byte_val;
    }
    return n_bytes;
}

/* ================================================================
 * BM Hardcore Bit Variants (L4, L5)
 * ================================================================ */

/* L4: Extract the k-th most significant bit of x.
 * Long & Wigderson (1988): O(log |p|) MSBs are simultaneously hardcore.
 * This means we can extract more than 1 bit per iteration. */
int bm_extract_bit(uint64_t x, size_t p_bits, size_t k) {
    if (k >= p_bits) return 0;
    return (x >> (p_bits - 1 - k)) & 1;
}

/* L5: Generate next bit using bit position k as hardcore.
 * Different bit positions provide different trade-offs:
 * k=0 (MSB): most studied, strongest security guarantee
 * k>0: allows more bits per iteration; O(log p_bits) are provably secure */
int bm_next_bit_position(BMState* bm, size_t k) {
    if (!bm || bm->p == 0) return -1;

    bm->state = mod_pow(bm->g, bm->state, bm->p);
    bm->iterations++;

    return bm_extract_bit(bm->state, bm->p_bits, k);
}

/* L5: Simultaneous hardcore: extract up to b bits per iteration.
 * Using O(log p) simultaneous hardcore bits increases throughput
 * from 1 bit/exp to ~log(log p) bits/exp.
 *
 * Returns number of bits generated. */
size_t bm_next_bits_simultaneous(BMState* bm, uint8_t* buffer, size_t n_bits) {
    if (!bm || !buffer) return 0;

    /* Number of safe simultaneous hardcore bits: floor(log2(p_bits)) */
    size_t safe_bits = 0;
    size_t tmp = bm->p_bits;
    while (tmp > 1) { safe_bits++; tmp >>= 1; }
    if (safe_bits == 0) safe_bits = 1;

    size_t generated = 0;
    while (generated < n_bits) {
        /* Advance state */
        bm->state = mod_pow(bm->g, bm->state, bm->p);
        bm->iterations++;

        /* Extract safe_bits MSBs */
        for (size_t k = 0; k < safe_bits && generated < n_bits; k++) {
            int bit = bm_extract_bit(bm->state, bm->p_bits, k);
            size_t byte_idx = generated / 8;
            size_t bit_idx = generated % 8;
            if (bit) buffer[byte_idx] |= (uint8_t)(1U << (7 - bit_idx));
            generated++;
        }
    }
    return generated;
}

/* ================================================================
 * BM as Generic PRG Interface (L5)
 * ================================================================ */

static int bm_prg_init(PRG* prg, const uint8_t* seed, size_t seed_bytes) {
    BMState* bm = (BMState*)prg->priv;
    if (!bm) return -1;

    uint64_t seed_val = 0;
    for (size_t i = 0; i < seed_bytes && i < 8; i++) {
        seed_val |= ((uint64_t)seed[i]) << (i * 8);
    }
    seed_val = 1 + (seed_val % (bm->p - 1));

    bm->seed = seed_val;
    bm->state = seed_val;
    bm->iterations = 0;
    return 0;
}

static int bm_prg_next(PRG* prg, uint8_t* output, size_t output_bytes) {
    BMState* bm = (BMState*)prg->priv;
    if (!bm) return -1;
    return (int)bm_generate_bytes(bm, output, output_bytes);
}

static void bm_prg_free(PRG* prg) {
    BMState* bm = (BMState*)prg->priv;
    if (bm) bm_free(bm);
    prg->priv = NULL;
}

/* L5: Wrap BMState as generic PRG. */
PRG* bm_to_prg(BMState* bm) {
    if (!bm) return NULL;
    PRG* prg = prg_create(bm->p_bits, bm->p_bits * 2);
    if (!prg) return NULL;
    prg->priv = bm;
    prg->init = bm_prg_init;
    prg->next = bm_prg_next;
    prg->free_ctx = bm_prg_free;
    return prg;
}

/* ================================================================
 * BM Security Analysis (L4)
 * ================================================================ */

/* L4: Verify that g is a valid generator of Z_p^*.
 * The security of BM relies on the DLP being hard in the group
 * generated by g. Using a full generator ensures maximal group order. */
int bm_verify_generator(uint64_t p, uint64_t g) {
    return is_generator_mod_p(g, p);
}

/* L4: Validate that current state is within Z_p^*.
 * All x_i should be in {1, ..., p-1}. State=0 would break iteration. */
int bm_validate_state(const BMState* bm) {
    if (!bm) return 0;
    return (bm->state > 0 && bm->state < bm->p);
}
