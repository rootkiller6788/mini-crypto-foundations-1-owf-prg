/*
 * blum_micali.h -- Blum-Micali Pseudorandom Generator
 *
 * L4 Fundamental Theorem:
 *   Blum-Micali (1984): If the Discrete Logarithm Problem (DLP)
 *   is hard in Z_p^*, then the Blum-Micali generator is a secure PRG.
 *
 *   Construction:
 *     - Let p be a large prime, g a generator of Z_p^*
 *     - Seed: random x_0 ? Z_p^*
 *     - Iterate: x_{i+1} = g^{x_i} mod p
 *     - Output: MSB(x_i) ? the most significant hardcore bit
 *
 *   The most significant bit (MSB) of g^x mod p is a hardcore predicate
 *   for the modular exponentiation function f(x) = g^x mod p.
 *   Predicting MSB(g^x mod p) given g^x mod p is as hard as computing
 *   discrete logarithms.
 *
 * L5 Algorithm:
 *   Safe prime generation
 *   Generator finding
 *   BM state initialization
 *   BM bit generation (iterated exponentiation + MSB extraction)
 *
 * Reference: Blum & Micali (1984) "How to Generate Cryptographically
 *            Strong Sequences of Pseudo-Random Bits", SIAM J. Comp.
 *            Long & Wigderson (1988) ? MSB hardcore for discrete log
 *
 * Courses: MIT 6.875, Stanford CS255, Princeton COS 551
 */

#ifndef BLUM_MICALI_H
#define BLUM_MICALI_H

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include "prg_number_theory.h"
#include "prg_crypto.h"

/* ================================================================
 * BM Configuration
 * ================================================================ */

#define BM_MIN_PRIME_BITS    16     /* minimum prime bits for demo */
#define BM_MAX_PRIME_BITS    32     /* maximum for 32-bit demo */
#define BM_MAX_OUTPUT_BYTES  1024

/*
 * Blum-Micali PRG State:
 *   p     = large prime (public)
 *   g     = generator of Z_p^* (public)
 *   x     = current state (secret)
 *   seed  = original seed x_0
 */
typedef struct {
    uint64_t p;              /* prime modulus */
    uint64_t g;              /* generator */
    uint64_t state;          /* x_i: current element */
    uint64_t seed;           /* x_0: original seed */
    size_t p_bits;           /* size of p in bits */
    size_t iterations;       /* bits produced so far */
} BMState;

/* ================================================================
 * BM Key Generation
 * ================================================================ */

/*
 * Generate BM parameters:
 *   1. Find a safe prime p = 2q + 1 (for simplicity, small for demo)
 *   2. Find a generator g of Z_p^*
 *   3. Pick random seed x_0 ? {1, ..., p-1}
 *
 * In practice, p should be 2048+ bits. Demo uses 16-32 bits.
 */
BMState* bm_keygen(size_t p_bits);

/*
 * Initialize BM state with given prime, generator, and seed.
 * Validates that g generates Z_p^*.
 */
int bm_init(BMState* bm, uint64_t p, uint64_t g, uint64_t seed);

/* Clone BM state */
BMState* bm_clone(const BMState* src);

/* Free BM state */
void bm_free(BMState* bm);

/* ================================================================
 * BM Bit Generation
 * ================================================================ */

/*
 * Generate the next pseudorandom bit:
 *   x_{i+1} = g^{x_i} mod p
 *   output bit = MSB(x_{i+1})
 *
 * The MSB is the most significant bit of x_{i+1}
 * (bit at position floor(log2(p)) or bit (p_bits - 1)).
 *
 * Returns 0 or 1, or -1 on error.
 */
int bm_next_bit(BMState* bm);

/*
 * Generate multiple bits into a byte buffer.
 * Returns number of bytes generated.
 */
size_t bm_generate_bytes(BMState* bm, uint8_t* buffer, size_t n_bytes);

/*
 * Generate n_bits of output, packed into byte array.
 */
size_t bm_generate_bits(BMState* bm, uint8_t* buffer, size_t n_bits);

/* ================================================================
 * BM Hardcore Bit Variants
 * ================================================================ */

/*
 * Beyond the MSB: other hardcore bits for discrete log.
 *
 * Long & Wigderson (1988) showed that O(log |p|) bits of g^x mod p
 * are simultaneously hardcore. We implement the MSB and a few alternatives.
 */

/* Extract the k-th most significant bit of x (0 = MSB) */
int bm_extract_bit(uint64_t x, size_t p_bits, size_t k);

/* Generate next bit using bit position k as hardcore */
int bm_next_bit_position(BMState* bm, size_t k);

/*
 * Simultaneous hardcore: generate b bits per iteration
 * (using O(log p) hardcore bits).
 * Returns number of bits generated (? b).
 */
size_t bm_next_bits_simultaneous(BMState* bm, uint8_t* buffer, size_t n_bits);

/* ================================================================
 * BM as PRG Interface
 * ================================================================ */

/* Wrap BM as generic PRG */
PRG* bm_to_prg(BMState* bm);

/* ================================================================
 * BM Security Analysis
 * ================================================================ */

/*
 * Discrete Logarithm Assumption (DLA):
 *   Given prime p, generator g, and y = g^x mod p,
 *   it is computationally hard to recover x.
 *
 * BM security theorem:
 *   If the DLA holds for the family of primes used, then the
 *   BM generator is a secure PRG. Distinguishing BM output from
 *   random implies solving the discrete log problem.
 *
 * The proof uses:
 *   1. H?stad et al. (1999): MSB is hardcore for discrete log
 *   2. Yao's theorem: next-bit unpredictable ? secure PRG
 */

/* Verify that g is a valid generator for prime p */
int bm_verify_generator(uint64_t p, uint64_t g);

/* Check if state transition is valid (within group) */
int bm_validate_state(const BMState* bm);

#endif /* BLUM_MICALI_H */
