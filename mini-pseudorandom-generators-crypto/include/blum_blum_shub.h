/*
 * blum_blum_shub.h -- Blum-Blum-Shub (BBS) Pseudorandom Generator
 *
 * L4 Fundamental Theorem:
 *   Blum-Blum-Shub (1986): If the Quadratic Residuosity Problem (QRP)
 *   is hard for Blum integers, then the BBS generator is a secure PRG.
 *
 *   Construction:
 *     - Let N = p*q be a Blum integer (p,q primes, p?q?3 mod 4)
 *     - Seed: random x_0 ? Z_N^*
 *     - Iterate: x_{i+1} = x_i^2 mod N
 *     - Output: LSB(x_i) at each step (least significant bit)
 *
 *   The LSB is a hardcore predicate for the squaring function modulo
 *   a Blum integer. This means predicting LSB(x) given x^2 mod N
 *   is as hard as factoring N.
 *
 * L5 Algorithm:
 *   BBS key generation (Blum integer selection)
 *   BBS state initialization
 *   BBS bit generation (iterated squaring + LSB extraction)
 *   CRT-accelerated BBS (using Chinese Remainder Theorem)
 *
 * Reference: Blum, Blum, Shub (1986) "A Simple Unpredictable Pseudo-Random
 *            Number Generator", SIAM Journal on Computing.
 *            Alexi, Chor, Goldreich, Schnorr (1988) ? LSB hardcore for RSA
 *            Vazirani & Vazirani (1984) ? BBS security proof
 *
 * Courses: MIT 6.875, Stanford CS255, Princeton COS 551
 */

#ifndef BLUM_BLUM_SHUB_H
#define BLUM_BLUM_SHUB_H

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include "prg_number_theory.h"
#include "prg_crypto.h"

/* ================================================================
 * BBS Configuration
 * ================================================================ */

#define BBS_MIN_BLUM_BITS    32     /* minimum Blum integer bits for demo */
#define BBS_MAX_BLUM_BITS    64     /* maximum (for 64-bit demo) */
#define BBS_MAX_OUTPUT_BYTES 1024   /* maximum output to generate */

/*
 * BBS PRG State:
 *   N = p*q (Blum integer, secret)
 *   x  = current state (quadratic residue chain)
 *   iteration count
 */
typedef struct {
    BlumInteger blum;         /* N = p*q, p, q (secret) */
    uint64_t state;           /* x_i: current quadratic residue */
    uint64_t seed;            /* x_0: original seed */
    size_t n_bits;            /* size of N in bits */
    size_t iterations;        /* how many bits produced so far */
    int use_crt;              /* whether to use CRT optimization */
    uint64_t x_p;             /* state mod p (for CRT) */
    uint64_t x_q;             /* state mod q (for CRT) */
} BBSState;

/* ================================================================
 * BBS Key Generation
 * ================================================================ */

/*
 * Generate BBS parameters:
 *   1. Find two primes p, q with p?q?3 mod 4
 *   2. Set N = p*q (Blum integer)
 *   3. Pick random seed x_0 ? Z_N^* with gcd(x_0, N)=1
 *
 * For production, N should be 1024+ bits. This demo uses 32-64.
 */
BBSState* bbs_keygen(size_t n_bits);

/*
 * Initialize an existing BBS state with given Blum integer and seed.
 * Validates that seed is in Z_N^*.
 */
int bbs_init(BBSState* bbs, uint64_t p, uint64_t q, uint64_t seed);

/*
 * Clone a BBS state (for testing/comparison).
 */
BBSState* bbs_clone(const BBSState* src);

/* Free BBS state */
void bbs_free(BBSState* bbs);

/* ================================================================
 * BBS Bit Generation
 * ================================================================ */

/*
 * Generate the next pseudorandom bit from BBS:
 *   x_{i+1} = x_i^2 mod N
 *   output bit = LSB(x_{i+1})
 *
 * Returns 0 or 1, or -1 on error.
 */
int bbs_next_bit(BBSState* bbs);

/*
 * Generate multiple bits into a byte buffer.
 * Uses iterated squaring. Returns number of bytes generated.
 */
size_t bbs_generate_bytes(BBSState* bbs, uint8_t* buffer, size_t n_bytes);

/*
 * Generate n_bits of output, packed into a byte array.
 * Returns number of bytes written (ceil(n_bits/8)).
 */
size_t bbs_generate_bits(BBSState* bbs, uint8_t* buffer, size_t n_bits);

/* ================================================================
 * BBS CRT-Accelerated Generation
 * ================================================================ */

/*
 * Using CRT, compute x^2 mod N as:
 *   x_p = x mod p,  x_p2 = x_p^2 mod p
 *   x_q = x mod q,  x_q2 = x_q^2 mod q
 *   x^2 mod N = CRT(x_p2, x_q2)
 *
 * This is approximately 4x faster than direct computation.
 */

/* Initialize CRT state from seed */
int bbs_crt_init(BBSState* bbs);

/* Generate next bit using CRT acceleration */
int bbs_crt_next_bit(BBSState* bbs);

/* Generate bytes using CRT acceleration */
size_t bbs_crt_generate_bytes(BBSState* bbs, uint8_t* buffer, size_t n_bytes);

/* ================================================================
 * BBS as PRG Interface
 * ================================================================ */

/*
 * Wrap BBS as a generic PRG (compatible with prg_crypto.h).
 */
PRG* bbs_to_prg(BBSState* bbs);

/* ================================================================
 * BBS Security Analysis
 * ================================================================ */

/*
 * Quadratic Residuosity Assumption (QRA):
 *   Given N = p*q (Blum integer) and a ? Z_N^* with Jacobi symbol (a/N)=1,
 *   it is computationally hard to decide if a is a quadratic residue
 *   modulo N without knowing the factorization.
 *
 * BBS security theorem (informal):
 *   If QRA holds for Blum integers, then the BBS generator is a
 *   secure PRG. Specifically, distinguishing BBS output from random
 *   implies deciding quadratic residuosity.
 */

/* Check if a number has Jacobi symbol +1 (QR candidate) */
int jacobi_is_plus_one(uint64_t a, uint64_t n);

/* Check if a is a quadratic residue mod n (requires factorization) */
int is_quadratic_residue(uint64_t a, uint64_t p, uint64_t q);

/*
 * Verify that a BBS state's current value is a quadratic residue.
 * (All x_i after the first iteration are quadratic residues by construction.)
 */
int bbs_state_is_qr(const BBSState* bbs);

#endif /* BLUM_BLUM_SHUB_H */
