/*
 * crypto_utils.h ? Cryptographic Utility Functions
 *
 * L3 Mathematical Structures:
 *   - GF(2) arithmetic and linear algebra
 *   - Modular exponentiation
 *   - Primality testing (Miller-Rabin)
 *   - Random number generation
 *   - Binary string operations (concatenation, XOR, slice)
 *   - Matrix operations over GF(2)
 *
 * These utilities support the core cryptographic constructions
 * (RSA, discrete log, subset sum, Goldreich-Levin, etc.)
 *
 * Reference:
 *   Menezes, van Oorschot, Vanstone (1996) ? Handbook of Applied Cryptography
 *   Goldreich (2001) ? Foundations of Cryptography, Vol 1, App A
 *
 * Courses: MIT 6.875, Stanford CS255, Princeton COS 522
 */

#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include "owf.h"
#include <stdint.h>
#include <stddef.h>

/* ================================================================
 * L3: GF(2) Vector Operations
 * ================================================================ */

/*
 * GF(2) = {0,1} with XOR as addition, AND as multiplication.
 * Vectors in GF(2)^n are bit strings of length n.
 */

/* Vector addition (XOR): out = a XOR b (bitwise) */
void gf2_add(const BitString *a, const BitString *b, BitString *out);

/* Scalar-vector multiplication: out = c * v (c in {0,1}) */
void gf2_scalar_mul(int c, const BitString *v, BitString *out);

/* Inner product: sum_{i} a_i * b_i (mod 2) */
int  gf2_dot_product(const BitString *a, const BitString *b);

/* Hamming weight: number of 1-bits */
int  gf2_hamming_weight(const BitString *v);

/* Matrix-vector multiplication over GF(2):
 *   out = A * x   where A is k x m matrix, x is m-dimensional vector
 *   out[i] = sum_j A[i][j] * x[j] (mod 2)
 */
void gf2_matrix_mul(const uint8_t *A, int k, int m,
                    const BitString *x, BitString *out);

/* ================================================================
 * L3: Modular Arithmetic
 * ================================================================ */

/* Modular exponentiation: base^exp mod modulus (square-and-multiply) */
uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t modulus);

/* Modular multiplication: (a * b) mod m (with overflow protection) */
uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t modulus);

/* Extended Euclidean algorithm: find gcd(a,b) and Bezout coefficients.
 * Returns gcd. Sets x,y such that a*x + b*y = gcd(a,b). */
uint64_t extended_gcd(uint64_t a, uint64_t b, int64_t *x, int64_t *y);

/* Modular inverse: a^{-1} mod m. Returns 0 if no inverse exists. */
uint64_t mod_inverse(uint64_t a, uint64_t modulus);

/* ================================================================
 * L3: Number Theoretic Utilities
 * ================================================================ */

/* Miller-Rabin primality test with given confidence.
 * Returns 1 if probably prime, 0 if composite.
 * k = number of rounds (probability of error <= 4^{-k}) */
int miller_rabin_prime(uint64_t n, int k);

/* Check if g is a generator of Z_p^* (for safe prime p = 2q+1) */
int is_generator(uint64_t g, uint64_t p);

/* Generate a random prime in range [2^{bits-1}, 2^bits) */
uint64_t generate_random_prime(int bits);

/* Check if n is a Blum integer: n = p*q with p,q == 3 (mod 4) */
int is_blum_integer(uint64_t n, uint64_t p, uint64_t q);

/* ================================================================
 * L3: Random Number Generation
 * ================================================================ */

/*
 * Simple PRNG for testing purposes (linear congruential generator).
 * NOT cryptographically secure ? only for experiments!
 */
typedef struct {
    uint64_t state;
    uint64_t a;
    uint64_t c;
    uint64_t m;
} LCG;

LCG    *lcg_create(uint64_t seed);
void    lcg_free(LCG *lcg);
uint64_t lcg_next(LCG *lcg);
uint64_t lcg_rand_range(LCG *lcg, uint64_t min, uint64_t max);

/* Seed the random subsystem with entropy (time-based) */
void seed_random(void);

/* ================================================================
 * L3: BitString Extended Operations
 * ================================================================ */

/* Concatenation: out = a || b */
void bitstring_concat(const BitString *a, const BitString *b, BitString *out);

/* XOR: out = a XOR b (bitwise, same length) */
void bitstring_xor(const BitString *a, const BitString *b, BitString *out);

/* Slice: out = bs[start .. start+len-1] (bit positions) */
void bitstring_slice(const BitString *bs, size_t start, size_t len, BitString *out);

/* Split: left = first n bits, right = remaining bits */
void bitstring_split(const BitString *bs, size_t n, BitString *left, BitString *right);

/* Compare lexicographically (return -1, 0, 1) */
int  bitstring_cmp(const BitString *a, const BitString *b);

/* Convert bitstring to hex string for printing */
void bitstring_to_hex(const BitString *bs, char *hex_out, size_t hex_len);

/* Parse hex string to bitstring */
int  hex_to_bitstring(const char *hex, BitString *out);

/* ================================================================
 * L7: Crypto Application Utilities
 * ================================================================ */

/*
 * Time-based key generation from system entropy.
 * Uses time() and clock() as entropy sources (for demonstration).
 * For real applications, use /dev/urandom or platform CSPRNG.
 */
int generate_crypto_key(size_t bit_len, BitString *key);

/*
 * Simple hash function (FNV-1a based) for demo purposes.
 * For real crypto, use SHA-256 or similar.
 */
uint64_t fnv_hash(const uint8_t *data, size_t len);

/*
 * HKDF-like key derivation: stretch a seed into longer key material.
 * Uses iterative hashing: K_0 = empty, K_{i+1} = H(K_i || seed || counter)
 */
int key_derivation_stretch(const BitString *seed, size_t output_len,
                           BitString *output);

#endif /* CRYPTO_UTILS_H */
