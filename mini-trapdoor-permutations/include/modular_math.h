/**
 * modular_math.h — Modular Arithmetic for Trapdoor Permutations
 *
 * Provides the mathematical foundations for RSA and other TDP constructions:
 *   - Big integer representation and basic operations
 *   - Modular arithmetic: addition, multiplication, exponentiation
 *   - Greatest Common Divisor (Euclidean algorithm)
 *   - Extended Euclidean algorithm (modular inverse)
 *   - Chinese Remainder Theorem (CRT)
 *   - Euler's totient function φ(n)
 *   - Legendre and Jacobi symbols
 *
 * Reference: Shoup, A Computational Introduction to Number Theory and Algebra (2008)
 *            Katz & Lindell, Introduction to Modern Cryptography (2014), Ch. 8
 *
 * Course mapping:
 *   Princeton COS 551 — Number-theoretic foundations for crypto
 *   Stanford CS255 — Introduction to Cryptography
 *   MIT 6.875 — Foundations of Cryptography
 *   ETH 263-4660 — Applied Cryptography
 *   Cambridge Part II — Mathematical Methods for Cryptography
 */

#ifndef MODULAR_MATH_H
#define MODULAR_MATH_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Re-use bigint_t from tdp_core.h */
#include "tdp_core.h"

/* ──── Big Integer Constants ──── */

#define BIGINT_ZERO   { .nlimbs = 1, .limbs = {0} }
#define BIGINT_ONE    { .nlimbs = 1, .limbs = {1} }
#define BIGINT_TWO    { .nlimbs = 1, .limbs = {2} }
#define BIGINT_THREE  { .nlimbs = 1, .limbs = {3} }

/* ──── Big Integer Construction and Comparison ──── */

/**
 * Initialize a bigint from a uint64_t value.
 * Complexity: O(1).
 */
bigint_t bigint_from_uint64(uint64_t val);

/**
 * Set a bigint to zero.
 * Complexity: O(1).
 */
void bigint_set_zero(bigint_t *a);

/**
 * Set a bigint to one.
 * Complexity: O(1).
 */
void bigint_set_one(bigint_t *a);

/**
 * Copy bigint: dst := src.
 * Complexity: O(nlimbs).
 */
void bigint_copy(bigint_t *dst, const bigint_t *src);

/**
 * Compare two bigints.
 * Returns: -1 if a < b, 0 if a == b, 1 if a > b.
 * Complexity: O(nlimbs).
 */
int bigint_compare(const bigint_t *a, const bigint_t *b);

/**
 * Check if bigint is zero.
 * Complexity: O(nlimbs).
 */
bool bigint_is_zero(const bigint_t *a);

/**
 * Check if bigint is one.
 * Complexity: O(nlimbs).
 */
bool bigint_is_one(const bigint_t *a);

/**
 * Check if bigint is even.
 * Complexity: O(1).
 */
bool bigint_is_even(const bigint_t *a);

/**
 * Get bit-length of a bigint (position of highest set bit + 1).
 * Complexity: O(nlimbs).
 */
uint32_t bigint_bit_length(const bigint_t *a);

/**
 * Get the value of a specific bit.
 * Complexity: O(1).
 */
bool bigint_get_bit(const bigint_t *a, uint32_t bit_index);

/**
 * Convert bigint to uint64_t (returns 0 on overflow).
 * Complexity: O(nlimbs).
 */
uint64_t bigint_to_uint64(const bigint_t *a);

/* ──── Big Integer Arithmetic ──── */

/**
 * Addition: c = a + b.
 * Returns true if no overflow occurred.
 * Complexity: O(max(nlimbs_a, nlimbs_b)).
 */
bool bigint_add(bigint_t *c, const bigint_t *a, const bigint_t *b);

/**
 * Subtraction: c = a - b.
 * Assumes a ≥ b. Returns false if a < b (result would be negative).
 * Complexity: O(max(nlimbs_a, nlimbs_b)).
 */
bool bigint_sub(bigint_t *c, const bigint_t *a, const bigint_t *b);

/**
 * Multiplication (schoolbook): c = a * b.
 * Complexity: O(nlimbs_a * nlimbs_b).
 */
void bigint_mul(bigint_t *c, const bigint_t *a, const bigint_t *b);

/**
 * Division with remainder: a = q * b + r, where 0 ≤ r < b.
 * Complexity: O(nlimbs_a * nlimbs_b).
 * Returns false if b == 0.
 */
bool bigint_divmod(bigint_t *q, bigint_t *r, const bigint_t *a, const bigint_t *b);

/**
 * Right shift by n bits: a >>= n.
 * Complexity: O(nlimbs).
 */
void bigint_shr(bigint_t *a, uint32_t n);

/**
 * Left shift by n bits: a <<= n.
 * Complexity: O(nlimbs).
 */
void bigint_shl(bigint_t *a, uint32_t n);

/**
 * Increment: a += 1.
 * Complexity: O(nlimbs) amortized.
 */
void bigint_inc(bigint_t *a);

/**
 * Decrement: a -= 1.
 * Assumes a > 0.
 * Complexity: O(nlimbs) amortized.
 */
void bigint_dec(bigint_t *a);

/* ──── Modular Arithmetic ──── */

/**
 * Modular addition: result = (a + b) mod m.
 * Complexity: O(nlimbs).
 */
void mod_add(bigint_t *result, const bigint_t *a, const bigint_t *b, const bigint_t *m);

/**
 * Modular subtraction: result = (a - b) mod m.
 * Complexity: O(nlimbs).
 */
void mod_sub(bigint_t *result, const bigint_t *a, const bigint_t *b, const bigint_t *m);

/**
 * Modular multiplication: result = (a * b) mod m.
 * Complexity: O(nlimbs^2).
 */
void mod_mul(bigint_t *result, const bigint_t *a, const bigint_t *b, const bigint_t *m);

/**
 * Modular exponentiation: result = base^exp mod m.
 * Uses square-and-multiply (binary exponentiation).
 * Complexity: O(log(exp) * log^2(m)).
 *
 * This is the core operation for RSA: encryption (x^e mod n) and
 * decryption (y^d mod n).
 *
 * Reference: Knuth, TAOCP Vol. 2, §4.6.3, Algorithm A.
 */
void mod_exp(bigint_t *result, const bigint_t *base, const bigint_t *exp, const bigint_t *m);

/**
 * Modular exponentiation with CRT optimization.
 * Given p, q (factors of n), d_p = d mod (p-1), d_q = d mod (q-1),
 * and q_inv = q^{-1} mod p, compute y^d mod n faster.
 * Complexity: ~4x faster than naive mod_exp for RSA.
 *
 * Reference: Menezes, van Oorschot, Vanstone, Handbook of Applied Cryptography,
 *            §14.75 (Garner's algorithm).
 */
void mod_exp_crt(bigint_t *result, const bigint_t *y,
                  const bigint_t *d_p, const bigint_t *d_q,
                  const bigint_t *q_inv, const bigint_t *p, const bigint_t *q);

/* ──── Number-Theoretic Functions ──── */

/**
 * Greatest Common Divisor: Euclidean algorithm.
 * Complexity: O(log(min(a,b)) * log^2(n)).
 * Reference: Euclid, Elements, Book VII (c. 300 BCE).
 */
void bigint_gcd(bigint_t *result, const bigint_t *a, const bigint_t *b);

/**
 * Extended Euclidean Algorithm.
 * Computes d = gcd(a,b) and finds x, y such that a*x + b*y = d.
 * Complexity: O(log(min(a,b)) * log^2(n)).
 *
 * Used for: computing modular inverse (when gcd(a,m)=1, a*x + m*y = 1
 * implies x = a^{-1} mod m).
 *
 * Reference: Knuth, TAOCP Vol. 2, §4.5.2, Algorithm X.
 */
void bigint_egcd(bigint_t *d, bigint_t *x, bigint_t *y, const bigint_t *a, const bigint_t *b);

/**
 * Modular Inverse: computes a^{-1} mod m.
 * Requires gcd(a, m) = 1.
 * Returns false if inverse does not exist.
 * Complexity: O(log(m) * log^2(m)).
 */
bool mod_inverse(bigint_t *result, const bigint_t *a, const bigint_t *m);

/**
 * Euler's Totient φ(n) for n = p*q (distinct primes).
 * φ(n) = (p-1)(q-1).
 * Complexity: O(log^2 p).
 *
 * Reference: Euler, Theoremata circa divisores numerorum (1760).
 */
void euler_totient_rsa(bigint_t *result, const bigint_t *p, const bigint_t *q);

/**
 * Check if a number is provably composite by Miller-Rabin witness.
 * Returns true if 'a' is a witness to the compositeness of 'n'.
 * Complexity: O(log^3 n).
 *
 * Reference: Miller (1976), Rabin (1980).
 */
bool miller_rabin_witness(const bigint_t *n, const bigint_t *a);

/**
 * Miller-Rabin primality test.
 * Returns true if n is probably prime with error probability ≤ 4^{-k}.
 * Complexity: O(k * log^3 n).
 */
bool miller_rabin_test(const bigint_t *n, uint32_t k);

/**
 * Generate a random bigint in range [0, max-1] (deterministic PRNG for testing).
 * Complexity: O(nlimbs).
 */
void bigint_rand_range(bigint_t *result, const bigint_t *max, uint32_t seed);

/**
 * Generate a random odd bigint of given bit-length.
 * Complexity: O(nlimbs).
 */
void bigint_rand_odd(bigint_t *result, uint32_t nbits, uint32_t seed);

/* ──── Chinese Remainder Theorem ──── */

/**
 * CRT for two moduli: Given x ≡ a1 (mod m1) and x ≡ a2 (mod m2),
 * with gcd(m1, m2) = 1, compute x mod (m1*m2).
 *
 * Using Gauss's algorithm:
 *   x = a1 * M1 * y1 + a2 * M2 * y2 mod M
 * where M = m1*m2, M1 = M/m1 = m2, y1 = m2^{-1} mod m1,
 *       M2 = M/m2 = m1, y2 = m1^{-1} mod m2.
 *
 * Complexity: O(log^2(max(m1,m2))).
 *
 * Reference: Gauss, Disquisitiones Arithmeticae (1801), §36.
 */
void crt_combine(bigint_t *result,
                  const bigint_t *a1, const bigint_t *m1,
                  const bigint_t *a2, const bigint_t *m2);

/* ──── Legendre and Jacobi Symbols ──── */

/**
 * Legendre Symbol (a/p): for odd prime p.
 * Returns: 1 if a is quadratic residue mod p, -1 if non-residue, 0 if p | a.
 * Complexity: O(log^3 p).
 *
 * Reference: Legendre, Essai sur la théorie des nombres (1798).
 */
int legendre_symbol(const bigint_t *a, const bigint_t *p);

/**
 * Jacobi Symbol (a/n): generalization of Legendre symbol to odd composite n.
 * Returns: 1 or -1 (or 0 if gcd(a,n) > 1).
 * Complexity: O(log^3 n).
 *
 * Reference: Jacobi, Über die Kreistheilung (1837).
 */
int jacobi_symbol(const bigint_t *a, const bigint_t *n);

/* ──── Utility Functions ──── */

/**
 * Print a bigint in hexadecimal format to stdout.
 * Complexity: O(nlimbs).
 */
void bigint_print_hex(const char *label, const bigint_t *a);

/**
 * Print a bigint in decimal format to stdout.
 * Complexity: O(nlimbs^2) due to repeated division.
 */
void bigint_print_dec(const char *label, const bigint_t *a);

/**
 * Get the number of limbs used.
 * Complexity: O(1).
 */
static inline uint32_t bigint_nlimbs(const bigint_t *a) {
    return a->nlimbs;
}

#endif /* MODULAR_MATH_H */
