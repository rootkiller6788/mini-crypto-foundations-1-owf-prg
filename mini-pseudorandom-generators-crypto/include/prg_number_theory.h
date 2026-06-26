/*
 * prg_number_theory.h -- Number Theory for Cryptographic PRGs
 *
 * L3 Mathematical Structures:
 *   Modular arithmetic over Z_n and Z_n^*
 *   Legendre symbol, Jacobi symbol
 *   Quadratic residues modulo prime and composite
 *   Blum integers (n = p*q where p,q = 3 mod 4)
 *   Finite cyclic groups, generators, group order
 *   Chinese Remainder Theorem
 *
 * These structures underpin:
 *   - Blum-Micali PRG: discrete log in Z_p^*
 *   - Blum-Blum-Shub PRG: quadratic residues modulo Blum integer
 *   - Goldreich-Levin: inner product mod 2 over vectors
 *
 * Reference: Shoup "A Computational Introduction to Number Theory and Algebra"
 *            Menezes-van Oorschot-Vanstone "Handbook of Applied Cryptography"
 */

#ifndef PRG_NUMBER_THEORY_H
#define PRG_NUMBER_THEORY_H

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>

/* ================================================================
 * Basic Modular Arithmetic (Z_n)
 * ================================================================ */

/* Modular addition: (a + b) mod n */
uint64_t mod_add(uint64_t a, uint64_t b, uint64_t n);

/* Modular subtraction: (a - b) mod n */
uint64_t mod_sub(uint64_t a, uint64_t b, uint64_t n);

/* Modular multiplication: (a * b) mod n (safe from overflow for moderate sizes) */
uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t n);

/* Modular exponentiation: a^e mod n using repeated squaring */
uint64_t mod_pow(uint64_t a, uint64_t e, uint64_t n);

/* Extended Euclidean Algorithm: gcd(a,b) = a*x + b*y */
uint64_t extended_gcd(uint64_t a, uint64_t b, int64_t* x, int64_t* y);

/* Modular inverse: a^{-1} mod n, returns 0 if no inverse exists */
uint64_t mod_inv(uint64_t a, uint64_t n);

/* GCD of two integers */
uint64_t gcd(uint64_t a, uint64_t b);

/* ================================================================
 * Legendre and Jacobi Symbols
 * ================================================================ */

/*
 * Legendre symbol (a/p) for odd prime p:
 *   (a/p) = 0  if p | a
 *         = 1  if a is quadratic residue mod p
 *         = -1 otherwise
 *
 * Euler's criterion: (a/p) ? a^{(p-1)/2} (mod p)
 */
int legendre_symbol(uint64_t a, uint64_t p);

/*
 * Jacobi symbol (a/n) for odd n (generalizes Legendre to composite n):
 *   (a/n) = ?_i (a/p_i)^{e_i} where n = ?_i p_i^{e_i}
 *
 * Key properties:
 *   (1/n) = 1
 *   (ab/n) = (a/n)?(b/n)
 *   (2/n) = (-1)^{(n^2-1)/8} if n odd
 *   Quadratic reciprocity: if m,n odd and gcd(m,n)=1,
 *     (m/n)?(n/m) = (-1)^{(m-1)(n-1)/4}
 */
int jacobi_symbol(uint64_t a, uint64_t n);

/* ================================================================
 * Quadratic Residues
 * ================================================================ */

/*
 * Quadratic residue: a ? Z_n^* is a QR mod n if ?x: x^2 ? a (mod n).
 *
 * For odd prime p:
 *   a is QR mod p ? (a/p) = 1
 *   Exactly (p-1)/2 residues and (p-1)/2 non-residues mod p
 *
 * For composite n = p*q (Blum integer):
 *   Checking QR is believed hard without knowing factorization
 *   This is the Quadratic Residuosity Problem (QRP)
 */

/* Test if a is quadratic residue mod prime p using Euler criterion */
int qr_test_prime(uint64_t a, uint64_t p);

/* Find a square root of a modulo prime p (Tonelli-Shanks algorithm) */
uint64_t mod_sqrt_prime(uint64_t a, uint64_t p);

/* ================================================================
 * Primality and Blum Integers
 * ================================================================ */

/*
 * Miller-Rabin primality test (probabilistic).
 * Returns: 1 if probably prime (error prob < 4^{-k}),
 *          0 if definitely composite.
 */
int miller_rabin(uint64_t n, int k_iterations);

/*
 * Trial division primality test (deterministic, suitable for small n < 2^32).
 * Returns 1 if prime, 0 if composite.
 */
int is_prime_bruteforce(uint64_t n);

/* Generate a small safe prime (p = 2q+1 with q prime) for demo purposes */
uint64_t safe_prime_generate(uint64_t min_val, uint64_t max_val);

/*
 * Blum integer: n = p * q where p, q are distinct primes,
 * and p ? q ? 3 (mod 4).
 * Properties: -1 is a quadratic non-residue with Jacobi symbol +1.
 * For any quadratic residue a, exactly one of its four square roots
 * is itself a quadratic residue ? the "principal" square root.
 */
typedef struct {
    uint64_t n;    /* Blum integer n = p * q */
    uint64_t p;    /* factor p */
    uint64_t q;    /* factor q */
} BlumInteger;

/* Check if n is a Blum integer (given its factorization) */
int blum_check(const BlumInteger* bi);

/* Generate a small Blum integer for demonstration */
BlumInteger blum_integer_generate(uint64_t min_factor, uint64_t max_factor);

/* ================================================================
 * Cyclic Groups and Generators
 * ================================================================ */

/*
 * A cyclic group G of order m has a generator g such that
 * G = {g^0, g^1, ..., g^{m-1}}.
 *
 * For prime p, Z_p^* is cyclic of order p-1.
 */

/* Check if g is a generator of Z_p^* */
int is_generator_mod_p(uint64_t g, uint64_t p);

/* Find a generator of Z_p^* */
uint64_t find_generator_mod_p(uint64_t p);

/* Compute the order of element a in Z_n^* */
uint64_t element_order(uint64_t a, uint64_t n);

/* Euler's totient function ?(n) for small n */
uint64_t euler_totient(uint64_t n);

/* ================================================================
 * Chinese Remainder Theorem (CRT)
 * ================================================================ */

/*
 * Given moduli n1, n2 (coprime) and residues a1, a2,
 * find x such that x ? a1 (mod n1) and x ? a2 (mod n2).
 *
 * This is fundamental to RSA and BBS: knowledge of factors
 * enables efficient operations via CRT.
 */
typedef struct {
    uint64_t n1, n2;       /* moduli (must be coprime) */
    uint64_t a1, a2;       /* target residues */
    uint64_t solution;     /* x (mod n1*n2) */
} CRTResult;

CRTResult crt_solve(uint64_t a1, uint64_t n1, uint64_t a2, uint64_t n2);

/*
 * CRT-based squaring in BBS:
 * Instead of x^2 mod N (N = p*q), compute:
 *   x_p^2 mod p, x_q^2 mod q, then combine via CRT.
 * This is ~4x faster than direct computation.
 */
uint64_t crt_square(uint64_t x, uint64_t p, uint64_t q);

/* ================================================================
 * Large Integer Helpers (up to 128-bit intermediate for safety)
 * ================================================================ */

/* 64-bit multiply with 128-bit result, return high 64 bits */
uint64_t mul_hi64(uint64_t a, uint64_t b);

/* Multiply two 64-bit numbers modulo n (safe for intermediate 128-bit) */
uint64_t mul_mod64(uint64_t a, uint64_t b, uint64_t n);

/* 64-bit exponentiation with 128-bit intermediate safety */
uint64_t pow_mod64(uint64_t base, uint64_t exp, uint64_t mod);

#endif /* PRG_NUMBER_THEORY_H */
