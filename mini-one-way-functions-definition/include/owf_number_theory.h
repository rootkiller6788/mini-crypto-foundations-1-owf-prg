/*
 * owf_number_theory.h — Number Theory Foundations for OWF Candidates
 *
 * L3 Mathematical Structures:
 *   - Multi-precision integers (big_nat, big_mod_n)
 *   - Modular arithmetic ring Z_n and field Z_p (p prime)
 *   - Multiplicative group Z_p^* of order p-1
 *   - Chinese Remainder Theorem (CRT)
 *   - Quadratic residues and Legendre/Jacobi symbols
 *
 * L5 Algorithms/Methods:
 *   - Extended Euclidean Algorithm (gcd, modular inverse)
 *   - Modular exponentiation (square-and-multiply)
 *   - Miller-Rabin primality test
 *   - Prime generation (random search + Miller-Rabin)
 *   - Chinese Remainder Theorem reconstruction
 *   - Baby-step Giant-step (for discrete log, small groups)
 *
 * Reference:
 *   Menezes, van Oorschot, Vanstone, "Handbook of Applied Cryptography"
 *   Cormen, Leiserson, Rivest, Stein, "Introduction to Algorithms" §31
 *   Goldreich, "Foundations of Cryptography" Vol 1, Appendix B
 *   Katz-Lindell, "Introduction to Modern Cryptography" Appendix B
 *
 * Courses:
 *   MIT 6.875, Stanford CS255, Berkeley CS276, Princeton COS 433
 *   CMU 15-859, Caltech CS 157, Cambridge Part III,
 *   Oxford Advanced Security, ETH 263-4660
 */

#ifndef OWF_NUMBER_THEORY_H
#define OWF_NUMBER_THEORY_H

#include "owf_core.h"
#include <stdint.h>
#include <stddef.h>

/* ================================================================
 * Big Natural Number (multi-precision integer)
 * ================================================================ */

#define BIG_NAT_MAX_DIGITS  256    /* supports up to ~2048-bit numbers */
#define BIG_NAT_BASE        1000000000  /* 10^9 per "digit" for easy decimal */
#define BIG_NAT_LOG_BASE    9

typedef struct {
    uint32_t digits[BIG_NAT_MAX_DIGITS];
    int      ndigits;        /* number of base-10^9 digits used */
} big_nat_t;

/* Construction */
big_nat_t  big_nat_zero(void);
big_nat_t  big_nat_from_uint64(uint64_t val);
big_nat_t  big_nat_from_decimal(const char* dec_str);
big_nat_t  big_nat_random_bits(size_t nbits);

/* Basic operations */
int        big_nat_is_zero(const big_nat_t* a);
int        big_nat_is_one(const big_nat_t* a);
int        big_nat_is_even(const big_nat_t* a);
int        big_nat_compare(const big_nat_t* a, const big_nat_t* b);
int        big_nat_equal(const big_nat_t* a, const big_nat_t* b);

big_nat_t  big_nat_add(const big_nat_t* a, const big_nat_t* b);
big_nat_t  big_nat_sub(const big_nat_t* a, const big_nat_t* b);
big_nat_t  big_nat_mul(const big_nat_t* a, const big_nat_t* b);

/* Division: a = b * q + r, 0 ≤ r < b */
void       big_nat_divmod(const big_nat_t* a, const big_nat_t* b,
                          big_nat_t* q, big_nat_t* r);

big_nat_t  big_nat_mod(const big_nat_t* a, const big_nat_t* m);
big_nat_t  big_nat_gcd(const big_nat_t* a, const big_nat_t* b);

/* Modular exponentiation: base^exp mod m */
big_nat_t  big_nat_modpow(const big_nat_t* base, const big_nat_t* exp,
                          const big_nat_t* m);

/* Extended Euclidean: a*s + b*t = gcd(a,b) */
void       big_nat_egcd(const big_nat_t* a, const big_nat_t* b,
                        big_nat_t* gcd, big_nat_t* s, big_nat_t* t);

/* Modular inverse: a^{-1} mod m, requires gcd(a,m)=1 */
big_nat_t  big_nat_modinv(const big_nat_t* a, const big_nat_t* m);

/* Convert between bit_string and big_nat */
big_nat_t     big_nat_from_bit_string(const bit_string_t* bs);
bit_string_t* big_nat_to_bit_string(const big_nat_t* n, size_t pad_bits);

/* Print */
void       big_nat_print(const big_nat_t* a, const char* label);
void       big_nat_print_hex(const big_nat_t* a, const char* label);

/* ================================================================
 * Primality Testing (Miller-Rabin)
 * ================================================================ */

/*
 * Miller-Rabin probabilistic primality test.
 *
 * Theorem (Rabin 1980): If n is composite, then at least 3/4 of
 * bases a ∈ {1,...,n-1} are witnesses.
 *
 * With k iterations: Pr[error] ≤ (1/4)^k
 * k=40 → error < 2^{-80}, sufficient for cryptographic use.
 */

/* Miller-Rabin single round with base a:
 *   returns 1 if n is PROBABLY PRIME w.r.t. base a
 *   returns 0 if n is COMPOSITE (a is a witness) */
int mr_test_single(const big_nat_t* n, const big_nat_t* a);

/* Miller-Rabin with k random bases:
 *   returns 1 if n passes all k rounds (probably prime)
 *   returns 0 if n is proven composite */
int mr_test(const big_nat_t* n, int k_rounds);

/* Check if proven composite by finding a divisor ≤ sqrt(n) */
int big_nat_is_composite_brute(const big_nat_t* n, big_nat_t* factor);

/* ================================================================
 * Prime Generation
 * ================================================================ */

/* Generate a random n-bit prime.
 * Uses: random n-bit odd number + Miller-Rabin filtering.
 * Typical k_rounds = 40 for cryptographic use. */
big_nat_t generate_random_prime(size_t nbits, int k_rounds, uint64_t* attempts);

/* Generate a safe prime p = 2q + 1 where q is also prime.
 * Used in Diffie-Hellman and some OWF constructions. */
big_nat_t generate_safe_prime(size_t nbits, int k_rounds,
                              uint64_t* attempts, big_nat_t* q_out);

/* ================================================================
 * Chinese Remainder Theorem (CRT)
 * ================================================================ */

/*
 * Given pairwise coprime moduli m1, m2, ..., mk and residues
 * a1, a2, ..., ak, find x such that x ≡ ai (mod mi) for all i.
 *
 * Used in RSA-CRT optimization and in some OWF proofs.
 */
big_nat_t crt_solve(const big_nat_t* residues, const big_nat_t* moduli, int k);

/* Garner's algorithm for CRT reconstruction (more efficient) */
big_nat_t crt_garner(const big_nat_t* residues, const big_nat_t* moduli, int k);

/* ================================================================
 * Legendre & Jacobi Symbols
 * ================================================================ */

/*
 * Legendre symbol (a/p) for odd prime p:
 *   +1 if a is quadratic residue mod p
 *   -1 if a is quadratic non-residue mod p
 *    0 if p divides a
 */
int legendre_symbol(const big_nat_t* a, const big_nat_t* p);

/*
 * Jacobi symbol (a/n) for odd n:
 *   Generalization of Legendre symbol to composite modulus.
 *   Used in Solovay-Strassen primality test and Rabin cryptosystem.
 */
int jacobi_symbol(const big_nat_t* a, const big_nat_t* n);

#endif /* OWF_NUMBER_THEORY_H */
