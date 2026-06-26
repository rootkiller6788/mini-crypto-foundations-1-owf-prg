/**
 * rsa_keygen.h — RSA Key Generation
 *
 * Key generation for RSA involves:
 *   1. Generating two random primes p, q of specified bit-length.
 *   2. Computing n = p*q and φ(n) = (p-1)(q-1).
 *   3. Selecting public exponent e with gcd(e, φ(n)) = 1.
 *   4. Computing private exponent d = e^{-1} mod φ(n).
 *   5. Precomputing CRT values for efficient decryption.
 *
 * Prime generation uses Miller-Rabin probabilistic primality test
 * with iterative random candidate generation.
 *
 * Reference: ANSI X9.44, IEEE P1363, PKCS#1 v2.2 (RFC 8017)
 *            Katz & Lindell (2014), Ch. 8.2
 *
 * Course mapping:
 *   Stanford CS255 — Key generation algorithms
 *   MIT 6.875 — Cryptographic constructions
 *   Princeton COS 551 — Algorithmic number theory
 *   ETH 263-4660 — Key generation in practice
 */

#ifndef RSA_KEYGEN_H
#define RSA_KEYGEN_H

#include "tdp_core.h"
#include "modular_math.h"
#include "rsa.h"

/* ──── Key Generation Parameters ──── */

/**
 * RSA key size options (common standards).
 * Note: In 2026, RSA-2048 is the minimum recommended by NIST.
 * RSA-1024 is included for educational/testing purposes only.
 */
typedef enum {
    RSA_KEY_1024 = 1024,  /* DEPRECATED for production */
    RSA_KEY_2048 = 2048,  /* NIST minimum through 2030 */
    RSA_KEY_3072 = 3072,  /* NIST recommended */
    RSA_KEY_4096 = 4096,  /* High security */
    RSA_KEY_8192 = 8192,  /* Very high security, slow */
} rsa_key_size_t;

/** Default Miller-Rabin iteration count for acceptable error ≤ 2^{-80}. */
#define MILLER_RABIN_ROUNDS 40

/** Size ratio for p and q: each is nbits/2 bits. */
#define RSA_PRIME_RATIO 2

/* ──── Prime Generation ──── */

/**
 * Test if a number is probably prime using Miller-Rabin.
 * Returns true with error probability ≤ 4^{-rounds}.
 *
 * Miller-Rabin Test:
 *   Write n-1 = 2^s * d where d is odd.
 *   For each random base a, compute a^d mod n:
 *     - If a^d ≡ 1 (mod n) → probably prime (for this a).
 *     - If a^{2^r * d} ≡ -1 for some r < s → probably prime.
 *     - Otherwise → definitely composite (a is a witness).
 *
 * Complexity: O(rounds * log^3 n).
 *
 * Reference: Miller, "Riemann's Hypothesis and Tests for Primality" (1976).
 *            Rabin, "Probabilistic Algorithm for Testing Primality" (1980).
 */
bool is_probable_prime(const bigint_t *n, uint32_t rounds);

/**
 * Generate a random prime of exactly nbits bits.
 * Uses rejection sampling:
 *   1. Generate random odd nbits-bit number.
 *   2. Test with trial division (small primes up to 256).
 *   3. Test with Miller-Rabin.
 *   4. Repeat until prime found.
 *
 * Complexity: O(nbits^4) expected (Pr[random nbit number is prime] ≈ 1/(ln 2^nbits)).
 *
 * Reference: Maurer, "Fast Generation of Prime Numbers" (1995).
 *            Brandt & Damgård, "On Generation of Probable Primes" (1993).
 */
bool generate_random_prime(bigint_t *p, uint32_t nbits, uint32_t seed);

/* ──── Sieve-Based Prime Candidate Filtering ──── */

/**
 * Trial division of n by first num_small small primes.
 * Returns true if no small factor found (candidate passes sieve).
 * Complexity: O(num_small * log n).
 */
bool trial_division_sieve(const bigint_t *n, uint32_t num_small);

/**
 * Small primes table (first 256 primes for trial division).
 * The largest is 1619.
 */
#define NUM_SMALL_PRIMES 256
extern const uint32_t SMALL_PRIMES[NUM_SMALL_PRIMES];

/* ──── RSA Key Generation ──── */

/**
 * Generate a complete RSA key pair.
 *
 * Algorithm:
 *   1. Generate random prime p of nbits/2 bits.
 *   2. Generate random prime q of nbits/2 bits, p ≠ q.
 *   3. Compute n = p * q, φ(n) = (p-1)(q-1).
 *   4. Select e = 65537 (or generate if gcd(e, φ(n)) ≠ 1).
 *   5. Compute d = e^{-1} mod φ(n).
 *   6. Precompute CRT values: d_p, d_q, q_inv.
 *
 * Complexity: O(nbits^4 + nbits^5) expected for primality tests.
 *
 * Theorem (RSA Correctness):
 *   For all x ∈ Z_n, x^{ed} ≡ x (mod n).
 *   Proof: By Euler's Theorem, if gcd(x,n)=1, x^{φ(n)} ≡ 1.
 *          ed ≡ 1 (mod φ(n)) → ed = 1 + kφ(n) → x^{ed} = x * x^{kφ(n)} = x.
 *          If gcd(x,n)≠1, use CRT to show x^{ed} ≡ x (mod p) and (mod q).
 *
 * Reference: Rivest, Shamir, Adleman (1978).
 */
tdp_status_t rsa_generate_keypair(rsa_keypair_t *key, uint32_t nbits, uint32_t seed);

/**
 * Generate RSA key pair from given primes (for testing with known primes).
 * Complexity: O(log^3 n).
 */
tdp_status_t rsa_keypair_from_primes(rsa_keypair_t *key,
                                      const bigint_t *p, const bigint_t *q,
                                      const bigint_t *e);

/**
 * Validate an RSA key pair:
 *   - p and q are prime.
 *   - n = p * q.
 *   - φ(n) = (p-1)(q-1).
 *   - gcd(e, φ(n)) = 1.
 *   - e * d ≡ 1 (mod φ(n)).
 *   - For random x: Dec(Enc(x)) = x.
 *
 * Complexity: O(k * log^3 n) for k-round Miller-Rabin + O(log^3 n) for ops.
 */
bool rsa_validate_keypair(const rsa_keypair_t *key);

/**
 * Compute d = e^{-1} mod φ(n) using extended Euclidean algorithm.
 * Complexity: O(log^2 φ(n)).
 */
bool rsa_compute_private_exponent(bigint_t *d, const bigint_t *e, const bigint_t *phi_n);

/* ──── CRT Precomputation ──── */

/**
 * Precompute CRT parameters for efficient RSA decryption:
 *   d_p = d mod (p-1)
 *   d_q = d mod (q-1)
 *   q_inv = q^{-1} mod p
 *
 * Then decryption uses Garner's algorithm:
 *   m1 = c^{d_p} mod p
 *   m2 = c^{d_q} mod q
 *   h = q_inv * (m1 - m2) mod p
 *   m = m2 + h * q
 *
 * Complexity: O(log^2 n) precomputation.
 */
void rsa_precompute_crt(rsa_keypair_t *key);

/* ──── Key Information ──── */

/**
 * Print RSA key information (for educational/demo purposes only).
 * Complexity: O(nlimbs^2).
 */
void rsa_print_key_info(const rsa_keypair_t *key);

#endif /* RSA_KEYGEN_H */
