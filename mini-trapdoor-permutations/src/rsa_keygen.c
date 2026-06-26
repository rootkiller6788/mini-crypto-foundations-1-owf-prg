/**
 * rsa_keygen.c -- RSA Key Generation Implementation
 *
 * Implements RSA key generation:
 *   1. Prime generation (Miller-Rabin + trial division)
 *   2. RSA parameter computation (n = p*q, phi(n), lambda(n))
 *   3. Public/private exponent selection and computation
 *   4. CRT precomputation for efficient decryption
 *   5. Key validation
 *
 * Security-critical: prime generation quality directly determines
 * the security of the entire RSA system.
 *
 * Reference: ANSI X9.44, IEEE P1363, PKCS#1 v2.2 (RFC 8017)
 *            Katz & Lindell (2014), Ch. 8.2
 *            Menezes et al., HAC, Ch. 4, 8
 */

#include "rsa_keygen.h"
#include "tdp_core.h"
#include <string.h>
#include <stdio.h>

/* =========================================================================
 * RSA Private Exponent Computation -- L4 Fundamental Law
 *
 * Theorem (RSA correctness): For ed = 1 (mod phi(n)),
 *   For all x in Z_n: x^{ed} = x (mod n).
 *
 * Proof: By Euler's Theorem, if gcd(x,n)=1, x^{phi(n)} = 1.
 * ed = 1 + k*phi(n) => x^{ed} = x * (x^{phi(n)})^k = x.
 * For gcd(x,n) != 1, use CRT to show x^{ed} = x mod p and mod q.
 *
 * Reference: Rivest, Shamir, Adleman (1978), Section VIII.
 * ========================================================================= */

bool rsa_compute_private_exponent(bigint_t *d, const bigint_t *e, const bigint_t *phi_n) {
    /* Compute d = e^{-1} mod phi(n) using extended Euclidean algorithm.
     *
     * Requires gcd(e, phi(n)) = 1 for d to exist.
     * This is guaranteed if e is prime and does not divide phi(n),
     * which holds for standard choices e = 3, 17, 65537 with proper p,q.
     *
     * Complexity: O(log^2 phi(n)). */
    if (!d || !e || !phi_n) return false;
    return mod_inverse(d, e, phi_n);
}

/* =========================================================================
 * RSA Key Generation -- Main Entry Point
 *
 * Algorithm:
 *   1. Generate distinct random primes p, q of nbits/2 bits each.
 *   2. Compute n = p*q, phi(n) = (p-1)(q-1).
 *   3. Select e = 65537 (or generate if gcd(e,phi(n)) != 1).
 *   4. Compute d = e^{-1} mod phi(n).
 *   5. Precompute CRT parameters for efficient decryption.
 *
 * Complexity: Expected O(nbits^4 + nbits^5) due to primality tests.
 *
 * Reference: Rivest, Shamir, Adleman (1978).
 *            PKCS#1 v2.2, Section 3.
 * ========================================================================= */

tdp_status_t rsa_generate_keypair(rsa_keypair_t *key, uint32_t nbits, uint32_t seed) {
    if (!key || nbits < 64) return TDP_ERR_INVALID_PARAM;

    memset(key, 0, sizeof(rsa_keypair_t));
    uint32_t p_bits = nbits / 2;
    uint32_t q_bits = nbits - p_bits;

    bigint_t p, q, one;
    bigint_set_zero(&p);
    bigint_set_zero(&q);
    bigint_set_one(&one);

    /* Step 1: Generate prime p */
    if (!generate_random_prime(&p, p_bits, seed)) {
        return TDP_ERR_PRIMALITY_FAILED;
    }

    /* Step 2: Generate prime q, ensuring q != p */
    uint32_t seed2 = seed + 1000;
    if (!generate_random_prime(&q, q_bits, seed2)) {
        return TDP_ERR_PRIMALITY_FAILED;
    }

    /* Ensure p != q */
    uint32_t attempt = 0;
    while (bigint_compare(&p, &q) == 0 && attempt < 100) {
        seed2 += 1000;
        if (!generate_random_prime(&q, q_bits, seed2)) {
            return TDP_ERR_PRIMALITY_FAILED;
        }
        attempt++;
    }
    if (bigint_compare(&p, &q) == 0) return TDP_ERR_PRIMALITY_FAILED;

    /* Step 3: Compute n = p * q */
    bigint_mul(&key->params.n, &p, &q);
    key->params.p = p;
    key->params.q = q;
    key->params.nbits = bigint_bit_length(&key->params.n);

    /* Step 4: Compute phi(n) = (p-1)(q-1) */
    euler_totient_rsa(&key->params.phi_n, &p, &q);

    /* Step 5: Select e = 65537 (standard public exponent) */
    bigint_t e_default = bigint_from_uint64(RSA_DEFAULT_E);
    bigint_copy(&key->params.e, &e_default);

    /* Verify gcd(e, phi(n)) = 1 */
    bigint_t gcd_check;
    bigint_gcd(&gcd_check, &key->params.e, &key->params.phi_n);
    if (!bigint_is_one(&gcd_check)) {
        /* Fall back to e=17, then e=3 */
        bigint_t e17 = bigint_from_uint64(RSA_E_17);
        bigint_gcd(&gcd_check, &e17, &key->params.phi_n);
        if (bigint_is_one(&gcd_check)) {
            bigint_copy(&key->params.e, &e17);
        } else {
            bigint_t e3 = bigint_from_uint64(RSA_E_3);
            bigint_gcd(&gcd_check, &e3, &key->params.phi_n);
            if (bigint_is_one(&gcd_check)) {
                bigint_copy(&key->params.e, &e3);
            } else {
                return TDP_ERR_KEYGEN_FAILED;
            }
        }
    }

    /* Step 6: Compute d = e^{-1} mod phi(n) */
    if (!rsa_compute_private_exponent(&key->params.d, &key->params.e, &key->params.phi_n)) {
        return TDP_ERR_KEYGEN_FAILED;
    }

    /* Step 7: Precompute CRT values */
    rsa_precompute_crt(key);

    return TDP_SUCCESS;
}

/* =========================================================================
 * RSA Key Generation from Given Primes -- for testing with known primes
 *
 * Allows deterministic testing with fixed small primes.
 * ========================================================================= */

tdp_status_t rsa_keypair_from_primes(rsa_keypair_t *key,
                                      const bigint_t *p, const bigint_t *q,
                                      const bigint_t *e) {
    if (!key || !p || !q || !e) return TDP_ERR_INVALID_PARAM;

    memset(key, 0, sizeof(rsa_keypair_t));

    /* Verify p and q are distinct */
    if (bigint_compare(p, q) == 0) return TDP_ERR_INVALID_PARAM;

    /* Copy primes */
    bigint_copy(&key->params.p, p);
    bigint_copy(&key->params.q, q);

    /* Compute n = p * q */
    bigint_mul(&key->params.n, p, q);
    key->params.nbits = bigint_bit_length(&key->params.n);

    /* Compute phi(n) = (p-1)(q-1) */
    euler_totient_rsa(&key->params.phi_n, p, q);

    /* Set public exponent */
    bigint_copy(&key->params.e, e);

    /* Check gcd(e, phi(n)) = 1 */
    bigint_t gcd_check;
    bigint_gcd(&gcd_check, e, &key->params.phi_n);
    if (!bigint_is_one(&gcd_check)) return TDP_ERR_KEYGEN_FAILED;

    /* Compute d = e^{-1} mod phi(n) */
    if (!rsa_compute_private_exponent(&key->params.d, e, &key->params.phi_n)) {
        return TDP_ERR_KEYGEN_FAILED;
    }

    /* Precompute CRT values */
    rsa_precompute_crt(key);

    return TDP_SUCCESS;
}

/* =========================================================================
 * RSA Key Validation -- L4 Verification
 *
 * Validates that a key pair satisfies all the mathematical constraints
 * required for RSA correctness.
 * ========================================================================= */

bool rsa_validate_keypair(const rsa_keypair_t *key) {
    if (!key) return false;

    /* Check n = p * q */
    bigint_t n_check;
    bigint_mul(&n_check, &key->params.p, &key->params.q);
    if (bigint_compare(&n_check, &key->params.n) != 0) return false;

    /* Check phi(n) = (p-1)(q-1) */
    bigint_t phi_check;
    euler_totient_rsa(&phi_check, &key->params.p, &key->params.q);
    if (bigint_compare(&phi_check, &key->params.phi_n) != 0) return false;

    /* Check gcd(e, phi(n)) = 1 */
    bigint_t gcd_check;
    bigint_gcd(&gcd_check, &key->params.e, &key->params.phi_n);
    if (!bigint_is_one(&gcd_check)) return false;

    /* Check e * d = 1 (mod phi(n)) */
    bigint_t prod_check;
    mod_mul(&prod_check, &key->params.e, &key->params.d, &key->params.phi_n);
    if (!bigint_is_one(&prod_check)) return false;

    /* Check CRT precomputations:
     *   d_p = d mod (p-1) */
    bigint_t pm1;
    bigint_copy(&pm1, &key->params.p); bigint_dec(&pm1);
    bigint_t dp_check;
    bigint_t q2;
    bigint_divmod(&q2, &dp_check, &key->params.d, &pm1);
    if (bigint_compare(&dp_check, &key->d_p) != 0) return false;

    /*   d_q = d mod (q-1) */
    bigint_t qm1;
    bigint_copy(&qm1, &key->params.q); bigint_dec(&qm1);
    bigint_t dq_check;
    bigint_divmod(&q2, &dq_check, &key->params.d, &qm1);
    if (bigint_compare(&dq_check, &key->d_q) != 0) return false;

    /*   q_inv * q = 1 (mod p) */
    bigint_t inv_check;
    mod_mul(&inv_check, &key->q_inv, &key->params.q, &key->params.p);
    if (!bigint_is_one(&inv_check)) return false;

    return true;
}

/* =========================================================================
 * CRT Precomputation -- L5 Optimization
 *
 * Precompute values needed for Garner's CRT-based RSA decryption:
 *   d_p = d mod (p-1)
 *   d_q = d mod (q-1)
 *   q_inv = q^{-1} mod p
 *
 * Garner's algorithm (used in mod_exp_crt):
 *   m1 = c^{d_p} mod p
 *   m2 = c^{d_q} mod q
 *   h = q_inv * (m1 - m2) mod p
 *   m = m2 + h * q
 *
 * This provides ~4x speedup for RSA decryption since exponentiation
 * is done modulo the half-sized primes p and q.
 *
 * Reference: Menezes et al., HAC, Algorithm 14.75.
 * ========================================================================= */

void rsa_precompute_crt(rsa_keypair_t *key) {
    if (!key) return;

    /* d_p = d mod (p-1) */
    bigint_t pm1, qm1;
    bigint_copy(&pm1, &key->params.p); bigint_dec(&pm1);
    bigint_copy(&qm1, &key->params.q); bigint_dec(&qm1);

    bigint_t q_dummy, r;
    bigint_divmod(&q_dummy, &r, &key->params.d, &pm1);
    bigint_copy(&key->d_p, &r);

    /* d_q = d mod (q-1) */
    bigint_divmod(&q_dummy, &r, &key->params.d, &qm1);
    bigint_copy(&key->d_q, &r);

    /* q_inv = q^{-1} mod p */
    /* Ensure q < p for the modular inverse (swap if needed) */
    if (bigint_compare(&key->params.q, &key->params.p) < 0) {
        mod_inverse(&key->q_inv, &key->params.q, &key->params.p);
    } else {
        /* q > p: compute q mod p, then invert */
        bigint_t q_mod_p;
        bigint_t q2;
        bigint_divmod(&q2, &q_mod_p, &key->params.q, &key->params.p);
        mod_inverse(&key->q_inv, &q_mod_p, &key->params.p);
    }
}

/* =========================================================================
 * RSA Key Print -- Educational display
 * ========================================================================= */

void rsa_print_key_info(const rsa_keypair_t *key) {
    if (!key) { printf("RSA Key: (null)\n"); return; }

    printf("========================================\n");
    printf("RSA Key Pair Information\n");
    printf("========================================\n");
    printf("Modulus size: %u bits\n", key->params.nbits);

    bigint_print_hex("p      = ", &key->params.p);
    bigint_print_hex("q      = ", &key->params.q);
    bigint_print_hex("n      = ", &key->params.n);
    bigint_print_hex("e      = ", &key->params.e);
    bigint_print_hex("d      = ", &key->params.d);
    bigint_print_hex("phi(n) = ", &key->params.phi_n);
    bigint_print_hex("d_p    = ", &key->d_p);
    bigint_print_hex("d_q    = ", &key->d_q);
    bigint_print_hex("q_inv  = ", &key->q_inv);
    printf("========================================\n");
}
