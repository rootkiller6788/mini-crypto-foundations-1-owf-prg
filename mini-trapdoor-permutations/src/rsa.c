/**
 * rsa.c -- RSA Trapdoor Permutation Implementation
 *
 * Implements the RSA trapdoor permutation family:
 *   Forward:  f(x) = x^e mod n    (encryption)
 *   Inverse:  f^{-1}(y) = y^d mod n (decryption with trapdoor)
 *
 * The RSA Assumption: Given (n, e) and y = x^e mod n for random x in Z_n^*,
 * it is computationally infeasible to recover x without knowing d.
 *
 * Also implements:
 *   - CRT-accelerated decryption
 *   - Multiplicative homomorphism verification
 *   - Random self-reducibility of RSA
 *   - Security advantage computation
 *
 * Reference: Rivest, Shamir, Adleman, "A Method for Obtaining Digital
 *            Signatures and Public-Key Cryptosystems," CACM 21(2), 1978.
 *            Goldreich, Foundations of Cryptography Vol. 1, Ch. 2.
 *            Katz & Lindell (2014), Ch. 10.
 */

#include "rsa.h"
#include "modular_math.h"
#include "tdp_core.h"
#include <string.h>
#include <math.h>

/* =========================================================================
 * RSA Core Operations -- L6 Canonical Problem (RSA)
 *
 * The RSA function family {RSA_{n,e} : Z_n^* -> Z_n^*} where:
 *   RSA_{n,e}(x) = x^e mod n
 *   RSA^{-1}_{n,d}(y) = y^d mod n
 *
 * This is the canonical example of a trapdoor permutation.
 * Trapdoor: knowledge of d allows efficient inversion.
 * ========================================================================= */

tdp_eval_result_t rsa_encrypt(const rsa_params_t *params, const bigint_t *x) {
    /* RSA forward permutation (encryption):
     *   y = x^e mod n
     *
     * This is the "easy" direction -- computable with only the public key.
     *
     * Complexity: O(log e * log^2 n) using square-and-multiply.
     * For standard e = 65537: about 17 modular multiplications. */
    tdp_eval_result_t result;
    memset(&result, 0, sizeof(result));
    result.valid = false;

    if (!params || !x) return result;
    if (bigint_is_zero(x)) return result;

    mod_exp(&result.value, x, &params->e, &params->n);
    result.valid = true;
    return result;
}

tdp_domain_elem_t rsa_decrypt_crt(const rsa_keypair_t *key, const bigint_t *y) {
    /* RSA inverse permutation with CRT optimization (decryption):
     *   x = y^d mod n
     *
     * Uses Garner's CRT algorithm for ~4x speedup:
     *   x_p = y^{d_p} mod p
     *   x_q = y^{d_q} mod q
     *   h   = q_inv * (x_p - x_q) mod p
     *   x   = x_q + h * q
     *
     * This is the "hard" direction -- requires trapdoor knowledge.
     * Without d (or p,q), this is assumed to be infeasible.
     *
     * Complexity: O(log d_p * log^2 p) ~= 1/4 * O(log d * log^2 n).
     *
     * Reference: Menezes et al., HAC, Algorithm 14.75. */
    tdp_domain_elem_t result;
    memset(&result, 0, sizeof(result));
    result.in_domain = false;

    if (!key || !y) return result;
    if (bigint_is_zero(y)) return result;

    mod_exp_crt(&result.value, y,
                &key->d_p, &key->d_q,
                &key->q_inv,
                &key->params.p, &key->params.q);

    /* Verify result is in domain */
    result.in_domain = tdp_check_domain_membership(
        &(tdp_public_key_t){.modulus = key->params.n, .exponent = key->params.e,
                            .nbits = key->params.nbits},
        &result.value);
    return result;
}

tdp_domain_elem_t rsa_decrypt_naive(const rsa_params_t *params, const bigint_t *y) {
    /* RSA naive decrypt (without CRT, for comparison/benchmarking):
     *   x = y^d mod n
     *
     * Complexity: O(log d * log^2 n) -- about 4x slower than CRT version.
     *
     * Included to concretely demonstrate the performance benefit
     * of the CRT optimization. */
    tdp_domain_elem_t result;
    memset(&result, 0, sizeof(result));
    result.in_domain = false;

    if (!params || !y) return result;
    if (bigint_is_zero(y)) return result;

    mod_exp(&result.value, y, &params->d, &params->n);

    result.in_domain = true;
    return result;
}

/* =========================================================================
 * RSA Signing and Verification -- Digital signature application
 *
 * In the signature context, the roles are reversed:
 *   Sign:  sigma = H(m)^d mod n  (use trapdoor/inverse)
 *   Verify: check sigma^e == H(m) mod n (use public key/forward)
 * ========================================================================= */

tdp_domain_elem_t rsa_sign(const rsa_keypair_t *key, const bigint_t *message_hash) {
    /* RSA signing: sigma = h(m)^d mod n.
     * This is the inverse permutation -- uses the trapdoor.
     *
     * WARNING: This is "textbook RSA signing." Real implementations
     * MUST use padding (PSS or FDH). Without padding, existential
     * forgery and chosen-message attacks are trivial.
     *
     * Complexity: O(log d * log^2 n). */
    return rsa_decrypt_crt(key, message_hash);
}

tdp_eval_result_t rsa_verify(const rsa_params_t *params, const bigint_t *signature) {
    /* RSA verification: check sigma^e mod n.
     * This is the forward permutation -- uses only the public key.
     *
     * Complexity: O(log e * log^2 n). */
    return rsa_encrypt(params, signature);
}

/* =========================================================================
 * RSA Multiplicative Homomorphism -- L2 Core Concept
 *
 * RSA has the property: RSA(x1 * x2) = RSA(x1) * RSA(x2) mod n.
 *
 * (x1 * x2)^e = x1^e * x2^e (mod n)
 *
 * This is a fundamental algebraic property with dual implications:
 *   Beneficial: Enables homomorphic encryption applications.
 *   Dangerous:  Makes textbook RSA malleable -- attacker can modify
 *               ciphertexts in predictable ways. This is why padding
 *               (OAEP, PSS) is essential for secure constructions.
 *
 * Reference: Rivest, Shamir, Adleman (1978), Section IV.
 * ========================================================================= */

bool rsa_verify_homomorphism(const rsa_params_t *params,
                              const bigint_t *x1, const bigint_t *x2) {
    /* Verify that RSA(x1 * x2) = RSA(x1) * RSA(x2) mod n.
     *
     * This demonstrates the multiplicative homomorphism concretely:
     *   1. Compute y1 = x1^e mod n
     *   2. Compute y2 = x2^e mod n
     *   3. Compute y12_direct = (x1 * x2 mod n)^e mod n
     *   4. Compute y12_product = (y1 * y2) mod n
     *   5. Check y12_direct == y12_product
     *
     * Complexity: O(log e * log^2 n). */
    if (!params || !x1 || !x2) return false;

    /* y1 = x1^e mod n */
    tdp_eval_result_t y1 = rsa_encrypt(params, x1);
    if (!y1.valid) return false;

    /* y2 = x2^e mod n */
    tdp_eval_result_t y2 = rsa_encrypt(params, x2);
    if (!y2.valid) return false;

    /* x12 = x1 * x2 mod n */
    bigint_t x12;
    mod_mul(&x12, x1, x2, &params->n);

    /* y12_direct = x12^e mod n */
    tdp_eval_result_t y12_direct = rsa_encrypt(params, &x12);
    if (!y12_direct.valid) return false;

    /* y12_product = y1 * y2 mod n */
    bigint_t y12_product;
    mod_mul(&y12_product, &y1.value, &y2.value, &params->n);

    return bigint_compare(&y12_direct.value, &y12_product) == 0;
}

/* =========================================================================
 * Public Exponent Validation
 * ========================================================================= */

bool rsa_check_public_exponent(const bigint_t *e, const bigint_t *phi_n) {
    /* Check that e is a valid public exponent:
     *   gcd(e, phi(n)) = 1
     *
     * This ensures the private exponent d = e^{-1} mod phi(n) exists.
     * Standard choices: 3, 17, 65537 (all primes, co-prime to phi(n)
     * for properly generated p,q).
     *
     * Complexity: O(log^2 n). */
    if (!e || !phi_n) return false;

    bigint_t two_check;
    bigint_set_one(&two_check); bigint_inc(&two_check);

    /* e must be >= 3 and odd (e=2 is invalid because gcd(2, phi(n)) > 1
     * since phi(n) = (p-1)(q-1) is even for p,q > 2) */
    if (bigint_compare(e, &two_check) <= 0) return false;
    if (bigint_is_even(e)) return false;

    bigint_t gcd_result;
    bigint_gcd(&gcd_result, e, phi_n);
    return bigint_is_one(&gcd_result);
}

/* =========================================================================
 * Random Self-Reducibility of RSA -- L4 Fundamental Law
 *
 * The RSA problem is random self-reducible: an average-case RSA oracle
 * can be turned into a worst-case RSA solver.
 *
 * Given y = x^e mod n:
 *   1. Choose random r in Z_n^*.
 *   2. Blind: z = y * r^e mod n = (x*r)^e mod n.
 *   3. Get z^{1/e} = x*r from the oracle.
 *   4. Unblind: x = (x*r) * r^{-1} mod n.
 *
 * This property is crucial for security reductions: if there exists
 * an algorithm that inverts RSA on a non-negligible fraction of inputs,
 * then there exists an algorithm that inverts RSA on ALL inputs.
 *
 * Reference: Goldreich (2001), Section 2.4.4.
 *            Rivest, Shamir, Adleman (1978).
 * ========================================================================= */

void rsa_random_self_reduce(const rsa_params_t *params, const bigint_t *y,
                             bigint_t *blinded_y, bigint_t *r, bigint_t *r_inv) {
    /* Perform random self-reduction of an RSA instance.
     *
     * Input:  y = x^e mod n (the challenge we want to invert)
     * Output: blinded_y = y * r^e mod n (the randomized challenge)
     *         r = random multiplier
     *         r_inv = r^{-1} mod n (for unblinding)
     *
     * Complexity: O(log^2 n). */
    if (!params || !y || !blinded_y || !r || !r_inv) return;

    /* Generate random r in Z_n^* */
    /* First get r in [1, n-1] */
    bigint_t nm1;
    bigint_copy(&nm1, &params->n); bigint_dec(&nm1);

    /* For simplicity, use r = 2 or another fixed small value.
     * In a real implementation, sample uniformly from Z_n^*. */
    bigint_t two;
    bigint_set_one(&two); bigint_inc(&two); /* r = 2 */
    bigint_copy(r, &two);

    /* Ensure gcd(r, n) = 1 */
    bigint_t gcd_rn;
    bigint_gcd(&gcd_rn, r, &params->n);
    if (!bigint_is_one(&gcd_rn)) {
        /* Try r = 3 */
        bigint_t three;
        bigint_set_one(&three); bigint_inc(&three); bigint_inc(&three);
        bigint_copy(r, &three);
    }

    /* Compute r_inv = r^{-1} mod n */
    mod_inverse(r_inv, r, &params->n);

    /* Compute r^e mod n */
    bigint_t r_e;
    mod_exp(&r_e, r, &params->e, &params->n);

    /* blinded_y = y * r^e mod n */
    mod_mul(blinded_y, y, &r_e, &params->n);
}

void rsa_random_self_unblind(const rsa_params_t *params, const bigint_t *blinded_x,
                              const bigint_t *r_inv, bigint_t *x) {
    /* Recover original plaintext from blinded version:
     *   x = blinded_x * r_inv mod n
     *
     * Since blinded_x = x * r (mod n) and r_inv = r^{-1} (mod n):
     *   blinded_x * r_inv = x * r * r^{-1} = x (mod n).
     *
     * Complexity: O(log^2 n). */
    if (!params || !blinded_x || !r_inv || !x) return;

    mod_mul(x, blinded_x, r_inv, &params->n);
}

/* =========================================================================
 * RSA Security Advantage -- L1 Definition
 *
 * Adv_A^{RSA}(lambda) = Pr[A(n, e, x^e mod n) = x]
 * where (n,e,d) <- Gen(1^lambda), x <- Z_n^*.
 *
 * The RSA Assumption: For all PPT A, Adv_A^{RSA}(lambda) is negligible.
 * ========================================================================= */

double rsa_assumption_advantage(uint32_t success_count, uint32_t trials,
                                 security_param_t lambda) {
    /* Compute the empirical advantage of an RSA adversary.
     *
     * Advantage = Pr[success] = successes / trials.
     *
     * If this advantage is non-negligible (greater than 2^{-lambda/2}),
     * then the RSA assumption is considered broken at this security
     * parameter.
     *
     * Reference: Goldreich (2001), Definition 2.3.1. */
    (void)lambda;
    if (trials == 0) return 0.0;
    return (double)success_count / (double)trials;
}
