/**
 * tdp_core.c — Core Trapdoor Permutation Implementation
 *
 * Implements the core TDP API: key pair management, domain sampling,
 * forward/inverse evaluation, permutation verification, and security
 * definitions (negligible functions, one-wayness advantage).
 *
 * Reference: Goldreich, Foundations of Cryptography Vol. 1 (2001), §2.4.4
 */

#include "tdp_core.h"
#include "modular_math.h"
#include <string.h>
#include <math.h>

/* ──── Negligible Function Check ──── */

bool tdp_is_negligible(double value, security_param_t lambda) {
    /* A function ε(λ) is negligible if for every positive polynomial p(·),
     * there exists an N such that for all λ > N, ε(λ) < 1/p(λ).
     *
     * We use the conservative threshold: ε(λ) < 2^{-λ}.
     * Since 2^{-λ} decays faster than any 1/poly(λ), any function
     * bounded by 2^{-λ} is indeed negligible.
     */
    if (value <= 0.0) return true;
    double threshold = pow(2.0, -(double)(int)lambda);
    return value < threshold;
}

/* ──── One-Wayness Advantage ──── */

double tdp_one_way_advantage(uint32_t success_count, uint32_t total_trials,
                              security_param_t lambda) {
    (void)lambda;
    if (total_trials == 0) return 0.0;
    /* Adv = Pr[success] = successes / trials */
    return (double)success_count / (double)total_trials;
}

bool tdp_advantage_is_significant(double advantage, security_param_t lambda) {
    /* Conservative bound: advantage > 2^{-λ/2} is significant. */
    double threshold = pow(2.0, -(double)(int)lambda / 2.0);
    return advantage > threshold;
}

/* ──── Key Pair Management ──── */

tdp_keypair_t tdp_keypair_init(void) {
    tdp_keypair_t kp;
    memset(&kp, 0, sizeof(kp));
    kp.pk.nbits = 0;
    kp.pk.modulus.nlimbs = 0;
    kp.pk.exponent.nlimbs = 0;
    kp.td.prime_p.nlimbs = 0;
    kp.td.prime_q.nlimbs = 0;
    kp.td.private_exp.nlimbs = 0;
    kp.td.totient.nlimbs = 0;
    kp.td.d_p.nlimbs = 0;
    kp.td.d_q.nlimbs = 0;
    kp.td.q_inv.nlimbs = 0;
    kp.lambda = 0;
    return kp;
}

void tdp_keypair_clear(tdp_keypair_t *kp) {
    if (kp) {
        memset(kp, 0, sizeof(*kp));
    }
}

/* ──── Domain Operations ──── */

tdp_domain_elem_t tdp_sample_domain(const tdp_public_key_t *pk) {
    tdp_domain_elem_t elem;
    memset(&elem, 0, sizeof(elem));

    if (!pk || pk->nbits == 0) {
        elem.in_domain = false;
        return elem;
    }

    /* For RSA domain D = Z_n^* = {x ∈ [1, n-1] : gcd(x, n) = 1}.
     * We sample by generating a random value in [1, n-1] and checking gcd.
     * For a proper sample, we should also ensure uniform distribution,
     * which we approximate here.
     *
     * In practice: Pr[gcd(x,n) ≠ 1] = 1 - φ(n)/n ≈ (p+q-1)/pq ≈ 2/√n,
     * which is negligible for RSA-sized n.
     */
    bigint_t one = BIGINT_ONE;
    bigint_t nm1;
    bigint_copy(&nm1, &pk->modulus);
    bigint_dec(&nm1); /* n-1 */

    /* Deterministic sampling for testing (not cryptographically secure).
     * In production, use a proper CSPRNG. */
    uint32_t seed = 42;
    bigint_rand_range(&elem.value, &nm1, seed);

    /* Ensure x ≥ 1 */
    if (bigint_is_zero(&elem.value)) {
        bigint_copy(&elem.value, &one);
    }

    /* Check domain membership */
    elem.in_domain = tdp_check_domain_membership(pk, &elem.value);

    return elem;
}

bool tdp_check_domain_membership(const tdp_public_key_t *pk, const bigint_t *x) {
    if (!pk || !x) return false;

    /* Check 1 ≤ x < n */
    bigint_t one = BIGINT_ONE;
    if (bigint_compare(x, &one) < 0) return false;
    if (bigint_compare(x, &pk->modulus) >= 0) return false;

    /* Check gcd(x, n) == 1 */
    bigint_t gcd;
    bigint_gcd(&gcd, x, &pk->modulus);
    return bigint_is_one(&gcd);
}

/* ──── Forward and Inverse Evaluation ──── */

tdp_eval_result_t tdp_eval_forward(const tdp_public_key_t *pk,
                                    const tdp_domain_elem_t *x) {
    tdp_eval_result_t result;
    memset(&result, 0, sizeof(result));
    result.valid = false;

    if (!pk || !x || !x->in_domain) {
        return result;
    }

    /* y = x^e mod n (RSA forward) */
    mod_exp(&result.value, &x->value, &pk->exponent, &pk->modulus);
    result.valid = true;

    return result;
}

tdp_domain_elem_t tdp_eval_inverse(const tdp_public_key_t *pk,
                                    const tdp_trapdoor_t *td,
                                    const tdp_eval_result_t *y) {
    tdp_domain_elem_t result;
    memset(&result, 0, sizeof(result));
    result.in_domain = false;

    if (!pk || !td || !y || !y->valid) {
        return result;
    }

    /* x = y^d mod n using CRT for speed */
    mod_exp_crt(&result.value, &y->value,
                &td->d_p, &td->d_q, &td->q_inv,
                &td->prime_p, &td->prime_q);

    result.in_domain = tdp_check_domain_membership(pk, &result.value);
    return result;
}

bool tdp_verify_permutation_property(const tdp_public_key_t *pk,
                                      const tdp_trapdoor_t *td,
                                      const tdp_domain_elem_t *x) {
    if (!pk || !td || !x || !x->in_domain) return false;

    /* Check f^{-1}(f(x)) == x */
    tdp_eval_result_t y = tdp_eval_forward(pk, x);
    if (!y.valid) return false;

    tdp_domain_elem_t recovered = tdp_eval_inverse(pk, td, &y);
    if (!recovered.in_domain) return false;

    bool forward_then_inverse = (bigint_compare(&recovered.value, &x->value) == 0);

    /* Check f(f^{-1}(x)) == x (for the x in the domain as image) */
    tdp_eval_result_t x_as_image;
    x_as_image.value = x->value;
    x_as_image.valid = true;

    tdp_domain_elem_t preimage = tdp_eval_inverse(pk, td, &x_as_image);
    if (!preimage.in_domain) return false;

    tdp_eval_result_t re_forward = tdp_eval_forward(pk, &preimage);
    if (!re_forward.valid) return false;

    bool inverse_then_forward = (bigint_compare(&re_forward.value, &x->value) == 0);

    return forward_then_inverse && inverse_then_forward;
}

/* ──── Domain Size ──── */

void tdp_domain_size_approx(const tdp_public_key_t *pk, const tdp_trapdoor_t *td,
                             bigint_t *out) {
    if (!pk || !td || !out) return;

    /* |D_i| = φ(n) = (p-1)(q-1) = n - (p+q) + 1 ≈ n */
    bigint_copy(out, &td->totient);
}

/* ──── TDP Collection Description ──── */

tdp_collection_info_t tdp_collection_describe(security_param_t lambda) {
    tdp_collection_info_t info;
    info.lambda = lambda;
    info.domain_size_bits = lambda;
    info.family_name = "RSA";
    info.hardness_assumption = "RSA Assumption / Factoring";
    return info;
}
