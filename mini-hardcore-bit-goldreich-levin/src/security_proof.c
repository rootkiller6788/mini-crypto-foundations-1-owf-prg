/*
 * security_proof.c — Security Parameters, Error Bounds & Probability
 *
 * Implements the security analysis framework needed for the
 * Goldreich-Levin theorem: negligible functions, Chernoff/Hoeffding
 * bounds, sample complexity calculations, and security level
 * estimation.
 *
 * Knowledge Points Covered:
 *   L1: Negligible function definition, security parameter
 *   L2: Concrete vs asymptotic security
 *   L3: Chernoff/Hoeffding bounds as probability inequalities
 *   L5: Sample complexity from concentration bounds
 *   L7: Security level estimation for cryptographic parameters
 *   L8: Statistical distance and computational indistinguishability
 *
 * Reference: Arora-Barak §9.1, Goldreich Vol.1 §1.2
 * Courses: MIT 6.875, Stanford CS255, Princeton COS 551
 */

#include "security_params.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* ───────────────────────────────────────────────────────────────
 * Negligible Functions
 *
 * Definition (L1): A function μ: ℕ → ℝ is negligible if for every
 * polynomial p(·), ∃ N such that ∀ n > N, μ(n) < 1/p(n).
 *
 * Standard negligible functions:
 *   - negl(n) = 2^{-n}        (exponential)
 *   - negl(n) = n^{-log n}    (super-polynomial)
 *   - negl(n) = 2^{-√n}       (sub-exponential)
 * ───────────────────────────────────────────────────────────── */

int is_negligible(double value, size_t n) {
    if (n == 0) return 0;
    /* Compare with 2^{-n} */
    double threshold = 1.0;
    for (size_t i = 0; i < n; i++) threshold /= 2.0;
    return value < threshold ? 1 : 0;
}

double negl_exponential(size_t n) {
    double val = 1.0;
    for (size_t i = 0; i < n; i++) val /= 2.0;
    return val;
}

double negl_superpoly(size_t n) {
    if (n == 0) return 1.0;
    /* n^{-log n} = exp(-(log n)^2) */
    double logn = log((double)n);
    return exp(-logn * logn);
}

double negl_subexponential(size_t n) {
    /* 2^{-√n} = exp(-√n · ln 2) */
    return exp(-sqrt((double)n) * log(2.0));
}

int verify_negligible(double (*f)(size_t), size_t max_n) {
    if (!f) return 0;
    /* Check that for polynomial p(n)=n, f(n) < 1/n eventually */
    int crossover_found = 0;
    for (size_t n = 1; n <= max_n; n++) {
        double fn = f(n);
        double threshold = 1.0 / (double)n;
        if (fn < threshold) crossover_found = 1;
        if (crossover_found && fn >= threshold) return 0; /* not monotonic enough */
    }
    return crossover_found;
}

/* ───────────────────────────────────────────────────────────────
 * Probability Bounds — Chernoff/Hoeffding
 *
 * Chernoff bound (multiplicative):
 *   Let X₁,...,X_m be i.i.d. {0,1} with E[X_i] = μ/m.
 *   For δ ∈ [0,1]:
 *     Pr[ΣX_i ≥ (1+δ)μ] ≤ exp(-δ²μ/3)
 *     Pr[ΣX_i ≤ (1-δ)μ] ≤ exp(-δ²μ/2)
 *
 * Hoeffding bound (additive):
 *   Pr[|(1/m)ΣX_i - p| ≥ ε] ≤ 2 exp(-2mε²)
 *
 * These bounds ensure that with enough samples, the empirical
 * average concentrates around the true mean.
 * ───────────────────────────────────────────────────────────── */

double chernoff_upper(double mu, double delta) {
    if (mu <= 0.0 || delta <= 0.0) return 1.0;
    return exp(-delta * delta * mu / 3.0);
}

double chernoff_lower(double mu, double delta) {
    if (mu <= 0.0 || delta <= 0.0) return 1.0;
    return exp(-delta * delta * mu / 2.0);
}

double hoeffding_bound(size_t m, double epsilon) {
    if (m == 0 || epsilon <= 0.0) return 1.0;
    return 2.0 * exp(-2.0 * (double)m * epsilon * epsilon);
}

double chernoff_two_sided(size_t m, double epsilon) {
    /* Pr[|(1/m)ΣX_i - p| ≥ ε] ≤ 2 exp(-2mε²/3) using Chernoff */
    if (m == 0 || epsilon <= 0.0) return 1.0;
    return 2.0 * exp(-2.0 * (double)m * epsilon * epsilon / 3.0);
}

/* ───────────────────────────────────────────────────────────────
 * Sample Complexity
 *
 * Given desired error ε and confidence δ, how many samples m
 * are needed for the empirical mean to be ε-close to the true mean?
 *
 * From Hoeffding: m ≥ ln(2/δ) / (2ε²)
 * From Chernoff:  m ≥ 3 ln(2/δ) / (ε²μ)  [multiplicative]
 *
 * GL-specific: m ≥ c · n / ε²  to amortize over n bits
 * ───────────────────────────────────────────────────────────── */

size_t chernoff_sample_size(double epsilon, double delta) {
    if (epsilon <= 0.0 || delta <= 0.0) return ~(size_t)0;
    double m = 3.0 * log(2.0 / delta) / (epsilon * epsilon);
    if (m < 1.0) m = 1.0;
    return (size_t)m;
}

size_t hoeffding_sample_size(double epsilon, double delta) {
    if (epsilon <= 0.0 || delta <= 0.0) return ~(size_t)0;
    double m = log(2.0 / delta) / (2.0 * epsilon * epsilon);
    if (m < 1.0) m = 1.0;
    return (size_t)m;
}

size_t gl_sample_complexity(size_t n, double epsilon, double delta) {
    if (epsilon <= 0.0 || delta <= 0.0) return ~(size_t)0;
    /* GL requires m = O(n/ε² · log(n/δ)) */
    double m = (double)n * log((double)n / delta) / (epsilon * epsilon);
    if (m < 10.0) m = 10.0;
    return (size_t)m;
}

/* ───────────────────────────────────────────────────────────────
 * Advantage and Error
 * ───────────────────────────────────────────────────────────── */

double advantage_to_accuracy(double epsilon) {
    return 0.5 + epsilon;
}

double accuracy_to_advantage(double accuracy) {
    double adv = accuracy - 0.5;
    return adv > 0.0 ? adv : 0.0;
}

int is_nonnegl_advantage(double epsilon, size_t n) {
    /* Advantage is non-negligible if ε > 1/poly(n) */
    if (n == 0) return epsilon > 0.0 ? 1 : 0;
    double poly_bound = 1.0 / (double)(n * n);
    return epsilon > poly_bound ? 1 : 0;
}

/* ───────────────────────────────────────────────────────────────
 * Probability Distributions
 *
 * Statistical distance (total variation distance):
 *   Δ(P, Q) = (1/2) Σ_i |P(i) - Q(i)|
 *
 * Two distributions are computationally indistinguishable if no
 * PPT distinguisher can tell them apart with non-negligible advantage.
 * ───────────────────────────────────────────────────────────── */

double rand_double(void) {
    return (double)rand() / (double)RAND_MAX;
}

size_t sample_discrete(const double* probs, size_t n) {
    if (!probs || n == 0) return 0;
    double r = rand_double();
    double cumulative = 0.0;
    for (size_t i = 0; i < n; i++) {
        cumulative += probs[i];
        if (r <= cumulative) return i;
    }
    return n - 1;
}

double statistical_distance(const double* p, const double* q, size_t n) {
    if (!p || !q || n == 0) return 0.0;
    double dist = 0.0;
    for (size_t i = 0; i < n; i++) {
        double diff = p[i] - q[i];
        if (diff < 0) diff = -diff;
        dist += diff;
    }
    return dist / 2.0;
}

double compute_advantage_distinguisher(const double* dist1, const double* dist2,
                                        size_t n) {
    /* The optimal distinguisher's advantage = statistical distance */
    return statistical_distance(dist1, dist2, n);
}

/* ───────────────────────────────────────────────────────────────
 * Error Correction — Majority Vote
 *
 * Majority vote amplifies correctness probability:
 * If each vote is correct with probability p > 1/2, then the
 * majority of m independent votes is correct with probability:
 *   Pr[majority correct] = Σ_{k=⌈m/2⌉}^m C(m,k) p^k (1-p)^{m-k}
 *
 * By Chernoff, this probability is ≥ 1 - exp(-2m(p-1/2)²).
 * ───────────────────────────────────────────────────────────── */

int majority_vote(const int* votes, size_t m) {
    if (!votes || m == 0) return 0;
    size_t ones = 0;
    for (size_t i = 0; i < m; i++) {
        if (votes[i]) ones++;
    }
    return (ones > m / 2) ? 1 : 0;
}

int weighted_majority_vote(const int* votes, const double* weights, size_t m) {
    if (!votes || !weights || m == 0) return 0;
    double wsum = 0.0;
    for (size_t i = 0; i < m; i++) {
        wsum += votes[i] ? weights[i] : -weights[i];
    }
    return (wsum > 0.0) ? 1 : 0;
}

double majority_correct_prob(size_t m, double p) {
    if (m == 0 || p <= 0.5) return p;
    /* Chernoff bound: Pr[majority wrong] ≤ exp(-2m(p-1/2)²) */
    double delta = p - 0.5;
    return 1.0 - exp(-2.0 * (double)m * delta * delta);
}

size_t majority_sample_size(double p, double delta) {
    if (p <= 0.5 || delta <= 0.0) return ~(size_t)0;
    double gap = p - 0.5;
    double m = log(1.0 / delta) / (2.0 * gap * gap);
    if (m < 1.0) m = 1.0;
    return (size_t)m;
}

/* ───────────────────────────────────────────────────────────────
 * Security Level
 *
 * Maps abstract security levels to concrete parameter sizes.
 * Based on NIST recommendations and current cryptanalytic
 * understanding (as of 2025).
 * ───────────────────────────────────────────────────────────── */

size_t security_level_to_n(SecurityLevel level) {
    switch (level) {
        case SEC_LEVEL_NONE:    return 0;
        case SEC_LEVEL_WEAK:    return 64;
        case SEC_LEVEL_MEDIUM:  return 128;
        case SEC_LEVEL_STANDARD: return 256;
        case SEC_LEVEL_HIGH:    return 384;
        case SEC_LEVEL_PARANOID: return 512;
        default: return 0;
    }
}

SecurityLevel estimate_security_level(size_t key_bits, double epsilon) {
    /* Rough estimation: security = min(key_bits/2, log(1/ε)) */
    double security = (double)key_bits / 2.0;
    if (epsilon > 0.0) {
        double eps_security = -log2(epsilon);
        if (eps_security < security) security = eps_security;
    }
    if (security >= 256) return SEC_LEVEL_PARANOID;
    if (security >= 192) return SEC_LEVEL_HIGH;
    if (security >= 128) return SEC_LEVEL_STANDARD;
    if (security >= 80)  return SEC_LEVEL_MEDIUM;
    if (security >= 40)  return SEC_LEVEL_WEAK;
    return SEC_LEVEL_NONE;
}

/* ───────────────────────────────────────────────────────────────
 * Key Length Recommendations
 * ───────────────────────────────────────────────────────────── */

KeyLenRecommendation* keylen_for_level(SecurityLevel level) {
    KeyLenRecommendation* rec = (KeyLenRecommendation*)malloc(sizeof(KeyLenRecommendation));
    if (!rec) return NULL;
    switch (level) {
        case SEC_LEVEL_NONE:
            rec->rsa_key_bits = 0; rec->dlog_key_bits = 0;
            rec->symmetric_key_bits = 0; rec->hash_output_bits = 0;
            break;
        case SEC_LEVEL_WEAK:
            rec->rsa_key_bits = 512; rec->dlog_key_bits = 512;
            rec->symmetric_key_bits = 64; rec->hash_output_bits = 128;
            break;
        case SEC_LEVEL_MEDIUM:
            rec->rsa_key_bits = 1024; rec->dlog_key_bits = 1024;
            rec->symmetric_key_bits = 80; rec->hash_output_bits = 160;
            break;
        case SEC_LEVEL_STANDARD:
            rec->rsa_key_bits = 3072; rec->dlog_key_bits = 3072;
            rec->symmetric_key_bits = 128; rec->hash_output_bits = 256;
            break;
        case SEC_LEVEL_HIGH:
            rec->rsa_key_bits = 7680; rec->dlog_key_bits = 7680;
            rec->symmetric_key_bits = 192; rec->hash_output_bits = 384;
            break;
        case SEC_LEVEL_PARANOID:
            rec->rsa_key_bits = 15360; rec->dlog_key_bits = 15360;
            rec->symmetric_key_bits = 256; rec->hash_output_bits = 512;
            break;
        default:
            free(rec); return NULL;
    }
    return rec;
}

void keylen_recommendation_free(KeyLenRecommendation* rec) {
    free(rec);
}

void keylen_print_recommendation(SecurityLevel level) {
    KeyLenRecommendation* rec = keylen_for_level(level);
    if (!rec) { printf("Invalid security level.\n"); return; }
    printf("Key Length Recommendations (Level %d):\n", (int)level);
    printf("  RSA key bits:        %zu\n", rec->rsa_key_bits);
    printf("  DLOG key bits:       %zu\n", rec->dlog_key_bits);
    printf("  Symmetric key bits:  %zu\n", rec->symmetric_key_bits);
    printf("  Hash output bits:    %zu\n", rec->hash_output_bits);
    keylen_recommendation_free(rec);
}

/* ───────────────────────────────────────────────────────────────
 * Randomness Generation
 *
 * In real cryptographic code, these would use OS entropy sources.
 * For educational purposes, we use rand() with additional mixing.
 * ───────────────────────────────────────────────────────────── */

void secure_random_seed(void) {
    srand((unsigned int)time(NULL));
}

void secure_random_bytes(uint8_t* buf, size_t n) {
    if (!buf) return;
    for (size_t i = 0; i < n; i++) {
        unsigned int r = (unsigned int)rand();
        buf[i] = (uint8_t)((r ^ (r >> 7) ^ (r >> 13)) & 0xFF);
    }
}

double estimate_entropy(const uint8_t* data, size_t len) {
    if (!data || len == 0) return 0.0;
    /* Estimate Shannon entropy from byte frequencies */
    size_t freq[256] = {0};
    for (size_t i = 0; i < len; i++) {
        freq[data[i]]++;
    }
    double entropy = 0.0;
    double inv_len = 1.0 / (double)len;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] * inv_len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}
