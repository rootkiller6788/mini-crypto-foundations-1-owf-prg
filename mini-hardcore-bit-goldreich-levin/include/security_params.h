/*
 * security_params.h — Security Parameters, Error Bounds & Probability
 *
 * This module provides the security analysis tools needed for the
 * Goldreich-Levin theorem: probability bounds, negligible functions,
 * Chernoff/Hoeffding inequalities, and concrete security parameter
 * calculations.
 *
 * Negligible Functions:
 *   A function μ: ℕ → ℝ is negligible if ∀ polynomial p(·), ∃ N s.t.
 *   ∀ n > N, μ(n) < 1/p(n). Notation: μ(n) = negl(n).
 *
 *   Examples: 2^{-n}, n^{-log n}, 2^{-√n}
 *   Non-examples: 1/n^{100}, 1/2^{log n} = 1/n
 *
 * Concrete vs Asymptotic Security:
 *   Asymptotic: "adversary succeeds with negl(n) probability"
 *   Concrete: "adversary succeeds with ≤ 2^{-128} probability for n=256"
 *
 * Chernoff Bound (Hoeffding Inequality):
 *   Let X₁,...,X_m be independent {0,1} random variables with
 *   E[X_i] = p. Let S = Σ X_i. Then for any δ ≥ 0:
 *     Pr[S ≥ (1+δ)pm] ≤ exp(-δ²pm/3)
 *     Pr[S ≤ (1-δ)pm] ≤ exp(-δ²pm/2)
 *
 * Reference: Arora-Barak §9.1, Goldreich Vol.1 §1.2
 * Courses: MIT 6.875, Stanford CS255, Princeton COS 551
 */

#ifndef SECURITY_PARAMS_H
#define SECURITY_PARAMS_H

#include <stdlib.h>
#include <stdint.h>
#include <math.h>

/* ── Negligible Functions ────────────────────────────────── */
/* Check if value is negligible (< 2^{-n}) */
int    is_negligible(double value, size_t n);
/* Standard negligible function: 2^{-n} */
double negl_exponential(size_t n);
/* Negligible function: n^{-log n} */
double negl_superpoly(size_t n);
/* Negligible function: 2^{-sqrt(n)} */
double negl_subexponential(size_t n);
/* Check if f(n) is negligible (∀ poly p, ∃ N, ∀ n>N, f(n) < 1/p(n)) */
int    verify_negligible(double (*f)(size_t), size_t max_n);

/* ── Probability Bounds ──────────────────────────────────── */
/* Chernoff bound: upper tail Pr[S ≥ (1+δ)μ] */
double chernoff_upper(double mu, double delta);
/* Chernoff bound: lower tail Pr[S ≤ (1-δ)μ] */
double chernoff_lower(double mu, double delta);
/* Hoeffding bound: Pr[|S/m - p| ≥ ε] ≤ 2 exp(-2mε²) */
double hoeffding_bound(size_t m, double epsilon);
/* Two-sided Chernoff: Pr[|S/m - p| ≥ δ] */
double chernoff_two_sided(size_t m, double epsilon);

/* ── Sample Complexity ───────────────────────────────────── */
/* Minimum samples for Chernoff: Pr[|avg - μ| ≥ ε] ≤ δ */
size_t chernoff_sample_size(double epsilon, double delta);
/* Minimum samples for Hoeffding */
size_t hoeffding_sample_size(double epsilon, double delta);
/* GL-specific sample complexity: O(n/ε²) */
size_t gl_sample_complexity(size_t n, double epsilon, double delta);

/* ── Advantage and Error ─────────────────────────────────── */
/* Convert between advantage ε and accuracy (1/2 + ε) */
double advantage_to_accuracy(double epsilon);
double accuracy_to_advantage(double accuracy);
/* Check if advantage is non-negligible */
int    is_nonnegl_advantage(double epsilon, size_t n);

/* ── Probability Distributions ───────────────────────────── */
/* Generate random double in [0, 1) */
double rand_double(void);
/* Generate random index with given probability distribution */
size_t sample_discrete(const double* probs, size_t n);
/* Statistical distance between two distributions */
double statistical_distance(const double* p, const double* q, size_t n);
/* Computational indistinguishability test framework */
double compute_advantage_distinguisher(const double* dist1, const double* dist2,
                                        size_t n);

/* ── Error Correction ────────────────────────────────────── */
/* Majority vote: given m bits (0/1), return majority */
int    majority_vote(const int* votes, size_t m);
/* Weighted majority */
int    weighted_majority_vote(const int* votes, const double* weights, size_t m);
/* Probability majority is correct given each vote correct w.p. p */
double majority_correct_prob(size_t m, double p);
/* Minimum m for majority to be correct w.p. ≥ 1-δ */
size_t majority_sample_size(double p, double delta);

/* ── Security Level ──────────────────────────────────────── */
typedef enum {
    SEC_LEVEL_NONE    = 0,
    SEC_LEVEL_WEAK    = 40,   /* 40-bit security */
    SEC_LEVEL_MEDIUM  = 80,   /* 80-bit security */
    SEC_LEVEL_STANDARD = 128, /* 128-bit security */
    SEC_LEVEL_HIGH    = 192,  /* 192-bit security */
    SEC_LEVEL_PARANOID = 256  /* 256-bit security */
} SecurityLevel;

/* Convert security level to parameter sizes */
size_t security_level_to_n(SecurityLevel level);
/* Estimate security level from parameters */
SecurityLevel estimate_security_level(size_t key_bits, double epsilon);

/* ── Key Length Recommendations ──────────────────────────── */
typedef struct {
    size_t rsa_key_bits;
    size_t dlog_key_bits;
    size_t symmetric_key_bits;
    size_t hash_output_bits;
} KeyLenRecommendation;

KeyLenRecommendation* keylen_for_level(SecurityLevel level);
void                  keylen_recommendation_free(KeyLenRecommendation* rec);
void                  keylen_print_recommendation(SecurityLevel level);

/* ── Randomness Generation ───────────────────────────────── */
/* Seed the RNG securely (platform-dependent) */
void   secure_random_seed(void);
/* Generate n cryptographically random bytes (simulated for educational use) */
void   secure_random_bytes(uint8_t* buf, size_t n);
/* Generate a random bit string with actual entropy estimation */
double estimate_entropy(const uint8_t* data, size_t len);

#endif /* SECURITY_PARAMS_H */
