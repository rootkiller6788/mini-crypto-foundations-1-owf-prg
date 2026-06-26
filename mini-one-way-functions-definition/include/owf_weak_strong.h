/*
 * owf_weak_strong.h — Weak OWF ⇒ Strong OWF (Yao's Amplification)
 *
 * L4 Fundamental Law (Yao 1982):
 *   If weak one-way functions exist, then strong one-way functions exist.
 *
 * L2 Core Concept:
 *   Weak OWF: ∃ polynomial q(·) s.t. ∀ PPT A,
 *              Pr[A(f(x)) ∉ f^{-1}(f(x))] > 1/q(n)
 *   Strong OWF: ∀ PPT A, Pr[A(f(x)) ∈ f^{-1}(f(x))] < negl(n)
 *
 * Construction (Yao):
 *   Given weak OWF f, define strong OWF F:
 *     F(x_1, ..., x_t) = (f(x_1), ..., f(x_t))
 *   where t = n·q(n) for the polynomial q from the weak OWF guarantee.
 *
 *   Intuition: To invert F, the adversary must invert f on all t
 *   independent instances. Since each inversion succeeds with
 *   probability ≤ 1 - 1/q(n), the probability of inverting all t
 *   is ≤ (1 - 1/q(n))^{t} ≈ e^{-n} which is negligible.
 *
 * L5 Algorithms/Methods:
 *   - Parallel repetition construction
 *   - Quantitative security amplification analysis
 *   - Empirical verification of amplification
 *
 * Reference:
 *   Yao, "Theory and Applications of Trapdoor Functions" (FOCS 1982)
 *   Goldreich Vol 1 §2.3 — Impagliazzo-Luby refinement
 *   Goldreich, Impagliazzo, Levin, Venkatesan, Zuckerman (1990)
 *   Katz-Lindell §7.4.2
 *
 * Courses:
 *   MIT 6.875, Stanford CS255, Berkeley CS276,
 *   Princeton COS 433, CMU 15-859, ETH 263-4660
 */

#ifndef OWF_WEAK_STRONG_H
#define OWF_WEAK_STRONG_H

#include "owf_core.h"

/* ================================================================
 * Yao Amplification Construction
 * ================================================================ */

/*
 * Yao's parallel repetition construction:
 *   F(x_1, ..., x_t) = (f(x_1), f(x_2), ..., f(x_t))
 *
 * Input: t copies of n-bit strings (total t*n bits)
 * Output: t copies of f's outputs
 */

typedef struct {
    owf_scheme_t*  base_owf;     /* underlying weak OWF */
    size_t         t;            /* number of parallel copies */
    sec_param_t    sec_param;

    /* Derived */
    size_t         input_bits;   /* t * base_owf->input_bits */
    size_t         output_bits;  /* t * base_owf->output_bits */

    /* Estimated security */
    double         weak_bound;   /* 1/q(n) — noticeable inversion prob */
    double         strong_bound; /* (1-1/q(n))^t — negligible bound */
} yao_amplification_t;

/*
 * Create Yao amplification from a candidate weak OWF.
 *
 * The parameter t should satisfy: (1 - ε)^t < negl(n)
 * where ε = lower bound on inversion failure probability.
 * Typically t = n * ceil(1/ε).
 */
yao_amplification_t* yao_amp_create(owf_scheme_t* base_owf,
                                     size_t t, double weak_bound);
void                 yao_amp_free(yao_amplification_t* amp);
void                 yao_amp_print(const yao_amplification_t* amp);

/* Evaluate the amplified function F */
int yao_amp_eval(void* ctx, const bit_string_t* x,
                 sec_param_t n, bit_string_t** y);

/* Inversion strategy for the amplified function */
int yao_amp_invert(void* ctx, const bit_string_t* y,
                   sec_param_t n, bit_string_t** x_prime);

/* Create an owf_scheme_t wrapping the amplification */
owf_scheme_t* yao_amp_as_owf(yao_amplification_t* amp);

/* ================================================================
 * Quantitative Security Analysis
 * ================================================================ */

/*
 * Compute the required number of repetitions t to achieve
 * target security (negligible inversion probability).
 *
 * Given weak inversion probability p_invert = 1 - ε,
 * we need t such that p_invert^t < 2^{-target_bits}.
 *
 * Formula: t ≥ target_bits / (-log2(p_invert))
 */
size_t yao_compute_t(double weak_invert_prob, int target_bits);

/*
 * Concrete security analysis result.
 */
typedef struct {
    double   base_invert_prob;       /* p = Pr[invert weak OWF] */
    double   base_failure_prob;      /* ε = 1 - p */
    size_t   repetitions_t;          /* parallel copies needed */
    double   amplified_invert_prob;  /* p^t */
    int      target_bits;            /* target security (bits) */
    int      achieved_bits;          /* actual security achieved */
} yao_security_analysis_t;

yao_security_analysis_t* yao_analyze_security(double weak_invert_prob,
                                               size_t t, int target_bits);
void                     yao_security_analysis_print(
                              const yao_security_analysis_t* analysis);

/* ================================================================
 * Direct Product Theorem (informational)
 * ================================================================ */

/*
 * Direct Product Theorem (informal):
 *   If computing f on ONE random input is hard, then computing f
 *   on MANY independent random inputs is MUCH harder.
 *
 * More precisely, if Pr[A inverts f] ≤ δ, then
 *   Pr[A inverts all t copies] ≤ δ^t.
 *
 * This is the foundation of Yao's amplification.
 */
double direct_product_bound(double single_invert_prob, size_t t);

/* ================================================================
 * Hardness Amplification Experiment
 * ================================================================ */

typedef struct {
    yao_amplification_t* amp;
    int                  num_trials;
    int                  base_successes;
    int                  amp_successes;
    double               base_success_rate;
    double               amp_success_rate;
    double               predicted_amp_rate;  /* δ^t */
    double               amplification_factor;
} amp_experiment_t;

/* Run amplification experiment comparing base vs amplified OWF */
amp_experiment_t* amp_experiment_run(yao_amplification_t* amp,
                                      int num_trials);
void              amp_experiment_free(amp_experiment_t* exp);
void              amp_experiment_print(const amp_experiment_t* exp);

#endif /* OWF_WEAK_STRONG_H */
