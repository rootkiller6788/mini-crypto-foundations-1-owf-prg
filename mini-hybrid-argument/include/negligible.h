/*
 * negligible.h - Negligible Functions in Cryptography
 *
 * A function mu: N -> R is negligible if for every positive polynomial p,
 * there exists an N such that for all n > N: mu(n) < 1/p(n).
 *
 * Negligible functions formalize "vanishingly small" probabilities in
 * cryptographic security definitions. The class of negligible functions
 * is closed under addition, multiplication, and multiplication by any
 * polynomial -- these closure properties are essential for composing
 * security reductions.
 *
 * L1 Definitions: Negligible function, noticeable, overwhelming
 * L2 Core Concepts: Asymptotic security, concrete vs asymptotic bounds
 * L3 Math Structures: Function closure under +, *, poly-multiplication
 *
 * Key Properties:
 *   1. If mu, nu are negligible, then mu + nu is negligible.
 *   2. If mu is negligible and p is any polynomial, then p(n)*mu(n)
 *      is negligible.
 *   3. If mu is negligible, then 1 - mu(n) is overwhelming (-> 1).
 *   4. If mu is NOT negligible, then mu is "noticeable": there exists
 *      c > 0 such that mu(n) >= 1/n^c for infinitely many n.
 *
 * Reference:
 *   Goldreich (2001) "Foundations of Cryptography" Vol 1, Section 3.2
 *   Bellare & Rogaway (2005) "Introduction to Modern Cryptography"
 *   Katz & Lindell (2014) Chapter 3
 *
 * Courses: MIT 6.875, Berkeley CS276, Stanford CS355, ETH 263-4660
 */

#ifndef NEGLIGIBLE_H
#define NEGLIGIBLE_H

#include "hybrid_argument.h"

/* ================================================================
 * Negligible Function Closure Properties
 * ================================================================ */

/*
 * Closure result: check whether the class of negligible functions
 * is closed under common operations for the given security parameter.
 * This verifies the theoretical properties empirically.
 */
typedef struct {
    NegligibleFunction f;
    NegligibleFunction g;
    int is_sum_negligible;
    int is_product_negligible;
    int is_poly_times_negligible;
    double sum_value;
    double product_value;
    double poly_times_value;
} NegligibleClosure;

NegligibleClosure negl_closure_check(const NegligibleFunction* f,
                                      const NegligibleFunction* g,
                                      security_param_t n,
                                      double poly_coeff,
                                      double poly_degree);
void negl_closure_print(const NegligibleClosure* nc);

/* ================================================================
 * Comparing Negligible Functions
 * ================================================================ */

/*
 * Some negligible functions vanish faster than others.
 * e.g., 2^{-n} is "more negligible" than n^{-log n}.
 * This comparison helps in concrete security parameter selection.
 */
typedef struct {
    double val_f;
    double val_g;
    int    f_smaller;
    double ratio;
} NegligibleComparison;

NegligibleComparison negl_compare(const NegligibleFunction* f,
                                   const NegligibleFunction* g,
                                   security_param_t n);
void negl_comparison_print(const NegligibleComparison* nc);

/* ================================================================
 * Negligible vs Noticeable vs Overwhelming
 * ================================================================ */

/*
 * Noticeable: NOT negligible. Exists c > 0 such that f(n) >= 1/n^c
 * for infinitely many n. This is the negation of negligible.
 */
int negl_is_noticeable(const NegligibleFunction* f, security_param_t n,
                        double threshold);

/*
 * Overwhelming: probability p(n) such that p(n) -> 1 as n -> infinity.
 * Equivalently: 1 - p(n) is negligible.
 * Example: Pr[correct decryption] = 1 - 2^{-n} is overwhelming.
 */
int negl_is_overwhelming(double prob, security_param_t n, double threshold);

/* ================================================================
 * Parameterized Negligible Function Constructors
 * ================================================================ */

/*
 * Create negligible functions from standard families with tunable
 * parameters for concrete security analysis.
 */

/* negl(n) = c * base^{-n} */
NegligibleFunction negl_make_exp(double base, double coeff);

/* negl(n) = c * n^deg * 2^{-n} */
NegligibleFunction negl_make_poly_over_exp(int deg, double coeff);

/* negl(n) = c * n^deg * 2^{-sqrt(n)} */
NegligibleFunction negl_make_exp_sqrt_poly(int deg, double coeff);

/* ================================================================
 * Batch Evaluation and Analysis
 * ================================================================ */

/*
 * Evaluate a negligible function across a range of security parameters
 * to visualize its decay rate.
 */
typedef struct {
    security_param_t* ns;
    double*           values;
    int               count;
} NegligibleEvalSeries;

NegligibleEvalSeries* negl_eval_series(const NegligibleFunction* f,
                                         security_param_t n_start,
                                         security_param_t n_end,
                                         int steps);
void negl_eval_series_free(NegligibleEvalSeries* s);
void negl_eval_series_print(const NegligibleEvalSeries* s);

/* Concrete security parameter analysis */
security_param_t negl_security_parameter_for_target(
    const NegligibleFunction* f, double target, security_param_t max_n);
security_param_t negl_half_life(const NegligibleFunction* f,
                                  security_param_t max_n);
int negl_compare_decay_rates(const NegligibleFunction* f,
                              const NegligibleFunction* g,
                              security_param_t n);

/* Polynomial negligibility check */
typedef struct {
    int k;
    security_param_t cross;
    double f_at_cross;
    double poly_at_cross;
} NeglPolyCheck;

NeglPolyCheck negl_check_against_polynomial(const NegligibleFunction* f,
                                              int k, security_param_t max_n);
void negl_print_polynomial_check_report(const NegligibleFunction* f,
                                         security_param_t max_n);

#endif /* NEGLIGIBLE_H */