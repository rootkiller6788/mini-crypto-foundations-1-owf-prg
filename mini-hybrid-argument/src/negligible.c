/*
 * negligible.c - Negligible Functions: Theory and Analysis
 *
 * A function mu: N -> R is negligible if for every positive polynomial p,
 * there exists N s.t. for all n > N: mu(n) < 1/p(n).
 *
 * Negligible functions are the fundamental tool for defining
 * "vanishingly small" probabilities in asymptotic cryptography.
 * They formalize the intuition that something is "so unlikely that
 * even repeating the experiment polynomially many times won't help."
 *
 * Key closure properties (proved below):
 *   1. mu + nu is negligible if mu, nu are negligible
 *   2. mu * nu is negligible if mu, nu are negligible
 *   3. p(n) * mu(n) is negligible for any polynomial p
 *   4. If mu is NOT negligible, it is "noticeable":
 *      exists c>0 s.t. mu(n) >= 1/n^c for infinitely many n
 *
 * Relationship to advantage:
 *   A distinguisher's advantage Adv_D(n) must be negligible for
 *   the scheme to be "secure." If Adv_D(n) is only 1/poly(n),
 *   then by repeating poly(n) times, the adversary succeeds
 *   with noticeable probability.
 *
 * L1: Negligible function, noticeable, overwhelming
 * L2: Asymptotic security, concrete vs asymptotic
 * L3: Function closure under +, *, poly-mult
 * L4: Negation of negligible = noticeable (characterization)
 * L5: Negligible function comparison, decay analysis
 *
 * Reference:
 *   Goldreich (2001) Foundations of Cryptography Vol 1, Sec 3.2
 *   Bellare & Rogaway (2005) Introduction to Modern Cryptography
 *   Katz & Lindell (2014) Ch 3
 *
 * Courses: MIT 6.875, Berkeley CS276, Stanford CS355, ETH 263-4660
 */

#include "negligible.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* ================================================================
 * Negligible Function Closure Properties
 *
 * Theorem 1 (Addition): If mu, nu are negligible, then mu + nu is negligible.
 * Proof: For any poly p, since mu is negligible: exists N1 s.t.
 *   forall n>N1: mu(n) < 1/(2p(n)).
 *   Similarly exists N2 s.t. forall n>N2: nu(n) < 1/(2p(n)).
 *   For n > max(N1,N2): (mu+nu)(n) < 1/(2p(n)) + 1/(2p(n)) = 1/p(n).
 *
 * Theorem 2 (Product): If mu, nu are negligible, then mu * nu is negligible.
 * Proof: For any poly p, since mu is negligible: exists N s.t.
 *   forall n>N: mu(n) < 1/p(n).
 *   Since nu(n) <= 1 (it's a probability-like function), we have
 *   (mu*nu)(n) < 1/p(n) * 1 = 1/p(n).
 *
 * Theorem 3 (Poly-mult): If mu is negligible and q is any polynomial,
 *   then q(n)*mu(n) is negligible.
 * Proof: For any poly p, apply negligibility of mu to poly p*q:
 *   exists N s.t. forall n>N: mu(n) < 1/(p(n)*q(n)).
 *   Then q(n)*mu(n) < q(n) * 1/(p(n)*q(n)) = 1/p(n).
 *
 * These properties enable composition of security reductions:
 * if each step of a hybrid argument loses at most negl(n) security,
 * then polynomially many steps still lose at most negl(n) security.
 * ================================================================ */

NegligibleClosure negl_closure_check(const NegligibleFunction* f,
                                      const NegligibleFunction* g,
                                      security_param_t n,
                                      double poly_coeff,
                                      double poly_degree) {
    NegligibleClosure nc;
    memset(&nc, 0, sizeof(nc));
    if (!f || !g) return nc;
    nc.f = *f;
    nc.g = *g;

    double vf = negl_eval(f, n);
    double vg = negl_eval(g, n);

    nc.sum_value = vf + vg;
    nc.product_value = vf * vg;
    /* Polynomial threshold: 1 / (poly_coeff * n^poly_degree) */
    double poly_threshold = 1.0 / (poly_coeff * pow((double)n, poly_degree));

    nc.is_sum_negligible = (nc.sum_value < poly_threshold) ? 1 : 0;
    nc.is_product_negligible = (nc.product_value < poly_threshold) ? 1 : 0;

    /* Poly-times-negligible: q(n)*f(n) */
    double qn = poly_coeff * pow((double)n, poly_degree);
    nc.poly_times_value = qn * vf;
    nc.is_poly_times_negligible = (nc.poly_times_value < poly_threshold) ? 1 : 0;

    return nc;
}

void negl_closure_print(const NegligibleClosure* nc) {
    if (!nc) return;
    printf("=== Negligible Closure Properties ===\n");
    printf("f(n): %s (coeff=%.2f)\n",
           negl_type_name(nc->f.type), nc->f.coefficient);
    printf("g(n): %s (coeff=%.2f)\n",
           negl_type_name(nc->g.type), nc->g.coefficient);
    printf("f+g = %.10f (negligible: %s)\n",
           nc->sum_value, nc->is_sum_negligible ? "YES" : "NO");
    printf("f*g = %.10f (negligible: %s)\n",
           nc->product_value, nc->is_product_negligible ? "YES" : "NO");
    printf("poly*f = %.10f (negligible: %s)\n",
           nc->poly_times_value, nc->is_poly_times_negligible ? "YES" : "NO");
}

/* ================================================================
 * Comparing Negligible Functions
 *
 * Different negligible functions decay at different rates.
 * At n=100:
 *   2^{-n}      = 7.89e-31   (fastest)
 *   n^{-log n}  = 4.98e-14   (super-polynomial)
 *   2^{-n/2}    = 8.88e-16   (half-exponential)
 *   2^{-sqrt(n)}= 9.77e-04   (slowest here)
 *
 * For concrete security parameter selection, we need to know how
 * large n must be to achieve a target security level (e.g., 2^{-80}).
 *
 * The ratio f(n)/g(n) shows relative decay rate. If ratio -> 0,
 * then f vanishes faster than g.
 * ================================================================ */

NegligibleComparison negl_compare(const NegligibleFunction* f,
                                   const NegligibleFunction* g,
                                   security_param_t n) {
    NegligibleComparison nc;
    memset(&nc, 0, sizeof(nc));
    if (!f || !g) return nc;

    nc.val_f = negl_eval(f, n);
    nc.val_g = negl_eval(g, n);
    nc.f_smaller = (nc.val_f < nc.val_g) ? 1 : 0;
    if (nc.val_g != 0.0)
        nc.ratio = nc.val_f / nc.val_g;
    else if (nc.val_f == 0.0)
        nc.ratio = 1.0;
    else
        nc.ratio = INFINITY;

    return nc;
}

void negl_comparison_print(const NegligibleComparison* nc) {
    if (!nc) return;
    printf("=== Negligible Function Comparison ===\n");
    printf("f(n) = %.10f\n", nc->val_f);
    printf("g(n) = %.10f\n", nc->val_g);
    printf("f < g: %s\n", nc->f_smaller ? "YES" : "NO");
    printf("f/g = %.6f\n", nc->ratio);
}

/* ================================================================
 * Negligible vs Noticeable vs Overwhelming
 *
 * A function f is NOTICEABLE if it is NOT negligible.
 * Equivalently: exists c > 0 such that f(n) >= 1/n^c for
 * infinitely many n.
 *
 * A probability p(n) is OVERWHELMING if p(n) -> 1 as n -> infinity.
 * Equivalently: 1 - p(n) is negligible.
 *
 * Examples:
 *   - Pr[correct decryption] = 1 - 2^{-n} is overwhelming
 *   - Pr[adversary forges signature] = 1/n^100 is noticeable
 *     (so the scheme is NOT secure)
 *   - Pr[adversary inverts OWF] = 2^{-n} is negligible
 *     (scheme IS secure if all adversaries have negl success)
 *
 * Knowledge: Distinguishes the three categories in crypto definitions.
 * ================================================================ */

int negl_is_noticeable(const NegligibleFunction* f, security_param_t n,
                        double threshold) {
    if (!f) return 0;
    double val = negl_eval(f, n);
    /* A function is noticeable at n if it exceeds 1/poly(n) threshold */
    return (val >= threshold) ? 1 : 0;
}

int negl_is_overwhelming(double prob, security_param_t n, double threshold) {
    /* prob is overwhelming if 1-prob < threshold (negligible complement) */
    (void)n;
    if (prob < 0.0) prob = 0.0;
    if (prob > 1.0) prob = 1.0;
    return ((1.0 - prob) < threshold) ? 1 : 0;
}

/* ================================================================
 * Parameterized Negligible Function Constructors
 *
 * These allow construction of negligible functions with specific
 * parameters for concrete security analysis. In concrete security,
 * we fix n and ask: is the advantage below 2^{-80}? This is a
 * different perspective from asymptotic negligibility.
 *
 * Concrete security example (Bellare-Rogaway):
 *   "If an adversary runs in time t and achieves advantage epsilon,
 *    then there exists an adversary running in time t' and achieving
 *    advantage epsilon' against the underlying assumption."
 * ================================================================ */

NegligibleFunction negl_make_exp(double base, double coeff) {
    NegligibleFunction nf;
    nf.type = NEGL_TYPE_EXP;
    nf.coefficient = coeff;
    nf.custom_fn = NULL;
    (void)base;  /* base fixed to 2 in this implementation */
    return nf;
}

NegligibleFunction negl_make_poly_over_exp(int deg, double coeff) {
    NegligibleFunction nf;
    nf.type = NEGL_TYPE_NEAR_EXP;
    nf.coefficient = coeff;
    nf.custom_fn = NULL;
    (void)deg;  /* degree encoded in type */
    return nf;
}

NegligibleFunction negl_make_exp_sqrt_poly(int deg, double coeff) {
    NegligibleFunction nf;
    nf.type = NEGL_TYPE_EXP_SQRT;
    nf.coefficient = coeff;
    nf.custom_fn = NULL;
    (void)deg;
    return nf;
}

/* ================================================================
 * Batch Evaluation and Analysis
 *
 * Evaluates a negligible function across a range of security
 * parameters to visualize decay rate. This is essential for
 * concrete parameter selection: "How large must n be to get
 * security 2^{-80}?"
 *
 * For example:
 *   With mu(n) = 2^{-n}: n=80 suffices for 2^{-80}
 *   With mu(n) = 2^{-sqrt(n)}: n=6400 needed for 2^{-80}
 *   With mu(n) = n^{-log n}: n~2^{9}=512 needed for 2^{-80}
 *
 * Knowledge: Concrete parameter estimation from asymptotic bounds.
 * ================================================================ */

NegligibleEvalSeries* negl_eval_series(const NegligibleFunction* f,
                                         security_param_t n_start,
                                         security_param_t n_end,
                                         int steps) {
    if (!f || steps <= 0 || n_start > n_end) return NULL;

    NegligibleEvalSeries* s = (NegligibleEvalSeries*)
        malloc(sizeof(NegligibleEvalSeries));
    if (!s) return NULL;

    s->count = steps;
    s->ns = (security_param_t*)calloc((size_t)steps, sizeof(security_param_t));
    s->values = (double*)calloc((size_t)steps, sizeof(double));
    if (!s->ns || !s->values) {
        free(s->ns); free(s->values); free(s);
        return NULL;
    }

    double step_size = (double)(n_end - n_start) / (double)(steps - 1);
    for (int i = 0; i < steps; i++) {
        security_param_t ni = n_start + (security_param_t)(step_size * (double)i);
        if (ni > n_end) ni = n_end;
        s->ns[i] = ni;
        s->values[i] = negl_eval(f, ni);
    }

    return s;
}

void negl_eval_series_free(NegligibleEvalSeries* s) {
    if (s) { free(s->ns); free(s->values); free(s); }
}

void negl_eval_series_print(const NegligibleEvalSeries* s) {
    if (!s) return;
    printf("=== Negligible Function Evaluation Series ===\n");
    printf("Steps: %d\n", s->count);
    for (int i = 0; i < s->count; i++) {
        printf("  n=%u: %.10f\n", s->ns[i], s->values[i]);
    }
}

/* ================================================================
 * Asymptotic Analysis: Negligibility Decay Rate Classification
 *
 * We classify negligible functions by their decay rate relative
 * to standard reference functions.
 *
 * Definition (dominance order):
 *   f << g if lim_{n->inf} f(n)/g(n) = 0
 *
 * Hierarchy (fastest to slowest decay among negligible functions):
 *   2^{-n} << n*2^{-n} << 2^{-n/2} << n^{-log n} << 2^{-sqrt(n)}
 *
 * This hierarchy matters because:
 *   - If f vanishes faster than g, then proving security with f
 *     gives a stronger guarantee than with g.
 *   - Composition: if each hybrid step loses 2^{-n} security,
 *     we can tolerate more steps than if each loses 2^{-sqrt(n)}.
 *
 * Knowledge: Asymptotic comparison of security bounds.
 * ================================================================ */

/*
 * negl_security_parameter_for_target:
 * Finds the smallest security parameter n such that f(n) < target.
 * This is the concrete security analog of the asymptotic definition.
 *
 * Returns 0 if the target is not reached within max_n.
 */
security_param_t negl_security_parameter_for_target(
    const NegligibleFunction* f,
    double target,
    security_param_t max_n) {
    if (!f) return 0;
    for (security_param_t n = 1; n <= max_n; n++) {
        if (negl_eval(f, n) < target) return n;
    }
    return 0;
}

/*
 * negl_half_life: finds n such that f(n) < f(1) / 2.
 * Measures how quickly the negligible function drops by half.
 */
security_param_t negl_half_life(const NegligibleFunction* f,
                                  security_param_t max_n) {
    if (!f) return 0;
    double initial = negl_eval(f, 1);
    if (initial <= 0.0) return 1;
    double target = initial / 2.0;
    for (security_param_t n = 1; n <= max_n; n++) {
        if (negl_eval(f, n) < target) return n;
    }
    return 0;
}

/*
 * negl_compare_decay_rates:
 * Compares which of two negligible functions decays faster at a given n.
 * Returns: -1 if f decays faster, 0 if equal, +1 if g decays faster.
 */
int negl_compare_decay_rates(const NegligibleFunction* f,
                              const NegligibleFunction* g,
                              security_param_t n) {
    if (!f || !g) return 0;
    double vf = negl_eval(f, n);
    double vg = negl_eval(g, n);
    if (vf < vg) return -1;
    if (vf > vg) return 1;
    return 0;
}

/* ================================================================
 * Empirical Negligibility Test
 *
 * Tests whether a function behaves negligibly over a range of n
 * by checking against the polynomial family 1/n^k for k=1..K.
 *
 * For true negligibility, f(n) must eventually drop below 1/n^k
 * for EVERY k. In practice, we check for k=1..10 over n=1..1000
 * and see if the crossing point exists.
 *
 * Knowledge: Empirical verification of the negligibility definition.
 * ================================================================ */

NeglPolyCheck negl_check_against_polynomial(const NegligibleFunction* f,
                                              int k,
                                              security_param_t max_n) {
    NeglPolyCheck result = {k, 0, 0.0, 0.0};
    if (!f || k <= 0) return result;

    for (security_param_t n = 1; n <= max_n; n++) {
        double poly_val = 1.0 / pow((double)n, (double)k);
        double f_val = negl_eval(f, n);
        if (f_val < poly_val) {
            result.cross = n;
            result.f_at_cross = f_val;
            result.poly_at_cross = poly_val;
            return result;
        }
    }
    return result;
}

/*
 * negl_print_polynomial_check_report:
 * For a given negligible function, checks against 1/n^k for k=1..10
 * and reports crossing points. A true negligible function must cross
 * ALL polynomial curves eventually.
 */
void negl_print_polynomial_check_report(const NegligibleFunction* f,
                                         security_param_t max_n) {
    if (!f) return;
    printf("=== Negligibility Check: %s ===\n", negl_type_name(f->type));
    printf("Checking against 1/n^k for k=1..10, max_n=%u\n", max_n);
    for (int k = 1; k <= 10; k++) {
        NeglPolyCheck c = negl_check_against_polynomial(f, k, max_n);
        if (c.cross > 0) {
            printf("  k=%d: crosses at n=%u (f=%.2e < 1/n^%d=%.2e)\n",
                   k, c.cross, c.f_at_cross, k, c.poly_at_cross);
        } else {
            printf("  k=%d: NOT NEGLIGIBLE for max_n=%u (f never < 1/n^%d)\n",
                   k, max_n, k);
        }
    }
}