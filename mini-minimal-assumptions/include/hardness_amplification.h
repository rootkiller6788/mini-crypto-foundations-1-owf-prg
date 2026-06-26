/*
 * hardness_amplification.h ? Yao's XOR Lemma & Hardness Amplification
 *
 * L4 Fundamental Laws / L5 Algorithms:
 * Starting from a ?-hard function (weak, e.g., ? = 0.01),
 * construct an ?-hard function (strong, ? ? 1/2) via XOR composition.
 *
 * This is THE central tool for constructing cryptographic primitives
 * from minimal assumptions. Weak hardness implies strong hardness.
 *
 * Core Theorems:
 *   Yao's XOR Lemma (1982): ?-hard ? (?+?)-hard via k = O(n/??) XORs
 *   Direct Product Theorem: ?-hard ? (1-?)^k hard for all-k copies
 *   Goldreich-Levin Theorem: Extract 1 bit of "perfect" hardness from any OWF
 *
 * Reference:
 *   Yao, "Theory and Applications of Trapdoor Functions" (FOCS 1982)
 *   Goldreich & Levin, "A Hard-Core Predicate for All One-Way Functions" (STOC 1989)
 *   Goldreich, Nisan, Wigderson, "On Yao's XOR-Lemma" (ECCC 1995)
 *   Levin, "One-Way Functions and Pseudorandom Generators" (Combinatorica 1987)
 */

#ifndef HARDNESS_AMPLIFICATION_H
#define HARDNESS_AMPLIFICATION_H

#include "minimal_assumptions.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * L1: Definitions ? Hardness Parameters
 * ================================================================ */

/*
 * A function f: {0,1}^n ? {0,1}^m is ?-hard against circuits of size s
 * if for every circuit C of size s: Pr[C(x) = f(x)] ? 1 - ?.
 *
 * Equivalently: ? = 1 - max_C Pr[C(x) = f(x)]
 */
typedef struct {
    size_t  input_bits;
    size_t  output_bits;
    double  delta;           /* hardness: 0 = easy, 1 = perfectly hard */
    double  circuit_size;    /* adversary budget: log(s) */
} HardnessParameters;

/*
 * For predicates (m=1): f: {0,1}^n ? {0,1}
 * ? = advantage over random guessing = Pr[correct] - 1/2
 */
double predicate_hardness(double accuracy);
double accuracy_from_hardness(double delta);

/* ================================================================
 * L3: Mathematical Structures ? XOR Composition
 * ================================================================ */

/*
 * Given f: {0,1}^n ? {0,1}, define F_k: ({0,1}^n)^k ? {0,1}:
 *   F_k(x_1, ..., x_k) = f(x_1) ? f(x_2) ? ... ? f(x_k)
 *
 * Input: k independent uniformly random strings.
 */
typedef struct {
    int      k;              /* number of copies */
    size_t   input_bits;     /* n, per copy */
    uint8_t* inputs;         /* k * ceil(n/8) bytes */
} XORComposition;

/* Create XOR composition input buffer */
XORComposition* xor_comp_create(int k, size_t input_bits);
void xor_comp_set_input(XORComposition* xc, int idx,
                         const uint8_t* val, size_t len);
int  xor_comp_eval_predicate(const XORComposition* xc,
                              int (*f)(const uint8_t*, size_t));
void xor_comp_free(XORComposition* xc);

/* ================================================================
 * L4: Fundamental Laws
 * ================================================================ */

/*
 * Theorem (Yao's XOR Lemma ? Quantitative):
 *
 * If f: {0,1}^n ? {0,1} is ?-hard against circuits of size s,
 * then F_k (XOR of k copies) is ?-hard against circuits of size s':
 *
 *   ? = (1-?)^k + O(s' ? k ? n / 2^n)
 *
 * Optimizing: choose k = n/?? to achieve ? = negl(n).
 * Circuit size degrades: s' ? s - O(k?n)
 *
 * Returns the ? bound (how close to 1/2 guessing).
 */
double yao_xor_bound_full(double delta, int k, double circuit_size,
                           double input_size, double* out_circuit_size);

/*
 * Direct Product Theorem (Chernoff-type):
 * Pr[circuit C of size s computes f(x_i) correctly for all i=1..k] ? (1-?)^k
 */
double direct_product_prob(double delta, int k);

/*
 * Tight bounds for specific parameter ranges:
 */
double yao_xor_epsilon_optimal(double delta, size_t input_bits,
                                double target_security);
int    yao_xor_optimal_k(double delta, double target_epsilon,
                          size_t input_bits);

/* ================================================================
 * L4: Goldreich-Levin Hardcore Bit Theorem
 * ================================================================ */

/*
 * Theorem (Goldreich-Levin 1989):
 * If f: {0,1}^n ? {0,1}^* is a one-way function, then
 *   g(x,r) = (f(x), r)
 *   B(x,r) = ?x, r? mod 2
 * is a hardcore predicate. That is, given (f(x), r), predicting
 * ?x,r? mod 2 is as hard as inverting f.
 *
 * This extracts 1 bit of PERFECT (unpredictable) hardness from
 * any OWF, which can then be XOR-amplified.
 */

typedef struct {
    uint8_t* fx;            /* f(x) = the OWF output */
    size_t   fxlen;
    uint8_t* r;             /* random vector, same length as x */
    size_t   rlen;
} GLInstance;

/* Compute B(x,r) = inner product mod 2 */
int gl_compute_hardcore_bit(const uint8_t* x, size_t xlen,
                             const uint8_t* r, size_t rlen);

/* Attempt to predict B(x,r) given only (f(x), r) */
double gl_adversary_advantage(const GLInstance* inst,
                               int (*predictor)(const uint8_t*, size_t,
                                                const uint8_t*, size_t));

/* ================================================================
 * L5: Algorithms ? List Decoding for Goldreich-Levin
 * ================================================================ */

/*
 * Goldreich-Levin List Decoding:
 * Given oracle access to a predictor P with advantage ?
 * (i.e., Pr_r[P(f(x), r) = ?x,r?] ? ?+?),
 * we can recover x in time poly(n, 1/?) by outputting a list of
 * size poly(n, 1/?) that contains x with high probability.
 *
 * Algorithm overview:
 * 1. Choose random s1,...,s? (? = O(log n/??))
 * 2. For each a ? {0,1}^?, guess ?x,sj? for each j
 * 3. For each guess vector, recover x[p] for each bit position p
 *    using majority vote over P(f(x), r ? e_p)
 * 4. Verify each candidate
 */

typedef struct {
    uint8_t** candidates;
    size_t    n_candidates;
    size_t    xlen;
} GLListDecodeResult;

GLListDecodeResult* gl_list_decode(size_t n_bits, double epsilon,
                                    int (*predictor)(const uint8_t*, size_t,
                                                     const uint8_t*, size_t),
                                    const uint8_t* fx, size_t fxlen);
void gl_list_decode_free(GLListDecodeResult* result);
int  gl_verify_candidate(const uint8_t* candidate, size_t len,
                          const uint8_t* fx, size_t fxlen,
                          int (*f)(const uint8_t*, size_t, uint8_t*, size_t*));

/* ================================================================
 * L5: Hardness Amplification via Iterated XOR
 * ================================================================ */

/*
 * Full pipeline: Weak OWF ? Strong OWF ? PRG
 *
 * Step 1: Weak OWF ? Strong OWF (hardness amplification)
 *   Given f: {0,1}^n ? {0,1}^n with success prob ? 1-1/p(n)
 *   Define F(x1||...||xk) = f(x1)||...||f(xk) for k = O(n?p(n))
 *   Then F is strongly one-way: success prob = negl(n)
 *
 * Step 2: Extract hardcore bit (Goldreich-Levin)
 *
 * Step 3: PRG via HILL construction
 */
typedef struct {
    double weak_delta;       /* initial hardness */
    double strong_delta;     /* after amplification */
    int    k;                /* amplification factor */
    size_t input_bits;
    size_t output_bits;
} HardnessAmplificationPipeline;

HardnessAmplificationPipeline* ha_pipeline_create(double weak_delta,
                                                    size_t input_bits);
void ha_pipeline_execute(HardnessAmplificationPipeline* hap);
void ha_pipeline_free(HardnessAmplificationPipeline* hap);

/* ================================================================
 * L6: Canonical Problems
 * ================================================================ */

/*
 * Problem 1: Given a (1/poly)-hard predicate, construct a (?-negl)-hard
 * predicate. Prove the epsilon bound matches Yao's lemma.
 */
int yao_canonical_example(double delta, int k);

/*
 * Problem 2: Hardcore bit extraction. Verify that GL hardcore bit
 * is unpredictable given f(x) and random r.
 */
int gl_canonical_example(size_t n_bits);

/*
 * Problem 3: Concatenation vs XOR. Show XOR achieves better
 * hardness amplification than concatenation (Direct Product).
 */
int compare_xor_vs_concatenation(double delta, int k);

#ifdef __cplusplus
}
#endif

#endif /* HARDNESS_AMPLIFICATION_H */
