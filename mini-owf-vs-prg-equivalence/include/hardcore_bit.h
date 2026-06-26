/*
 * hardcore_bit.h ? Hardcore Predicates and the Goldreich-Levin Theorem
 *
 * L4 Fundamental Theorem (Goldreich-Levin, 1989):
 *   Let f: {0,1}^n ? {0,1}^* be any one-way function.
 *   Define g(x,r) = (f(x), r) where |r| = |x| = n.
 *   Then g is a one-way function, and
 *     h(x,r) = <x, r> = sum x_i * r_i (mod 2)
 *   is a hardcore predicate for g.
 *
 * Intuition: Even given f(x), it is hard to predict the inner product
 * of x with a random r significantly better than 1/2.
 *
 * Reference:
 *   Goldreich & Levin (1989) ? A Hard-Core Predicate for All One-Way Functions
 *   Goldreich (2001) ? Foundations of Cryptography, Vol 1, Sec 2.5
 *   Arora & Barak (2009) ? Computational Complexity, Sec 9.3
 *
 * Courses: MIT 6.875, Stanford CS255, Princeton COS 522
 */

#ifndef HARDCORE_BIT_H
#define HARDCORE_BIT_H

#include "owf.h"
#include <stdint.h>
#include <stddef.h>

/* ================================================================
 * L1: Hardcore Predicate Definition
 * ================================================================ */

typedef int (*HardcorePredicate)(const BitString *x);

typedef struct {
    OWF               *owf;
    HardcorePredicate  pred;
    int                input_len;
    char               name[64];
} HardcorePred;

HardcorePred *hc_create(OWF *owf, HardcorePredicate pred, int input_len, const char *name);
void          hc_free(HardcorePred *hc);
int           hc_evaluate(const HardcorePred *hc, const BitString *x);

/* ================================================================
 * L4: Goldreich-Levin Inner Product Hardcore Bit
 * ================================================================ */

/*
 * GL(x, r) = <x, r> mod 2 = (sum_{i=0}^{n-1} x_i * r_i) mod 2
 */
int gl_inner_product(const BitString *x, const BitString *r);

/*
 * GL OWF: g(x, r) = (f(x), r)
 * If f is OWF, g is OWF, and GL is hardcore for g.
 */
int gl_owf_eval(const OWF *owf, const BitString *x, BitString *y);
void *gl_params_create(OWF *base_owf);

/* ================================================================
 * L5: List Decoding Algorithm for Goldreich-Levin
 * ================================================================ */

/*
 * Goldreich-Levin List Decoding:
 * Given predictor P with Pr[P(r) = <x,r>] >= 1/2 + epsilon,
 * recover list L of poly(1/epsilon) strings containing x.
 *
 * Algorithm:
 *   1. Choose l = O(log(n/epsilon)) random strings s_1..s_l
 *   2. For each a in {0,1}^l, guess <x, s_i> = a_i
 *   3. Reconstruct candidate x from these guesses using pairwise
 *      independent recovery and majority voting
 *   4. Check each candidate against f(x) = y
 *
 * Complexity: poly(n, 1/epsilon)
 */

typedef struct {
    BitString **entries;
    int         n_entries;
    int         capacity;
    int         n;
} GLCandidateList;

typedef int (*GLPredictor)(const BitString *r);

GLCandidateList *gl_list_decode(int n, GLPredictor predictor,
                                double epsilon, double confidence);
void             gl_candidate_list_free(GLCandidateList *list);

/* Find correct preimage from candidate list */
BitString *gl_find_preimage(const GLCandidateList *candidates,
                            const OWF *owf, const BitString *y);

/* ================================================================
 * L5: Pairwise Independent Hash Family over GF(2)
 * ================================================================ */

/*
 * Pairwise independent hash: h_{A,b}(x) = A*x + b (mod 2)
 * where A is m x k binary matrix, b is m-bit offset.
 * For any distinct x,x': Pr[h(x)=y AND h(x')=y'] = 1/2^{2m}
 */

typedef struct {
    int      k;
    int      m;
    uint8_t *matrix;
    uint8_t *offset;
} GF2HashFunc;

GF2HashFunc *gf2_hash_create(int k, int m);
void         gf2_hash_free(GF2HashFunc *h);
void         gf2_hash_set_random(GF2HashFunc *h);
void         gf2_hash_eval(const GF2HashFunc *h, const BitString *x, BitString *out);
int          gf2_hash_verify_pairwise_independence(int k, int m, int n_trials);

/* ================================================================
 * L8: Universal Hardcore Predicate Analysis
 * ================================================================ */

/*
 * Measure predictor advantage for GL bit.
 * Given y = f(x), estimate:
 *   adv = |Pr[P(y, r) = <x,r>] - 1/2|
 */
double gl_measure_advantage(const OWF *owf, const BitString *x,
                            GLPredictor predictor, int n_samples);

#endif /* HARDCORE_BIT_H */
