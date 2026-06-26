/*
 * hardcore_bit.c — Hardcore Predicates and Goldreich-Levin Theorem
 *
 * Implements:
 *   - Hardcore predicate framework (L1)
 *   - Goldreich-Levin inner product hardcore bit (L4)
 *   - Goldreich-Levin list decoding algorithm (L5)
 *   - Pairwise independent hash families over GF(2) (L5)
 *   - Universal hardcore predicate advantage measurement (L8)
 *
 * L4 Theorem (Goldreich-Levin 1989):
 *   For any OWF f, the function g(x,r) = (f(x), r) is a OWF
 *   and h(x,r) = <x,r> is a hardcore predicate for g.
 *
 * L5 Algorithm: Goldreich-Levin list decoding
 *   Given a predictor P with advantage ε, recover list L containing x
 *   in time poly(n, 1/ε) using pairwise independent sampling.
 *
 * Reference:
 *   Goldreich & Levin (1989) — A Hard-Core Predicate for All One-Way Functions
 *   Goldreich (2001) — Foundations of Cryptography, Vol 1, Sec 2.5
 *   Arora & Barak (2009) — Computational Complexity, Sec 9.3
 *
 * Courses: MIT 6.875, Stanford CS255, Princeton COS 522
 */

#include "hardcore_bit.h"
#include "crypto_utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

/* ================================================================
 * L1: Hardcore Predicate Framework
 * ================================================================
 * A hardcore predicate b: {0,1}^n → {0,1} for a OWF f satisfies:
 *   Given f(x), no PPT algorithm can predict b(x) with
 *   probability > 1/2 + negl(n).
 */

HardcorePred *hc_create(OWF *owf, HardcorePredicate pred, int input_len,
                         const char *name) {
    HardcorePred *hc = (HardcorePred *)malloc(sizeof(HardcorePred));
    if (!hc) return NULL;
    hc->owf = owf;
    hc->pred = pred;
    hc->input_len = input_len;
    if (name) {
        strncpy(hc->name, name, 63);
        hc->name[63] = '\0';
    } else {
        hc->name[0] = '\0';
    }
    return hc;
}

void hc_free(HardcorePred *hc) {
    free(hc);
}

int hc_evaluate(const HardcorePred *hc, const BitString *x) {
    if (!hc || !hc->pred || !x) return 0;
    return hc->pred(x);
}

/* ================================================================
 * L4: Goldreich-Levin Inner Product Hardcore Bit
 * ================================================================
 * GL(x, r) = <x, r> mod 2 = sum_i x_i * r_i mod 2
 *
 * Security argument (high-level):
 *   Suppose there exists PPT A that predicts GL(x,r) given (f(x), r)
 *   with advantage ε. Then there exists PPT B that inverts f(x) with
 *   probability poly(ε, 1/n).
 *
 *   B works by list-decoding: sample random r, use A to learn
 *   information about x, and reconstruct x from the list of candidates.
 */

int gl_inner_product(const BitString *x, const BitString *r) {
    if (!x || !r) return 0;
    assert(x->bit_len == r->bit_len);
    return gf2_dot_product(x, r);
}

/*
 * GL augmented OWF: g(x, r) = (f(x), r)
 * where |x| = |r| = input_len/2.
 *
 * If f is length-preserving on {0,1}^n, then g works on {0,1}^{2n}.
 */
int gl_owf_eval(const OWF *owf, const BitString *x, BitString *y) {
    if (!owf || !x || !y) return -1;
    /* x encodes (x, r) pair. First half = x input, second half = r. */
    size_t half = x->bit_len / 2;
    OWF *base = (OWF *)owf->params;
    if (!base) return -1;

    BitString *x_in = bitstring_create(half);
    BitString *fx = bitstring_create(base->n);

    /* Extract x part */
    for (size_t i = 0; i < half; i++) {
        bitstring_set_bit(x_in, i, bitstring_get_bit(x, i));
    }
    x_in->bit_len = half;

    if (owf_eval(base, x_in, fx) != 0) {
        bitstring_free(x_in);
        bitstring_free(fx);
        return -1;
    }

    /* Output: f(x) || r */
    BitString *r_part = bitstring_create(half);
    for (size_t i = 0; i < half; i++) {
        bitstring_set_bit(r_part, i, bitstring_get_bit(x, half + i));
    }
    r_part->bit_len = half;

    bitstring_concat(fx, r_part, y);

    bitstring_free(x_in);
    bitstring_free(fx);
    bitstring_free(r_part);
    return 0;
}

void *gl_params_create(OWF *base_owf) {
    return base_owf; /* Just store the base OWF pointer */
}

/* ================================================================
 * L5: Goldreich-Levin List Decoding Algorithm
 * ================================================================
 * Given a predictor P with Pr[P(r) = <x,r>] >= 1/2 + ε,
 * recover a list L of candidates containing x.
 *
 * Algorithm highlights:
 *   1. Choose l = O(log(n/ε)) random strings s_1, ..., s_l
 *   2. For each a ∈ {0,1}^l (guess values of <x,s_i>):
 *      a. For each r, predict <x,r> using pairwise independent
 *         decomposition: r = r' ⊗ sum of s_i's
 *      b. Reconstruct candidate x'
 *      c. Check if f(x') = f(x); if so, add to list
 */

/*
 * Reconstruct candidate x from guesses a_i of <x, s_i>.
 * Uses the pairwise independent decomposition:
 * For any r, write r = s_i ⊕ (r ⊕ s_i).
 * Then <x, r> = <x, s_i> ⊕ <x, r ⊕ s_i>.
 * Predict <x, r ⊕ s_i> using the predictor, and take majority.
 */
static void gl_reconstruct_candidate(int n,
                                      const BitString **s,    /* l random strings */
                                      const int *a,           /* guesses a_i = <x, s_i> */
                                      int l,
                                      GLPredictor predictor,
                                      BitString *candidate) {
    /*
     * For each bit position j ∈ [0, n-1]:
     *   Let e_j be the j-th unit vector.
     *   For each sample t ∈ [T]:
     *     Pick random i ∈ [l], let r = e_j ⊕ s_i (ensuring pairwise independence)
     *     Predict <x, r> = P(r)
     *     Guess <x, e_j> = <x, r> ⊕ <x, s_i> = P(r) ⊕ a_i
     *   Take majority over all guesses.
     */
    int T = 100;  /* Number of trials per bit */
    for (int j = 0; j < n; j++) {
        int votes_1 = 0;
        int total = 0;
        for (int t = 0; t < T; t++) {
            int i = rand() % l;
            /* Build r = e_j ⊕ s_i */
            BitString *r = bitstring_create((size_t)n);
            /* Start with e_j */
            for (int k = 0; k < n; k++) {
                bitstring_set_bit(r, (size_t)k, (k == j) ? 1 : 0);
            }
            /* XOR with s_i */
            for (int k = 0; k < n; k++) {
                int b = bitstring_get_bit(r, (size_t)k) ^
                        bitstring_get_bit(s[i], (size_t)k);
                bitstring_set_bit(r, (size_t)k, b);
            }
            r->bit_len = (size_t)n;

            int pred = predictor(r);
            int guess = pred ^ a[i];
            if (guess) votes_1++;
            total++;
            bitstring_free(r);
        }
        /* Majority vote */
        bitstring_set_bit(candidate, (size_t)j, (votes_1 > total / 2) ? 1 : 0);
    }
    candidate->bit_len = (size_t)n;
}

GLCandidateList *gl_list_decode(int n, GLPredictor predictor,
                                double epsilon, double confidence) {
    (void)confidence;  /* Used in probability analysis, not in basic reconstruction */
    /*
     * Goldreich-Levin list decoding.
     *
     * Parameters:
     *   n: input length
     *   predictor: P(r) attempting to predict <x,r> given (f(x), r)
     *   epsilon: advantage over 1/2 (Pr[correct] >= 1/2 + epsilon)
     *   confidence: 1 - delta (success probability target)
     *
     * Returns a list of O(poly(n, 1/epsilon)) candidate strings.
     *
     * Steps:
     *   1. Choose l = ceil(log2(n/epsilon^2)) random strings s_1,...,s_l
     *   2. For each a ∈ {0,1}^l (guess of <x, s_1>,...,<x, s_l>):
     *      Reconstruct candidate x, add to list
     *   3. Return list
     */
    GLCandidateList *list = (GLCandidateList *)malloc(sizeof(GLCandidateList));
    if (!list) return NULL;

    /* Choose l = ceil(log2(2n / epsilon^2)) */
    double val = 2.0 * n / (epsilon * epsilon);
    int l = 1;
    while ((1 << l) < (int)val && l < 16) l++;
    if (l > n) l = n;

    list->n = n;
    list->capacity = (1 << l) + 4;
    list->n_entries = 0;
    list->entries = (BitString **)malloc((size_t)list->capacity * sizeof(BitString *));
    if (!list->entries) {
        free(list);
        return NULL;
    }

    /* Generate l random strings s_1, ..., s_l of length n */
    BitString **s = (BitString **)malloc((size_t)l * sizeof(BitString *));
    for (int i = 0; i < l; i++) {
        s[i] = bitstring_create((size_t)n);
        bitstring_randomize(s[i]);
    }

    /* For each a ∈ {0,1}^l, reconstruct candidate */
    int *a = (int *)malloc((size_t)l * sizeof(int));
    for (int guess_idx = 0; guess_idx < (1 << l); guess_idx++) {
        /* Set a[i] = i-th bit of guess_idx */
        for (int i = 0; i < l; i++) {
            a[i] = (guess_idx >> i) & 1;
        }

        BitString *candidate = bitstring_create((size_t)n);
        gl_reconstruct_candidate(n, (const BitString **)s, a, l, predictor,
                                 candidate);

        /* Add to list (check for duplicates) */
        int is_dup = 0;
        for (int e = 0; e < list->n_entries; e++) {
            if (bitstring_equal(list->entries[e], candidate)) {
                is_dup = 1;
                break;
            }
        }
        if (!is_dup) {
            if (list->n_entries >= list->capacity) {
                list->capacity *= 2;
                list->entries = (BitString **)realloc(list->entries,
                    (size_t)list->capacity * sizeof(BitString *));
            }
            list->entries[list->n_entries++] = candidate;
        } else {
            bitstring_free(candidate);
        }
    }

    /* Cleanup */
    for (int i = 0; i < l; i++) bitstring_free(s[i]);
    free(s);
    free(a);

    return list;
}

void gl_candidate_list_free(GLCandidateList *list) {
    if (!list) return;
    for (int i = 0; i < list->n_entries; i++) {
        bitstring_free(list->entries[i]);
    }
    free(list->entries);
    free(list);
}

/*
 * Find correct preimage from candidate list by checking f(x') = y.
 */
BitString *gl_find_preimage(const GLCandidateList *candidates,
                             const OWF *owf, const BitString *y) {
    if (!candidates || !owf || !y) return NULL;

    BitString *y_check = bitstring_create(owf->n);
    for (int i = 0; i < candidates->n_entries; i++) {
        if (owf_eval(owf, candidates->entries[i], y_check) == 0 &&
            bitstring_equal(y_check, y)) {
            bitstring_free(y_check);
            return bitstring_clone(candidates->entries[i]);
        }
    }
    bitstring_free(y_check);
    return NULL;
}

/* ================================================================
 * L5: Pairwise Independent Hash Family over GF(2)
 * ================================================================
 * h_{A,b}(x) = Ax + b (mod 2)
 * where A is m × k binary matrix, b is m-bit offset.
 *
 * Pairwise independence: For any distinct x, x':
 *   Pr_{A,b}[h(x) = y AND h(x') = y'] = 1/2^{2m}
 *
 * Uses: Goldreich-Levin list decoding analysis
 *       Leftover hash lemma (entropy extraction)
 *       Universal hashing in HILL construction
 */

GF2HashFunc *gf2_hash_create(int k, int m) {
    GF2HashFunc *h = (GF2HashFunc *)malloc(sizeof(GF2HashFunc));
    if (!h) return NULL;
    h->k = k;
    h->m = m;
    size_t matrix_bytes = (size_t)m * ((size_t)k + 7) / 8;
    h->matrix = (uint8_t *)calloc(matrix_bytes, 1);
    h->offset = (uint8_t *)calloc((size_t)((m + 7) / 8), 1);
    if (!h->matrix || !h->offset) {
        free(h->matrix);
        free(h->offset);
        free(h);
        return NULL;
    }
    return h;
}

void gf2_hash_free(GF2HashFunc *h) {
    if (!h) return;
    free(h->matrix);
    free(h->offset);
    free(h);
}

void gf2_hash_set_random(GF2HashFunc *h) {
    if (!h) return;
    size_t matrix_bytes = (size_t)h->m * ((size_t)h->k + 7) / 8;
    for (size_t i = 0; i < matrix_bytes; i++) {
        h->matrix[i] = (uint8_t)(rand() & 0xFF);
    }
    size_t offset_bytes = (size_t)((h->m + 7) / 8);
    for (size_t i = 0; i < offset_bytes; i++) {
        h->offset[i] = (uint8_t)(rand() & 0xFF);
    }
}

void gf2_hash_eval(const GF2HashFunc *h, const BitString *x, BitString *out) {
    if (!h || !x || !out) return;
    assert((int)x->bit_len <= h->k);
    /*
     * y = A*x + b mod 2
     * y_i = b_i + sum_{j=0}^{k-1} A[i][j] * x_j mod 2
     */
    for (int i = 0; i < h->m; i++) {
        int sum = 0;
        /* Get b_i */
        size_t off_byte = (size_t)i / 8;
        int off_bit = 7 - (i % 8);
        sum = (h->offset[off_byte] >> off_bit) & 1;

        /* Compute A[i] · x */
        for (int j = 0; j < h->k && (size_t)j < x->bit_len; j++) {
            size_t mat_byte = (size_t)i * ((size_t)h->k + 7) / 8 + (size_t)j / 8;
            int mat_bit = 7 - (j % 8);
            int A_ij = (h->matrix[mat_byte] >> mat_bit) & 1;
            sum ^= (A_ij & bitstring_get_bit(x, (size_t)j));
        }
        bitstring_set_bit(out, (size_t)i, sum);
    }
    out->bit_len = (size_t)h->m;
}

int gf2_hash_verify_pairwise_independence(int k, int m, int n_trials) {
    /*
     * Empirically verify pairwise independence.
     * For many random hash functions and pairs (x, x') with x ≠ x',
     * check that collision probability ≈ 1/2^m.
     *
     * This is a validation check, not a proof.
     */
    int collisions = 0;
    int total = 0;
    GF2HashFunc *h = gf2_hash_create(k, m);
    BitString *x = bitstring_create((size_t)k);
    BitString *xp = bitstring_create((size_t)k);
    BitString *hx = bitstring_create((size_t)m);
    BitString *hxp = bitstring_create((size_t)m);

    for (int trial = 0; trial < n_trials; trial++) {
        gf2_hash_set_random(h);
        bitstring_randomize(x);
        bitstring_randomize(xp);
        /* Ensure x ≠ x' */
        bitstring_set_bit(xp, 0, 1 ^ bitstring_get_bit(x, 0));

        gf2_hash_eval(h, x, hx);
        gf2_hash_eval(h, xp, hxp);

        if (bitstring_equal(hx, hxp)) collisions++;
        total++;
    }

    bitstring_free(x);
    bitstring_free(xp);
    bitstring_free(hx);
    bitstring_free(hxp);
    gf2_hash_free(h);

    if (total == 0) return 0;
    /* Expected collision prob = 1/2^m. Check it's within reasonable range. */
    double observed = (double)collisions / total;
    double expected = 1.0 / (1 << m);
    /* Tolerance: within factor 3 */
    return (observed >= expected / 3.0 && observed <= expected * 3.0) ? 1 : 0;
}

/* ================================================================
 * L8: Universal Hardcore Predicate Analysis
 * ================================================================
 * Measure the advantage of a predictor for the GL hardcore bit.
 * This quantifies "how hardcore" the bit is against a specific
 * predictor algorithm.
 */

double gl_measure_advantage(const OWF *owf, const BitString *x,
                            GLPredictor predictor, int n_samples) {
    /*
     * Estimate: adv = |Pr[P(r) = <x,r>] - 1/2|
     *
     * For each sample:
     *   1. Choose random r
     *   2. Compute correct answer: <x, r>
     *   3. Get prediction P(r)
     *   4. Count correct predictions
     */
    if (!owf || !x || !predictor || n_samples <= 0) return 0.0;

    int correct = 0;
    size_t n = x->bit_len;
    BitString *r = bitstring_create(n);

    for (int t = 0; t < n_samples; t++) {
        bitstring_randomize(r);
        int truth = gf2_dot_product(x, r);
        int pred = predictor(r);
        if (truth == pred) correct++;
    }

    bitstring_free(r);

    double prob = (double)correct / n_samples;
    double advantage = prob - 0.5;
    if (advantage < 0) advantage = -advantage;
    return advantage;
}
