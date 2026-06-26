/*
 * owf_hardcore.c - Hardcore Predicates and Goldreich-Levin Theorem
 *
 * L4 Fundamental Law: Goldreich-Levin (1989) - Every OWF has a
 * hardcore predicate. GL(x, r) = <x, r> mod 2 is hardcore for
 * g(x, r) = (f(x), r).
 *
 * L2 Core Concept: Hardcore predicate hc is efficiently computable
 * from x but unpredictable given f(x):
 *   Pr[A(f(x)) = hc(x)] <= 1/2 + negl(n)
 *
 * L8 Advanced Topic:
 *   - GL list decoding algorithm (learning parity with noise)
 *   - General hardcore predicates from any OWF
 *   - k-bit hardcore functions
 *
 * Reference: Goldreich, Levin (STOC 1989); Goldreich Vol 1 Sec 2.5;
 *   Katz-Lindell Sec 7.4.1; Arora-Barak Sec 19.3
 */

#include "owf_hardcore.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* ================================================================
 * Hardcore Predicate: Creation and Management (L2)
 * ================================================================ */

hardcore_predicate_t* hcp_create(const char* name, hardcore_pred_fn compute,
                                  owf_scheme_t* owf) {
    hardcore_predicate_t* hcp = (hardcore_predicate_t*)calloc(1, sizeof(hardcore_predicate_t));
    if (!hcp) return NULL;
    hcp->name    = name ? strdup(name) : NULL;
    hcp->compute = compute;
    hcp->owf     = owf;
    hcp->empirical_bias = 0.0;
    hcp->num_trials     = 0;
    return hcp;
}

void hcp_free(hardcore_predicate_t* hcp) {
    if (hcp) { free(hcp->name); free(hcp); }
}

int hcp_evaluate(const hardcore_predicate_t* hcp, const bit_string_t* x) {
    if (!hcp || !hcp->compute || !x) return 0;
    return hcp->compute(x);
}


/* ================================================================
 * Goldreich-Levin Predicate (L4)
 *
 * GL(x, r) = <x, r> mod 2 = XOR of x_i AND r_i
 *
 * Universal hardcore predicate: for ANY OWF f, the function
 * g(x, r) = (f(x), r) has GL as hardcore predicate.
 * ================================================================ */

int gl_predicate(const bit_string_t* x, const bit_string_t* r) {
    if (!x || !r) return 0;
    size_t min_len = x->bit_len < r->bit_len ? x->bit_len : r->bit_len;
    int bit_xor = 0;
    for (size_t i = 0; i < min_len; i++) {
        size_t byte_idx = i / 8, bit_idx = i % 8;
        if (byte_idx >= x->byte_cap || byte_idx >= r->byte_cap) break;
        int xi = (x->data[byte_idx] >> bit_idx) & 1;
        int ri = (r->data[byte_idx] >> bit_idx) & 1;
        bit_xor ^= (xi & ri);
    }
    return bit_xor;
}

int gl_predicate_combined(const bit_string_t* xr_combined) {
    if (!xr_combined) return 0;
    size_t half = xr_combined->bit_len / 2;
    bit_string_t x_view;
    x_view.data     = xr_combined->data;
    x_view.bit_len  = half;
    x_view.byte_cap = (half + 7) / 8;
    size_t half_bytes = (half + 7) / 8;
    bit_string_t r_view;
    r_view.data     = xr_combined->data + half_bytes;
    r_view.bit_len  = half;
    r_view.byte_cap = xr_combined->byte_cap - half_bytes;
    return gl_predicate(&x_view, &r_view);
}

/* ================================================================
 * Goldreich-Levin Construction: g(x, r) = (f(x), r)  (L4)
 *
 * Transforms any OWF f into g with hardcore predicate GL.
 * The elegance: r is output alongside f(x), making it available
 * for list decoding in the security proof.
 * ================================================================ */

gl_construction_t* gl_construct_create(owf_scheme_t* base_owf) {
    if (!base_owf) return NULL;
    gl_construction_t* gl = (gl_construction_t*)calloc(1, sizeof(gl_construction_t));
    if (!gl) return NULL;
    gl->base_owf  = base_owf;
    gl->n         = base_owf->input_bits;
    gl->sec_param = base_owf->sec_param;
    return gl;
}

void gl_construct_free(gl_construction_t* construct) {
    free(construct);
}

int gl_construct_eval(void* ctx, const bit_string_t* xr,
                      sec_param_t n, bit_string_t** y) {
    (void)n;
    gl_construction_t* gl = (gl_construction_t*)ctx;
    if (!gl || !xr || !y) return -1;
    size_t half = gl->n;
    if (xr->bit_len < 2 * half) return -1;
    bit_string_t* x = bs_create(half);
    bit_string_t* r = bs_create(half);
    if (!x || !r) { bs_free(x); bs_free(r); return -1; }
    for (size_t i = 0; i < half; i++) {
        size_t byte_i = i / 8, bit_i = i % 8;
        if (byte_i < xr->byte_cap && byte_i < x->byte_cap) {
            int b = (xr->data[byte_i] >> bit_i) & 1;
            if (b) x->data[byte_i] |= (1u << bit_i);
        }
        size_t r_byte_i = (half + i) / 8, r_bit_i = (half + i) % 8;
        if (r_byte_i < xr->byte_cap && byte_i < r->byte_cap) {
            int b = (xr->data[r_byte_i] >> r_bit_i) & 1;
            if (b) r->data[byte_i] |= (1u << bit_i);
        }
    }
    bit_string_t* fx = NULL;
    int ret = owf_evaluate(gl->base_owf, x, &fx);
    bs_free(x);
    if (ret != 0 || !fx) { bs_free(r); return -1; }
    /* total_bytes computed below */
    size_t total_bits  = fx->bit_len + r->bit_len;
    *y = bs_create(total_bits);
    if (!*y) { bs_free(fx); bs_free(r); return -1; }
    memcpy((*y)->data, fx->data, fx->byte_cap);
    memcpy((*y)->data + fx->byte_cap, r->data, r->byte_cap);
    bs_free(fx); bs_free(r);
    return 0;
}

owf_scheme_t* gl_construct_as_owf(gl_construction_t* construct) {
    if (!construct) return NULL;
    size_t out_bits = construct->base_owf->output_bits + construct->n;
    return owf_scheme_create("GL-Construction",
        "Goldreich-Levin (any OWF -> OWF with hardcore predicate)",
        gl_construct_eval, NULL, NULL, construct,
        construct->sec_param, 2 * construct->n, out_bits);
}


/* ================================================================
 * GL List Data Structure (L8)
 * ================================================================ */

gl_list_t* gl_list_create(size_t capacity) {
    gl_list_t* list = (gl_list_t*)calloc(1, sizeof(gl_list_t));
    if (!list) return NULL;
    list->capacity = capacity > 0 ? capacity : 64;
    list->cand_list = (bit_string_t**)calloc(list->capacity, sizeof(bit_string_t*));
    if (!list->cand_list) { free(list); return NULL; }
    return list;
}

void gl_list_free(gl_list_t* list) {
    if (list) {
        for (size_t i = 0; i < list->num_candidates; i++)
            bs_free(list->cand_list[i]);
        free(list->cand_list);
        free(list);
    }
}

int gl_list_add(gl_list_t* list, const bit_string_t* candidate) {
    if (!list || !candidate) return -1;
    if (list->num_candidates >= list->capacity) {
        size_t new_cap = list->capacity * 2;
        bit_string_t** new_arr = (bit_string_t**)realloc(
            list->cand_list, new_cap * sizeof(bit_string_t*));
        if (!new_arr) return -1;
        list->cand_list = new_arr;
        list->capacity = new_cap;
    }
    list->cand_list[list->num_candidates] = bs_clone(candidate);
    if (!list->cand_list[list->num_candidates]) return -1;
    list->num_candidates++;
    return 0;
}

/* ================================================================
 * GL List Decoding Algorithm (L8)
 *
 * Core of the GL proof: given predictor P with Pr[P(r)=<x,r>] >= 1/2+eps,
 * efficiently find x. Uses pairwise independent sampling.
 *
 * 1. Select k = O(n/eps^2) random strings r_1..r_k
 * 2. For each z in {0,1}^k: estimate each x_j by majority over
 *    P(r_i XOR e_j) XOR P(r_i) for i with z_i=1
 * 3. Verify candidate, output list of all passing candidates
 *
 * Complexity: poly(n,1/eps)*2^{O(n/eps^2)} queries
 * ================================================================ */

int gl_list_decode(gl_predictor_fn predictor, void* pred_ctx,
                   size_t n, double epsilon, gl_list_t* out_list) {
    if (!predictor || !out_list || epsilon <= 0.0 || epsilon > 0.5) return -1;
    size_t k = (size_t)ceil(2.0 * (double)n / (epsilon * epsilon));
    if (k > 64) k = 64;
    if (k < 8) k = 8;
    bit_string_t** r_samples = (bit_string_t**)calloc(k, sizeof(bit_string_t*));
    if (!r_samples) return -1;
    for (size_t i = 0; i < k; i++) r_samples[i] = bs_random(n);
    bit_string_t* ej = bs_create(n);
    if (!ej) {
        for (size_t i = 0; i < k; i++) bs_free(r_samples[i]);
        free(r_samples); return -1;
    }
    size_t max_candidates = (size_t)1 << (k < 10 ? k : 10);
    size_t found = 0;
    for (size_t z_mask = 0; z_mask < max_candidates && found < out_list->capacity; z_mask++) {
        bit_string_t* candidate = bs_create(n);
        if (!candidate) continue;
        int valid = 1;
        for (size_t j = 0; j < n && valid; j++) {
            int votes_0 = 0, votes_1 = 0;
            memset(ej->data, 0, ej->byte_cap);
            size_t ej_byte = j / 8, ej_bit = j % 8;
            if (ej_byte < ej->byte_cap) ej->data[ej_byte] = (1u << ej_bit);
            for (size_t i = 0; i < k; i++) {
                if ((z_mask >> i) & 1) {
                    bit_string_t* r_plus_ej = bs_create(n);
                    if (!r_plus_ej) { valid = 0; break; }
                    for (size_t b = 0; b < r_samples[i]->byte_cap && b < r_plus_ej->byte_cap; b++)
                        r_plus_ej->data[b] = r_samples[i]->data[b] ^ ej->data[b];
                    int pr = predictor(r_samples[i], pred_ctx);
                    int pp = predictor(r_plus_ej, pred_ctx);
                    int bg = pr ^ pp;
                    if (bg) votes_1++; else votes_0++;
                    bs_free(r_plus_ej);
                }
            }
            if (valid) {
                if (votes_1 > votes_0) {
                    size_t bj = j / 8, bjt = j % 8;
                    if (bj < candidate->byte_cap) candidate->data[bj] |= (1u << bjt);
                }
            }
        }
        if (valid) {
            double agree = gl_verify_candidate(predictor, pred_ctx, candidate, 32);
            if (agree >= 0.5 + epsilon / 2.0) {
                if (gl_list_add(out_list, candidate) == 0) found++;
            }
        }
        bs_free(candidate);
    }
    bs_free(ej);
    for (size_t i = 0; i < k; i++) bs_free(r_samples[i]);
    free(r_samples);
    return (int)found;
}

double gl_verify_candidate(gl_predictor_fn predictor, void* pred_ctx,
                           const bit_string_t* candidate, size_t num_tests) {
    if (!predictor || !candidate || num_tests == 0) return 0.0;
    size_t correct = 0, n = candidate->bit_len;
    for (size_t t = 0; t < num_tests; t++) {
        bit_string_t* r = bs_random(n);
        if (!r) continue;
        int pred = predictor(r, pred_ctx);
        int truth = gl_predicate(candidate, r);
        if (pred == truth) correct++;
        bs_free(r);
    }
    return (double)correct / (double)num_tests;
}


/* ================================================================
 * Hardcore Predicate Experiment (L2)
 *
 * Game: Sample x, give adversary y=f(x) but NOT x.
 * Adversary tries to predict hc(x). Measure bias.
 * ================================================================ */

hcp_experiment_t* hcp_experiment_run(hardcore_predicate_t* hcp,
                                      owf_invert_fn adversary, void* adv_ctx,
                                      int num_trials) {
    if (!hcp || !adversary || num_trials <= 0) return NULL;
    hcp_experiment_t* exp = (hcp_experiment_t*)calloc(1, sizeof(hcp_experiment_t));
    if (!exp) return NULL;
    exp->hcp = hcp;
    exp->num_trials = num_trials;
    size_t n = hcp->owf ? hcp->owf->input_bits : 128;
    for (int i = 0; i < num_trials; i++) {
        bit_string_t* x = bs_random(n);
        if (!x) continue;
        int truth = hcp_evaluate(hcp, x);
        bit_string_t* y = NULL;
        if (hcp->owf) owf_evaluate(hcp->owf, x, &y);
        bit_string_t* adv_output = NULL;
        if (hcp->owf && y) adversary(adv_ctx, y, hcp->owf->sec_param, &adv_output);
        int guess = 0;
        if (adv_output && adv_output->byte_cap > 0) guess = adv_output->data[0] & 1;
        if (guess == truth) exp->correct_guesses++;
        else exp->wrong_guesses++;
        bs_free(x); bs_free(y); bs_free(adv_output);
    }
    int total = exp->correct_guesses + exp->wrong_guesses;
    exp->success_rate = total > 0 ? (double)exp->correct_guesses / (double)total : 0.0;
    exp->bias = fabs(exp->success_rate - 0.5);
    exp->is_hardcore = (exp->bias < 0.2) ? 1 : 0;
    hcp->empirical_bias = exp->bias;
    hcp->num_trials = num_trials;
    return exp;
}

void hcp_experiment_free(hcp_experiment_t* exp) {
    free(exp);
}

void hcp_experiment_print(const hcp_experiment_t* exp) {
    if (!exp) { printf("HCP Experiment: NULL\n"); return; }
    printf("=== Hardcore Predicate Experiment ===\n");
    printf("  Predicate: %s\n", exp->hcp ? exp->hcp->name : "unknown");
    printf("  Trials: %d\n", exp->num_trials);
    printf("  Correct guesses: %d\n", exp->correct_guesses);
    printf("  Wrong guesses: %d\n", exp->wrong_guesses);
    printf("  Success rate: %.4f\n", exp->success_rate);
    printf("  Bias |Pr - 1/2|: %.4f\n", exp->bias);
    printf("  Hardcore? %s\n", exp->is_hardcore ? "YES" : "NO");
}

/* Trivial predictors (baselines) */
int trivial_constant_predictor(const bit_string_t* r, void* ctx) {
    (void)r;
    int constant = ctx ? *(int*)ctx : 0;
    return constant;
}

int trivial_random_predictor(const bit_string_t* r, void* ctx) {
    (void)r; (void)ctx;
    return rand() & 1;
}

/* ================================================================
 * k-Bit Hardcore Function (L8)
 *
 * Extend GL to output k simultaneous hardcore bits:
 *   hc_k(x, r_1,...,r_k) = (<x,r_1>, ..., <x,r_k>) mod 2
 *
 * Theorem: If f is OWF, all k bits simultaneously unpredictable
 * given (f(x), r_1,...,r_k). Enables PRG construction.
 * ================================================================ */

int gl_kbit_hardcore(const bit_string_t* x,
                     const bit_string_t** r_list, int k,
                     uint8_t* out_bits) {
    if (!x || !r_list || k <= 0 || !out_bits) return -1;
    *out_bits = 0;
    for (int i = 0; i < k && i < 8; i++) {
        if (r_list[i]) {
            int bit = gl_predicate(x, r_list[i]);
            if (bit) *out_bits |= (1u << i);
        }
    }
    return 0;
}
