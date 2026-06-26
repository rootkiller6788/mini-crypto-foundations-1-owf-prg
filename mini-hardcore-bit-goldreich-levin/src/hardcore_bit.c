/*
 * hardcore_bit.c — Hardcore Predicates & Hardcore Bits
 *
 * Implements hardcore predicate functions and the Goldreich-Levin
 * hardcore bit construction. A hardcore predicate hc for function f
 * is easy to compute given x but hard to predict given only f(x).
 *
 * Knowledge Points Covered:
 *   L1: Formal definition of hardcore predicate
 *   L2: Hardcore bit vs one-way function relationship
 *   L3: GL bit: b(x,r) = ⟨x,r⟩ mod 2 as mathematical structure
 *   L4: GL theorem statement: ⟨x,r⟩ is hardcore for g(x,r)=(f(x),r)
 *   L5: Security estimation via statistical sampling
 *   L7: Applications in cryptographic PRG construction
 *
 * Reference: Goldreich-Levin STOC 1989; Arora-Barak §9.3
 * Courses: MIT 6.875, Stanford CS255, CMU 15-859
 */

#include "hardcore_bit.h"
#include "bit_operations.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#ifndef _strdup
#define _strdup strdup
#endif

/* ───────────────────────────────────────────────────────────────
 * GL Inner Product Bit — The Goldreich-Levin Hardcore Bit
 *
 * Definition: hc_GL(x, r) = ⟨x, r⟩ mod 2 = Σ_i x_i · r_i (mod 2)
 *
 * This is the single bit of information about x that remains
 * computationally hidden given f(x) and r.
 *
 * Key properties:
 *   1. Bilinearity: ⟨x, r₁⊕r₂⟩ = ⟨x, r₁⟩ ⊕ ⟨x, r₂⟩
 *   2. Self-correction: ⟨x, r⟩ ⊕ ⟨x, r⊕e_i⟩ = ⟨x, e_i⟩ = x_i
 *   3. The GL theorem proves this is hardcore for g(x,r)=(f(x),r)
 *      whenever f is a one-way function.
 * ───────────────────────────────────────────────────────────── */

int hc_inner_product(const BitString* x, const BitString* r, void* params) {
    (void)params;
    if (!x || !r) return 0;
    size_t n = x->n_words;
    if (r->n_words < n) n = r->n_words;
    return bit_inner_product(x->data, r->data, n);
}

double hc_inner_product_parity(const BitString* x) {
    if (!x) return 0.0;
    return (double)bit_parity_buf(x->data, x->n_words);
}

int hc_inner_product_mod2(const BitString* x, const BitString* r) {
    return hc_inner_product(x, r, NULL);
}

/* ───────────────────────────────────────────────────────────────
 * Specific Hardcore Bits for Candidate OWFs
 *
 * MSB — Most Significant Bit
 *   For discrete log based OWFs (Blum-Micali 1984):
 *   Given g^x mod p, the MSB of x is a hardcore bit.
 *
 * LSB — Least Significant Bit
 *   For RSA based OWFs (Alexi-Chor-Goldreich-Schnorr 1988):
 *   Given x^e mod N, the LSB of x is a hardcore bit.
 *
 * GL Bit — Goldreich-Levin generic construction:
 *   Applies to any OWF via the g(x,r) = (f(x), r) transformation.
 * ───────────────────────────────────────────────────────────── */

int hc_msb(const BitString* x, const BitString* r, void* params) {
    (void)r;
    (void)params;
    if (!x || x->n_bits == 0) return 0;
    return bs_get_bit(x, x->n_bits - 1);
}

int hc_lsb(const BitString* x, const BitString* r, void* params) {
    (void)r;
    (void)params;
    if (!x || x->n_bits == 0) return 0;
    return bs_get_bit(x, 0);
}

int hc_gl_bit(const BitString* x, const BitString* r, void* params) {
    return hc_inner_product(x, r, params);
}

/* ───────────────────────────────────────────────────────────────
 * Hardcore Predicate Management
 * ───────────────────────────────────────────────────────────── */

HardcorePredicate* hc_create(const char* name,
                              int (*predict)(const BitString*, const BitString*, void*),
                              void* params, size_t params_size) {
    if (!predict) return NULL;
    HardcorePredicate* hc = (HardcorePredicate*)malloc(sizeof(HardcorePredicate));
    if (!hc) return NULL;
    hc->name        = name ? _strdup(name) : _strdup("unnamed");
    hc->description = _strdup("");
    hc->predict     = predict;
    hc->params      = params;
    hc->params_size = params_size;
    return hc;
}

void hc_free(HardcorePredicate* hc) {
    if (hc) {
        free(hc->name);
        free(hc->description);
        free(hc);
    }
}

int hc_eval(const HardcorePredicate* hc, const BitString* x, const BitString* r) {
    if (!hc || !hc->predict || !x) return 0;
    return hc->predict(x, r, hc->params);
}

/* ───────────────────────────────────────────────────────────────
 * Security Estimation
 *
 * Estimate how well an adversary can predict the hardcore bit.
 * A hardcore predicate should satisfy:
 *   |Pr[Adversary predicts hc(x) given f(x)] - 1/2| ≤ negl(n)
 *
 * We estimate this via statistical sampling.
 * ───────────────────────────────────────────────────────────── */

HCSecurityEstimate* hc_estimate_security(const HardcorePredicate* hc,
                                          const OWF* owf,
                                          int num_samples) {
    if (!hc || !owf || num_samples <= 0) return NULL;
    HCSecurityEstimate* est = (HCSecurityEstimate*)malloc(sizeof(HCSecurityEstimate));
    if (!est) return NULL;
    est->num_samples = num_samples;
    est->confidence  = 0.0;

    int correct = 0;
    for (int i = 0; i < num_samples; i++) {
        BitString* x = bs_create_random(owf->input_bits);
        BitString* r = bs_create_random(owf->input_bits);
        BitString* fx = bs_create(owf->output_bits);
        if (!x || !r || !fx) { bs_free(x); bs_free(r); bs_free(fx); continue; }
        owf_eval(owf, x, fx);
        /* Simulate a naive adversary: random guess */
        int guess = rand() & 1;
        int truth = hc_eval(hc, x, r);
        if (guess == truth) correct++;
        bs_free(x); bs_free(r); bs_free(fx);
    }
    double accuracy = (double)correct / (double)num_samples;
    est->advantage  = accuracy - 0.5;
    if (est->advantage < 0) est->advantage = -est->advantage;
    /* Confidence: Hoeffding bound based estimate */
    est->confidence = 1.0 - 2.0 * exp(-2.0 * num_samples * est->advantage * est->advantage);
    if (est->confidence > 1.0) est->confidence = 1.0;
    return est;
}

void hc_security_estimate_free(HCSecurityEstimate* est) {
    free(est);
}

int hc_verify_hardcore(const HardcorePredicate* hc, const OWF* owf,
                        int num_samples, double threshold) {
    HCSecurityEstimate* est = hc_estimate_security(hc, owf, num_samples);
    if (!est) return 0;
    int result = (est->advantage <= threshold) ? 1 : 0;
    hc_security_estimate_free(est);
    return result;
}

/* ───────────────────────────────────────────────────────────────
 * GL Construction: g(x,r) = (f(x), r)
 *
 * The standard GL formulation wraps an OWF f and constructs
 *     g(x, r) = (f(x), r)    where |x| = |r|
 * with hardcore predicate hc(x, r) = ⟨x, r⟩ mod 2.
 *
 * Theorem (Goldreich-Levin): If f is a OWF, then hc_GL is a
 * hardcore predicate for g.
 * ───────────────────────────────────────────────────────────── */

GLConstruction* gl_construct(OWF* owf) {
    if (!owf) return NULL;
    GLConstruction* gl = (GLConstruction*)malloc(sizeof(GLConstruction));
    if (!gl) return NULL;
    gl->base_owf   = owf;
    gl->expansion  = 1;
    /* Set up the GL hardcore predicate */
    gl->hc_pred.name        = _strdup("Goldreich-Levin Hardcore Bit");
    gl->hc_pred.description = _strdup("hc(x,r) = ⟨x,r⟩ mod 2");
    gl->hc_pred.predict     = hc_gl_bit;
    gl->hc_pred.params      = NULL;
    gl->hc_pred.params_size = 0;
    return gl;
}

void gl_construct_free(GLConstruction* gl) {
    if (gl) {
        free(gl->hc_pred.name);
        free(gl->hc_pred.description);
        free(gl);
    }
}

int gl_compute_output(const GLConstruction* gl,
                       const BitString* x, const BitString* r,
                       BitString* g_out, int* hc_out) {
    if (!gl || !x || !r || !g_out) return 0;
    /* Compute f(x) */
    if (!owf_eval(gl->base_owf, x, g_out)) return 0;
    /* Compute hc(x, r) = ⟨x, r⟩ mod 2 */
    if (hc_out) {
        *hc_out = hc_eval(&gl->hc_pred, x, r);
    }
    return 1;
}

int gl_verify_hardcore(const GLConstruction* gl, int num_trials) {
    if (!gl) return 0;
    return hc_verify_hardcore(&gl->hc_pred, gl->base_owf, num_trials, 0.1);
}

/* ───────────────────────────────────────────────────────────────
 * Predictor Operations
 *
 * A predictor P attempts to guess ⟨x,r⟩ given (f(x), r).
 * The advantage ε = |Pr[P correct] - 1/2| quantifies how much
 * better than random guessing the predictor performs.
 * ───────────────────────────────────────────────────────────── */

HCPredictor* hc_predictor_create(const char* name,
                                   int (*query)(const BitString*, const BitString*,
                                                int*, void*),
                                   void* ctx) {
    if (!query) return NULL;
    HCPredictor* pred = (HCPredictor*)malloc(sizeof(HCPredictor));
    if (!pred) return NULL;
    pred->name      = name ? _strdup(name) : _strdup("unnamed");
    pred->advantage = 0.0;
    pred->query     = query;
    pred->ctx       = ctx;
    return pred;
}

void hc_predictor_free(HCPredictor* pred) {
    if (pred) {
        free(pred->name);
        free(pred);
    }
}

double hc_predictor_estimate_advantage(const HCPredictor* pred,
                                        const OWF* owf,
                                        int num_trials) {
    if (!pred || !owf || num_trials <= 0) return 0.0;
    int correct = 0;
    for (int t = 0; t < num_trials; t++) {
        BitString* x = bs_create_random(owf->input_bits);
        BitString* r = bs_create_random(owf->input_bits);
        BitString* fx = bs_create(owf->output_bits);
        if (!x || !r || !fx) { bs_free(x); bs_free(r); bs_free(fx); continue; }
        owf_eval(owf, x, fx);
        int pred_bit, truth;
        pred->query(fx, r, &pred_bit, pred->ctx);
        truth = bit_inner_product(x->data, r->data,
                                   x->n_words < r->n_words ? x->n_words : r->n_words);
        if (pred_bit == truth) correct++;
        bs_free(x); bs_free(r); bs_free(fx);
    }
    double accuracy = (double)correct / (double)num_trials;
    return accuracy - 0.5;
}

int hc_predictor_guess(const HCPredictor* pred,
                        const BitString* fx, const BitString* r) {
    if (!pred || !pred->query || !fx || !r) return 0;
    int prediction;
    pred->query(fx, r, &prediction, pred->ctx);
    return prediction;
}

/* ───────────────────────────────────────────────────────────────
 * Predictor Statistics
 * ───────────────────────────────────────────────────────────── */

PredictorStats* hc_predictor_stats(const HCPredictor* pred,
                                     const BitString** fx_samples,
                                     const BitString** r_samples,
                                     const int* true_values,
                                     size_t num_samples) {
    if (!pred || !fx_samples || !r_samples || !true_values || num_samples == 0)
        return NULL;
    PredictorStats* stats = (PredictorStats*)malloc(sizeof(PredictorStats));
    if (!stats) return NULL;
    stats->correct = 0;
    stats->total   = num_samples;
    for (size_t i = 0; i < num_samples; i++) {
        int guess = hc_predictor_guess(pred, fx_samples[i], r_samples[i]);
        if (guess == true_values[i]) stats->correct++;
    }
    stats->accuracy  = (double)stats->correct / (double)stats->total;
    stats->advantage = stats->accuracy - 0.5;
    if (stats->advantage < 0) stats->advantage = -stats->advantage;
    return stats;
}

void hc_predictor_stats_free(PredictorStats* stats) {
    free(stats);
}
