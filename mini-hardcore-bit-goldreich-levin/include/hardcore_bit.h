/*
 * hardcore_bit.h — Hardcore Predicates & Hardcore Bits
 *
 * Formal Definition (L1, L2):
 *   A polynomial-time computable predicate hc: {0,1}* → {0,1} is a hardcore
 *   predicate of a function f: {0,1}* → {0,1}* if for every PPT algorithm A,
 *   there exists a negligible function negl such that:
 *
 *     Pr[A(1^n, f(x)) = hc(x)] ≤ 1/2 + negl(n)
 *
 *   where the probability is taken over uniform choice of x ∈ {0,1}^n and
 *   the randomness of A.
 *
 *   Equivalently: |Pr[A(f(x)) = hc(x)] - 1/2| ≤ negl(n)
 *
 * Hardcore Bit vs Goldreich-Levin Bit:
 *   - A hardcore bit for f is a specific bit position of x
 *   - The GL theorem shows that for any OWF f, the inner product ⟨x,r⟩
 *     is a hardcore bit for the function g(x,r) = (f(x), r)
 *
 * Construction Types:
 *   - Generic GL construction: hc_{GL}((x,r)) = ⟨x,r⟩ mod 2
 *   - Blum-Micali (1984): hc(x) = MSB(x) for discrete log
 *   - RSA LSB: hc(x) = LSB(x) for RSA (Alexi-Chor-Goldreich-Schnorr 1988)
 *
 * Reference: Goldreich-Levin (STOC 1989), Arora-Barak §9.3
 * Courses: MIT 6.875, Stanford CS255, CMU 15-859
 */

#ifndef HARDCORE_BIT_H
#define HARDCORE_BIT_H

#include "owf.h"

/* ── Hardcore Predicate Type ─────────────────────────────── */
typedef struct {
    char*   name;
    char*   description;
    /* Evaluation: given input x (and auxiliary r), output 0 or 1 */
    int (*predict)(const BitString* x, const BitString* r, void* params);
    void*   params;
    size_t  params_size;
} HardcorePredicate;

/* ── Hardcore Bit Security ───────────────────────────────── */
typedef struct {
    double advantage;        /* |Pr[predict correct] - 1/2| */
    int    num_samples;      /* samples used to estimate */
    double confidence;       /* statistical confidence */
} HCSecurityEstimate;

/* ── GL Bit (Inner Product) ──────────────────────────────── */
/* b(x,r) = Σ_i x_i · r_i mod 2 = ⟨x,r⟩ mod 2 */
int    hc_inner_product(const BitString* x, const BitString* r, void* params);
double hc_inner_product_parity(const BitString* x);
int    hc_inner_product_mod2(const BitString* x, const BitString* r);

/* ── Specific Hardcore Bits for Candidate OWFs ───────────── */
/* Most significant bit (used for discrete log OWF) */
int    hc_msb(const BitString* x, const BitString* r, void* params);

/* Least significant bit (used for RSA OWF) */
int    hc_lsb(const BitString* x, const BitString* r, void* params);

/* Goldreich-Levin constructed hardcore bit */
int    hc_gl_bit(const BitString* x, const BitString* r, void* params);

/* ── Hardcore Predicate Management ───────────────────────── */
HardcorePredicate* hc_create(const char* name,
                              int (*predict)(const BitString*, const BitString*, void*),
                              void* params, size_t params_size);
void               hc_free(HardcorePredicate* hc);
int                hc_eval(const HardcorePredicate* hc,
                           const BitString* x, const BitString* r);

/* ── Security Estimation ─────────────────────────────────── */
HCSecurityEstimate* hc_estimate_security(const HardcorePredicate* hc,
                                          const OWF* owf,
                                          int num_samples);
void                hc_security_estimate_free(HCSecurityEstimate* est);
int                 hc_verify_hardcore(const HardcorePredicate* hc,
                                        const OWF* owf,
                                        int num_samples, double threshold);

/* ── Hardcore Bit for g(x,r) = (f(x), r) ────────────────── */
/* The standard GL formulation: given OWF f, define 
 * g(x,r) = (f(x), r) and hc(x,r) = ⟨x,r⟩ mod 2 */
typedef struct {
    OWF*              base_owf;       /* f */
    HardcorePredicate hc_pred;       /* hc */
    size_t            expansion;     /* seed expansion factor */
} GLConstruction;

GLConstruction* gl_construct(OWF* owf);
void            gl_construct_free(GLConstruction* gl);
int             gl_compute_output(const GLConstruction* gl,
                                   const BitString* x, const BitString* r,
                                   BitString* g_out, int* hc_out);
int             gl_verify_hardcore(const GLConstruction* gl, int num_trials);

/* ── Predictor Definition ────────────────────────────────── */
/* A predictor P: given (f(x), r), tries to predict ⟨x,r⟩ mod 2 */
typedef struct {
    char*   name;
    double  advantage;       /* |Pr[correct] - 1/2| */
    int (*query)(const BitString* fx, const BitString* r, int* pred, void* ctx);
    void*   ctx;
} HCPredictor;

/* ── Predictor Operations ────────────────────────────────── */
HCPredictor* hc_predictor_create(const char* name,
                                   int (*query)(const BitString*, const BitString*,
                                                int*, void*),
                                   void* ctx);
void         hc_predictor_free(HCPredictor* pred);
double       hc_predictor_estimate_advantage(const HCPredictor* pred,
                                              const OWF* owf,
                                              int num_trials);
int          hc_predictor_guess(const HCPredictor* pred,
                                 const BitString* fx, const BitString* r);

/* ── Prediction Confidence ───────────────────────────────── */
typedef struct {
    size_t correct;
    size_t total;
    double accuracy;
    double advantage;
} PredictorStats;

PredictorStats* hc_predictor_stats(const HCPredictor* pred,
                                     const BitString** fx_samples,
                                     const BitString** r_samples,
                                     const int* true_values,
                                     size_t num_samples);
void            hc_predictor_stats_free(PredictorStats* stats);

#endif /* HARDCORE_BIT_H */
