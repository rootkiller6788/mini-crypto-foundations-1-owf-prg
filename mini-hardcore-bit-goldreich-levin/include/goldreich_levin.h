/*
 * goldreich_levin.h — Goldreich-Levin Theorem & Reduction
 *
 * Theorem (Goldreich-Levin, 1989):
 *   Let f: {0,1}^n → {0,1}^* be a one-way function. Define
 *     g(x, r) = (f(x), r)  where |x| = |r| = n.
 *   Then the predicate b(x, r) = ⟨x, r⟩ = Σ_i x_i · r_i (mod 2)
 *   is a hardcore predicate for g.
 *
 * Equivalently: If there exists a PPT algorithm P such that
 *   Pr_{x,r}[P(f(x), r) = ⟨x, r⟩] ≥ 1/2 + ε(n)
 * for non-negligible ε(n), then there exists a PPT algorithm
 * that inverts f with non-negligible probability.
 *
 * The Proof (Reduction):
 *   Given a predictor P with advantage ε, we construct an inverter A:
 *   1. For each candidate x, we use P to estimate ⟨x, r⟩ for many r
 *   2. Using list-decoding of the Hadamard code, we recover x
 *   3. The core technique: P(f(x), r) ⊕ P(f(x), r⊕e_i) ≈ ⟨x, e_i⟩ = x_i
 *      (this uses the self-correctability of the Goldreich-Levin predicate)
 *
 * Key Lemma:
 *   If Pr_r[P(f(x), r) = ⟨x, r⟩] ≥ 1/2 + ε, then for each bit i,
 *     Pr_r[P(f(x), r) ⊕ P(f(x), r ⊕ e_i) = x_i] ≥ 1/2 + 2ε^2
 *
 *   This follows from the identity:
 *     ⟨x, r⟩ ⊕ ⟨x, r⊕e_i⟩ = ⟨x, r⟩ ⊕ (⟨x, r⟩ ⊕ ⟨x, e_i⟩) = ⟨x, e_i⟩ = x_i
 *
 * Reference: Goldreich-Levin, STOC 1989; Arora-Barak §9.3
 * Courses: MIT 6.875, Stanford CS255, Princeton COS 551
 */

#ifndef GOLDREICH_LEVIN_H
#define GOLDREICH_LEVIN_H

#include "owf.h"
#include "hardcore_bit.h"
#include "list_decoding.h"

/* ── GL Reduction State ──────────────────────────────────── */
typedef struct {
    OWF*            owf;           /* the one-way function f */
    HCPredictor*    predictor;     /* predictor P for ⟨x,r⟩ */
    double          epsilon;       /* predictor advantage ε */
    size_t          n;             /* security parameter (|x| = n) */
    BitString*      target_fx;     /* f(x) — the value to invert */
    size_t          num_queries;   /* number of queries made */
    size_t          max_queries;   /* query budget (poly(n, 1/ε)) */
} GLCtx;

/* ── Reduction Algorithm Parameters ──────────────────────── */
typedef struct {
    size_t n;                  /* input length */
    double epsilon;            /* predictor advantage */
    size_t m;                  /* samples per bit estimate (m = poly(n, 1/ε)) */
    double confidence;         /* desired confidence level */
} GLParams;

/* ── Reconstruction Result ───────────────────────────────── */
typedef struct {
    BitString*  candidate;       /* candidate preimage x' */
    int         success;         /* f(x') == f(x) ? */
    double      probability;     /* estimated success probability */
    size_t      queries_made;
    int*        bit_confidences; /* confidence for each recovered bit */
} GLReconstruction;

/* ── Core Goldreich-Levin Algorithm ──────────────────────── */
/* Full GL reduction: given OWF f and predictor P, reconstruct x */
GLReconstruction* gl_invert(const OWF* owf, const HCPredictor* predictor,
                             const BitString* fx, const GLParams* params);
GLReconstruction* gl_invert_with_params(const OWF* owf, const BitString* fx,
                                         const HCPredictor* pred,
                                         double epsilon, size_t n);

/* ── GL Bit Recovery ─────────────────────────────────────── */
/* Recover bit i of x using self-correction:
 *   x_i ≈ P(f(x), r) ⊕ P(f(x), r ⊕ e_i) for random r
 * Repeat m times and take majority */
int    gl_recover_bit(GLCtx* ctx, const BitString* fx, size_t i, size_t m);
double gl_estimate_bit(GLCtx* ctx, const BitString* fx, size_t i, size_t m);

/* ── GL Self-Correction Lemma ────────────────────────────── */
/* Lemma: For any a,b ∈ {0,1}^n, ⟨x,a⟩ ⊕ ⟨x,b⟩ = ⟨x, a⊕b⟩
 * Used to relate predictor responses to individual bits */
int    gl_self_correct(const HCPredictor* pred, const BitString* fx,
                        const BitString* r, const BitString* shift);

/* ── GL Parameters Calculation ───────────────────────────── */
/* Compute optimal sample count m given n and ε */
size_t gl_compute_m(size_t n, double epsilon, double confidence);
/* Estimate ε from predictor accuracy */
double gl_estimate_epsilon(size_t correct, size_t total);
/* Compute query complexity of the GL reduction */
size_t gl_query_complexity(size_t n, double epsilon);

/* ── GL Reduction Analysis ───────────────────────────────── */
/* Success probability analysis using Chernoff bounds */
double gl_prob_success_per_bit(size_t m, double epsilon);
/* Overall success probability for all n bits */
double gl_prob_success_overall(size_t n, size_t m, double epsilon);

/* ── GL Validation ───────────────────────────────────────── */
int gl_validate_reduction(const OWF* owf, const HCPredictor* pred,
                           const BitString* x, const GLParams* params);

/* ── GL Sampling ─────────────────────────────────────────── */
/* Generate random r for GL queries */
BitString* gl_sample_r(size_t n);
/* Generate r ⊕ e_i (r with i-th bit flipped) */
BitString* gl_sample_r_shifted(const BitString* r, size_t i);
/* Sample m pairs (r_j, r_j ⊕ e_i) for bit i estimation */
void       gl_sample_pairs(size_t n, size_t m, size_t i,
                            BitString*** r_out, BitString*** r_shifted_out);

/* ── GL Context Management ───────────────────────────────── */
GLCtx* gl_ctx_create(OWF* owf, HCPredictor* pred, double epsilon,
                      const BitString* target_fx, size_t max_queries);
void   gl_ctx_free(GLCtx* ctx);
int    gl_ctx_query(GLCtx* ctx, const BitString* r, int* prediction);
size_t gl_ctx_queries_remaining(const GLCtx* ctx);

/* ── GL Utility Functions ────────────────────────────────── */
double gl_advantage_to_epsilon(double advantage);
double gl_epsilon_to_advantage(double epsilon);
int    gl_bit_majority(int* votes, size_t m);
void   gl_print_params(const GLParams* params);
void   gl_print_reconstruction(const GLReconstruction* rec);

#endif /* GOLDREICH_LEVIN_H */
