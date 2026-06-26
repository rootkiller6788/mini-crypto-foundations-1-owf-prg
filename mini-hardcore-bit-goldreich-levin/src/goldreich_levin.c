/*
 * goldreich_levin.c — Goldreich-Levin Theorem & Reduction
 *
 * Implements the full Goldreich-Levin inversion algorithm:
 * Given a one-way function f and a predictor P that guesses the
 * inner product ⟨x, r⟩ with advantage ε > 0 (non-negligible),
 * reconstruct x with high probability.
 *
 * The core algorithm:
 *   1. For each bit i of x, estimate x_i by measuring
 *      P(f(x), r) ⊕ P(f(x), r ⊕ e_i) for many random r
 *   2. Use majority vote to decide each bit
 *   3. Output the reconstructed candidate x'
 *
 * Knowledge Points Covered:
 *   L1: GL theorem statement, hardcore bit definition
 *   L2: Self-correctability of the Hadamard code
 *   L3: Multiplicative Chernoff bound for bit recovery
 *   L4: GL theorem: reduction from predicting inner product to inverting OWF
 *   L5: List-decoding of Hadamard code (Goldreich-Levin algorithm)
 *   L7: Cryptographic hardness amplification
 *
 * Reference: Goldreich-Levin STOC 1989; Arora-Barak §9.3
 * Courses: MIT 6.875, Stanford CS255, Princeton COS 551
 */

#include "goldreich_levin.h"
#include "bit_operations.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* ───────────────────────────────────────────────────────────────
 * GL Context Management
 *
 * GLCtx holds the state of one GL inversion: the OWF f,
 * the predictor P, and metadata (queries, budget).
 * ───────────────────────────────────────────────────────────── */

GLCtx* gl_ctx_create(OWF* owf, HCPredictor* pred, double epsilon,
                      const BitString* target_fx, size_t max_queries) {
    if (!owf || !pred) return NULL;
    GLCtx* ctx = (GLCtx*)malloc(sizeof(GLCtx));
    if (!ctx) return NULL;
    ctx->owf         = owf;
    ctx->predictor   = pred;
    ctx->epsilon     = epsilon;
    ctx->n           = owf->input_bits;
    ctx->target_fx   = target_fx ? bs_clone(target_fx) : NULL;
    ctx->num_queries = 0;
    ctx->max_queries = max_queries;
    return ctx;
}

void gl_ctx_free(GLCtx* ctx) {
    if (ctx) {
        bs_free(ctx->target_fx);
        free(ctx);
    }
}

int gl_ctx_query(GLCtx* ctx, const BitString* r, int* prediction) {
    if (!ctx || !r || !prediction) return 0;
    if (ctx->num_queries >= ctx->max_queries) return 0;
    ctx->num_queries++;
    if (!ctx->target_fx) {
        *prediction = 0;
        return 1;
    }
    return ctx->predictor->query(ctx->target_fx, r, prediction, ctx->predictor->ctx);
}

size_t gl_ctx_queries_remaining(const GLCtx* ctx) {
    if (!ctx) return 0;
    return ctx->max_queries - ctx->num_queries;
}

/* ───────────────────────────────────────────────────────────────
 * GL Bit Recovery — The Core Reduction
 *
 * Key identity (self-correction of Hadamard code):
 *   ⟨x, r⟩ ⊕ ⟨x, r ⊕ e_i⟩ = ⟨x, e_i⟩ = x_i
 *
 * Therefore, if P approximates ⟨x, ·⟩ with advantage ε:
 *   Pr[P(f(x), r) ⊕ P(f(x), r ⊕ e_i) = x_i] ≥ 1/2 + 2ε²
 *
 * Algorithm for recovering bit i:
 *   1. Sample m random strings r_1, ..., r_m
 *   2. For each r_j, compute guess_j = P(r_j) ⊕ P(r_j ⊕ e_i)
 *   3. Take majority vote over all m guesses
 *
 * The number of samples m needed depends on ε and the desired
 * confidence δ, bounded by Chernoff/Hoeffding.
 * ───────────────────────────────────────────────────────────── */

int gl_recover_bit(GLCtx* ctx, const BitString* fx, size_t i, size_t m) {
    if (!ctx || !fx || m == 0) return 0;
    size_t n = ctx->n;
    int* votes = (int*)malloc(m * sizeof(int));
    if (!votes) return 0;

    for (size_t j = 0; j < m; j++) {
        /* Sample random r */
        BitString* r = bs_create_random(n);
        BitString* r_shifted = bs_clone(r);
        if (!r || !r_shifted) {
            bs_free(r); bs_free(r_shifted);
            votes[j] = 0;
            continue;
        }
        /* r_shifted = r ⊕ e_i (flip bit i) */
        bs_set_bit(r_shifted, i, 1 - bs_get_bit(r_shifted, i));

        int pred_r, pred_shift;
        int ok = ctx->predictor->query(fx, r, &pred_r, ctx->predictor->ctx);
        ctx->num_queries++;
        int ok2 = ctx->predictor->query(fx, r_shifted, &pred_shift, ctx->predictor->ctx);
        ctx->num_queries++;

        votes[j] = (ok && ok2) ? (pred_r ^ pred_shift) : 0;

        bs_free(r);
        bs_free(r_shifted);
    }

    int bit = gl_bit_majority(votes, m);
    free(votes);
    return bit;
}

double gl_estimate_bit(GLCtx* ctx, const BitString* fx, size_t i, size_t m) {
    if (!ctx || !fx || m == 0) return 0.5;
    size_t n = ctx->n;
    int ones = 0;
    for (size_t j = 0; j < m; j++) {
        BitString* r = bs_create_random(n);
        BitString* r_shifted = bs_clone(r);
        if (!r || !r_shifted) { bs_free(r); bs_free(r_shifted); continue; }
        bs_set_bit(r_shifted, i, 1 - bs_get_bit(r_shifted, i));
        int pred_r, pred_shift;
        if (ctx->predictor->query(fx, r, &pred_r, ctx->predictor->ctx) &&
            ctx->predictor->query(fx, r_shifted, &pred_shift, ctx->predictor->ctx)) {
            if (pred_r ^ pred_shift) ones++;
            ctx->num_queries += 2;
        }
        bs_free(r);
        bs_free(r_shifted);
    }
    return (double)ones / (double)m;
}

/* ───────────────────────────────────────────────────────────────
 * Full GL Inversion Algorithm
 *
 * Given OWF f and predictor P with advantage ε:
 *   1. Compute m = poly(n, 1/ε) samples per bit
 *   2. For each bit i = 0..n-1:
 *      a. Sample m pairs (r_j, r_j ⊕ e_i)
 *      b. Estimate x_i via majority vote
 *   3. Reconstruct candidate x' from recovered bits
 *   4. Verify: f(x') == f(x)
 *
 * Query complexity: O(n·m) = O(n·poly(n, 1/ε)) = poly(n)
 * ───────────────────────────────────────────────────────────── */

GLReconstruction* gl_invert(const OWF* owf, const HCPredictor* predictor,
                             const BitString* fx, const GLParams* params) {
    if (!owf || !predictor || !fx || !params) return NULL;
    size_t n = params->n;
    double epsilon = params->epsilon;
    size_t m = params->m;
    if (m == 0) m = gl_compute_m(n, epsilon, params->confidence);

    GLReconstruction* rec = (GLReconstruction*)malloc(sizeof(GLReconstruction));
    if (!rec) return NULL;
    rec->candidate     = bs_create(n);
    rec->success       = 0;
    rec->probability   = 0.0;
    rec->queries_made  = 0;
    rec->bit_confidences = (int*)malloc((int)n * sizeof(int));
    if (!rec->candidate || !rec->bit_confidences) {
        free(rec->candidate);
        free(rec->bit_confidences);
        free(rec);
        return NULL;
    }

    GLCtx* ctx = gl_ctx_create((OWF*)owf, (HCPredictor*)predictor,
                                epsilon, fx, m * n * 2 + 100);
    if (!ctx) {
        bs_free(rec->candidate);
        free(rec->bit_confidences);
        free(rec);
        return NULL;
    }

    /* Recover each bit */
    for (size_t i = 0; i < n; i++) {
        int bit = gl_recover_bit(ctx, fx, i, m);
        bs_set_bit(rec->candidate, i, bit);
        /* Estimate confidence for this bit */
        double prob = gl_estimate_bit(ctx, fx, i, m / 4 + 1);
        rec->bit_confidences[i] = (int)(prob * 100);
    }

    rec->queries_made = ctx->num_queries;

    /* Verify: check if f(candidate) == f(x) */
    BitString* cand_out = bs_create(owf->output_bits);
    if (cand_out) {
        owf_eval(owf, rec->candidate, cand_out);
        rec->success = bs_equal(cand_out, fx);
        bs_free(cand_out);
    }

    /* Estimate probability of success */
    rec->probability = gl_prob_success_overall(n, m, epsilon);

    gl_ctx_free(ctx);
    return rec;
}

GLReconstruction* gl_invert_with_params(const OWF* owf, const BitString* fx,
                                         const HCPredictor* pred,
                                         double epsilon, size_t n) {
    GLParams params;
    params.n          = n;
    params.epsilon    = epsilon;
    params.m          = gl_compute_m(n, epsilon, 0.99);
    params.confidence = 0.99;
    return gl_invert(owf, pred, fx, &params);
}

/* ───────────────────────────────────────────────────────────────
 * GL Self-Correction Lemma
 *
 * Lemma: For any a, b ∈ {0,1}^n:
 *   ⟨x, a⟩ ⊕ ⟨x, b⟩ = ⟨x, a ⊕ b⟩
 *
 * This bilinearity property is the key to the GL reduction.
 * It allows us to relate two predictor queries to a single bit:
 *   P(r) ⊕ P(r ⊕ e_i) ≈ ⟨x, r⟩ ⊕ ⟨x, r ⊕ e_i⟩ = ⟨x, e_i⟩ = x_i
 * ───────────────────────────────────────────────────────────── */

int gl_self_correct(const HCPredictor* pred, const BitString* fx,
                     const BitString* r, const BitString* shift) {
    if (!pred || !fx || !r || !shift) return 0;
    int p1, p2;
    if (!pred->query(fx, r, &p1, pred->ctx)) return 0;
    if (!pred->query(fx, shift, &p2, pred->ctx)) return 0;
    return p1 ^ p2;
}

/* ───────────────────────────────────────────────────────────────
 * GL Parameters Calculation
 *
 * The number of samples m per bit is determined by the
 * Chernoff/Hoeffding bound to achieve confidence δ:
 *
 *   m ≥ (c / ε²) · ln(n/δ)
 *
 * for some constant c. This ensures:
 *   Pr[bit i correct] ≥ 1 - δ/n
 *   Pr[all n bits correct] ≥ 1 - δ   (union bound)
 * ───────────────────────────────────────────────────────────── */

size_t gl_compute_m(size_t n, double epsilon, double confidence) {
    if (epsilon <= 0.0) return n * 1000;
    double delta = 1.0 - confidence;
    if (delta <= 0.0) delta = 1e-6;
    /* Hoeffding: m ≥ ln(2n/δ) / (2·ε²) for two-sided test */
    /* Actually for the GL bit recovery, we need m ≥ c·n/ε² */
    double m = (2.0 * log((double)n / delta)) / (epsilon * epsilon);
    /* Add a constant factor for safety */
    m *= 4.0;
    if (m < 10.0) m = 10.0;
    return (size_t)m;
}

double gl_estimate_epsilon(size_t correct, size_t total) {
    if (total == 0) return 0.0;
    double accuracy = (double)correct / (double)total;
    double advantage = accuracy - 0.5;
    return advantage > 0 ? advantage : 0.0;
}

size_t gl_query_complexity(size_t n, double epsilon) {
    size_t m = gl_compute_m(n, epsilon, 0.99);
    return n * m * 2;  /* 2 queries per sample (r and r⊕e_i) */
}

/* ───────────────────────────────────────────────────────────────
 * GL Reduction Analysis — Success Probability
 *
 * Using the Hoeffding inequality:
 *   Pr[|(1/m)ΣX_j - p| ≥ δ] ≤ 2 exp(-2mδ²)
 *
 * For the GL bit recovery with advantage ε:
 *   Pr[bit estimate correct] ≥ 1 - 2 exp(-2m(2ε²)²)
 *
 * And using union bound over n bits:
 *   Pr[all bits correct] ≥ 1 - 2n exp(-2m(2ε²)²)
 * ───────────────────────────────────────────────────────────── */

double gl_prob_success_per_bit(size_t m, double epsilon) {
    if (epsilon <= 0.0) return 0.5;
    double advantage_per_sample = 2.0 * epsilon * epsilon;
    /* Hoeffding: Pr[wrong] ≤ exp(-2m·(advantage)^2) */
    double prob_wrong = exp(-2.0 * (double)m * advantage_per_sample * advantage_per_sample);
    double prob_correct = 1.0 - prob_wrong;
    if (prob_correct < 0.5) prob_correct = 0.5;
    if (prob_correct > 1.0) prob_correct = 1.0;
    return prob_correct;
}

double gl_prob_success_overall(size_t n, size_t m, double epsilon) {
    double per_bit = gl_prob_success_per_bit(m, epsilon);
    /* Union bound: Pr[all correct] ≥ 1 - n·(1 - per_bit) */
    double prob_all = 1.0 - (double)n * (1.0 - per_bit);
    if (prob_all < 0.0) prob_all = 0.0;
    if (prob_all > 1.0) prob_all = 1.0;
    return prob_all;
}

/* ───────────────────────────────────────────────────────────────
 * GL Validation
 *
 * End-to-end test: given a known input x, verify that the GL
 * reduction can recover x given a perfect predictor.
 * ───────────────────────────────────────────────────────────── */

int gl_validate_reduction(const OWF* owf, const HCPredictor* pred,
                           const BitString* x, const GLParams* params) {
    if (!owf || !pred || !x || !params) return 0;
    /* Compute f(x) */
    BitString* fx = bs_create(owf->output_bits);
    if (!fx) return 0;
    owf_eval(owf, x, fx);
    /* Run GL inversion */
    GLReconstruction* rec = gl_invert(owf, pred, fx, params);
    int result = 0;
    if (rec && rec->success) {
        result = 1;
    }
    if (rec) {
        bs_free(rec->candidate);
        free(rec->bit_confidences);
        free(rec);
    }
    bs_free(fx);
    return result;
}

/* ───────────────────────────────────────────────────────────────
 * GL Sampling — Generate random strings for GL queries
 * ───────────────────────────────────────────────────────────── */

BitString* gl_sample_r(size_t n) {
    return bs_create_random(n);
}

BitString* gl_sample_r_shifted(const BitString* r, size_t i) {
    if (!r) return NULL;
    BitString* shifted = bs_clone(r);
    if (shifted) {
        bs_set_bit(shifted, i, 1 - bs_get_bit(shifted, i));
    }
    return shifted;
}

void gl_sample_pairs(size_t n, size_t m, size_t i,
                      BitString*** r_out, BitString*** r_shifted_out) {
    if (!r_out || !r_shifted_out) return;
    *r_out         = (BitString**)malloc(m * sizeof(BitString*));
    *r_shifted_out = (BitString**)malloc(m * sizeof(BitString*));
    if (!*r_out || !*r_shifted_out) {
        free(*r_out); free(*r_shifted_out);
        *r_out = NULL; *r_shifted_out = NULL;
        return;
    }
    for (size_t j = 0; j < m; j++) {
        (*r_out)[j] = gl_sample_r(n);
        (*r_shifted_out)[j] = gl_sample_r_shifted((*r_out)[j], i);
    }
}

/* ───────────────────────────────────────────────────────────────
 * GL Utility Functions
 * ───────────────────────────────────────────────────────────── */

double gl_advantage_to_epsilon(double advantage) {
    /* |Pr[correct] - 1/2| = |(1/2 + ε) - 1/2| = ε, so advantage = ε */
    return advantage;
}

double gl_epsilon_to_advantage(double epsilon) {
    return epsilon;
}

int gl_bit_majority(int* votes, size_t m) {
    int ones = 0;
    for (size_t i = 0; i < m; i++) {
        if (votes[i]) ones++;
    }
    return (ones > (int)m / 2) ? 1 : 0;
}

void gl_print_params(const GLParams* params) {
    if (!params) return;
    printf("GL Parameters:\n");
    printf("  n (input length):      %zu\n", params->n);
    printf("  epsilon (advantage):    %f\n", params->epsilon);
    printf("  m (samples per bit):    %zu\n", params->m);
    printf("  confidence:             %f\n", params->confidence);
}

void gl_print_reconstruction(const GLReconstruction* rec) {
    if (!rec) { printf("(null)\n"); return; }
    printf("GL Reconstruction:\n");
    printf("  Success:                %s\n", rec->success ? "YES" : "NO");
    printf("  Probability estimate:   %.4f\n", rec->probability);
    printf("  Queries made:           %zu\n", rec->queries_made);
    printf("  Candidate:              ");
    if (rec->candidate) {
        bs_print_hex(rec->candidate);
    } else {
        printf("(null)\n");
    }
}
