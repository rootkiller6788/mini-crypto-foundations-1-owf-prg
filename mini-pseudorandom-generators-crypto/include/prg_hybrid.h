/*
 * prg_hybrid.h -- Hybrid Argument for PRG Security Proofs
 *
 * L4 Fundamental Theorem:
 *   The Hybrid Argument is the central proof technique in cryptography
 *   for showing that two distributions are computationally indistinguishable
 *   by a sequence of intermediate "hybrid" distributions.
 *
 * L2 Core Concept:
 *   Hybrid Argument for PRG:
 *     Given PRG G: {0,1}^n ? {0,1}^{l(n)}, define l = l(n) hybrids:
 *       H_0: U_l  (truly random l-bit string)
 *       H_i: G(s)_1 ... G(s)_i || U_{l-i}  (first i bits PRG, rest random)
 *       H_l: G(s)  (fully pseudorandom)
 *
 *     If D distinguishes H_0 from H_l with advantage ?,
 *     then ?i: D distinguishes H_{i-1} from H_i with advantage ?/l.
 *     H_{i-1} and H_i differ only in the i-th bit.
 *
 *     This yields a next-bit predictor with advantage ?/l,
 *     proving that PRG security ? next-bit unpredictability (Yao 1982).
 *
 * Reference: Yao (1982), Goldreich (2001) Vol 1, Section 3.2.3
 *            Goldreich (2008) "Computational Complexity: A Conceptual Perspective"
 *
 * Courses: MIT 6.875, Stanford CS255, Berkeley CS276, Princeton COS 551
 */

#ifndef PRG_HYBRID_H
#define PRG_HYBRID_H

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include "prg_crypto.h"

/* ================================================================
 * Hybrid Distribution Framework
 * ================================================================ */

/*
 * A hybrid distribution H_i over {0,1}^l where:
 *   - First i bits come from distribution A (e.g., PRG output)
 *   - Remaining l-i bits come from distribution B (e.g., uniform random)
 *
 * This is a conceptual tool; we implement it for simulation/testing.
 */
typedef struct {
    size_t l;                    /* total output length in bits */
    size_t i;                    /* hybrid index (0 ? i ? l) */
    size_t block_size;           /* bits per block */
    size_t n_blocks;             /* total number of blocks = ceil(l/block_size) */
} HybridConfig;

/*
 * Create a hybrid distribution configuration.
 * block_size: granularity of hybrid (typically 1 for bit-by-bit)
 */
HybridConfig hybrid_config_create(size_t l, size_t block_size);

/*
 * Given a PRG, generate a sample from hybrid H_i:
 *   First i bits: G(s) prefix (pseudorandom)
 *   Last l-i bits: truly random
 *
 * Returns 0 on success, -1 on error.
 */
int hybrid_generate_sample(const HybridConfig* cfg, size_t i,
                           PRG* prg, const uint8_t* seed,
                           uint8_t* output, size_t output_bytes);

/* ================================================================
 * Hybrid Gap Analysis
 * ================================================================ */

/*
 * Hybrid Gap Decomposition:
 *   If D distinguishes H_0 from H_l with advantage ?,
 *   then D's advantage between adjacent hybrids H_{i-1} and H_i
 *   must be at least ?/l for some i.
 *
 *   Adv_{D, H_0, H_l} ? ?_{i=1}^l Adv_{D, H_{i-1}, H_i}
 *
 * This is the triangle inequality applied to statistical distance.
 */

/*
 * Run a hybrid analysis: for each hybrid H_i, measure
 * the distinguisher's success probability.
 */
typedef struct {
    size_t l;                    /* number of hybrids */
    double* success_prob;       /* Pr[D(H_i) = 1] for each i */
    double* adjacent_gap;       /* |Pr[D(H_i)] - Pr[D(H_{i-1})]| */
    double total_gap;           /* |Pr[D(H_l)] - Pr[D(H_0)]| */
    double max_adjacent_gap;    /* max_i |Pr[D(H_i)] - Pr[D(H_{i-1})]| */
    size_t max_gap_index;       /* i where gap is maximal */
} HybridAnalysis;

/* Initialize hybrid analysis for l hybrids */
HybridAnalysis* hybrid_analysis_create(size_t l);

/* Record distinguisher success probability for hybrid H_i */
void hybrid_analysis_record(HybridAnalysis* ha, size_t i, double success_prob);

/* Compute gaps between adjacent hybrids */
void hybrid_analysis_compute(HybridAnalysis* ha);

/* Get the hybrid index with maximum distinguishing gap */
size_t hybrid_analysis_max_gap_index(const HybridAnalysis* ha);

/* Get the advantage at the best gap point */
double hybrid_analysis_max_advantage(const HybridAnalysis* ha);

/* Free hybrid analysis */
void hybrid_analysis_free(HybridAnalysis* ha);

/* ================================================================
 * Yao's Theorem: PRG ? Next-bit Unpredictability (Implementation)
 * ================================================================ */

/*
 * Forward direction (PRG security ? NBU):
 *   Assume PRG G is secure. Suppose ? predictor A that predicts bit i
 *   with advantage ?. Construct distinguisher D:
 *     D(y) = A(y_{1..i-1}) ? y_i
 *   Then Pr[D(G(s)) = 1] - Pr[D(U_l) = 1] ? ?.
 *   This contradicts PRG security, so no such predictor exists.
 */

/*
 * Construct the forward-direction distinguisher.
 * Given:
 *   - predictor_advantage: A's advantage at position i
 *   - expected_predictions: predictions from A for given prefix
 * Returns 1 if distinguisher would output 1.
 */
int yao_forward_distinguisher(int predicted_bit, int actual_bit,
                              double predictor_advantage);

/*
 * Reverse direction (NBU ? PRG security):
 *   Assume G is next-bit unpredictable. Suppose ? distinguisher D
 *   with advantage ?. Via the hybrid argument, ?i such that
 *   D distinguishes H_{i-1} from H_i with advantage ?/l.
 *
 *   Construct predictor A for bit i:
 *     On input prefix y_{1..i-1}:
 *       - Sample r_i ... r_l ? {0,1}^{l-i+1}
 *       - If D(y_{1..i-1} || r_i ... r_l) = 1, predict r_i
 *       - Else, predict 1 - r_i
 *
 *   Then A predicts bit i with advantage ? ?/l.
 *   This contradicts NBU, so no such distinguisher exists.
 */

/*
 * Run the reverse-direction predictor simulation.
 * Given distinguisher D's behavior on hybrid H_{i-1} vs H_i,
 * estimate the predictor's advantage.
 */
double yao_reverse_predictor_advantage(double dist_adv_at_i, size_t l);

/* ================================================================
 * Generic Hybrid Argument for Distinguishing Games
 * ================================================================ */

/*
 * The hybrid argument is not specific to PRGs. It applies broadly:
 *
 *   - PRG security (Yao 1982)
 *   - Pseudorandom functions (Goldreich-Goldwasser-Micali 1986)
 *   - Encryption security (IND-CPA ? IND-CCA via hybrid)
 *   - Zero-knowledge proofs (sequential composition)
 *   - Oblivious transfer protocols
 *
 * General template:
 *   1. Define H_0 (ideal world) and H_k (real world)
 *   2. Define intermediate hybrids H_1, ..., H_{k-1}
 *   3. Show H_{i-1} ?_c H_i for all i (by reduction to assumption)
 *   4. Conclude H_0 ?_c H_k by triangle inequality
 */

/*
 * Generic hybrid game with k+1 hybrids.
 * Each hybrid has a sampler function that generates a sample.
 */
typedef struct {
    size_t k;                    /* number of hybrid steps */
    size_t l;                    /* sample bit-length */
    void** hybrid_states;        /* one state per hybrid */
} HybridGame;

/* Create hybrid game with k steps */
HybridGame* hybrid_game_create(size_t k, size_t l);

/* Set state for a specific hybrid index */
void hybrid_game_set_state(HybridGame* game, size_t i, void* state);

/* Get state for a specific hybrid index */
void* hybrid_game_get_state(const HybridGame* game, size_t i);

/* Free hybrid game */
void hybrid_game_free(HybridGame* game);

/* ================================================================
 * Hybrid Argument Verification (Self-Test)
 * ================================================================ */

/*
 * Verify the hybrid argument decomposition property:
 *   |Pr[D(H_k)=1] - Pr[D(H_0)=1]| ? ?_{i=1}^k |Pr[D(H_i)=1] - Pr[D(H_{i-1})=1]|
 *
 * This is a mathematical identity (triangle inequality),
 * but we verify it numerically as a sanity check.
 */

int hybrid_verify_triangle_inequality(const HybridAnalysis* ha);

/*
 * Verify the PRG security reduction:
 * If max adjacent gap = ?, then there exists a next-bit predictor
 * with advantage ? (up to statistical noise).
 */
int hybrid_verify_yao_reduction(const HybridAnalysis* ha, double tolerance);

/* ================================================================
 * Computational Hybrid Argument
 * ================================================================ */

/*
 * The computational variant: adjacent hybrids H_{i-1} ?_c H_i
 * (computationally indistinguishable), not necessarily
 * statistically close.
 *
 * Computational indistinguishability is transitive for
 * a polynomial number of hybrids (by triangle inequality
 * applied to advantage).
 */

/*
 * Check if the advantage accumulated across k hybrids
 * is still negligible when each individual advantage is negligible.
 *   If ?i: Adv_{H_{i-1}, H_i} ? negl(n), then Adv_{H_0, H_k} ? k?negl(n)
 *   which is still negl(n) when k = poly(n).
 */
int hybrid_advantage_still_negligible(double indiv_advantage, size_t k,
                                      size_t n, double poly_degree);

#endif /* PRG_HYBRID_H */
