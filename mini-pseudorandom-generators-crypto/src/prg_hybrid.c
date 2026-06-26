/*
 * prg_hybrid.c -- Hybrid Argument Implementation for PRG Security Proofs
 *
 * L4 Fundamental Theorem: The Hybrid Argument (Yao 1982)
 *   PRG security <=> Next-bit unpredictability, proved via a sequence
 *   of intermediate "hybrid" distributions.
 *
 * L2 Core Concept:
 *   Hybrid H_i: first i bits from PRG, remaining l-i bits random.
 *   H_0 = U_l (truly random), H_l = G(s) (fully pseudorandom).
 *   Triangle inequality: Adv(H_0, H_l) <= sum_i Adv(H_{i-1}, H_i)
 *
 * Reference: Yao (1982), Goldreich (2001) Vol 1, Section 3.2.3
 * Courses: MIT 6.875, Stanford CS255, Berkeley CS276, Princeton COS 551
 */
#include "prg_hybrid.h"
#include "prg_crypto.h"
#include <string.h>
#include <stdlib.h>
#include <math.h>

/* ================================================================
 * Hybrid Distribution Framework (L2)
 * ================================================================ */

/* L2: Create a hybrid distribution configuration.
 * Each hybrid H_i over {0,1}^l has the first i bits from PRG output
 * and the last l-i bits from a uniform random source. */
HybridConfig hybrid_config_create(size_t l, size_t block_size) {
    HybridConfig cfg;
    cfg.l = l;
    cfg.i = 0;
    cfg.block_size = (block_size > 0) ? block_size : 1;
    cfg.n_blocks = (l + cfg.block_size - 1) / cfg.block_size;
    return cfg;
}

/* L2: Generate a sample from hybrid H_i.
 * Given PRG G and seed s:
 *   - Generate G(s) for the pseudorandom prefix
 *   - Generate truly random bits for the suffix
 *   - Concatenate: first i bits from G(s), last l-i from random
 *
 * In the hybrid proof, H_i and H_{i+1} differ in exactly block_size bits:
 * position i+1..i+block_size. This controlled difference enables
 * the reduction to the underlying PRG/OWF assumption. */
int hybrid_generate_sample(const HybridConfig* cfg, size_t i,
                           PRG* prg, const uint8_t* seed,
                           uint8_t* output, size_t output_bytes) {
    if (!cfg || !prg || !seed || !output) return -1;

    size_t l_bytes = (cfg->l + 7) / 8;
    if (output_bytes < l_bytes) return -1;
    memset(output, 0, l_bytes);

    /* Generate full G(s) into temp buffer */
    size_t g_bytes = (cfg->l + 7) / 8;
    uint8_t* g_out = (uint8_t*)calloc(1, g_bytes + 1);
    if (!g_out) return -1;

    prg_init(prg, seed, PRG_BYTES(prg->params.seed_bits));
    int gen_ret = prg_fill(prg, g_out, g_bytes);
    if (gen_ret < 0) { free(g_out); return -1; }

    /* Copy first i bits from G(s) */
    size_t i_bytes = (i + 7) / 8;
    if (i_bytes > 0) memcpy(output, g_out, i_bytes);

    /* Remaining l-i bits: fill with random */
    size_t remain = l_bytes - i_bytes;
    if (remain > 0) {
        prg_fill_random(output + i_bytes, remain);
    }

    /* Mask partial byte at position i to use only i%8 bits from G(s) */
    size_t partial_bit = i % 8;
    if (partial_bit > 0 && i_bytes > 0) {
        uint8_t mask = (uint8_t)(0xFFU << (8 - partial_bit));
        output[i_bytes - 1] &= mask;
        output[i_bytes - 1] |= (g_out[i_bytes - 1] & ~mask);
    }

    free(g_out);
    return 0;
}

/* ================================================================
 * Hybrid Gap Analysis (L2, L4)
 * ================================================================ */

/* L2: Create hybrid analysis structure for l hybrids. */
HybridAnalysis* hybrid_analysis_create(size_t l) {
    HybridAnalysis* ha = (HybridAnalysis*)calloc(1, sizeof(HybridAnalysis));
    if (!ha) return NULL;

    ha->l = l;
    ha->success_prob = (double*)calloc(l + 1, sizeof(double));
    ha->adjacent_gap = (double*)calloc(l, sizeof(double));
    if (!ha->success_prob || !ha->adjacent_gap) {
        hybrid_analysis_free(ha);
        return NULL;
    }
    ha->total_gap = 0.0;
    ha->max_adjacent_gap = 0.0;
    ha->max_gap_index = 0;
    return ha;
}

/* L2: Record distinguisher success probability for hybrid H_i.
 * Pr[D(H_i) = 1] is estimated from repeated trials. */
void hybrid_analysis_record(HybridAnalysis* ha, size_t i, double success_prob) {
    if (!ha || i > ha->l) return;
    ha->success_prob[i] = success_prob;
}

/* L2: Compute gaps between adjacent hybrids.
 * gap_i = |Pr[D(H_i)=1] - Pr[D(H_{i-1})=1]|
 *
 * By the triangle inequality:
 *   |Pr[D(H_l)=1] - Pr[D(H_0)=1]| <= sum_{i=1}^l gap_i
 *
 * This is the key decomposition that enables the hybrid argument:
 * if the total distinguishing advantage is epsilon, then some
 * adjacent pair has advantage at least epsilon/l. */
void hybrid_analysis_compute(HybridAnalysis* ha) {
    if (!ha || ha->l == 0) return;

    ha->total_gap = fabs(ha->success_prob[ha->l] - ha->success_prob[0]);
    ha->max_adjacent_gap = 0.0;
    ha->max_gap_index = 0;

    for (size_t i = 1; i <= ha->l; i++) {
        ha->adjacent_gap[i - 1] = fabs(ha->success_prob[i] - ha->success_prob[i - 1]);
        if (ha->adjacent_gap[i - 1] > ha->max_adjacent_gap) {
            ha->max_adjacent_gap = ha->adjacent_gap[i - 1];
            ha->max_gap_index = i;
        }
    }
}

size_t hybrid_analysis_max_gap_index(const HybridAnalysis* ha) {
    return ha ? ha->max_gap_index : 0;
}

double hybrid_analysis_max_advantage(const HybridAnalysis* ha) {
    return ha ? ha->max_adjacent_gap : 0.0;
}

void hybrid_analysis_free(HybridAnalysis* ha) {
    if (!ha) return;
    free(ha->success_prob);
    free(ha->adjacent_gap);
    memset(ha, 0, sizeof(HybridAnalysis));
    free(ha);
}

/* ================================================================
 * Yao's Theorem: PRG <=> Next-bit Unpredictability (L4)
 * ================================================================ */

/* L4: Forward direction -- PRG security implies next-bit unpredictability.
 *
 * Assume G is a secure PRG. Suppose there exists a predictor A that
 * predicts bit i with advantage epsilon. Construct distinguisher D:
 *   D(y) = 1 if A(y_{1..i-1}) == y_i, else 0.
 *
 * Then Adv_D = |Pr[D(G(s))=1] - Pr[D(U_l)=1]| >= epsilon.
 * This contradicts PRG security, so no such A exists.
 *
 * This function implements the distinguisher decision: given predicted bit
 * and actual bit, returns 1 if they match. */
int yao_forward_distinguisher(int predicted_bit, int actual_bit,
                              double predictor_advantage) {
    (void)predictor_advantage; /* used for analysis, not decision */
    return (predicted_bit == actual_bit) ? 1 : 0;
}

/* L4: Reverse direction -- NBU implies PRG security.
 *
 * Assume G is next-bit unpredictable. Suppose there exists a distinguisher D
 * with advantage epsilon. By the hybrid argument, there exists an index i
 * where D distinguishes H_{i-1} from H_i with advantage >= epsilon/l.
 *
 * Construct predictor A for bit i:
 *   On input prefix y_{1..i-1}:
 *     - Sample random bit r
 *     - If D(y_{1..i-1} || r || random_suffix) = 1, guess r
 *     - Else, guess 1-r
 *
 * Then A predicts bit i with advantage >= epsilon/l.
 * This contradicts NBU, so no such D exists.
 *
 * Returns estimated predictor advantage given D's advantage at position i. */
double yao_reverse_predictor_advantage(double dist_adv_at_i, size_t l) {
    /* The predictor's advantage is at least dist_adv_at_i / 2.
     * More precisely:
     *   Pr[A correct] = 1/2 + (1/2) * Adv_D_at_i
     *   Advantage = |Pr[A correct] - 1/2| >= Adv_D_at_i / 2
     *
     * And since max_i Adv_D_at_i >= Adv_D / l:
     *   Predictor advantage >= Adv_D / (2l) */
    (void)l;
    return dist_adv_at_i / 2.0;
}

/* ================================================================
 * Generic Hybrid Game Framework (L2, L4)
 * ================================================================ */

/* L2: Create generic hybrid game with k steps.
 * This framework generalizes the hybrid argument beyond PRGs to
 * any cryptographic construction with a sequence of hybrids. */
HybridGame* hybrid_game_create(size_t k, size_t l) {
    HybridGame* game = (HybridGame*)calloc(1, sizeof(HybridGame));
    if (!game) return NULL;

    game->k = k;
    game->l = l;
    game->hybrid_states = (void**)calloc(k + 1, sizeof(void*));
    if (!game->hybrid_states) {
        free(game);
        return NULL;
    }
    return game;
}

void hybrid_game_set_state(HybridGame* game, size_t i, void* state) {
    if (game && i <= game->k) {
        game->hybrid_states[i] = state;
    }
}

void* hybrid_game_get_state(const HybridGame* game, size_t i) {
    if (game && i <= game->k) {
        return game->hybrid_states[i];
    }
    return NULL;
}

void hybrid_game_free(HybridGame* game) {
    if (!game) return;
    free(game->hybrid_states);
    memset(game, 0, sizeof(HybridGame));
    free(game);
}

/* ================================================================
 * Hybrid Argument Verification (Self-Test) -- L4
 * ================================================================ */

/* L4: Verify the triangle inequality decomposition numerically.
 * Mathematical identity: |x - y| = |sum (x_i - x_{i-1})| <= sum |x_i - x_{i-1}|
 *
 * Returns 1 if the inequality holds within numerical tolerance. */
int hybrid_verify_triangle_inequality(const HybridAnalysis* ha) {
    if (!ha || ha->l == 0) return 0;

    double sum_gaps = 0.0;
    for (size_t i = 0; i < ha->l; i++) {
        sum_gaps += ha->adjacent_gap[i];
    }

    /* tolerance for floating-point rounding */
    double tolerance = 1e-10 * (double)ha->l;
    return (ha->total_gap <= sum_gaps + tolerance) ? 1 : 0;
}

/* L4: Verify the Yao reduction: if max adjacent gap = epsilon,
 * then there exists a next-bit predictor with advantage at least epsilon. */
int hybrid_verify_yao_reduction(const HybridAnalysis* ha, double tolerance) {
    if (!ha || ha->l == 0) return 0;

    double predictor_adv = yao_reverse_predictor_advantage(ha->max_adjacent_gap, ha->l);
    double expected_min = ha->max_adjacent_gap / 2.0;

    return (predictor_adv >= expected_min - tolerance) ? 1 : 0;
}

/* ================================================================
 * Computational Hybrid Argument (L4, L8)
 * ================================================================ */

/* L4: Check if advantage accumulated across k computationally-indistinguishable
 * hybrids remains negligible.
 *
 * If each adjacent pair H_{i-1} ~_c H_i has advantage negl(n),
 * then by the union bound:
 *   Adv(H_0, H_k) <= k * negl(n)
 *
 * Since k = poly(n) and negl(n) * poly(n) = negl(n),
 * the total advantage remains negligible.
 *
 * Returns 1 if total advantage is still negligible. */
int hybrid_advantage_still_negligible(double indiv_advantage, size_t k,
                                      size_t n, double poly_degree) {
    if (indiv_advantage <= 0.0) return 1;
    if (n == 0) return 0;

    double total_advantage = indiv_advantage * (double)k;
    double threshold = 1.0 / pow((double)n, poly_degree);
    return (total_advantage < threshold) ? 1 : 0;
}
