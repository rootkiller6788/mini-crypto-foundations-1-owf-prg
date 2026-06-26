/*
 * next_bit_unpredictable.h - Next-Bit Unpredictability & Yao's Theorem
 *
 * A PRG G: {0,1}^n -> {0,1}^{l(n)} passes the next-bit test if no PPT
 * predictor A, given the first i bits of G(s), can predict the (i+1)-th
 * bit with probability significantly better than 1/2.
 *
 * Yao's Theorem (1982): A PRG is secure (computationally indistinguishable
 * from uniform) IF AND ONLY IF it passes the next-bit test.
 *
 * This equivalence is foundational: it links the "indistinguishability"
 * definition to the "unpredictability" definition. The proof in both
 * directions uses the hybrid argument.
 *
 * Direction 1 (Predictor => Distinguisher): Easy.
 * Direction 2 (Distinguisher => Predictor): Uses the hybrid argument
 *   with l(n)+1 hybrids. Given D with advantage epsilon, there exists i
 *   with predictor advantage >= epsilon/l(n).
 *
 * L1 Definitions: Next-bit predictor, prediction advantage, next-bit test
 * L2 Core Concepts: Equivalence of security definitions
 * L4 Fundamental Laws: Yao's Theorem (both directions)
 * L5 Algorithms: Predictor construction from distinguisher (hybrid)
 * L6 Canonical Problems: Next-bit prediction game
 *
 * Reference:
 *   Yao (1982) "Theory and Applications of Trapdoor Functions", FOCS
 *   Goldreich (2001) Foundations of Cryptography Vol 1, Section 3.3.5
 *   Katz & Lindell (2014) Introduction to Modern Cryptography, Ch 3.3
 *   Arora & Barak (2009) Computational Complexity, Section 9.3
 *
 * Courses: MIT 6.875, Stanford CS355, Princeton COS 522, Berkeley CS276
 */

#ifndef NEXT_BIT_UNPREDICTABLE_H
#define NEXT_BIT_UNPREDICTABLE_H

#include "hybrid_argument.h"
#include "prg_hybrid.h"
#include "distinguisher.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

/* ================================================================
 * Next-Bit Predictor
 *
 * A PPT algorithm A that:
 *   - Input: first i bits of PRG output (the "prefix")
 *   - Output: a guess for the (i+1)-th bit (0 or 1)
 *
 * Prediction advantage:
 *   pred_adv_A(i,n) = |Pr[A(prefix_i) = bit_{i+1}] - 1/2|
 *
 * If for all PPT A and all i: pred_adv_A(i,n) <= negl(n),
 * then G passes the next-bit test.
 * ================================================================ */

typedef struct NextBitPredictor NextBitPredictor;

typedef int (*predictor_fn)(const NextBitPredictor* P,
                             const uint8_t* prefix_bits,
                             size_t prefix_len,
                             size_t target_position,
                             size_t total_output_len);

struct NextBitPredictor {
    char*         name;
    predictor_fn  predict;
    void*         state;
    size_t        time_complexity;
};

NextBitPredictor* predictor_create(const char* name,
                                     predictor_fn pred_fn,
                                     void* state,
                                     size_t time_complexity);
void predictor_free(NextBitPredictor* P);
int  predictor_predict(const NextBitPredictor* P,
                        const uint8_t* prefix_bits,
                        size_t prefix_len,
                        size_t target_position,
                        size_t total_output_len);

/* ================================================================
 * Next-Bit Prediction Game
 *
 * 1. Challenger samples s <- {0,1}^n, computes y = G(s)
 * 2. Give y[0..i-1] to predictor P for target position i
 * 3. P outputs guess b' for y[i]; succeeds if b' = y[i]
 * 4. Advantage = |success_rate - 1/2|
 * ================================================================ */

typedef struct {
    int     target_bit_position;
    int     predictor_guess;
    int     actual_bit;
    int     correct;
    double  prediction_advantage;
    int     num_trials;
    double  success_rate;
} NextBitGameResult;

NextBitGameResult next_bit_game_run(const PRG* g,
                                     const NextBitPredictor* P,
                                     size_t target_position,
                                     security_param_t n,
                                     int num_trials);
void next_bit_game_print(const NextBitGameResult* res);

/* Full next-bit test across all positions */
typedef struct {
    NextBitGameResult* position_results;
    size_t             num_positions;
    double             max_advantage;
    int                worst_position;
    double             avg_advantage;
} NextBitTestReport;

NextBitTestReport* next_bit_test_full(const PRG* g,
                                       const NextBitPredictor* P,
                                       security_param_t n,
                                       int num_trials,
                                       size_t check_every_nth_position);
void next_bit_test_report_free(NextBitTestReport* rpt);
void next_bit_test_report_print(const NextBitTestReport* rpt);

/* ================================================================
 * Yao's Theorem: Two Directions (L4 Fundamental Laws)
 * ================================================================ */

/*
 * Direction 1: Predictor => Distinguisher
 *
 * Given predictor P with advantage delta for position i,
 * construct D distinguishing G(U_n) from U_{l(n)} with advantage delta.
 *
 * D(y): extract prefix y[0..i-1], run P, output 1 iff P's guess == y[i].
 * Pr[D(G(U_n))=1] = 1/2+delta, Pr[D(U)=1] = 1/2. Adv = delta.
 */
Distinguisher* yao_predictor_to_distinguisher(const NextBitPredictor* P,
                                                size_t position);

/*
 * Direction 2: Distinguisher => Predictor (Hybrid Argument)
 *
 * Given D with advantage epsilon against G, construct predictor P
 * for some position i with prediction advantage >= epsilon / l(n).
 *
 * Hybrid H_i = (first i bits of G) || (l(n)-i random bits).
 * Let p_i = Pr[D(H_i)=1]. Since |p_0 - p_l| = epsilon,
 * exists i: |p_i - p_{i+1}| >= epsilon / l(n).
 *
 * Predictor for position i+1 given prefix y[0..i]:
 *   - Fill i+1..l-1 with random r; pick random bit b
 *   - Run D on (prefix || b || r)
 *   - If D=1, guess b; else guess 1-b
 * Advantage >= epsilon / l(n).
 */
NextBitPredictor* yao_distinguisher_to_predictor(const Distinguisher* D,
                                                   size_t total_output_len);

/*
 * Empirical verification of Yao's equivalence theorem.
 */
typedef struct {
    double original_dist_advantage;
    double derived_pred_advantage;
    double roundtrip_dist_advantage;
    int    equivalence_holds;
} YaoEquivalenceResult;

YaoEquivalenceResult yao_verify_equivalence(
    const PRG* g,
    const Distinguisher* D,
    security_param_t n,
    size_t output_len,
    int num_trials);
void yao_equivalence_print(const YaoEquivalenceResult* yr);

/* ================================================================
 * Standard Predictor Constructions (L5)
 * ================================================================ */

/* Trivial predictor: always guesses constant_bit. */
NextBitPredictor* predictor_create_constant(int guess_bit);

/* Majority predictor: guesses the majority value of prefix_window bits. */
NextBitPredictor* predictor_create_majority_prefix(size_t prefix_window);

/* XOR predictor: next bit = XOR of previous k bits. Catches LFSR patterns. */
NextBitPredictor* predictor_create_xor_of_prefix(size_t k);

/* Complement predictor: next bit = ~last_bit. Catches alternating patterns. */
NextBitPredictor* predictor_create_complement_of_last(void);

/* Periodic predictor: next bit = bit at i - period. Catches periodicity. */
NextBitPredictor* predictor_create_periodic(size_t period);

/* ================================================================
 * Prediction-Based PRG Security Assessment
 * ================================================================ */

typedef struct {
    int     passes_next_bit_test;
    double  max_pred_advantage;
    double  avg_pred_advantage;
    size_t  worst_position;
    int     positions_tested;
    double  indistinguishability_bound; /* l(n) * max_adv by Yao */
} PRGPredictionSecurity;

PRGPredictionSecurity prg_assess_via_prediction(
    const PRG* g,
    security_param_t n,
    int num_trials,
    double security_threshold);

void prg_prediction_security_print(const PRGPredictionSecurity* ps);

#endif /* NEXT_BIT_UNPREDICTABLE_H */
