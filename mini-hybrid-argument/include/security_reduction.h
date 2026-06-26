/*
 * security_reduction.h - Concrete Security Reductions
 *
 * A security reduction is a constructive proof that if an assumption A
 * holds (e.g., "factoring is hard"), then scheme S is secure (e.g.,
 * "RSA encryption is CPA-secure"). Formally, given any PPT adversary
 * Adv against S, the reduction constructs a PPT adversary B against A
 * such that:
 *   time(B) ¡Ö poly(time(Adv))
 *   advantage(B) ¡Ý advantage(Adv) / poly(n)  (tightness factor)
 *
 * This file formalizes the reduction framework used in cryptographic
 * proofs, including the concrete security approach of Bellare-Rogaway.
 *
 * L1: Reduction, tightness, concrete security
 * L2: Security proof methodology
 * L4: Probability preservation lemmas (difference lemma)
 * L5: Reduction construction algorithms
 * L8: Concrete vs asymptotic security tradeoffs
 *
 * Reference:
 *   Bellare & Rogaway (2005) "Introduction to Modern Cryptography"
 *   Goldreich (2001) Foundations of Cryptography Vol 1, Ch 3
 *   Katz & Lindell (2014) Introduction to Modern Cryptography, Ch 3
 *
 * Courses: MIT 6.875, Berkeley CS276, Princeton COS 522, ETH 263-4660
 */

#ifndef SECURITY_REDUCTION_H
#define SECURITY_REDUCTION_H

#include "hybrid_argument.h"
#include "prg_hybrid.h"
#include "distinguisher.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

/* ================================================================
 * (t, epsilon) Adversary Profile
 *
 * In concrete security, an adversary is characterized by:
 *   - running time t (e.g., CPU cycles, logical steps)
 *   - advantage epsilon (probability of breaking the scheme)
 *
 * A scheme is (t, epsilon)-secure if no adversary running in
 * time <= t has advantage >= epsilon.
 * ================================================================ */

typedef struct {
    double  running_time;
    double  advantage;
    int     is_ppt;
    double  poly_degree;
} AdversaryProfile;

AdversaryProfile adv_profile_create(double running_time, double advantage);
int adv_profile_is_negligible_advantage(const AdversaryProfile* ap,
                                         security_param_t n);
void adv_profile_print(const AdversaryProfile* ap, const char* label);

/* ================================================================
 * Reduction Cost Model
 *
 * A reduction from scheme S2 to assumption A with cost (c_t, c_e):
 *   time(B) = c_t * time(Adv) + overhead
 *   advantage(B) >= advantage(Adv) / c_e
 *
 * The product c_t * c_e measures total reduction tightness.
 * Smaller = tighter reduction (better concrete security).
 * ================================================================ */

typedef struct {
    double  time_factor;       /* c_t: multiplicative time cost */
    double  advantage_factor;  /* c_e: 1 / advantage factor (>= 1) */
    double  time_overhead;     /* additive time overhead */
    int     is_tight;          /* c_e close to 1 */
    double  tightness_score;   /* 1 / (c_t * c_e): 1=perfect, 0=vacuous */
} ReductionCost;

ReductionCost reduction_cost_create(double time_factor,
                                      double advantage_factor,
                                      double time_overhead);
void reduction_cost_print(const ReductionCost* rc);

/* ================================================================
 * Reduction Result
 *
 * Given an adversary Adv1 against scheme S1 with profile (t1, eps1),
 * apply reduction R to obtain adversary Adv2 against assumption A
 * with profile (t2, eps2).
 * ================================================================ */

typedef struct {
    AdversaryProfile input_profile;
    ReductionCost    cost;
    AdversaryProfile output_profile;
    int              security_preserved;
    double           security_loss;  /* eps_out / eps_in >= 1/c_e */
} ReductionResult;

ReductionResult reduction_apply(const AdversaryProfile* input,
                                 const ReductionCost* cost);
void reduction_result_print(const ReductionResult* rr);

/* ================================================================
 * Difference Lemma (Shoup's Lemma)
 *
 * Let E1, E2, F be events in some probability space.
 * If Pr[E1 ¡Ä ?F] = Pr[E2 ¡Ä ?F], then
 *   |Pr[E1] - Pr[E2]| <= Pr[F]
 *
 * This is the fundamental tool for bounding the advantage loss
 * in game-hopping proofs. The hybrid argument is a special case
 * where F is the "bad" event that adjacent hybrids differ.
 * ================================================================ */

typedef struct {
    double pr_e1;           /* Pr[Event 1] */
    double pr_e2;           /* Pr[Event 2] */
    double pr_f;            /* Pr[Bad event] */
    double bound;           /* |Pr[E1] - Pr[E2]| (measured) */
    int    satisfies_lemma; /* bound <= Pr[F] */
} DifferenceLemma;

DifferenceLemma difference_lemma_check(double pr_e1, double pr_e2,
                                         double pr_f);
void difference_lemma_print(const DifferenceLemma* dl);

/* ================================================================
 * Game-Hopping Reduction
 *
 * A sequence of games Game_0, Game_1, ..., Game_m where:
 *   - Game_0: the real security game
 *   - Game_m: an idealized game (adversary has no advantage)
 *   - Adjacent games are identical unless some "bad" event F_i occurs
 *   - Total advantage <= Sum Pr[F_i] (by difference lemma)
 *
 * This is the modern formulation of the hybrid argument
 * (Bellare & Rogaway 2005, Shoup 2004).
 * ================================================================ */

typedef struct GameHopStep GameHopStep;

struct GameHopStep {
    char*  description;
    double pr_good_event;    /* Pr[adversary succeeds in this game] */
    double pr_bad_event;     /* Pr[bad event F_i occurs] */
};

typedef struct {
    GameHopStep* steps;
    int          num_steps;
    double       total_advantage_bound;
    double       measured_total_advantage;
    int          bound_holds;
} GameHoppingSequence;

GameHoppingSequence* game_hop_create(int max_steps);
void game_hop_free(GameHoppingSequence* gs);
int  game_hop_add(GameHoppingSequence* gs,
                   const char* description,
                   double pr_good,
                   double pr_bad);
void game_hop_compute_bound(GameHoppingSequence* gs);
void game_hop_print(const GameHoppingSequence* gs);

/* ================================================================
 * Hybrid Argument as a Reduction
 *
 * Explicitly computes the reduction cost when using the hybrid
 * argument to prove PRG security by reducing to single-step
 * indistinguishability.
 *
 * If a PRG has l(n)-bit output and each hybrid step has
 * advantage <= epsilon, then:
 *   - Number of hybrids: m = l(n)
 *   - Reduction advantage factor: c_e = m
 *   - Reduction time factor: c_t = 1 (no extra computation)
 *   - tightness_score = 1 / (1 * m) = 1/m
 * ================================================================ */

ReductionCost hybrid_argument_reduction_cost(
    double num_hybrids,
    double single_step_advantage);

/* ================================================================
 * Polynomial Repetition Lemma (Amplification)
 *
 * If an adversary has constant advantage delta > 0, repeating
 * the experiment poly(n)/delta^2 times and taking majority vote
 * amplifies the advantage to 1 - negl(n).
 *
 * By Chernoff bound: Pr[majority wrong] <= exp(-2*N*delta^2)
 * where N is the number of repetitions.
 *
 * This is used to amplify weak distinguishers into strong ones.
 * ================================================================ */

typedef struct {
    double base_advantage;
    double target_advantage;
    int    repetitions_needed;
    double chernoff_bound;
    double amplified_advantage;
} RepetitionAmplification;

RepetitionAmplification repetition_amplify(
    double base_advantage,
    double target_advantage,
    double confidence);
void repetition_amplification_print(const RepetitionAmplification* ra);

/* ================================================================
 * Concrete Security Parameter Selection
 *
 * Given an asymptotic reduction with tightness factor L (poly(n)),
 * determine the security parameter n needed to achieve concrete
 * security level 2^{-k} (e.g., k=80, 128, 256).
 *
 * The effective security after reduction:
 *   k_effective = k - log2(L(n))
 *
 * If log2(L(n)) >= k, the reduction is vacuous (provides no
 * meaningful security guarantee at that parameter).
 * ================================================================ */

typedef struct {
    double target_security_bits;
    double reduction_loss_bits;  /* log2 of tightness factor */
    double effective_security_bits;
    int    provides_meaningful_guarantee;
    security_param_t recommended_n;
} ConcreteSecurityEstimate;

ConcreteSecurityEstimate concrete_security_estimate(
    double tightness_factor,
    double target_security_bits,
    security_param_t n);
void concrete_security_print(const ConcreteSecurityEstimate* cse);

/* ================================================================
 * Bounds Verification
 *
 * Monte Carlo verification that reduction bounds hold in practice.
 * Samples multiple runs of the game and checks that the adversary's
 * measured advantage does not exceed the theoretical bound (within
 * statistical confidence).
 * ================================================================ */

typedef struct {
    double  theoretical_bound;
    double  measured_advantage;
    double  confidence_95;
    int     bound_holds;
    int     num_trials;
} BoundVerification;

BoundVerification bound_verify_monte_carlo(
    double (*game_runner)(int trial),
    double theoretical_bound,
    int num_trials);

void bound_verification_print(const BoundVerification* bv);

#endif /* SECURITY_REDUCTION_H */
