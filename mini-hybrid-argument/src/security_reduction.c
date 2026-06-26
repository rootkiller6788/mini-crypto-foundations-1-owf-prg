/*
 * security_reduction.c - Concrete Security Reductions
 *
 * Implements the formal framework for security reductions in
 * cryptography. A reduction transforms an adversary against a
 * scheme into an adversary against an underlying assumption,
 * preserving advantage up to a polynomial factor.
 *
 * This framework concretizes the "proof by reduction" methodology
 * that underlies virtually all modern cryptographic security proofs.
 *
 * L1: Reduction, tightness, concrete security, (t,eps)-adversary
 * L2: Security proof methodology, game-hopping
 * L4: Difference Lemma (Shoup), hybrid argument as reduction
 * L5: Reduction construction, Monte Carlo bound verification
 * L8: Concrete vs asymptotic security tradeoffs
 *
 * Reference:
 *   Bellare & Rogaway (2005) "Introduction to Modern Cryptography"
 *   Shoup (2004) "Sequences of Games: A Tool for Taming Complexity"
 *   Goldreich (2001) Foundations of Cryptography Vol 1
 *   Katz & Lindell (2014) Introduction to Modern Cryptography
 *
 * Courses: MIT 6.875, Berkeley CS276, Princeton COS 522, ETH 263-4660
 */

#include "security_reduction.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* ================================================================
 * Adversary Profile: (t, epsilon) characterization
 *
 * In concrete security analysis, we measure adversaries by:
 *   t = running time (logical steps)
 *   epsilon = success probability advantage
 *
 * A scheme is (t, eps)-secure if NO adversary running in time <= t
 * has advantage >= eps. This refines the asymptotic "PPT + negl"
 * into an exact, parameterized guarantee.
 * ================================================================ */

AdversaryProfile adv_profile_create(double running_time, double advantage) {
    AdversaryProfile ap;
    ap.running_time = (running_time > 0.0) ? running_time : 1.0;
    ap.advantage = (advantage >= 0.0) ? advantage : 0.0;
    ap.is_ppt = (running_time < 1e12) ? 1 : 0;
    ap.poly_degree = (running_time > 0.0) ?
        log(running_time) / log(2.0) : 0.0;
    return ap;
}

int adv_profile_is_negligible_advantage(const AdversaryProfile* ap,
                                          security_param_t n) {
    if (!ap) return 0;
    /* Check if advantage < 1/poly for a reference poly n^2 */
    double poly_bound = 1.0 / ((double)n * (double)n);
    return (ap->advantage < poly_bound) ? 1 : 0;
}

void adv_profile_print(const AdversaryProfile* ap, const char* label) {
    if (!ap) return;
    printf("=== Adversary Profile: %s ===\n", label ? label : "(unnamed)");
    printf("Running time: %.2e steps (poly deg ~%.1f)\n",
           ap->running_time, ap->poly_degree);
    printf("Advantage:    %.6f\n", ap->advantage);
    printf("PPT: %s\n", ap->is_ppt ? "YES" : "NO");
}

/* ================================================================
 * Reduction Cost Model
 *
 * A reduction transforms an adversary Adv against scheme S into
 * an adversary B against assumption A. The cost is:
 *   time(B) <= c_t * time(Adv) + overhead
 *   advantage(B) >= advantage(Adv) / c_e
 *
 * Key insight: c_e is the "security loss" factor. If c_e = poly(n),
 * then we lose at most a polynomial factor in security. This is
 * acceptable asymptotically but may be problematic concretely.
 *
 * Tightness: an ideal reduction has c_e = 1 (no advantage loss).
 * A reduction with c_e = 2^40 is "non-tight" and may not provide
 * meaningful concrete security.
 * ================================================================ */

ReductionCost reduction_cost_create(double time_factor,
                                      double advantage_factor,
                                      double time_overhead) {
    ReductionCost rc;
    rc.time_factor = (time_factor >= 1.0) ? time_factor : 1.0;
    rc.advantage_factor = (advantage_factor >= 1.0) ? advantage_factor : 1.0;
    rc.time_overhead = (time_overhead >= 0.0) ? time_overhead : 0.0;
    rc.is_tight = (advantage_factor < 2.0) ? 1 : 0;  /* <= 1 bit loss */
    rc.tightness_score = 1.0 / (rc.time_factor * rc.advantage_factor);
    return rc;
}

void reduction_cost_print(const ReductionCost* rc) {
    if (!rc) return;
    printf("=== Reduction Cost ===\n");
    printf("Time factor (c_t):      %.1f\n", rc->time_factor);
    printf("Advantage factor (c_e): %.1f\n", rc->advantage_factor);
    printf("Time overhead:          %.1e\n", rc->time_overhead);
    printf("Tight: %s\n", rc->is_tight ? "YES" : "NO");
    printf("Tightness score:        %.4f (1=perfect)\n", rc->tightness_score);
}

/* ================================================================
 * Reduction Application
 *
 * Applies the reduction to an input adversary profile,
 * producing the output adversary profile according to the
 * reduction cost model.
 *
 * The fundamental inequality of reductionist security:
 *   If Adv breaks S with (t, eps),
 *   then B breaks A with (t' <= c_t*t+ovhd, eps' >= eps/c_e)
 * ================================================================ */

ReductionResult reduction_apply(const AdversaryProfile* input,
                                 const ReductionCost* cost) {
    ReductionResult rr;
    memset(&rr, 0, sizeof(rr));
    if (!input || !cost) return rr;

    rr.input_profile = *input;
    rr.cost = *cost;

    double t_out = cost->time_factor * input->running_time + cost->time_overhead;
    double eps_out = input->advantage / cost->advantage_factor;
    rr.output_profile = adv_profile_create(t_out, eps_out);
    rr.security_loss = cost->advantage_factor;
    rr.security_preserved = (eps_out > 0.0) ? 1 : 0;

    return rr;
}

void reduction_result_print(const ReductionResult* rr) {
    if (!rr) return;
    printf("=== Reduction Result ===\n");
    printf("Input:  t=%.1e, eps=%.6f\n",
           rr->input_profile.running_time, rr->input_profile.advantage);
    printf("Output: t=%.1e, eps=%.6f\n",
           rr->output_profile.running_time, rr->output_profile.advantage);
    printf("Security loss factor: %.1f\n", rr->security_loss);
    printf("Security preserved: %s\n",
           rr->security_preserved ? "YES" : "NO");
}

/* ================================================================
 * Difference Lemma (Shoup 2004)
 *
 * Lemma: Let E1, E2, F be events. If E1 … ?F occurs iff E2 … ?F,
 * then |Pr[E1] - Pr[E2]| <= Pr[F].
 *
 * Proof: Pr[E1] = Pr[E1 … F] + Pr[E1 … ?F]
 *        Pr[E2] = Pr[E2 … F] + Pr[E2 … ?F]
 *        = Pr[E2 … F] + Pr[E1 … ?F]  (by assumption)
 *   Therefore |Pr[E1] - Pr[E2]| = |Pr[E1 … F] - Pr[E2 … F]|
 *        <= max(Pr[E1 … F], Pr[E2 … F]) <= Pr[F]
 *
 * This lemma is the workhorse of game-hopping proofs.
 * Each hop changes the game in a way that is indistinguishable
 * UNLESS some "bad event" F occurs. The adversary's advantage
 * change is bounded by Pr[F].
 * ================================================================ */

DifferenceLemma difference_lemma_check(double pr_e1, double pr_e2,
                                         double pr_f) {
    DifferenceLemma dl;
    dl.pr_e1 = pr_e1;
    dl.pr_e2 = pr_e2;
    dl.pr_f = pr_f;
    dl.bound = fabs(pr_e1 - pr_e2);
    dl.satisfies_lemma = (dl.bound <= pr_f + 1e-10) ? 1 : 0;
    return dl;
}

void difference_lemma_print(const DifferenceLemma* dl) {
    if (!dl) return;
    printf("=== Difference Lemma Check ===\n");
    printf("Pr[E1] = %.6f\n", dl->pr_e1);
    printf("Pr[E2] = %.6f\n", dl->pr_e2);
    printf("|P1-P2| = %.6f\n", dl->bound);
    printf("Pr[F]   = %.6f\n", dl->pr_f);
    printf("Satisfies |P1-P2| <= Pr[F]: %s\n",
           dl->satisfies_lemma ? "YES" : "NO");
}

/* ================================================================
 * Game-Hopping Sequence
 *
 * The modern formulation of hybrid arguments as a sequence of
 * games. The adversary's advantage in Game_0 is bounded by
 * the sum of "bad event" probabilities over all hops to Game_m,
 * where in Game_m the adversary has zero advantage.
 *
 * This structure generalizes the classic hybrid argument to
 * arbitrary game transformations, not just bit-by-bit swaps.
 * ================================================================ */

GameHoppingSequence* game_hop_create(int max_steps) {
    GameHoppingSequence* gs = (GameHoppingSequence*)
        malloc(sizeof(GameHoppingSequence));
    if (!gs) return NULL;
    gs->steps = (GameHopStep*)calloc((size_t)max_steps, sizeof(GameHopStep));
    if (!gs->steps) { free(gs); return NULL; }
    gs->num_steps = 0;
    gs->total_advantage_bound = 0.0;
    gs->measured_total_advantage = 0.0;
    gs->bound_holds = 1;
    return gs;
}

void game_hop_free(GameHoppingSequence* gs) {
    if (gs) {
        for (int i = 0; i < gs->num_steps; i++)
            free(gs->steps[i].description);
        free(gs->steps);
        free(gs);
    }
}

int game_hop_add(GameHoppingSequence* gs,
                  const char* description,
                  double pr_good,
                  double pr_bad) {
    if (!gs || !description) return -1;
    /* We don't have a hard capacity limit in the struct, so allocate more */
    int idx = gs->num_steps;
    GameHopStep* new_steps = (GameHopStep*)
        realloc(gs->steps, (size_t)(idx + 1) * sizeof(GameHopStep));
    if (!new_steps) return -1;
    gs->steps = new_steps;
    gs->steps[idx].description = _strdup(description);
    gs->steps[idx].pr_good_event = pr_good;
    gs->steps[idx].pr_bad_event = pr_bad;
    gs->num_steps = idx + 1;
    return idx;
}

void game_hop_compute_bound(GameHoppingSequence* gs) {
    if (!gs || gs->num_steps == 0) return;

    /* Sum of Pr[F_i] over all hops */
    double sum_bad = 0.0;
    for (int i = 0; i < gs->num_steps; i++)
        sum_bad += gs->steps[i].pr_bad_event;

    gs->total_advantage_bound = sum_bad;

    /* Measured total = |Pr[Game_0 succeeds] - Pr[Game_m succeeds]| */
    double first = gs->steps[0].pr_good_event;
    double last = gs->steps[gs->num_steps - 1].pr_good_event;
    gs->measured_total_advantage = fabs(first - last);

    gs->bound_holds = (gs->measured_total_advantage <=
                        gs->total_advantage_bound + 1e-10) ? 1 : 0;
}

void game_hop_print(const GameHoppingSequence* gs) {
    if (!gs) return;
    printf("=== Game-Hopping Proof ===\n");
    printf("Steps: %d\n", gs->num_steps);
    for (int i = 0; i < gs->num_steps; i++) {
        printf("  Game_%d (%s): Pr[good]=%.4f, Pr[bad]=%.4f\n",
               i, gs->steps[i].description,
               gs->steps[i].pr_good_event, gs->steps[i].pr_bad_event);
    }
    printf("Total advantage bound: %.6f\n", gs->total_advantage_bound);
    printf("Measured advantage:    %.6f\n", gs->measured_total_advantage);
    printf("Bound holds: %s\n", gs->bound_holds ? "YES" : "NO");
}

/* ================================================================
 * Hybrid Argument as a Reduction
 *
 * The hybrid argument is a reduction from distinguishing
 * G(U_n) from U_{n+k} (far apart) to distinguishing adjacent
 * hybrids (close together).
 *
 * If each adjacent pair has advantage <= epsilon, then:
 *   advantage(G_k, U) <= k * epsilon
 *
 * Reduction cost:
 *   c_t = 1 (no extra computation ！ same distinguisher)
 *   c_e = k (advantage loss factor = number of hybrids)
 *   tightness: 1/k
 *
 * For a PRG with stretch k = poly(n), this is a polynomial
 * tightness loss, which is acceptable asymptotically.
 * ================================================================ */

ReductionCost hybrid_argument_reduction_cost(
    double num_hybrids,
    double single_step_advantage) {
    (void)single_step_advantage;
    return reduction_cost_create(1.0, num_hybrids, 0.0);
}

/* ================================================================
 * Polynomial Repetition Lemma (Chernoff-based amplification)
 *
 * If base advantage is delta, repeating N times and taking
 * majority amplifies advantage.
 *
 * For each trial, let X_i = 1 if adversary succeeds, 0 otherwise.
 * E[X_i] = 1/2 + delta. By Chernoff:
 *   Pr[sum X_i / N < 1/2] <= exp(-2 * N * delta^2)
 *
 * Setting N = ln(1/confidence) / (2 * delta^2):
 *   amplified advantage >= 1 - confidence
 *
 * This enables transforming a weak distinguisher (delta = 1/poly(n))
 * into a strong distinguisher (delta 「 1) using poly(n) repetitions.
 * The cost is polynomial in 1/delta^2.
 * ================================================================ */

RepetitionAmplification repetition_amplify(
    double base_advantage,
    double target_advantage,
    double confidence) {
    RepetitionAmplification ra;
    memset(&ra, 0, sizeof(ra));

    ra.base_advantage = base_advantage;
    ra.target_advantage = target_advantage;

    if (base_advantage <= 0.0 || base_advantage > 0.5) {
        ra.repetitions_needed = 0;
        ra.chernoff_bound = 1.0;
        ra.amplified_advantage = base_advantage;
        return ra;
    }

    /* N = ln(1/confidence) / (2 * delta^2) */
    double delta = base_advantage;
    double ln_inv_conf = log(1.0 / confidence);
    double n_double = ln_inv_conf / (2.0 * delta * delta);
    ra.repetitions_needed = (int)ceil(n_double);
    if (ra.repetitions_needed < 1) ra.repetitions_needed = 1;

    /* Bound: Pr[majority wrong] <= exp(-2*N*delta^2) */
    ra.chernoff_bound = exp(-2.0 * (double)ra.repetitions_needed * delta * delta);
    ra.amplified_advantage = 1.0 - ra.chernoff_bound;
    if (ra.amplified_advantage > 1.0) ra.amplified_advantage = 1.0;

    return ra;
}

void repetition_amplification_print(const RepetitionAmplification* ra) {
    if (!ra) return;
    printf("=== Repetition Amplification ===\n");
    printf("Base advantage:     %.6f\n", ra->base_advantage);
    printf("Target advantage:   %.6f\n", ra->target_advantage);
    printf("Repetitions needed: %d\n", ra->repetitions_needed);
    printf("Chernoff bound:     %.2e\n", ra->chernoff_bound);
    printf("Amplified advantage: %.6f\n", ra->amplified_advantage);
}

/* ================================================================
 * Concrete Security Parameter Selection
 *
 * Asymptotic security: "scheme is secure for sufficiently large n"
 * Concrete security: "for n=2048, scheme is (2^80, 2^{-80})-secure"
 *
 * The key formula:
 *   effective_security = asymptotic_security - log2(reduction_loss)
 *
 * where reduction_loss = product of all tightness factors in the
 * reduction chain. If the effective security drops below a target
 * threshold (e.g., 80 bits), the parameter n must be increased.
 * ================================================================ */

ConcreteSecurityEstimate concrete_security_estimate(
    double tightness_factor,
    double target_security_bits,
    security_param_t n) {

    ConcreteSecurityEstimate cse;
    memset(&cse, 0, sizeof(cse));

    cse.target_security_bits = target_security_bits;

    /* Reduction loss in bits: log2(tightness_factor) */
    double loss_bits = (tightness_factor > 0.0) ?
        log2(tightness_factor) : 0.0;
    cse.reduction_loss_bits = loss_bits;

    /* Effective security = n - loss_bits (n is raw security parameter) */
    double raw_bits = log2((double)n);
    cse.effective_security_bits = raw_bits - loss_bits;
    if (cse.effective_security_bits < 0.0) cse.effective_security_bits = 0.0;

    cse.provides_meaningful_guarantee =
        (cse.effective_security_bits >= target_security_bits / 2.0) ? 1 : 0;

    /* Recommended n: need raw_bits = target + loss */
    double needed_raw = pow(2.0, target_security_bits + loss_bits);
    cse.recommended_n = (security_param_t)needed_raw;
    if (cse.recommended_n < n) cse.recommended_n = n;

    return cse;
}

void concrete_security_print(const ConcreteSecurityEstimate* cse) {
    if (!cse) return;
    printf("=== Concrete Security Estimate ===\n");
    printf("Target security (bits):     %.1f\n", cse->target_security_bits);
    printf("Reduction loss (bits):      %.1f\n", cse->reduction_loss_bits);
    printf("Effective security (bits):  %.1f\n", cse->effective_security_bits);
    printf("Meaningful guarantee:       %s\n",
           cse->provides_meaningful_guarantee ? "YES" : "NO");
    printf("Recommended n:              %u\n", cse->recommended_n);
}

/* ================================================================
 * Bound Verification via Monte Carlo
 *
 * In real reductions, we verify empirically that the measured
 * advantage does not exceed the theoretical bound. This is a
 * sanity check ！ it does NOT replace a mathematical proof, but
 * helps catch implementation errors in the reduction.
 *
 * The verification runs multiple independent trials, computes
 * the sample mean advantage, and compares to the bound.
 * ================================================================ */

BoundVerification bound_verify_monte_carlo(
    double (*game_runner)(int trial),
    double theoretical_bound,
    int num_trials) {

    BoundVerification bv;
    memset(&bv, 0, sizeof(bv));
    bv.theoretical_bound = theoretical_bound;
    bv.num_trials = num_trials;

    if (!game_runner || num_trials <= 0) return bv;

    double sum_adv = 0.0;
    for (int t = 0; t < num_trials; t++) {
        sum_adv += game_runner(t);
    }
    bv.measured_advantage = sum_adv / (double)num_trials;

    /* 95% confidence half-width using CLT */
    double se = (bv.measured_advantage * (1.0 - bv.measured_advantage)) /
                (double)num_trials;
    if (se > 0.0) se = sqrt(se);
    bv.confidence_95 = 1.96 * se;

    bv.bound_holds = (bv.measured_advantage <=
                       theoretical_bound + bv.confidence_95) ? 1 : 0;

    return bv;
}

void bound_verification_print(const BoundVerification* bv) {
    if (!bv) return;
    printf("=== Bound Verification ===\n");
    printf("Theoretical bound:    %.6f\n", bv->theoretical_bound);
    printf("Measured advantage:   %.6f\n", bv->measured_advantage);
    printf("95%% CI half-width:    %.6f\n", bv->confidence_95);
    printf("Bound holds:          %s\n",
           bv->bound_holds ? "YES" : "NO");
    printf("Trials: %d\n", bv->num_trials);
}
