/*
 * distinguisher.h - Distinguisher Taxonomy and Constructions
 *
 * Distinguishers are the algorithmic "attackers" in cryptographic
 * definitions. A distinguisher D takes a sample x and outputs a bit
 * D(x) in {0,1}, attempting to determine whether x came from
 * distribution X or distribution Y.
 *
 * The advantage Adv_D(X,Y) = |Pr_{x<-X}[D(x)=1] - Pr_{y<-Y}[D(y)=1]|
 * measures how much better than random guessing D performs.
 * If Adv_D(X,Y) is negligible for all PPT D, then X and Y are
 * computationally indistinguishable (written X ~=~_c Y).
 *
 * Taxonomy:
 *   Trivial distinguisher: always outputs constant (Adv = 0)
 *   Statistical test: checks structural properties (e.g., bias)
 *   PPT distinguisher: runs in polynomial time
 *   Non-uniform distinguisher: receives auxiliary advice string
 *
 * L1 Definitions: PPT distinguisher, advantage, distinguishing experiment
 * L2 Core Concepts: Statistical vs computational indistinguishability
 * L5 Algorithms: Specific distinguisher constructions
 *
 * Reference:
 *   Goldreich (2001) "Foundations of Cryptography" Vol 1, Ch 3
 *   Arora & Barak (2009) Ch 9
 *   Yao (1982) "Theory and Applications of Trapdoor Functions"
 *
 * Courses: MIT 6.875, Princeton COS 522, CMU 15-859
 */

#ifndef DISTINGUISHER_H
#define DISTINGUISHER_H

#include "hybrid_argument.h"

/* ================================================================
 * Distinguisher Construction Helpers
 * ================================================================ */

/* Trivial distinguisher: always returns constant_output (0 or 1).
   Advantage is always 0 -- the baseline "random guessing" attacker. */
Distinguisher* dist_create_trivial(int constant_output);

/* First-k-bits-zero test: checks if the first k bits of the sample
   are all zero. Useful for detecting uniform vs biased distributions.
   For uniform random bits: Pr[first k bits = 0] = 2^{-k}.
   For constant-zero distribution: Pr[first k bits = 0] = 1. */
Distinguisher* dist_create_first_k_zero(size_t k);

/* Bit-count threshold test: counts the number of 1's in the sample
   and compares to expected_ones. Returns 1 if |count - expected| <= tol.
   Detects bias: uniform bits have ~half 1's; biased have different count. */
Distinguisher* dist_create_bit_count_threshold(size_t expected_ones,
                                                 double tolerance);

/* Bit-pattern test: checks if a specific bit at position pos equals
   expected_bit. Simple but effective for detecting structured output. */
Distinguisher* dist_create_bit_pattern(size_t position, int expected_bit);

/* Linear test (parity-based): computes the dot product (mod 2) of
   the sample with a fixed mask. Returns the parity bit.
   Useful for detecting linear structure in PRG output. */
Distinguisher* dist_create_linear_test(const uint8_t* mask, size_t mask_len);

/* Repeated-pattern test: checks if the sample contains a repeating
   pattern of given period. Many weak PRGs produce periodic output. */
Distinguisher* dist_create_repeat_pattern(size_t period);

/* Run-test: counts the number of runs (consecutive identical bits)
   in the sample. Truly random bits have expected runs = n/2 + 1.
   Detects alternating or sticky patterns. */
Distinguisher* dist_create_runs_test(double expected_runs, double tolerance);

/* ================================================================
 * Distinguisher Composition
 * ================================================================ */

/*
 * Majority-vote distinguisher: combines N distinguishers by taking
 * the majority of their outputs. If each individual distinguisher
 * has small advantage, the majority may amplify the signal.
 *
 * By the Chernoff bound: if each D_i has advantage >= delta and
 * they are independent, majority has advantage -> 1 exponentially
 * fast in N.
 */
Distinguisher* dist_create_majority(Distinguisher** dists, int num_dists);

/*
 * Conjunction distinguisher: returns 1 only if ALL sub-distinguishers
 * return 1. Useful when each D_i tests an independent condition.
 */
Distinguisher* dist_create_conjunction(Distinguisher** dists, int num_dists);

/*
 * XOR distinguisher: returns XOR of all sub-distinguisher outputs.
 * Amplifies small biases through the XOR lemma.
 */
Distinguisher* dist_create_xor_composition(Distinguisher** dists, int num_dists);

/* ================================================================
 * Adaptive Distinguisher
 * ================================================================ */

/*
 * An adaptive distinguisher can make multiple queries and adapt
 * its strategy based on previous responses. This models adversaries
 * that can interact with the system (e.g., chosen-plaintext attacks).
 *
 * State includes query history. After each query, the distinguisher
 * updates its internal state before making the next query.
 */
typedef struct {
    Distinguisher** queries;
    int             num_queries;
    int*            results;
    int             capacity;
    int             current_query;
} AdaptiveDistinguisher;

AdaptiveDistinguisher* adaptive_dist_create(int max_queries);
void adaptive_dist_free(AdaptiveDistinguisher* ad);
int  adaptive_dist_query(AdaptiveDistinguisher* ad,
                          const DistributionSample* x);
int  adaptive_dist_decide(const AdaptiveDistinguisher* ad);
void adaptive_dist_reset(AdaptiveDistinguisher* ad);

/* ================================================================
 * Distinguishing Experiment
 * ================================================================ */

/*
 * A single distinguishing experiment between X and Y using D.
 * Samples many times from each distribution and estimates
 * Pr[D(X)=1] and Pr[D(Y)=1] to compute the advantage.
 */
typedef struct {
    double prob_x_outputs_1;
    double prob_y_outputs_1;
    double advantage;
    int    num_trials;
    int    significant;
    double confidence_95;
} DistinguishingExperiment;

DistinguishingExperiment dist_experiment_run(
    const Distinguisher* D,
    const DistributionEnsemble* X,
    const DistributionEnsemble* Y,
    security_param_t n,
    int num_trials);

void dist_experiment_print(const DistinguishingExperiment* exp);

/*
 * Batch experiment: run multiple distinguishers against the same
 * pair of distributions. Useful for comparing distinguisher power.
 */
typedef struct {
    DistinguishingExperiment* exps;
    int                       num_distinguishers;
    double                    max_advantage;
    int                       best_distinguisher_index;
} DistinguisherBatchResult;

DistinguisherBatchResult* dist_batch_experiment(
    Distinguisher** dists, int num_dists,
    const DistributionEnsemble* X,
    const DistributionEnsemble* Y,
    security_param_t n, int num_trials);
void dist_batch_result_free(DistinguisherBatchResult* br);
void dist_batch_result_print(const DistinguisherBatchResult* br);

/*
 * Free distinguisher AND its internal state.
 * dist_free() only frees the Distinguisher struct; this function
 * also frees the state pointer based on the distinguisher type.
 */
void dist_free_with_state(Distinguisher* D);

#endif /* DISTINGUISHER_H */