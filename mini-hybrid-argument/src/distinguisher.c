/*
 * distinguisher.c - Distinguisher Taxonomy and Constructions
 *
 * A distinguisher D is a PPT algorithm D: {0,1}^* -> {0,1} that
 * attempts to determine which distribution a given sample came from.
 * The advantage Adv_D(X,Y) = |Pr[D(X)=1] - Pr[D(Y)=1]| measures
 * how much better than random guessing D performs.
 *
 * This file provides a taxonomy of distinguisher constructions,
 * from trivial baseline distinguishers to composite distinguishers
 * that combine multiple strategies.
 *
 * L1: PPT distinguisher, advantage, distinguishing experiment
 * L2: Statistical vs computational indistinguishability
 * L5: Specific distinguisher constructions (structural, linear, runs)
 * L8: Distinguisher composition (majority, conjunction, XOR)
 *
 * Reference:
 *   Yao (1982) "Theory and Applications of Trapdoor Functions"
 *   Goldreich (2001) Foundations of Cryptography Vol 1, Ch 3
 *   Katz & Lindell (2014) Introduction to Modern Cryptography, Ch 3
 *
 * Courses: MIT 6.875, Stanford CS355, Princeton COS 522, CMU 15-859
 */

#include "distinguisher.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* ================================================================
 * Helper: count one-bits in a sample
 * ================================================================ */
static size_t count_ones(const DistributionSample* x) {
    if (!x || !x->data) return 0;
    size_t cnt = 0;
    for (size_t i = 0; i < x->length; i++) {
        if ((x->data[i/8] >> (7 - (i%8))) & 1) cnt++;
    }
    return cnt;
}

/* Helper: get bit at position */
static int get_bit(const DistributionSample* x, size_t pos) {
    if (!x || pos >= x->length) return 0;
    return (x->data[pos/8] >> (7 - (pos%8))) & 1;
}

/* ================================================================
 * 1. Trivial Distinguisher — always returns constant_output
 *
 * This is the baseline "random guessing" attacker.
 * Adv_trivial(X, Y) = |c - c| = 0 for ANY pair of distributions.
 *
 * Any non-trivial distinguisher must have Adv > 0 for at least
 * one pair of distributions; otherwise it conveys no information.
 *
 * Knowledge: Defines the baseline for advantage comparison.
 * ================================================================ */

typedef struct {
    int constant_output;
} TrivialState;

static int trivial_eval(const Distinguisher* D, const DistributionSample* x) {
    (void)x;
    if (!D || !D->state) return 0;
    return ((TrivialState*)D->state)->constant_output;
}

Distinguisher* dist_create_trivial(int constant_output) {
    TrivialState* ts = (TrivialState*)malloc(sizeof(TrivialState));
    if (!ts) return NULL;
    ts->constant_output = (constant_output != 0) ? 1 : 0;
    return dist_create("Trivial", trivial_eval, ts, 1);
}

/* ================================================================
 * 2. First-K-Bits-Zero Test
 *
 * D(x) = 1 iff the first k bits of x are all zero.
 * Pr_U[D=1] = 2^{-k} (exponentially small for uniform)
 * Pr_constzero[D=1] = 1 (always passes for all-zero distribution)
 *
 * Advantage: |1 - 2^{-k}| approx 1, so this is a powerful distinguisher
 * when one distribution is heavily biased toward leading zeros.
 *
 * Knowledge: Demonstrates structural (prefix-based) distinguishing.
 * ================================================================ */

typedef struct {
    size_t k;
} FirstKZeroState;

static int first_k_zero_eval(const Distinguisher* D, const DistributionSample* x) {
    if (!D || !D->state || !x) return 0;
    FirstKZeroState* fs = (FirstKZeroState*)D->state;
    size_t check = (fs->k < x->length) ? fs->k : x->length;
    for (size_t i = 0; i < check; i++) {
        if (get_bit(x, i) == 1) return 0;
    }
    return 1;
}

Distinguisher* dist_create_first_k_zero(size_t k) {
    FirstKZeroState* fs = (FirstKZeroState*)malloc(sizeof(FirstKZeroState));
    if (!fs) return NULL;
    fs->k = k;
    return dist_create("FirstKZero", first_k_zero_eval, fs, k);
}

/* ================================================================
 * 3. Bit-Count Threshold Test
 *
 * D(x) = 1 iff |count_ones(x) - expected_ones| <= tolerance * length.
 *
 * For uniform n-bit strings: E[ones] = n/2, Var = n/4.
 * By Chernoff, Pr[|ones - n/2| > t*n/2] <= 2*exp(-t^2*n/6).
 *
 * This distinguisher detects bias: distributions with significantly
 * different expected number of 1-bits from the reference.
 *
 * Knowledge: Statistical test based on concentration inequalities.
 * ================================================================ */

typedef struct {
    size_t expected_ones;
    double tolerance;  /* relative tolerance */
} BitCountState;

static int bit_count_eval(const Distinguisher* D, const DistributionSample* x) {
    if (!D || !D->state || !x) return 0;
    BitCountState* bs = (BitCountState*)D->state;
    size_t ones = count_ones(x);
    double diff = (double)((ones > bs->expected_ones) ?
        (ones - bs->expected_ones) : (bs->expected_ones - ones));
    double rel = diff / (double)x->length;
    return (rel <= bs->tolerance) ? 1 : 0;
}

Distinguisher* dist_create_bit_count_threshold(size_t expected_ones,
                                                 double tolerance) {
    BitCountState* bs = (BitCountState*)malloc(sizeof(BitCountState));
    if (!bs) return NULL;
    bs->expected_ones = expected_ones;
    bs->tolerance = tolerance;
    return dist_create("BitCount", bit_count_eval, bs, expected_ones);
}

/* ================================================================
 * 4. Bit-Pattern Test
 *
 * D(x) = 1 iff x[position] == expected_bit.
 * Simple but effective when one distribution has a fixed bit.
 *
 * For uniform: Pr[D=1] = 1/2.
 * For biased: if x[position] always equals expected_bit, Pr[D=1] = 1.
 * Advantage: |1 - 1/2| = 1/2.
 *
 * Knowledge: Demonstrates single-coordinate distinguishers.
 * ================================================================ */

typedef struct {
    size_t position;
    int expected_bit;
} BitPatternState;

static int bit_pattern_eval(const Distinguisher* D, const DistributionSample* x) {
    if (!D || !D->state || !x) return 0;
    BitPatternState* bp = (BitPatternState*)D->state;
    return (get_bit(x, bp->position) == bp->expected_bit) ? 1 : 0;
}

Distinguisher* dist_create_bit_pattern(size_t position, int expected_bit) {
    BitPatternState* bp = (BitPatternState*)malloc(sizeof(BitPatternState));
    if (!bp) return NULL;
    bp->position = position;
    bp->expected_bit = (expected_bit != 0) ? 1 : 0;
    return dist_create("BitPattern", bit_pattern_eval, bp, position);
}

/* ================================================================
 * 5. Linear Test (Parity-Based)
 *
 * D(x) = dot(x, mask) mod 2 = XOR of x[i] for bits where mask[i]=1.
 *
 * This is a fundamental building block in Fourier analysis of
 * Boolean functions. Any Boolean function on n bits can be expressed
 * as a sum (mod 2) of parity functions (its Fourier expansion).
 *
 * For uniform x: Pr[D=1] = 1/2 (regardless of mask).
 * For structured x (e.g., PRG output): parity may be biased.
 *
 * The Fourier coefficient f_hat(S) = E_x[f(x) * (-1)^{dot(x,S)}]
 * measures the correlation of f with parity S.
 *
 * Knowledge: Linear/Fourier distinguisher — foundation of
 *   Fourier analysis of Boolean functions.
 * Reference: O'Donnell (2014) "Analysis of Boolean Functions"
 * ================================================================ */

typedef struct {
    uint8_t* mask;
    size_t mask_len;      /* bits */
    size_t mask_bytes;
} LinearTestState;

static int linear_test_eval(const Distinguisher* D, const DistributionSample* x) {
    if (!D || !D->state || !x) return 0;
    LinearTestState* ls = (LinearTestState*)D->state;
    int parity = 0;
    size_t check = (ls->mask_len < x->length) ? ls->mask_len : x->length;
    for (size_t i = 0; i < check; i++) {
        if ((ls->mask[i/8] >> (7 - (i%8))) & 1) {
            parity ^= get_bit(x, i);
        }
    }
    return parity;
}

Distinguisher* dist_create_linear_test(const uint8_t* mask, size_t mask_len) {
    if (!mask || mask_len == 0) return NULL;
    LinearTestState* ls = (LinearTestState*)malloc(sizeof(LinearTestState));
    if (!ls) return NULL;
    size_t mb = (mask_len + 7) / 8;
    ls->mask = (uint8_t*)malloc(mb);
    if (!ls->mask) { free(ls); return NULL; }
    memcpy(ls->mask, mask, mb);
    ls->mask_len = mask_len;
    ls->mask_bytes = mb;
    return dist_create("LinearTest", linear_test_eval, ls, mask_len);
}

/* ================================================================
 * 6. Repeated-Pattern Test
 *
 * D(x) = 1 iff x has a repeating pattern with the given period.
 *
 * Many weak PRGs produce periodic output. For truly random bits,
 * the probability of period-p pattern is 2^{-p}.
 *
 * This distinguishes:
 *   - Periodic PRG: Pr[D=1] approx 1
 *   - Uniform: Pr[D=1] = 2^{-p}
 *
 * Knowledge: Periodicity-based distinguisher.
 * ================================================================ */

typedef struct {
    size_t period;
} RepeatState;

static int repeat_pattern_eval(const Distinguisher* D, const DistributionSample* x) {
    if (!D || !D->state || !x) return 0;
    RepeatState* rs = (RepeatState*)D->state;
    if (rs->period == 0 || x->length < 2 * rs->period) return 0;
    /* Check if blocks of length 'period' repeat */
    size_t blocks = x->length / rs->period;
    for (size_t b = 1; b < blocks; b++) {
        for (size_t j = 0; j < rs->period; j++) {
            size_t i0 = (b-1) * rs->period + j;
            size_t i1 = b * rs->period + j;
            if (get_bit(x, i0) != get_bit(x, i1)) return 0;
        }
    }
    return 1;
}

Distinguisher* dist_create_repeat_pattern(size_t period) {
    if (period == 0) return NULL;
    RepeatState* rs = (RepeatState*)malloc(sizeof(RepeatState));
    if (!rs) return NULL;
    rs->period = period;
    return dist_create("RepeatPattern", repeat_pattern_eval, rs, period);
}

/* ================================================================
 * 7. Runs Test (Wald-Wolfowitz)
 *
 * A run is a maximal sequence of consecutive identical bits.
 * For n uniform random bits, the expected number of runs is n/2 + 1.
 *
 * Alternative patterns:
 *   - "Sticky" bits: runs >> n/2 + 1 (frequent alternation)
 *   - "Sticky" regions: runs << n/2 + 1 (long constant blocks)
 *
 * The runs test is part of the NIST statistical test suite for
 * random number generators (SP 800-22).
 *
 * Knowledge: Runs-based statistical test for randomness.
 * ================================================================ */

typedef struct {
    double expected_runs;
    double tolerance;
} RunsState;

static int runs_test_eval(const Distinguisher* D, const DistributionSample* x) {
    if (!D || !D->state || !x || x->length < 2) return 0;
    RunsState* rs = (RunsState*)D->state;
    size_t runs = 1;
    for (size_t i = 1; i < x->length; i++) {
        if (get_bit(x, i) != get_bit(x, i-1)) runs++;
    }
    double diff = fabs((double)runs - rs->expected_runs);
    return (diff <= rs->tolerance * (double)x->length) ? 1 : 0;
}

Distinguisher* dist_create_runs_test(double expected_runs, double tolerance) {
    RunsState* rs = (RunsState*)malloc(sizeof(RunsState));
    if (!rs) return NULL;
    rs->expected_runs = expected_runs;
    rs->tolerance = tolerance;
    return dist_create("RunsTest", runs_test_eval, rs,
                        (size_t)expected_runs);
}

/* ================================================================
 * 8. Majority-Vote Distinguisher (Amplification)
 *
 * D_maj(x) = majority(D_1(x), D_2(x), ..., D_N(x))
 *
 * By the Chernoff bound: if each D_i has advantage >= delta and
 * they are independent, then for any target confidence 1-2^{-k}:
 *   N = O(k / delta^2) suffices for D_maj to achieve advantage
 *   arbitrarily close to 1.
 *
 * This is the canonical "amplification" technique: weak distinguishers
 * can be combined into a strong distinguisher.
 *
 * Knowledge: Chernoff-bound based distinguisher amplification.
 * ================================================================ */

typedef struct {
    Distinguisher** dists;
    int num_dists;
} MajorityState;

static int majority_eval(const Distinguisher* D, const DistributionSample* x) {
    if (!D || !D->state || !x) return 0;
    MajorityState* ms = (MajorityState*)D->state;
    int votes = 0;
    for (int i = 0; i < ms->num_dists; i++) {
        if (ms->dists[i] && dist_evaluate(ms->dists[i], x))
            votes++;
    }
    return (votes > ms->num_dists / 2) ? 1 : 0;
}

Distinguisher* dist_create_majority(Distinguisher** dists, int num_dists) {
    if (!dists || num_dists <= 0) return NULL;
    MajorityState* ms = (MajorityState*)malloc(sizeof(MajorityState));
    if (!ms) return NULL;
    ms->dists = dists;  /* caller owns */
    ms->num_dists = num_dists;
    return dist_create("Majority", majority_eval, ms, (size_t)num_dists);
}

/* ================================================================
 * 9. Conjunction Distinguisher
 *
 * D_and(x) = D_1(x) AND D_2(x) AND ... AND D_N(x)
 *
 * Returns 1 only if ALL sub-distinguishers return 1.
 * Useful when each D_i tests an independent necessary condition.
 *
 * Probability: Pr[D_and=1] = Prod_i Pr[D_i=1] (if independent).
 * This DECREASES false-positive rate but also decreases sensitivity.
 *
 * Knowledge: Boolean combination of distinguisher tests.
 * ================================================================ */

typedef struct {
    Distinguisher** dists;
    int num_dists;
} ConjunctState;

static int conjunction_eval(const Distinguisher* D, const DistributionSample* x) {
    if (!D || !D->state || !x) return 0;
    ConjunctState* cs = (ConjunctState*)D->state;
    for (int i = 0; i < cs->num_dists; i++) {
        if (cs->dists[i] && !dist_evaluate(cs->dists[i], x)) return 0;
    }
    return 1;
}

Distinguisher* dist_create_conjunction(Distinguisher** dists, int num_dists) {
    if (!dists || num_dists <= 0) return NULL;
    ConjunctState* cs = (ConjunctState*)malloc(sizeof(ConjunctState));
    if (!cs) return NULL;
    cs->dists = dists;
    cs->num_dists = num_dists;
    return dist_create("Conjunction", conjunction_eval, cs, (size_t)num_dists);
}

/* ================================================================
 * 10. XOR Composition Distinguisher (XOR Lemma)
 *
 * D_xor(x_1, ..., x_k) = XOR of D(x_i) over k independent samples.
 *
 * Yao's XOR Lemma: If a Boolean function f is weakly hard to
 * compute with advantage delta, then the k-fold XOR of f is
 * essentially unpredictable, with advantage at most (1-delta)^k.
 *
 * In the distinguisher context: if each D_i has small advantage
 * epsilon, the XOR of k calls amplifies structure when the
 * individual advantages are correlated.
 *
 * Knowledge: Yao's XOR Lemma applied to distinguishers.
 * ================================================================ */

typedef struct {
    Distinguisher** dists;
    int num_dists;
} XorState;

static int xor_composition_eval(const Distinguisher* D, const DistributionSample* x) {
    if (!D || !D->state || !x) return 0;
    XorState* xs = (XorState*)D->state;
    int result = 0;
    for (int i = 0; i < xs->num_dists; i++) {
        if (xs->dists[i]) result ^= dist_evaluate(xs->dists[i], x);
    }
    return result;
}

Distinguisher* dist_create_xor_composition(Distinguisher** dists, int num_dists) {
    if (!dists || num_dists <= 0) return NULL;
    XorState* xs = (XorState*)malloc(sizeof(XorState));
    if (!xs) return NULL;
    xs->dists = dists;
    xs->num_dists = num_dists;
    return dist_create("XORComposition", xor_composition_eval, xs,
                        (size_t)num_dists);
}

/* ================================================================
 * Adaptive Distinguisher
 *
 * Models an adversary that can make multiple adaptive queries.
 * After each query, the distinguisher updates its internal state
 * based on the response, and can choose different strategies.
 *
 * This captures the power of chosen-plaintext attacks (CPA),
 * chosen-ciphertext attacks (CCA), and other interactive
 * adversarial models in cryptography.
 *
 * The adaptive distinguisher maintains:
 *   - A list of query distinguishers
 *   - Result history from previous queries
 *   - Current query counter
 *
 * Knowledge: Adaptive (interactive) adversary model.
 * ================================================================ */

AdaptiveDistinguisher* adaptive_dist_create(int max_queries) {
    AdaptiveDistinguisher* ad = (AdaptiveDistinguisher*)
        malloc(sizeof(AdaptiveDistinguisher));
    if (!ad) return NULL;
    ad->queries = (Distinguisher**)calloc((size_t)max_queries,
                                            sizeof(Distinguisher*));
    ad->results = (int*)calloc((size_t)max_queries, sizeof(int));
    if (!ad->queries || !ad->results) {
        free(ad->queries); free(ad->results); free(ad);
        return NULL;
    }
    ad->num_queries = 0;
    ad->capacity = max_queries;
    ad->current_query = 0;
    return ad;
}

void adaptive_dist_free(AdaptiveDistinguisher* ad) {
    if (ad) {
        free(ad->queries);
        free(ad->results);
        free(ad);
    }
}

int adaptive_dist_query(AdaptiveDistinguisher* ad,
                         const DistributionSample* x) {
    if (!ad || ad->current_query >= ad->capacity) return -1;
    int idx = ad->current_query;
    if (ad->queries[idx]) {
        ad->results[idx] = dist_evaluate(ad->queries[idx], x);
    } else {
        ad->results[idx] = 0;
    }
    ad->current_query++;
    return ad->results[idx];
}

int adaptive_dist_decide(const AdaptiveDistinguisher* ad) {
    /* Decision rule: succeed if any query returned 1 (union strategy) */
    if (!ad) return 0;
    for (int i = 0; i < ad->current_query && i < ad->capacity; i++) {
        if (ad->results[i]) return 1;
    }
    return 0;
}

void adaptive_dist_reset(AdaptiveDistinguisher* ad) {
    if (ad) {
        ad->current_query = 0;
        memset(ad->results, 0, (size_t)ad->capacity * sizeof(int));
    }
}

/* ================================================================
 * Distinguishing Experiment
 *
 * A single experiment between ensembles X and Y using D:
 *   1. Sample x_1, ..., x_T from X, count fraction where D(x)=1.
 *   2. Sample y_1, ..., y_T from Y, count fraction where D(y)=1.
 *   3. Report advantage = |p_X - p_Y|.
 *
 * Significance: the experiment is "significant" if the advantage
 * exceeds 2 * confidence_half_width (i.e., the 95% CI excludes 0).
 *
 * Knowledge: Formalizes the distinguishing experiment from
 *   cryptographic security definitions.
 * ================================================================ */

DistinguishingExperiment dist_experiment_run(
    const Distinguisher* D,
    const DistributionEnsemble* X,
    const DistributionEnsemble* Y,
    security_param_t n,
    int num_trials) {
    DistinguishingExperiment exp;
    memset(&exp, 0, sizeof(exp));

    double hw = 1.0;
    exp.advantage = dist_estimate_advantage(D, X, Y, n, num_trials, &hw);
    exp.num_trials = num_trials;
    exp.confidence_95 = hw;

    /* Estimate individual probabilities */
    size_t out_len = X->output_length ? X->output_length(n) : 256;
    DistributionSample* sample = dsample_create(out_len);
    if (sample) {
        double cx = 0.0;
        for (int t = 0; t < num_trials; t++) {
            dens_sample(X, n, sample);
            if (dist_evaluate(D, sample)) cx += 1.0;
        }
        exp.prob_x_outputs_1 = cx / (double)num_trials;

        double cy = 0.0;
        for (int t = 0; t < num_trials; t++) {
            dens_sample(Y, n, sample);
            if (dist_evaluate(D, sample)) cy += 1.0;
        }
        exp.prob_y_outputs_1 = cy / (double)num_trials;

        dsample_free(sample);
    }
    exp.significant = (exp.advantage > 2.0 * hw) ? 1 : 0;
    return exp;
}

void dist_experiment_print(const DistinguishingExperiment* exp) {
    if (!exp) return;
    printf("=== Distinguisher Experiment ===\n");
    printf("Trials: %d\n", exp->num_trials);
    printf("Pr[D(X)=1]: %.6f\n", exp->prob_x_outputs_1);
    printf("Pr[D(Y)=1]: %.6f\n", exp->prob_y_outputs_1);
    printf("Advantage: %.6f\n", exp->advantage);
    printf("95%% CI half-width: %.6f\n", exp->confidence_95);
    printf("Significant: %s\n", exp->significant ? "YES" : "NO");
}

/* ================================================================
 * Batch Distinguisher Experiment
 *
 * Runs multiple distinguishers against the same pair of distributions.
 * Reports which distinguisher achieves the maximum advantage.
 *
 * This enables comparison of distinguisher power:
 *   - Are structural tests more effective than statistical tests?
 *   - Does composition amplify advantage?
 *   - Do PPT distinguishers approach the statistical distance bound?
 *
 * Knowledge: Comparative analysis of distinguisher effectiveness.
 * ================================================================ */

DistinguisherBatchResult* dist_batch_experiment(
    Distinguisher** dists, int num_dists,
    const DistributionEnsemble* X,
    const DistributionEnsemble* Y,
    security_param_t n, int num_trials) {
    if (!dists || num_dists <= 0) return NULL;

    DistinguisherBatchResult* br = (DistinguisherBatchResult*)
        malloc(sizeof(DistinguisherBatchResult));
    if (!br) return NULL;

    br->exps = (DistinguishingExperiment*)
        calloc((size_t)num_dists, sizeof(DistinguishingExperiment));
    if (!br->exps) { free(br); return NULL; }

    br->num_distinguishers = num_dists;
    br->max_advantage = 0.0;
    br->best_distinguisher_index = 0;

    for (int i = 0; i < num_dists; i++) {
        br->exps[i] = dist_experiment_run(dists[i], X, Y, n, num_trials);
        if (br->exps[i].advantage > br->max_advantage) {
            br->max_advantage = br->exps[i].advantage;
            br->best_distinguisher_index = i;
        }
    }
    return br;
}

void dist_batch_result_free(DistinguisherBatchResult* br) {
    if (br) { free(br->exps); free(br); }
}

void dist_batch_result_print(const DistinguisherBatchResult* br) {
    if (!br) return;
    printf("=== Batch Distinguisher Report ===\n");
    printf("Distinguishers tested: %d\n", br->num_distinguishers);
    printf("Best: index %d, advantage %.6f\n",
           br->best_distinguisher_index, br->max_advantage);
    for (int i = 0; i < br->num_distinguishers; i++) {
        printf("  D[%d]: adv=%.6f, sig=%d\n",
               i, br->exps[i].advantage, br->exps[i].significant);
    }
}

/* ================================================================
 * Distinguisher State Cleanup
 *
 * When dist_free is called, the state pointer must also be freed
 * if it was dynamically allocated. The individual distinguisher
 * constructors allocate state, but dist_free only frees the
 * Distinguisher struct itself.
 *
 * We provide a cleanup helper that also frees state based on
 * the distinguisher type (identified by name prefix matching).
 * ================================================================ */

void dist_free_with_state(Distinguisher* D) {
    if (!D) return;
    /* Free the internal state based on name */
    if (D->state) {
        if (strncmp(D->name, "Trivial", 7) == 0)
            free(D->state);
        else if (strncmp(D->name, "FirstKZero", 10) == 0)
            free(D->state);
        else if (strncmp(D->name, "BitCount", 8) == 0)
            free(D->state);
        else if (strncmp(D->name, "BitPattern", 10) == 0)
            free(D->state);
        else if (strncmp(D->name, "LinearTest", 10) == 0) {
            LinearTestState* ls = (LinearTestState*)D->state;
            free(ls->mask);
            free(D->state);
        }
        else if (strncmp(D->name, "RepeatPattern", 13) == 0)
            free(D->state);
        else if (strncmp(D->name, "RunsTest", 8) == 0)
            free(D->state);
        else if (strncmp(D->name, "Majority", 8) == 0)
            free(D->state);
        else if (strncmp(D->name, "Conjunction", 11) == 0)
            free(D->state);
        else if (strncmp(D->name, "XORComposition", 14) == 0)
            free(D->state);
        else
            free(D->state); /* best-effort for unknown types */
    }
    dist_free(D);
}