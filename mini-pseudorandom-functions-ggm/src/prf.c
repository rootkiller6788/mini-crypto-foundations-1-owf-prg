/*
 * prf.c - Pseudorandom Function Implementations
 *
 * Implements:
 *   L1: PRF family definition, oracle interface
 *   L2: Distinguisher framework, advantage computation
 *   L5: Truly random function (lazy sampling)
 *   L5: Simple/insecure PRF families (trivial, linear) for pedagogy
 *   Security metrics and adaptive/non-adaptive queries
 *
 * Reference: GGM (1986), Arora-Barak section 9.2-9.3
 */

#include "prf.h"
#include "crypto_utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <assert.h>

/* ================================================================
 * PRF Oracle Implementation
 * ================================================================ */

PRFOracle* prf_oracle_create_real(const PRF_Family* family) {
    if (!family) return NULL;
    PRFOracle* oracle = (PRFOracle*)calloc(1, sizeof(PRFOracle));
    if (!oracle) return NULL;

    oracle->type = PRF_ORACLE_REAL;
    oracle->family = family;
    oracle->max_queries = 10000;

    /* Generate random key */
    if (family->keygen) {
        oracle->key = family->keygen(family);
    } else {
        oracle->key = bs_create_random(family->key_len, 12345);
    }

    /* Tracking arrays */
    oracle->queried_inputs = (BitString**)calloc(
        (size_t)oracle->max_queries, sizeof(BitString*));
    oracle->recorded_outputs = (BitString**)calloc(
        (size_t)oracle->max_queries, sizeof(BitString*));

    return oracle;
}

PRFOracle* prf_oracle_create_real_with_key(const PRF_Family* family,
                                            const BitString* key) {
    if (!family || !key) return NULL;
    PRFOracle* oracle = (PRFOracle*)calloc(1, sizeof(PRFOracle));
    if (!oracle) return NULL;

    oracle->type = PRF_ORACLE_REAL;
    oracle->family = family;
    oracle->max_queries = 10000;
    oracle->key = bs_clone(key);

    oracle->queried_inputs = (BitString**)calloc(
        (size_t)oracle->max_queries, sizeof(BitString*));
    oracle->recorded_outputs = (BitString**)calloc(
        (size_t)oracle->max_queries, sizeof(BitString*));

    return oracle;
}

PRFOracle* prf_oracle_create_random(
        int input_len __attribute__((unused)),
        int output_len __attribute__((unused))) {
    PRFOracle* oracle = (PRFOracle*)calloc(1, sizeof(PRFOracle));
    if (!oracle) return NULL;

    oracle->type = PRF_ORACLE_RANDOM;
    oracle->max_queries = 10000;

    /* Lazy random cache */
    oracle->random_cache.capacity = 1024;
    oracle->random_cache.count = 0;
    oracle->random_cache.inputs = (BitString**)calloc(
        (size_t)oracle->random_cache.capacity, sizeof(BitString*));
    oracle->random_cache.outputs = (BitString**)calloc(
        (size_t)oracle->random_cache.capacity, sizeof(BitString*));

    /* Dummy family for input/output lengths */
    oracle->queried_inputs = (BitString**)calloc(
        (size_t)oracle->max_queries, sizeof(BitString*));
    oracle->recorded_outputs = (BitString**)calloc(
        (size_t)oracle->max_queries, sizeof(BitString*));

    return oracle;
}

void prf_oracle_free(PRFOracle* oracle) {
    if (!oracle) return;
    bs_free(oracle->key);

    /* Free tracking arrays */
    if (oracle->queried_inputs) {
        for (int i = 0; i < oracle->query_count; i++) {
            bs_free(oracle->queried_inputs[i]);
        }
        free(oracle->queried_inputs);
    }
    if (oracle->recorded_outputs) {
        for (int i = 0; i < oracle->query_count; i++) {
            bs_free(oracle->recorded_outputs[i]);
        }
        free(oracle->recorded_outputs);
    }

    /* Free random cache */
    if (oracle->random_cache.inputs) {
        for (int i = 0; i < oracle->random_cache.count; i++) {
            bs_free(oracle->random_cache.inputs[i]);
            bs_free(oracle->random_cache.outputs[i]);
        }
        free(oracle->random_cache.inputs);
        free(oracle->random_cache.outputs);
    }

    free(oracle);
}

/*
 * Query oracle. For RANDOM mode, use lazy sampling:
 *   If input already seen, return same output (function consistency).
 *   If input new, generate random output and cache it.
 */
BitString* prf_oracle_query(PRFOracle* oracle, const BitString* input) {
    if (!oracle || !input) return NULL;

    if (oracle->type == PRF_ORACLE_REAL) {
        /* Real PRF evaluation */
        if (!oracle->family || !oracle->family->eval || !oracle->key)
            return NULL;
        BitString* result = oracle->family->eval(
            oracle->family, oracle->key, input);

        /* Record query */
        if (oracle->query_count < oracle->max_queries && result) {
            oracle->queried_inputs[oracle->query_count] = bs_clone(input);
            oracle->recorded_outputs[oracle->query_count] = bs_clone(result);
            oracle->query_count++;
        }

        return result;
    }

    if (oracle->type == PRF_ORACLE_RANDOM) {
        /* Lazy random sampling: check cache first */
        for (int i = 0; i < oracle->random_cache.count; i++) {
            if (bs_equal(oracle->random_cache.inputs[i], input)) {
                /* Return cached output */
                BitString* result = bs_clone(oracle->random_cache.outputs[i]);

                /* Record query (but not output, to avoid double-free) */
                if (oracle->query_count < oracle->max_queries) {
                    oracle->queried_inputs[oracle->query_count] = bs_clone(input);
                    oracle->recorded_outputs[oracle->query_count] = bs_clone(result);
                    oracle->query_count++;
                }

                return result;
            }
        }

        /* Not in cache: generate random output */
        /* Output length depends on family; use a sensible default */
        int out_len = 128; /* default */
        if (oracle->family)
            out_len = oracle->family->output_len;

        BitString* random_out = bs_create_random(out_len,
            (uint64_t)(oracle->query_count + oracle->random_cache.count + 999));

        /* Cache the new (input, output) pair */
        if (oracle->random_cache.count < oracle->random_cache.capacity) {
            oracle->random_cache.inputs[oracle->random_cache.count] = bs_clone(input);
            oracle->random_cache.outputs[oracle->random_cache.count] = bs_clone(random_out);
            oracle->random_cache.count++;
        }

        /* Record query */
        if (oracle->query_count < oracle->max_queries) {
            oracle->queried_inputs[oracle->query_count] = bs_clone(input);
            oracle->recorded_outputs[oracle->query_count] = bs_clone(random_out);
            oracle->query_count++;
        }

        return random_out;
    }

    return NULL;
}

void prf_oracle_reset(PRFOracle* oracle) {
    if (!oracle) return;
    /* Clear query tracking */
    for (int i = 0; i < oracle->query_count; i++) {
        bs_free(oracle->queried_inputs[i]);
        bs_free(oracle->recorded_outputs[i]);
        oracle->queried_inputs[i] = NULL;
        oracle->recorded_outputs[i] = NULL;
    }
    oracle->query_count = 0;

    /* Clear random cache */
    for (int i = 0; i < oracle->random_cache.count; i++) {
        bs_free(oracle->random_cache.inputs[i]);
        bs_free(oracle->random_cache.outputs[i]);
    }
    oracle->random_cache.count = 0;
}

/* ================================================================
 * PRF Distinguisher
 * ================================================================ */

PRFDistResult prf_run_distinguisher(const PRF_Family* family,
                                    PRFDistinguisher D,
                                    int max_queries, void* aux) {
    PRFDistResult result = {0, 0, 0.0};
    if (!family || !D) return result;

    /* Create oracle with fresh random key */
    PRFOracle* oracle = prf_oracle_create_real(family);
    if (!oracle) return result;
    oracle->max_queries = max_queries;

    result.result = D(oracle, max_queries, aux);
    result.queries_made = oracle->query_count;
    result.elapsed_ms = 0.0; /* simplified */

    prf_oracle_free(oracle);
    return result;
}

/* ================================================================
 * PRF Advantage Computation
 * ================================================================ */

PRFAdvantage prf_estimate_advantage(const PRF_Family* family,
                                    PRFDistinguisher D,
                                    int max_queries,
                                    int num_trials,
                                    void* aux) {
    PRFAdvantage result = {0.0, 0.0, 0.0, 0, 0, 0};
    if (!family || !D || num_trials <= 0) return result;

    result.key_len = family->key_len;
    result.input_len = family->input_len;
    result.num_trials = num_trials;

    int real_outputs_1 = 0;
    int rand_outputs_1 = 0;
    int real_trials = num_trials / 2;
    int rand_trials = num_trials - real_trials;

    /* Random function distinguisher */
    PRFOracle* rand_oracle = prf_oracle_create_random(
        family->input_len, family->output_len);
    if (!rand_oracle) return result;

    for (int t = 0; t < rand_trials; t++) {
        prf_oracle_reset(rand_oracle);
        rand_oracle->max_queries = max_queries;
        rand_oracle->type = PRF_ORACLE_RANDOM;
        int b = D(rand_oracle, max_queries, aux);
        if (b == 1) rand_outputs_1++;
    }
    prf_oracle_free(rand_oracle);

    /* Real PRF distinguisher */
    for (int t = 0; t < real_trials; t++) {
        PRFOracle* real_oracle = prf_oracle_create_real(family);
        if (!real_oracle) continue;
        real_oracle->max_queries = max_queries;
        int b = D(real_oracle, max_queries, aux);
        if (b == 1) real_outputs_1++;
        prf_oracle_free(real_oracle);
    }

    if (real_trials > 0)
        result.prob_real_outputs_1 = (double)real_outputs_1 / real_trials;
    if (rand_trials > 0)
        result.prob_rand_outputs_1 = (double)rand_outputs_1 / rand_trials;

    result.advantage = fabs(result.prob_real_outputs_1
                            - result.prob_rand_outputs_1);
    return result;
}

/* ================================================================
 * PRF Security Properties
 * ================================================================ */

double prf_security_bits(const PRFAdvantage* adv) {
    if (!adv || adv->advantage <= 0.0) return 128.0;
    return -log2(adv->advantage);
}

int prf_is_secure_40bit(const PRFAdvantage* adv) {
    if (!adv) return 0;
    return (adv->advantage < pow(2.0, -40.0)) ? 1 : 0;
}

int prf_is_negligible_advantage(const PRFAdvantage* adv, int n) {
    if (!adv || n <= 0) return 0;
    /* Advantage is negligible if < 2^{-n} for sufficiently large n */
    /* We check if advantage < 1/n^2 (a typical super-polynomial gap check) */
    return (adv->advantage < 1.0 / (double)(n * n)) ? 1 : 0;
}

/* ================================================================
 * Truly Random Function (lazy sampling)
 * ================================================================ */

RandomFunc* rf_create(int input_len, int output_len) {
    RandomFunc* rf = (RandomFunc*)calloc(1, sizeof(RandomFunc));
    if (!rf) return NULL;
    rf->input_len = input_len;
    rf->output_len = output_len;
    rf->domain_size = 1LL << input_len;
    rf->range_size = 1LL << output_len;
    rf->lazy_cache_capacity = 1024;
    rf->know_inputs = (BitString**)calloc(
        (size_t)rf->lazy_cache_capacity, sizeof(BitString*));
    rf->know_outputs = (BitString**)calloc(
        (size_t)rf->lazy_cache_capacity, sizeof(BitString*));
    rf->lazy_count = 0;
    return rf;
}

void rf_free(RandomFunc* rf) {
    if (!rf) return;
    for (int i = 0; i < rf->lazy_count; i++) {
        bs_free(rf->know_inputs[i]);
        bs_free(rf->know_outputs[i]);
    }
    free(rf->know_inputs);
    free(rf->know_outputs);
    free(rf);
}

BitString* rf_evaluate(RandomFunc* rf, const BitString* input) {
    if (!rf || !input) return NULL;

    /* Check cache */
    for (int i = 0; i < rf->lazy_count; i++) {
        if (bs_equal(rf->know_inputs[i], input)) {
            rf->query_count++;
            return bs_clone(rf->know_outputs[i]);
        }
    }

    /* Generate new random output */
    BitString* out = bs_create_random(rf->output_len,
        (uint64_t)(rf->lazy_count + rf->query_count + 777));

    /* Cache it */
    if (rf->lazy_count < rf->lazy_cache_capacity && out) {
        rf->know_inputs[rf->lazy_count] = bs_clone(input);
        rf->know_outputs[rf->lazy_count] = bs_clone(out);
        rf->lazy_count++;
    }

    rf->query_count++;
    return out;
}

void rf_reset(RandomFunc* rf) {
    if (!rf) return;
    for (int i = 0; i < rf->lazy_count; i++) {
        bs_free(rf->know_inputs[i]);
        bs_free(rf->know_outputs[i]);
    }
    rf->lazy_count = 0;
    rf->query_count = 0;
}

long long rf_unique_queries(const RandomFunc* rf) {
    if (!rf) return 0;
    return (long long)rf->lazy_count;
}

/* ================================================================
 * Trivial 1-bit PRF (insecure, for pedagogy)
 * ================================================================ */

/*
 * Trivial family: f_k(x) = MSB of key (constant, ignores input)
 * Advantage: 100% �� any distinguisher that queries two different
 * inputs will see identical outputs with PRF but truly random
 * outputs with a random function.
 */

typedef struct {
    int key_len;
    int input_len;
} TrivialPRFState;

static BitString* trivial_prf_eval(const PRF_Family* family,
                                    const BitString* key,
                                    const BitString* input) {
    (void)family; (void)input; /* ignored �� this is the weakness! */
    BitString* out = bs_create(1);
    if (!out) return NULL;
    if (key && key->length > 0) {
        bs_set_bit(out, 0, bs_get_bit(key, 0));
    }
    return out;
}

static BitString* trivial_prf_keygen(const PRF_Family* family) {
    TrivialPRFState* state = (TrivialPRFState*)family->state;
    return bs_create_random(state->key_len, 99991);
}

PRF_Family* prf_create_trivial_1bit(int key_len, int input_len) {
    PRF_Family* fam = (PRF_Family*)calloc(1, sizeof(PRF_Family));
    if (!fam) return NULL;

    TrivialPRFState* state = (TrivialPRFState*)malloc(
        sizeof(TrivialPRFState));
    if (!state) { free(fam); return NULL; }
    state->key_len = key_len;
    state->input_len = input_len;

    fam->key_len = key_len;
    fam->input_len = input_len;
    fam->output_len = 1;
    fam->key_space = 1LL << key_len;
    fam->func_count = fam->key_space;
    fam->is_efficient = 1;
    fam->eval = trivial_prf_eval;
    fam->keygen = trivial_prf_keygen;
    fam->state = state;

    return fam;
}

/* ================================================================
 * Linear Inner Product PRF (insecure, for pedagogy)
 * ================================================================ */

/*
 * f_k(x) = <k, x> mod 2 (GF(2) inner product)
 * This is NOT a PRF because linearity can be detected:
 * f_k(x) xor f_k(y) xor f_k(x xor y) = 0 always
 * whereas for random function, this holds with prob 1/2.
 * Distinguishing advantage: approx 1/2 with 3 queries.
 */

typedef struct {
    int n;
} LinearPRFState;

static BitString* linear_prf_eval(const PRF_Family* family,
                                   const BitString* key,
                                   const BitString* input) {
    (void)family;
    int n = key->length;
    BitString* out = bs_create(1);
    if (!out) return NULL;
    int dot = 0;
    for (int i = 0; i < n; i++) {
        dot ^= (bs_get_bit(key, i) & bs_get_bit(input, i));
    }
    bs_set_bit(out, 0, dot);
    return out;
}

static BitString* linear_prf_keygen(const PRF_Family* family) {
    LinearPRFState* state = (LinearPRFState*)family->state;
    return bs_create_random(state->n, 77777);
}

PRF_Family* prf_create_linear_inner_product(int n) {
    PRF_Family* fam = (PRF_Family*)calloc(1, sizeof(PRF_Family));
    if (!fam) return NULL;

    LinearPRFState* state = (LinearPRFState*)malloc(
        sizeof(LinearPRFState));
    if (!state) { free(fam); return NULL; }
    state->n = n;

    fam->key_len = n;
    fam->input_len = n;
    fam->output_len = 1;
    fam->key_space = 1LL << n;
    fam->func_count = 1LL << n;
    fam->is_efficient = 1;
    fam->eval = linear_prf_eval;
    fam->keygen = linear_prf_keygen;
    fam->state = state;

    return fam;
}

/* ================================================================
 * PRF Metrics
 * ================================================================ */

PRFMetrics* prf_metrics_create(void) {
    PRFMetrics* m = (PRFMetrics*)calloc(1, sizeof(PRFMetrics));
    return m;
}

void prf_metrics_free(PRFMetrics* m) {
    free(m);
}

void prf_metrics_reset(PRFMetrics* m) {
    if (!m) return;
    m->eval_count = 0;
    m->keygen_count = 0;
    m->avg_eval_us = 0.0;
}

/* ================================================================
 * Adaptive Query Support
 * ================================================================ */

int prf_dist_adaptive_capable(PRFDistinguisher D) {
    (void)D;
    return 1; /* Most distinguishers can be adaptive */
}

void prf_set_query_mode(PRFOracle* oracle, PRFQueryMode mode) {
    (void)oracle;
    (void)mode;
    /* Mode is tracked implicitly by how the distinguisher queries */
}
