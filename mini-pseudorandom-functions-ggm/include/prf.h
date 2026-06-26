/*
 * prf.h - Pseudorandom Function (PRF) Definitions
 *
 * L1 Definition
 *   A pseudorandom function family is a collection of functions
 *   F = {f_k : {0,1}^n -> {0,1}^m}_{k in {0,1}^s}
 *   such that for every PPT oracle adversary A,
 *   |Pr[A^{f_k}(1^n) = 1] - Pr[A^{f}(1^n) = 1]| <= negl(n)
 *   where f is a truly random function from {0,1}^n to {0,1}^m.
 *
 * L2 Core Concepts
 *   - Keyed function vs random function
 *   - Oracle access (black-box)
 *   - Distinguisher model
 *   - Adaptive vs non-adaptive queries
 *   - Advantage and security parameter
 *
 * L3 Mathematical Structure
 *   PRF_Family = (KeyGen, Eval, params)
 *     KeyGen(1^n) -> k in {0,1}^s(n)  (generate key)
 *     Eval(k, x) -> f_k(x) in {0,1}^m(n)  (evaluate)
 *
 * Reference:
 *   Goldreich-Goldwasser-Micali (STOC 1984 / JACM 1986)
 *   "How to Construct Random Functions"
 *   Arora-Barak section 9.2-9.3
 *   Katz-Lindell sections 3.5-3.6
 *
 * Courses:
 *   Princeton COS 522, MIT 6.875, Stanford CS255,
 *   Berkeley CS276, CMU 15-859
 */

#ifndef PRF_H
#define PRF_H

#include "prg.h"

/* ================================================================
 * PRF Family Definition (L1)
 * ================================================================ */

/*
 * PRF_Family: A set of keyed functions {f_k}
 *   key_len:    length of key k in bits (s in definition)
 *   input_len:  length of input x in bits (n in definition)
 *   output_len: length of output f_k(x) in bits (m in definition)
 *   key_space:  total number of keys = 2^key_len
 *   func_count: total functions in family = key_space
 *   is_efficient: 1 if evaluation is polynomial-time
 */
typedef struct PRF_Family_impl PRF_Family;

struct PRF_Family_impl {
    int key_len;
    int input_len;
    int output_len;
    long long key_space;
    long long func_count;
    int is_efficient;

    /* Evaluate: f_k(x) -> y */
    BitString* (*eval)(const PRF_Family* family,
                       const BitString* key,
                       const BitString* input);

    /* Key generation: sample random key */
    BitString* (*keygen)(const PRF_Family* family);

    void* state;
};

/* ================================================================
 * PRF Oracle: Black-box access interface
 * ================================================================ */

/*
 * An oracle is a black-box function that an adversary can query.
 * Two types:
 *   REAL_PRF:  the oracle implements f_k for random hidden k
 *   RANDOM_FUNC: the oracle implements a truly random function
 */
typedef enum {
    PRF_ORACLE_REAL = 0,
    PRF_ORACLE_RANDOM = 1,
    PRF_ORACLE_CLOSED = 2
} PRFOracleType;

/*
 * PRF Oracle state: tracks queries for distinguishing experiment.
 */
typedef struct {
    PRFOracleType type;
    const PRF_Family* family;
    BitString* key;         /* hidden: only used in REAL mode */

    /* Query tracking for adaptive vs non-adaptive distinguishers */
    int query_count;
    int max_queries;
    BitString** queried_inputs;
    BitString** recorded_outputs;

    /* For random oracle simulation: lazy sampling */
    struct {
        int      capacity;
        BitString** inputs;
        BitString** outputs;
        int      count;
    } random_cache;
} PRFOracle;

/* Create/destroy/copy oracles */
PRFOracle* prf_oracle_create_real(const PRF_Family* family);
PRFOracle* prf_oracle_create_random(int input_len, int output_len);
PRFOracle* prf_oracle_create_real_with_key(const PRF_Family* family,
                                            const BitString* key);
void       prf_oracle_free(PRFOracle* oracle);

/* Query the oracle: y = O(x). Opaque to adversary. */
BitString* prf_oracle_query(PRFOracle* oracle, const BitString* input);

/* Reset oracle (fresh randomness for RANDOM) */
void prf_oracle_reset(PRFOracle* oracle);

/* ================================================================
 * PRF Distinguisher (L2)
 * ================================================================ */

/*
 * A distinguisher is an algorithm D that interacts with an oracle O
 * and outputs a bit b:
 *   b = 0 means D thinks O is a PRF
 *   b = 1 means D thinks O is a truly random function
 *
 * Distinguisher function signature:
 *   int D(PRFOracle* O, int max_queries, void* aux)
 *     returns 0 (PRF) or 1 (random)
 */
typedef int (*PRFDistinguisher)(PRFOracle* oracle, int max_queries, void* aux);

/*
 * Distinguishing experiment: Run D with oracle and return result.
 */
typedef struct {
    int    result;           /* 0=PRF, 1=random */
    int    queries_made;
    double elapsed_ms;
} PRFDistResult;

PRFDistResult prf_run_distinguisher(const PRF_Family* family,
                                    PRFDistinguisher D,
                                    int max_queries, void* aux);

/* ================================================================
 * PRF Advantage Computation (L2)
 * ================================================================ */

/*
 * The advantage of distinguisher D against PRF family F is:
 *   Adv_D(F) = |Pr[D^{real}(1^n) = 1] - Pr[D^{random}(1^n) = 1]|
 *
 * where:
 *   Pr[D^{real}(1^n) = 1]  = probability D outputs 1 when oracle = f_k
 *   Pr[D^{random}(1^n) = 1] = probability D outputs 1 when oracle = truly random f
 */

typedef struct {
    double advantage;           /* estimated Adv_D(F) */
    double prob_real_outputs_1; /* estimated Pr_D^{real}[output=1] */
    double prob_rand_outputs_1; /* estimated Pr_D^{random}[output=1] */
    int    num_trials;          /* number of independent experiments */
    int    key_len;
    int    input_len;
} PRFAdvantage;

/*
 * Estimate advantage by running distinguisher repeatedly
 * with fresh random keys and fresh random functions.
 */
PRFAdvantage prf_estimate_advantage(const PRF_Family* family,
                                    PRFDistinguisher D,
                                    int max_queries,
                                    int num_trials,
                                    void* aux);

/* ================================================================
 * PRF Security Properties
 * ================================================================ */

/* Security level: bits of security = -log2(advantage) */
double prf_security_bits(const PRFAdvantage* adv);

/* Check if PRF family is secure: advantage < 2^{-40} */
int prf_is_secure_40bit(const PRFAdvantage* adv);

/* Check if advantage is negligible in security parameter n */
int prf_is_negligible_advantage(const PRFAdvantage* adv, int n);

/* ================================================================
 * Truly Random Function (for comparison)
 * ================================================================ */

/*
 * Simulate a truly random function f: {0,1}^n -> {0,1}^m
 * using lazy sampling: on each new query x, sample random y.
 */
typedef struct RandomFunc_impl RandomFunc;

struct RandomFunc_impl {
    int input_len;
    int output_len;
    long long domain_size;
    long long range_size;
    int query_count;
    int lazy_cache_capacity;
    BitString** know_inputs;
    BitString** know_outputs;
    int lazy_count;
};

RandomFunc* rf_create(int input_len, int output_len);
void        rf_free(RandomFunc* rf);
BitString*  rf_evaluate(RandomFunc* rf, const BitString* input);
void        rf_reset(RandomFunc* rf);
long long   rf_unique_queries(const RandomFunc* rf);

/* ================================================================
 * PRF Warm-up: Simple Insecure Constructions (for pedagogy)
 * ================================================================ */

/*
 * Trivial 1-bit-output PRF family (insecure, for demonstration).
 * The trivial family: F = {f_k(x) = MSB(k) for all x}
 * Advantage = 1/2 for any distinguisher that queries twice.
 */
PRF_Family* prf_create_trivial_1bit(int key_len, int input_len);

/*
 * Linear PRF family: f_k(x) = <k, x> mod 2 (inner product).
 * NOT a PRF (can be distinguished with O(n) queries via linearity).
 */
PRF_Family* prf_create_linear_inner_product(int n);

/* ================================================================
 * PRF Evaluation Counters and Metrics
 * ================================================================ */

typedef struct {
    long long eval_count;
    long long keygen_count;
    double   avg_eval_us;
} PRFMetrics;

PRFMetrics* prf_metrics_create(void);
void        prf_metrics_free(PRFMetrics* m);
void        prf_metrics_reset(PRFMetrics* m);

/* ================================================================
 * Adaptive vs Non-adaptive Query Distinction
 * ================================================================ */

/*
 * Non-adaptive distinguisher: all queries prepared in advance.
 * Adaptive distinguisher: each query may depend on previous answers.
 *
 * The GGM proof works against adaptive distinguishers,
 * which is strictly stronger than non-adaptive security.
 */

typedef enum {
    PRF_QUERY_NONADAPTIVE = 0,
    PRF_QUERY_ADAPTIVE = 1
} PRFQueryMode;

int prf_dist_adaptive_capable(PRFDistinguisher D);
void prf_set_query_mode(PRFOracle* oracle, PRFQueryMode mode);

#endif /* PRF_H */
