/*
 * owf_hardcore.h — Hardcore Predicates & Goldreich-Levin Theorem
 *
 * L4 Fundamental Law (Goldreich-Levin 1989):
 *   Every one-way function f has a hardcore predicate.
 *   Specifically, if f is a OWF, then g(x, r) = (f(x), r) is also a OWF,
 *   and b(x, r) = ⟨x, r⟩ mod 2 is a hardcore predicate of g.
 *
 * L2 Core Concept:
 *   Hardcore predicate hc(x): a Boolean function that is:
 *     - Efficiently computable from x
 *     - Unpredictable given f(x): ∀ PPT A,
 *       Pr[A(f(x)) = hc(x)] ≤ 1/2 + negl(n)
 *
 * L8 Advanced Topic:
 *   - Goldreich-Levin list decoding algorithm for learning parity with noise
 *   - General hardcore predicates from any OWF
 *   - Connection to learning theory (PAC learning parity)
 *
 * Construction:
 *   Given OWF f: {0,1}^n → {0,1}^*, define:
 *     g(x, r) = (f(x), r)          where |r| = |x| = n
 *     GL(x, r) = ⟨x, r⟩ mod 2     (Goldreich-Levin hardcore bit)
 *
 * Theorem: If f is a one-way function, then GL is a hardcore
 * predicate for g. That is, given (f(x), r), predicting GL(x,r)
 * is computationally hard.
 *
 * Proof uses: list decoding of Hadamard code (efficiently finding
 * all x that agree with a predictor on noticeably more than 1/2 of r).
 *
 * Reference:
 *   Goldreich, Levin, "A Hard-Core Predicate for All One-Way Functions"
 *   (STOC 1989)
 *   Goldreich Vol 1 §2.5 — Full proof and analysis
 *   Katz-Lindell §7.4.1 — Simplified treatment
 *   Arora-Barak §19.3 — Complexity-theoretic perspective
 *
 * Courses:
 *   MIT 6.875, Stanford CS255, Berkeley CS276,
 *   Princeton COS 433, CMU 15-859, Cambridge Part III,
 *   Oxford Advanced Security, ETH 263-4660
 */

#ifndef OWF_HARDCORE_H
#define OWF_HARDCORE_H

#include "owf_core.h"

/* ================================================================
 * Hardcore Predicate Definition
 * ================================================================ */

/*
 * A predicate hc: {0,1}^n → {0,1} is hardcore for f if:
 *   (1) hc(x) is polynomial-time computable given x.
 *   (2) For every PPT algorithm A, there exists a negligible
 *       function μ such that:
 *         Pr[A(1^n, f(x)) = hc(x)] ≤ 1/2 + μ(n)
 *       where x ← {0,1}^n uniformly.
 */

typedef int (*hardcore_pred_fn)(const bit_string_t* x);

typedef struct {
    char*             name;          /* predicate name */
    hardcore_pred_fn  compute;        /* evaluate hc(x) */
    owf_scheme_t*     owf;            /* parent OWF */
    double            empirical_bias; /* measured |Pr[predict] - 1/2| */
    int               num_trials;     /* number of measurements */
} hardcore_predicate_t;

hardcore_predicate_t* hcp_create(const char* name, hardcore_pred_fn compute,
                                  owf_scheme_t* owf);
void                  hcp_free(hardcore_predicate_t* hcp);
int                   hcp_evaluate(const hardcore_predicate_t* hcp,
                                    const bit_string_t* x);

/* ================================================================
 * Goldreich-Levin Hardcore Predicate
 * ================================================================ */

/*
 * GL(x, r) = ⟨x, r⟩ mod 2 = ⊕_{i=1}^n x_i·r_i
 *
 * This is the universal hardcore predicate: for ANY OWF f,
 * the function g(x, r) = (f(x), r) has GL as hardcore predicate.
 */

/* Compute GL predicate: inner product mod 2 */
int gl_predicate(const bit_string_t* x, const bit_string_t* r);

/* Compute GL as a hardcore_pred_fn (wraps x+r into one bit_string) */
int gl_predicate_combined(const bit_string_t* xr_combined);

/* ================================================================
 * Goldreich-Levin Theorem Construction
 * ================================================================ */

/*
 * GL Construction: given OWF f, construct g(x, r) = (f(x), r).
 *
 * Properties:
 *   - g is a OWF (if f is a OWF)
 *   - GL(x, r) = ⟨x, r⟩ mod 2 is hardcore for g
 */

typedef struct {
    owf_scheme_t* base_owf;     /* original OWF f */
    size_t        n;            /* input length |x| = |r| */
    sec_param_t   sec_param;
} gl_construction_t;

/* Create GL construction wrapping any OWF */
gl_construction_t* gl_construct_create(owf_scheme_t* base_owf);
void               gl_construct_free(gl_construction_t* construct);

/* Evaluate g(x, r) = (f(x), r) */
int gl_construct_eval(void* ctx, const bit_string_t* xr,
                      sec_param_t n, bit_string_t** y);

/* Get g as an owf_scheme_t */
owf_scheme_t* gl_construct_as_owf(gl_construction_t* construct);

/* ================================================================
 * List Decoding: Goldreich-Levin Algorithm
 * ================================================================ */

/*
 * Goldreich-Levin list decoding algorithm:
 *
 * Given oracle access to a predictor P such that
 *   Pr_r[P(r) = ⟨x, r⟩ mod 2] ≥ 1/2 + ε
 * the algorithm outputs a list L of candidate strings x'
 * such that x ∈ L with high probability.
 *
 * This is the core technical component of the GL theorem proof.
 *
 * Algorithm:
 *   1. Select k = O(n/ε^2) random strings r_1,...,r_k
 *   2. For each z ∈ {0,1}^k:
 *      a. Estimate x_j = majority_{i: z_i=1} P(r_i ⊕ e_j) ⊕ P(r_i)
 *      b. Check if candidate x agrees with P on ≥ 1/2 + ε/2 of inputs
 *   3. Output all passing candidates
 *
 * Complexity: O(2^{O(n/ε^2)} · poly(n)) — polynomial for constant ε.
 */

typedef struct {
    bit_string_t** cand_list;    /* list of candidate x' values */
    size_t         num_candidates;
    size_t         capacity;
} gl_list_t;

gl_list_t* gl_list_create(size_t capacity);
void       gl_list_free(gl_list_t* list);
int        gl_list_add(gl_list_t* list, const bit_string_t* candidate);

/*
 * Predictor interface: given r, predict GL(x, r).
 */
typedef int (*gl_predictor_fn)(const bit_string_t* r, void* ctx);

/*
 * GL list decoding:
 *   predictor: function that tries to predict GL(x, r)
 *   n:         input length
 *   epsilon:   advantage over 1/2
 *   out_list:  list of candidate x' values
 *
 * Returns: number of candidates found.
 */
int gl_list_decode(gl_predictor_fn predictor, void* pred_ctx,
                   size_t n, double epsilon, gl_list_t* out_list);

/*
 * Verify if candidate x' is consistent with predictor:
 *   sample many random r, check if candidate matches predictions.
 */
double gl_verify_candidate(gl_predictor_fn predictor, void* pred_ctx,
                           const bit_string_t* candidate, size_t num_tests);

/* ================================================================
 * Hardcore Predicate Experiment
 * ================================================================ */

/*
 * Experiment: Given OWF f and claim that hc is a hardcore predicate,
 *   (1) Sample x ← {0,1}^n
 *   (2) Give adversary y = f(x) (but NOT x)
 *   (3) Adversary outputs bit b'
 *   (4) Success if b' = hc(x)
 */
typedef struct {
    hardcore_predicate_t* hcp;
    int                   num_trials;
    int                   correct_guesses;
    int                   wrong_guesses;
    double                success_rate;
    double                bias;          /* |success_rate - 0.5| */
    int                   is_hardcore;   /* bias < threshold? */
} hcp_experiment_t;

hcp_experiment_t* hcp_experiment_run(hardcore_predicate_t* hcp,
                                      owf_invert_fn adversary, void* adv_ctx,
                                      int num_trials);
void              hcp_experiment_free(hcp_experiment_t* exp);
void              hcp_experiment_print(const hcp_experiment_t* exp);

/*
 * Trivial predictor: always guesses 0 (or random).
 * Used as baseline for comparison.
 */
int trivial_constant_predictor(const bit_string_t* r, void* ctx);
int trivial_random_predictor(const bit_string_t* r, void* ctx);

/* ================================================================
 * Extended Hardcore Predicates
 * ================================================================ */

/*
 * General construction: from any hardcore predicate hc(x) for f,
 * and any OWF f, one can construct:
 *   - Multiple hardcore bits via independent inner products
 *   - Hardcore functions (output multiple unpredictable bits)
 */

/*
 * Compute k-bit hardcore function using GL:
 *   hc_k(x, r_1, ..., r_k) = (⟨x,r_1⟩, ..., ⟨x,r_k⟩) mod 2
 *
 * Theorem: If f is a OWF, then hc_k is a hardcore function
 * (k bits are simultaneously unpredictable).
 */
int gl_kbit_hardcore(const bit_string_t* x,
                     const bit_string_t** r_list, int k,
                     uint8_t* out_bits);

#endif /* OWF_HARDCORE_H */
