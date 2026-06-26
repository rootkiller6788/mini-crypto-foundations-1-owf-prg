/*
 * owf_core.h — Core Definitions for One-Way Functions
 *
 * L1 Definitions:
 *   A function f: {0,1}* → {0,1}* is a one-way function (OWF) if:
 *     (1) Easy to compute: ∃ poly-time algorithm E s.t. E(x) = f(x) ∀x
 *     (2) Hard to invert: ∀ PPT adversary A, ∀ positive polynomial p(·),
 *         ∃ N s.t. ∀ n > N: Pr[A(f(x), 1^n) ∈ f^{-1}(f(x))] < 1/p(n)
 *         where x ← {0,1}^n and probability is over x and A's randomness.
 *
 * L2 Core Concepts:
 *   - Security parameter (1^n): unary encoding, enforces polynomial runtime
 *   - Negligible function:  μ(n) = o(1/p(n)) for every polynomial p
 *   - Inversion experiment: formal game between challenger and adversary
 *   - Strong vs weak OWF: quantitative difference in inversion probability
 *
 * L3 Mathematical Structures:
 *   - Function families indexed by security parameter
 *   - Ensemble of distributions on inputs
 *   - PPT (Probabilistic Polynomial Time) formalization
 *
 * Reference:
 *   Goldreich, "Foundations of Cryptography" Vol 1, Section 2.1-2.4
 *   Katz-Lindell, "Introduction to Modern Cryptography" Chapter 7
 *   Arora-Barak, "Computational Complexity: A Modern Approach" Chapter 9
 *
 * Courses:
 *   MIT 6.875, Stanford CS255, Berkeley CS276, Princeton COS 433
 *   CMU 15-859, Caltech CS 157, Cambridge Part III Crypto,
 *   Oxford Advanced Security, ETH 263-4660
 */

#ifndef OWF_CORE_H
#define OWF_CORE_H

#include <stdint.h>
#include <stddef.h>

/* ================================================================
 * Security Parameter & Length Constants
 * ================================================================ */

/* Security parameter n (unary: 1^n).
 * In practice, this maps to key sizes: n ∈ {128, 192, 256, 512, 1024, 2048} */
typedef uint32_t sec_param_t;

#define SEC_PARAM_MIN     128
#define SEC_PARAM_STD     256
#define SEC_PARAM_HIGH    512

/* Input/output lengths for concrete OWF constructions */
#define OWF_MAX_INPUT_BYTES    4096
#define OWF_MAX_OUTPUT_BYTES   4096
#define OWF_MAX_KEY_BYTES      8192

/* ================================================================
 * Negligible Function
 * ================================================================ */

/*
 * μ: N → [0,1] is negligible if for every positive polynomial p(·),
 * ∃ N s.t. ∀ n > N: μ(n) < 1/p(n).
 *
 * Common negligible functions:
 *   μ(n) = 2^{-n},  μ(n) = 2^{-sqrt(n)},  μ(n) = n^{-log n}
 */
typedef double (*negligible_fn)(sec_param_t n);

/* Standard negligible functions */
double negligible_exponential(sec_param_t n);
double negligible_super_poly(sec_param_t n);
double negligible_neglog(sec_param_t n);

/* Check if a function value is "negligibly small" at security level n */
int is_negligible(double value, sec_param_t n);

/* ================================================================
 * OWF Input/Output Representation
 * ================================================================ */

/* Bit string of arbitrary length */
typedef struct {
    uint8_t* data;      /* buffer */
    size_t   bit_len;   /* length in bits */
    size_t   byte_cap;  /* allocated capacity */
} bit_string_t;

bit_string_t* bs_create(size_t bit_len);
bit_string_t* bs_from_bytes(const uint8_t* bytes, size_t byte_len);
bit_string_t* bs_random(size_t bit_len);
bit_string_t* bs_clone(const bit_string_t* bs);
void          bs_free(bit_string_t* bs);
int           bs_equal(const bit_string_t* a, const bit_string_t* b);
void          bs_print_hex(const bit_string_t* bs, const char* label);

/* ================================================================
 * One-Way Function Interface
 * ================================================================ */

/* Forward declaration */
typedef struct owf_scheme owf_scheme_t;

/*
 * OWF Evaluator: the "easy direction"
 *   eval(ctx, x, 1^n) → y = f(x)
 * Must run in poly(|x|, n) time.
 */
typedef int (*owf_eval_fn)(void* ctx, const bit_string_t* x,
                           sec_param_t n, bit_string_t** y);

/*
 * OWF Inverter (Adversary):
 *   invert(ctx, y, 1^n) → x' such that f(x') = y
 *
 * In the formal definition, this is a PPT algorithm.
 * We record its success probability empirically.
 */
typedef int (*owf_invert_fn)(void* ctx, const bit_string_t* y,
                             sec_param_t n, bit_string_t** x_prime);

/*
 * OWF Key Generator:
 *   keygen(1^n) → (pk, sk)  for trapdoor variants
 *   For plain OWFs, may return NULL for both.
 */
typedef int (*owf_keygen_fn)(void* ctx, sec_param_t n,
                             bit_string_t** pk, bit_string_t** sk);

/* ================================================================
 * OWF Scheme: complete description
 * ================================================================ */

/*
 * A one-way function scheme encapsulates:
 *   - The evaluation algorithm (easy direction)
 *   - The domain (input distribution)
 *   - The security parameter
 *   - Metadata: name, underlying assumption, expected hardness
 */
struct owf_scheme {
    char*           name;           /* e.g., "RSA-OWF", "DL-OWF" */
    char*           assumption;     /* e.g., "Factoring Assumption" */

    owf_keygen_fn   keygen;         /* key generation (may be NULL) */
    owf_eval_fn     eval;           /* f(x) evaluation */
    owf_invert_fn   invert;         /* best known inverter (for testing) */

    void*           ctx;            /* scheme-specific context */
    sec_param_t     sec_param;      /* current security parameter n */

    size_t          input_bits;     /* |x| for given n */
    size_t          output_bits;    /* |f(x)| for given n */

    /* Statistics */
    uint64_t        eval_count;     /* number of evaluations performed */
    uint64_t        invert_count;   /* number of inversion attempts */
    uint64_t        success_count;  /* number of successful inversions */
};

owf_scheme_t* owf_scheme_create(const char* name, const char* assumption,
                                owf_eval_fn eval, owf_invert_fn invert,
                                owf_keygen_fn keygen, void* ctx,
                                sec_param_t n, size_t in_bits, size_t out_bits);
void          owf_scheme_free(owf_scheme_t* owf);

/* Evaluate f(x) using the scheme */
int owf_evaluate(owf_scheme_t* owf, const bit_string_t* x, bit_string_t** y);

/* Attempt to invert: returns 1 if f(x') = y (successful inversion) */
int owf_attempt_invert(owf_scheme_t* owf, const bit_string_t* y,
                       bit_string_t** x_prime);

/* ================================================================
 * Inversion Experiment (formal security game)
 * ================================================================ */

/*
 * Invert_{A,f}(n) Game:
 *   1. Choose x ← {0,1}^n uniformly
 *   2. Compute y = f(x)
 *   3. A receives (y, 1^n) and outputs x'
 *   4. Experiment outputs 1 if f(x') = y, else 0
 */
typedef struct {
    owf_scheme_t*    owf;
    bit_string_t*    challenge_x;
    bit_string_t*    challenge_y;
    bit_string_t*    adversary_output;
    int              success;        /* 1 if f(x') = y */
    double           advantage;      /* Pr[success] - 1/2^{|x|} */
} invert_experiment_t;

invert_experiment_t* invert_experiment_run(owf_scheme_t* owf, owf_invert_fn A,
                                            void* adv_ctx, sec_param_t n);
void                 invert_experiment_free(invert_experiment_t* exp);
void                 invert_experiment_print(const invert_experiment_t* exp);

/* Run K independent inversion experiments and compute empirical advantage */
double invert_experiment_batch(owf_scheme_t* owf, owf_invert_fn A,
                               void* adv_ctx, sec_param_t n, int K,
                               double* avg_time_ms);

/* ================================================================
 * Strong vs Weak One-Way Functions
 * ================================================================ */

/*
 * Strong OWF: ∀ PPT A, Pr[A(f(x)) ∈ f^{-1}(f(x))] < negl(n)
 *
 * Weak OWF: ∃ polynomial q(·) such that ∀ PPT A,
 *            Pr[A(f(x)) ∉ f^{-1}(f(x))] > 1/q(n)
 *   i.e., A fails to invert with noticeable probability.
 *
 * Yao (1982): Weak OWF ⇒ Strong OWF via parallel repetition.
 */

typedef enum {
    OWF_TYPE_WEAK,
    OWF_TYPE_STRONG,
    OWF_TYPE_CANDIDATE_UNKNOWN
} owf_strength_t;

/* Estimate OWF strength from empirical inversion probability */
owf_strength_t owf_estimate_strength(double invert_prob, sec_param_t n,
                                      int num_samples);

/* ================================================================
 * OWF Family (collection of OWFs indexed by key)
 * ================================================================ */

/*
 * A family of one-way functions F = {f_k : D_k → R_k}_{k∈K}:
 *   - Key generation Gen(1^n) → k uniformly from K_n
 *   - Domain sampling Samp(k) → x uniformly from D_k
 *   - Evaluation f_k(x) → y
 *
 * Used for RSA, discrete-log based constructions.
 */
typedef struct {
    owf_scheme_t**  functions;
    size_t          count;
    size_t          capacity;
    sec_param_t     sec_param;
} owf_family_t;

owf_family_t* owf_family_create(sec_param_t n, size_t capacity);
void          owf_family_free(owf_family_t* family);
int           owf_family_add(owf_family_t* family, owf_scheme_t* owf);
owf_scheme_t* owf_family_sample(owf_family_t* family);

/* ================================================================
 * Utility: random bit string generation
 * ================================================================ */

/* Generate cryptographically random bytes (uses system CSPRNG) */
int random_bytes(uint8_t* buf, size_t len);

/* Generate a random integer in [0, max_val) */
uint64_t random_uint64_below(uint64_t max_val);

#endif /* OWF_CORE_H */
