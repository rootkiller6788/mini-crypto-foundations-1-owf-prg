/*
 * owf.h — One-Way Functions: Definitions and Constructions
 *
 * L1 Definition:
 *   A function f: {0,1}^* → {0,1}^* is one-way if:
 *   1. Easy to compute: there exists PPT algorithm A such that A(x) = f(x)
 *   2. Hard to invert: for every PPT adversary A, for every polynomial p,
 *      Pr[A(f(x), 1^n) ∈ f^{-1}(f(x))] < 1/p(n) for sufficiently large n
 *
 * L2 Core Concepts:
 *   - One-wayness: easy forward, hard backward
 *   - Security parameter: n (input length)
 *   - Negligible success probability
 *   - Candidate constructions (RSA, discrete log, factoring, subset sum)
 *   - Weak vs strong one-way functions (Yao's amplification)
 *
 * L3 Mathematical Structures:
 *   - GF(p) finite fields for RSA/discrete log candidates
 *   - Product groups Z_N* for factoring-based candidates
 *   - Binary strings over {0,1}^n
 *   - Function families indexed by security parameter
 *
 * Reference:
 *   Diffie & Hellman (1976) — New Directions in Cryptography
 *   Yao (1982) — Theory and Applications of Trapdoor Functions
 *   Goldreich (2001) — Foundations of Cryptography, Vol 1, Ch 2
 *   Arora & Barak (2009) — Computational Complexity, Ch 9
 *
 * Courses: MIT 6.875, Stanford CS255, Princeton COS 522, Berkeley CS276
 */

#ifndef OWF_H
#define OWF_H

#include <stdint.h>
#include <stddef.h>

/* ================================================================
 * L1: Core OWF Type Definition
 * ================================================================ */

/* Security parameter: key/input length in bits */
typedef int SecurityParam;

/* A bit string representing input/output of OWF */
typedef struct {
    uint8_t *data;          /* Byte buffer (MSB first per byte, MSB first overall) */
    size_t   bit_len;       /* Length in bits (not bytes!) */
} BitString;

/* OWF function handle */
typedef struct OWF OWF;
typedef int (*OWFEvalFunc)(const OWF *owf, const BitString *x, BitString *y);

/*
 * One-Way Function descriptor.
 * For candidate OWFs, this holds the function-specific parameters
 * (RSA modulus, group generator, etc.) and the evaluation function.
 */
struct OWF {
    SecurityParam n;
    OWFEvalFunc   eval;
    void         *params;
    char          name[64];
};

/* Create/destroy OWF instances */
OWF   *owf_create(SecurityParam n, OWFEvalFunc eval, void *params, const char *name);
void   owf_free(OWF *owf);
int    owf_eval(const OWF *owf, const BitString *x, BitString *y);

/* ================================================================
 * L1: Inversion Experiment
 * ================================================================ */

/*
 * OWF Inversion Experiment (Exp_{A,f}^{inv}(n)):
 *   1. Choose x ← {0,1}^n uniformly
 *   2. Compute y = f(x)
 *   3. Run A on (y, 1^n), get x'
 *   4. Output 1 if f(x') = y, else 0
 */
typedef struct {
    int   n_trials;
    int   n_successes;
    double success_probability;
} OWFInversionResult;

/* Adversary function pointer: given f(x), try to find preimage */
typedef int (*OWFAdversaryFunc)(const OWF *owf, const BitString *y, BitString *x_out);

/* Run the inversion experiment for a given OWF */
OWFInversionResult owf_inversion_experiment(const OWF *owf, int n_trials,
                                            OWFAdversaryFunc adversary);

/* ================================================================
 * L2: Candidate One-Way Functions
 * ================================================================ */

/*
 * Candidate 1: RSA Function
 *   f_{N,e}(x) = x^e mod N
 *   Inversion requires computing e-th roots mod N
 */
typedef struct {
    uint64_t N;
    uint64_t e;
    uint64_t phi;
    uint64_t d;
} RSAParams;

int   rsa_owf_eval(const OWF *owf, const BitString *x, BitString *y);
void *rsa_params_create(uint64_t p, uint64_t q, uint64_t e);

/*
 * Candidate 2: Discrete Logarithm
 *   f_{p,g}(x) = g^x mod p
 */
typedef struct {
    uint64_t p;
    uint64_t g;
    uint64_t order;
} DiscreteLogParams;

int   dlog_owf_eval(const OWF *owf, const BitString *x, BitString *y);
void *dlog_params_create(uint64_t p, uint64_t g);

/*
 * Candidate 3: Rabin Squaring Function
 *   f_N(x) = x^2 mod N  (N = p·q, Blum integer)
 *   Inversion is provably as hard as factoring
 */
typedef struct {
    uint64_t N;
    uint64_t p;
    uint64_t q;
} RabinParams;

int   rabin_owf_eval(const OWF *owf, const BitString *x, BitString *y);
void *rabin_params_create(uint64_t p, uint64_t q);

/*
 * Candidate 4: Subset Sum
 *   f_{a_1,...,a_n}(x_1,...,x_n) = Σ x_i · a_i
 *   Based on average-case hardness of random subset sum
 */
typedef struct {
    uint64_t *a;
    uint64_t  modulus;
    int       n;
} SubsetSumParams;

int   subset_sum_owf_eval(const OWF *owf, const BitString *x, BitString *y);
void *subsetsum_params_create(int n, const uint64_t *weights, uint64_t modulus);

/* ================================================================
 * L2: One-Way Function Properties
 * ================================================================ */

/* Check if f(x1) = f(x2) — collision detection */
int   owf_check_collision(const OWF *owf, const BitString *x1, const BitString *x2);

/* Iterate OWF: f^{(k)}(x) = f(f(...f(x)...)) */
int   owf_iterate(const OWF *owf, const BitString *x, int k, BitString *y);

/* Composition: (f∘g)(x) = f(g(x)) — preserves one-wayness */
int   owf_compose(const OWF *f, const OWF *g, const BitString *x, BitString *y);

/* ================================================================
 * L2: Weak vs Strong One-Way Functions (Yao's Amplification)
 * ================================================================ */

/*
 * Yao (1982): Weak OWF ⇒ Strong OWF
 * Construction: f'(x1,...,x_{q(n)}) = (f(x1), ..., f(x_{q(n)}))
 * where q(n) = n · p(n). Parallel repetition amplifies hardness.
 */
typedef struct {
    OWF  *base_owf;
    int   n_copies;
} YaoAmplification;

int   yao_amplify_owf_eval(const OWF *owf, const BitString *x, BitString *y);
void *yao_amplify_params_create(OWF *base_owf, int n_copies);

/* ================================================================
 * L7: BitString Utility Functions
 * ================================================================ */

BitString *bitstring_create(size_t bit_len);
void       bitstring_free(BitString *bs);
BitString *bitstring_clone(const BitString *bs);
void       bitstring_randomize(BitString *bs);
int        bitstring_equal(const BitString *a, const BitString *b);
void       bitstring_print(const BitString *bs, const char *label);
int        bitstring_to_uint64(const BitString *bs, uint64_t *out);
int        uint64_to_bitstring(uint64_t val, size_t bit_len, BitString *out);
void       bitstring_set_bit(BitString *bs, size_t pos, int value);
int        bitstring_get_bit(const BitString *bs, size_t pos);

#endif /* OWF_H */
