/*
 * owf.h — One-Way Functions: Definitions & Candidate Constructions
 *
 * Formal Definition (L1, L3):
 *   A function f: {0,1}* → {0,1}* is a one-way function (OWF) if:
 *   (1) Easy to compute: ∃ PPT algorithm A such that ∀x, A(x) = f(x)
 *   (2) Hard to invert: ∀ PPT algorithm A', ∀ polynomial p(·),
 *       Pr[A'(f(x), 1^n) ∈ f^{-1}(f(x))] < 1/p(n)
 *       for all sufficiently large n, where x ← {0,1}^n
 *
 *   A collection of OWFs is a family {f_i: D_i → R_i} with PPT Gen, Sample,
 *   Eval, where inversion is hard given only Eval output.
 *
 * Strong vs Weak OWF:
 *   Strong: ∀ PPT A, Pr[A inverts] ≤ negl(n)
 *   Weak: ∃ poly q(n) such that ∀ PPT A, Pr[A inverts] ≤ 1 - 1/q(n)
 *
 * Theorem (Yao 1982): Weak OWF ⇒ Strong OWF via parallel repetition.
 *
 * Candidate OWFs:
 *   - Integer factorization: f_mult(p,q) = p·q
 *   - Modular exponentiation (discrete log): f_exp(g, x) = g^x mod p
 *   - RSA function: f_RSA(N, e, x) = x^e mod N
 *   - Subset sum (knapsack): f_subset(a_1,...,a_n, S) = (a_1,...,a_n, Σ_{i∈S} a_i)
 *
 * Reference: Arora-Barak §9.1-9.2, Goldreich Vol.1 §2.1-2.4
 * Courses: MIT 6.875, Stanford CS255, Princeton COS 551
 */

#ifndef OWF_H
#define OWF_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* ── Bit String Type ─────────────────────────────────────── */
typedef struct {
    uint64_t* data;
    size_t    n_bits;
    size_t    n_words;
} BitString;

/* ── Security Parameter ──────────────────────────────────── */
typedef struct {
    size_t lambda;
    double negl_eps;
} SecParam;

/* ── OWF Domain and Range Types ──────────────────────────── */
typedef struct {
    BitString* input;
    BitString* output;
    size_t     n_in;
    size_t     n_out;
} OWFInstance;

/* ── OWF Candidate Type ──────────────────────────────────── */
typedef enum {
    OWF_MULTIPLICATION = 0,
    OWF_MODULAR_EXP   = 1,
    OWF_RSA           = 2,
    OWF_SUBSET_SUM    = 3,
    OWF_SQUARING      = 4,
    OWF_CUSTOM        = 5
} OWFType;

typedef struct {
    OWFType type;
    char*   name;
    char*   description;
    size_t  input_bits;
    size_t  output_bits;
    int (*eval)(const BitString* in, BitString* out, void* params);
    void*   params;
    size_t  params_size;
} OWF;

/* ── Inversion Attempt Result ────────────────────────────── */
typedef struct {
    BitString* preimage;
    int        success;
    double     time_seconds;
    size_t     queries;
} InversionResult;

/* ── BitString Construction ──────────────────────────────── */
BitString* bs_create(size_t n_bits);
BitString* bs_create_from_bytes(const uint8_t* bytes, size_t n_bytes);
BitString* bs_create_random(size_t n_bits);
BitString* bs_clone(const BitString* bs);
void       bs_free(BitString* bs);
void       bs_set_bit(BitString* bs, size_t pos, int value);
int        bs_get_bit(const BitString* bs, size_t pos);
void       bs_set_all(BitString* bs, int value);
void       bs_xor(BitString* dst, const BitString* a, const BitString* b);
void       bs_and(BitString* dst, const BitString* a, const BitString* b);
int        bs_equal(const BitString* a, const BitString* b);
void       bs_print(const BitString* bs);
void       bs_print_hex(const BitString* bs);
size_t     bs_popcount(const BitString* bs);
int        bs_is_zero(const BitString* bs);

/* ── OWF Construction and Management ─────────────────────── */
OWF* owf_create(OWFType type, size_t input_bits);
void owf_free(OWF* owf);
int  owf_eval(const OWF* owf, const BitString* input, BitString* output);
int  owf_validate(const OWF* owf);

/* ── Candidate OWF Implementations ───────────────────────── */
OWF* owf_create_mult(size_t n_bits);
int  owf_eval_mult(const BitString* in, BitString* out, void* params);

OWF* owf_create_modexp(size_t n_bits);
int  owf_eval_modexp(const BitString* in, BitString* out, void* params);

OWF* owf_create_rsa(size_t n_bits);
int  owf_eval_rsa(const BitString* in, BitString* out, void* params);

OWF* owf_create_subset_sum(size_t n_bits);
int  owf_eval_subset_sum(const BitString* in, BitString* out, void* params);

OWF* owf_create_squaring(size_t n_bits);
int  owf_eval_squaring(const BitString* in, BitString* out, void* params);

/* ── Weak vs Strong OWF ──────────────────────────────────── */
BitString* owf_parallel_repeat(const OWF* owf, const BitString* input, int k);
double     owf_inversion_probability(const OWF* owf, int num_trials);
int        owf_is_weak_to_strong_reduction(const OWF* weak_owf, int k,
                                           OWF** strong_owf_out);

/* ── Inversion (for testing/benchmarking) ─────────────────── */
InversionResult* owf_invert_bruteforce(const OWF* owf, const BitString* output,
                                        double timeout_seconds);
InversionResult* owf_invert_with_oracle(const OWF* owf, const BitString* output,
                                         int (*oracle)(const BitString*, int*));
void             inversion_result_free(InversionResult* res);

/* ── Security Analysis ───────────────────────────────────── */
double owf_estimate_hardness(const OWF* owf);
int    owf_verify_oneway_property(const OWF* owf, int num_samples);

/* ── BitString Arithmetic (for OWF implementations) ──────── */
void   bs_add(BitString* result, const BitString* a, const BitString* b);
void   bs_sub(BitString* result, const BitString* a, const BitString* b);
void   bs_mul(BitString* result, const BitString* a, const BitString* b);
void   bs_div(BitString* quotient, BitString* remainder,
              const BitString* a, const BitString* b);
void   bs_mod(BitString* result, const BitString* a, const BitString* modulus);
void   bs_mod_exp(BitString* result, const BitString* base,
                  const BitString* exp, const BitString* modulus);
void   bs_gcd(BitString* result, const BitString* a, const BitString* b);
int    bs_is_prime(const BitString* n, int num_rounds);
void   bs_rand_prime(BitString* result, size_t n_bits);

#endif /* OWF_H */
