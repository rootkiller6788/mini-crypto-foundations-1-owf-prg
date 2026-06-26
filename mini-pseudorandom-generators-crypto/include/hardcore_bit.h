/*
 * hardcore_bit.h -- Goldreich-Levin Hardcore Predicate
 *
 * L4 Fundamental Theorem:
 *   Goldreich-Levin (1989): If f: {0,1}^n ? {0,1}^* is a one-way function,
 *   then the predicate B(x, r) = ?x, r? mod 2 is hardcore for the
 *   function f'(x, r) = (f(x), r).
 *
 *   Formally: Let f be a OWF. Define g(x, r) = (f(x), r) where |x| = |r| = n.
 *   Then B(x,r) = ?_i x_i?r_i mod 2 is a hardcore predicate for g.
 *
 *   This is the foundational result showing that any OWF can be used
 *   to construct a PRG with stretch 1 (one extra pseudorandom bit).
 *
 * L3 Mathematical Structure:
 *   Inner product over GF(2): ?x, r? = ?_i (x_i ? r_i)
 *   This is a universal hash function from the pairwise independent family.
 *
 * L5 Algorithm:
 *   Inner product mod 2 computation
 *   List decoding: Given oracle access to g(x,r), recover x
 *   Goldreich-Levin inversion using Walsh-Hadamard transform
 *
 * Reference: Goldreich & Levin (1989) "A Hard-Core Predicate for All
 *            One-Way Functions", STOC 1989.
 *            Goldreich (2001) "Foundations of Cryptography", Vol 1, Ch 2.5
 *            H?stad, Impagliazzo, Levin, Luby (1999) ? extended hardcore
 *
 * Courses: MIT 6.876, Stanford CS255, Berkeley CS276, Princeton COS 551
 */

#ifndef HARDCORE_BIT_H
#define HARDCORE_BIT_H

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include "prg_crypto.h"

/* ================================================================
 * One-Way Function Interface
 * ================================================================ */

/*
 * A One-Way Function (OWF) f: {0,1}^n ? {0,1}^m is:
 *   1. Easy to compute: there is a PPT algorithm computing f(x)
 *   2. Hard to invert: for every PPT adversary A,
 *        Pr_{x?{0,1}^n}[A(1^n, f(x)) ? f^{-1}(f(x))] ? negl(n)
 */
typedef struct OWF OWF;
typedef int (*OWFEvalFunc)(const OWF* owf, const uint8_t* input,
                           size_t input_bits, uint8_t* output, size_t* output_bits);
typedef void (*OWFFreeFunc)(OWF* owf);

struct OWF {
    size_t input_bits;        /* n: input length */
    size_t output_bits;       /* m: output length */
    const char* name;          /* human-readable name */
    OWFEvalFunc eval;          /* evaluation function */
    void* param;               /* algorithm-specific parameters */
};

/* Create a OWF instance */
OWF* owf_create(size_t n, size_t m, const char* name,
                OWFEvalFunc eval, OWFFreeFunc free_func, void* param);

/* Evaluate OWF on input (input is n bits packed into bytes) */
int owf_evaluate(const OWF* owf, const uint8_t* input, size_t input_bytes,
                 uint8_t* output, size_t output_capacity, size_t* output_bytes);

/* Check if y is a valid output for some input (in image of f) */
int owf_is_in_image(const OWF* owf, const uint8_t* y, size_t y_bytes);

/* Free OWF */
void owf_free(OWF* owf);

/* ================================================================
 * One-Way Permutation (OWP)
 * ================================================================ */

/*
 * A One-Way Permutation is a OWF that is also a permutation
 * (bijection from {0,1}^n to {0,1}^n).
 *
 * OWPs are the simplest building block for PRG:
 *   Given OWP f with hardcore bit B, define:
 *   G(s) = f(s) || B(s)
 *   where G: {0,1}^n ? {0,1}^{n+1} has stretch 1.
 */
typedef struct OWP OWP;
typedef int (*OWPEvalFunc)(const OWP* owp, const uint8_t* input,
                           size_t input_bits, uint8_t* output);
typedef int (*OWPInvertFunc)(const OWP* owp, const uint8_t* image,
                             size_t input_bits, uint8_t* preimage);

struct OWP {
    OWF owf;                   /* inherited OWF */
    size_t domain_bits;        /* n: domain = {0,1}^n */
    OWPEvalFunc eval_perm;     /* permutation evaluation */
    OWPInvertFunc invert;      /* inversion (with trapdoor, not used for OWP hardness) */
};

/* Create an OWP instance */
OWP* owp_create(size_t n, const char* name,
                OWPEvalFunc eval_perm, void* param);

/* Evaluate permutation: output is n bits (packed into bytes) */
int owp_evaluate(const OWP* owp, const uint8_t* input, size_t input_bytes,
                 uint8_t* output, size_t output_capacity);

/* Free OWP */
void owp_free(OWP* owp);

/* ================================================================
 * Goldreich-Levin Hardcore Predicate
 * ================================================================ */

/*
 * GL Predicate: B(x, r) = ?x, r? mod 2 = (?_{i=0}^{n-1} x_i?r_i) mod 2
 *
 * Given OWF f: {0,1}^n ? {0,1}^*, define:
 *   g(x, r) = (f(x), r)  where |x| = |r| = n
 *   h(x, r) = B(x, r) = ?x, r? mod 2
 *
 * Then h is a hardcore predicate for g.
 */

/*
 * Compute the inner product mod 2 of two bit vectors.
 * x and r are packed into byte arrays, each of byte_len bytes
 * representing bit_len bits.
 */
int gl_inner_product(const uint8_t* x, const uint8_t* r,
                     size_t byte_len, size_t bit_len);

/*
 * GL Hardcore Bit structure: combines a OWF with the GL predicate.
 *
 *   HardcoreBit(x, r) = ?x, r? mod 2
 *
 * Given f(x) and r, predicting ?x, r? mod 2 is as hard as inverting f.
 */
typedef struct {
    OWF* owf;                  /* underlying one-way function */
    size_t n;                  /* security parameter: |x| = |r| = n */
    size_t total_input_bits;   /* 2n: |x| + |r| */
    size_t total_output_bits;  /* |f(x)| + n */
} GLHardcoreBit;

/* Create GL hardcore bit structure */
GLHardcoreBit* gl_create(OWF* owf, size_t n);

/* Compute (f(x), r) output */
int gl_compute_g(const GLHardcoreBit* gl, const uint8_t* x, const uint8_t* r,
                 size_t n_bytes, uint8_t* g_out, size_t* g_out_bytes);

/* Compute hardcore bit B(x,r) = inner product mod 2 */
int gl_compute_h(const GLHardcoreBit* gl, const uint8_t* x, const uint8_t* r,
                 size_t n_bytes);

/* Free GL structure */
void gl_free(GLHardcoreBit* gl);

/* ================================================================
 * Goldreich-Levin Inversion (List Decoding)
 * ================================================================ */

/*
 * The Goldreich-Levin theorem is proven constructively via list decoding:
 * given oracle access to a predictor that computes ?x,r? mod 2 with
 * advantage ?, we can recover x by querying on poly(n, 1/?) random r values
 * and solving a system of linear equations over GF(2).
 *
 * This implements the GL inversion algorithm as a proof-of-concept.
 */

/*
 * List of candidate preimages from GL inversion.
 * Each candidate is n_bits long, packed into bytes.
 */
typedef struct {
    size_t n_bits;
    size_t n_candidates;
    uint8_t** candidates;      /* array of candidate preimages */
    double* scores;            /* confidence score for each candidate */
} GLCandidateList;

/* Create candidate list */
GLCandidateList* gl_candidate_list_create(size_t n_bits, size_t max_candidates);

/* Add a candidate to the list */
int gl_candidate_list_add(GLCandidateList* list, const uint8_t* candidate,
                          size_t byte_len, double score);

/* Free candidate list */
void gl_candidate_list_free(GLCandidateList* list);

/*
 * GL List Decoding Algorithm:
 * Given f(x) and oracle access to B(x, r) = ?x, r? mod 2,
 * recover x by:
 *   1. Guess ? = O(log n) bits of x
 *   2. For each guess, query oracle on poly(n) random r's
 *   3. Majority vote to recover each remaining bit
 *   4. Output list of candidates
 *
 * The actual GL algorithm uses pairwise independence and
 * Walsh-Hadamard transform (list decoding of Hadamard code).
 *
 * This is a simplified implementation for educational purposes.
 */

/* GL list decode: given f(x) value, recover candidate list for x */
GLCandidateList* gl_list_decode(const GLHardcoreBit* gl,
                                const uint8_t* f_of_x, size_t f_bytes,
                                size_t list_size);

/* Verify which candidate matches the true x (given for testing) */
int gl_verify_candidate(const GLCandidateList* list,
                        const uint8_t* true_x, size_t byte_len);

/* ================================================================
 * Hardcore Predicate Abstraction
 * ================================================================ */

/*
 * Generic hardcore predicate interface.
 * A predicate B: {0,1}^n ? {0,1} is hardcore for function f if
 * predicting B(x) given f(x) is as hard as inverting f.
 */
typedef struct {
    const char* name;
    size_t n;                  /* input length */
    int (*predict)(const uint8_t* x, size_t byte_len);   /* compute B(x) */
    void* param;
} HardcorePredicate;

/* Create a hardcore predicate */
HardcorePredicate* hc_create(const char* name, size_t n,
                             int (*predict)(const uint8_t*, size_t),
                             void* param);

/* Evaluate hardcore predicate */
int hc_evaluate(const HardcorePredicate* hc, const uint8_t* x, size_t byte_len);

/* Free hardcore predicate */
void hc_free(HardcorePredicate* hc);

/* The GL predicate as a HardcorePredicate */
HardcorePredicate* hc_from_gl(const GLHardcoreBit* gl);

/* The LSB predicate (hardcore for RSA squaring) */
HardcorePredicate* hc_lsb_create(size_t n);

/* The MSB predicate (hardcore for discrete log) */
HardcorePredicate* hc_msb_create(size_t n);

#endif /* HARDCORE_BIT_H */
