/*
 * list_decoding.h — Hadamard Code List Decoding
 *
 * Background:
 *   The Goldreich-Levin reduction inherently uses list decoding of the
 *   Hadamard code. The Hadamard code encodes a message x ∈ {0,1}^n as
 *   the 2^n-bit string (⟨x, r⟩)_{r∈{0,1}^n}. This is a [2^n, n, 2^{n-1}]
 *   linear code — the first-order Reed-Muller code RM(1, n).
 *
 * List Decoding (Goldreich-Levin):
 *   Given oracle access to a word w that agrees with the Hadamard encoding
 *   of x on ≥ 1/2 + ε fraction of positions, the Goldreich-Levin algorithm
 *   produces a list of poly(n, 1/ε) strings that includes x.
 *
 *   The algorithm works by:
 *   1. Sampling random strings r ∈ {0,1}^n
 *   2. For each r, using the self-correction property to estimate bits
 *   3. Constructing candidate x' using majority vote
 *
 * Walsh-Hadamard Transform:
 *   The true Hadamard code is the Walsh-Hadamard transform:
 *     H(x)[r] = (-1)^{⟨x,r⟩} ∈ {+1, -1}
 *   Equivalently, mapping +1 → 0, -1 → 1 gives the binary Hadamard code.
 *
 * Reference: Goldreich-Levin STOC 1989; Arora-Barak §19.4
 * Courses: MIT 6.875, Stanford CS255, CMU 15-859
 */

#ifndef LIST_DECODING_H
#define LIST_DECODING_H

#include "owf.h"

/* ── Hadamard Code Definition ────────────────────────────── */
typedef struct {
    size_t   n;            /* message length (bits) */
    size_t   code_len;     /* codeword length: 2^n */
    int      bipolar;      /* 0=binary encoding, 1=bipolar (+1/-1) */
} HadamardCode;

/* ── Codeword Type ───────────────────────────────────────── */
typedef struct {
    size_t   length;       /* length of codeword (2^n) */
    int*     symbols;      /* binary: 0/1, or bipolar: +1/-1 */
    size_t   n;            /* message length */
} HadamardCodeword;

/* ── List Decoding Result ────────────────────────────────── */
typedef struct {
    size_t      list_size;
    size_t      list_capacity;
    BitString** candidates;   /* list of candidate messages */
    double*     scores;       /* agreement scores for each candidate */
    double      epsilon;      /* advantage over 1/2 */
    size_t      queries;      /* number of queries used */
} ListDecodingResult;

/* ── Hadamard Code Operations ────────────────────────────── */
HadamardCode*    hadamard_create(size_t n);
void             hadamard_free(HadamardCode* code);
HadamardCodeword* hadamard_encode(const HadamardCode* code, const BitString* msg);
void             hadamard_codeword_free(HadamardCodeword* cw);
int              hadamard_decode_at(const HadamardCodeword* cw, const BitString* r);

/* ── Walsh-Hadamard Transform ────────────────────────────── */
/* Fast Walsh-Hadamard Transform (FWHT) — O(n·2^n) vs O(2^{2n}) naive */
void hadamard_transform(int* data, size_t n);
void hadamard_inverse_transform(int* data, size_t n);
void hadamard_transform_real(double* data, size_t n, int inverse);

/* ── List Decoding Algorithm (Goldreich-Levin) ───────────── */
/* Given oracle access to a noisy Hadamard codeword via a predictor,
 * recover a list of candidate messages.
 *
 * The oracle returns Pr[oracle(r) = ⟨x, r⟩] ≥ 1/2 + ε */
ListDecodingResult* hadamard_list_decode(
    int (*oracle)(const BitString* r, void* ctx),
    void* ctx,
    size_t n,
    double epsilon,
    size_t max_candidates);

/* Simplified: directly using predictor type */
ListDecodingResult* hadamard_list_decode_predictor(
    int (*predict)(const BitString* fx, const BitString* r, int* out, void* ctx),
    void* ctx,
    const BitString* fx,
    size_t n,
    double epsilon,
    size_t max_candidates);

/* ── List Decoding Result Management ─────────────────────── */
ListDecodingResult* list_decode_result_create(size_t max_candidates);
void                list_decode_result_free(ListDecodingResult* res);
int                 list_decode_result_add(ListDecodingResult* res,
                                            const BitString* candidate,
                                            double score);
void                list_decode_result_sort_by_score(ListDecodingResult* res);
BitString*          list_decode_result_best(const ListDecodingResult* res);
void                list_decode_result_print(const ListDecodingResult* res);

/* ── Checking and Verification ───────────────────────────── */
/* Check if x is in the candidate list */
int    list_contains(const ListDecodingResult* lst, const BitString* x);
/* Verify that the best candidate matches oracle on fraction of positions */
double list_verify_candidate(const BitString* candidate,
                              int (*oracle)(const BitString*, void*),
                              void* ctx, size_t n, size_t num_checks);

/* ── Self-Correction Property ────────────────────────────── */
/* The Hadamard code is self-correctable:
 * If we want ⟨x, r⟩ but only have noisy access, we can query at
 * random r' and r'⊕r, then XOR the results.
 *
 * Pr[oracle(r') ⊕ oracle(r'⊕r) = ⟨x, r⟩] ≥ 1/2 + 2ε^2 */
int    hadamard_self_correct(int (*oracle)(const BitString*, void*),
                              void* ctx, const BitString* r, size_t n,
                              size_t num_trials);

/* ── Fourier Analysis over Boolean Cube ──────────────────── */
/* For analysis: compute Fourier coefficient at position α
 *   f̂(α) = (1/2^n) Σ_{x∈{0,1}^n} f(x)(-1)^{⟨α,x⟩} */
double fourier_coefficient(const int* truth_table, size_t n, const BitString* alpha);
void   fourier_transform(const int* truth_table, size_t n, double* coefficients);

/* ── List Size Bounds ────────────────────────────────────── */
/* Johnson bound: list size ≤ 1/(1 - 2(1-δ)) = 1/(4ε^2) for δ=1/2+ε */
size_t hadamard_list_size_bound(double epsilon);
/* Actual GL list size: O(n/ε^2) */
size_t gl_list_size_bound(size_t n, double epsilon);

/* ── Hadamard Code Properties ────────────────────────────── */
/* Minimum distance: 2^{n-1} (relative distance 1/2) */
double hadamard_min_distance(size_t n);
/* Rate: log(2^n) / 2^n = n / 2^n */
double hadamard_rate(size_t n);
/* Check if codeword is valid Hadamard encoding */
int    hadamard_is_codeword(const HadamardCodeword* cw);

#endif /* LIST_DECODING_H */
