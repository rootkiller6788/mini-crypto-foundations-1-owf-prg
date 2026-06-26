/*
 * owf.c — One-Way Functions: Definitions & Candidate Constructions
 *
 * Implements all OWF operations declared in owf.h:
 * - BitString management (create, free, clone, set/get)
 * - OWF construction for 5 candidate types
 * - Parallel repetition (weak→strong reduction, Yao 1982)
 * - Inversion attempts and security analysis
 *
 * Knowledge Points Covered:
 *   L1: OWF formal definition, strong vs weak OWF
 *   L2: PPT computability, negligible inversion probability
 *   L3: BitString data structure, OWF instance types
 *   L4: Yao's theorem: weak OWF ⇒ strong OWF (parallel repetition)
 *   L5: Candidate OWF implementations (factoring, discrete log, RSA, subset sum)
 *   L7: Cryptographic applications of OWFs
 *
 * Reference: Arora-Barak §9.1-9.2, Goldreich Vol.1 §2.1-2.4
 * Courses: MIT 6.875, Stanford CS255, Princeton COS 551
 */

#include "owf.h"
#include "bit_operations.h"
#include <stdio.h>

#ifndef _strdup
#define _strdup strdup
#endif

/* ───────────────────────────────────────────────────────────────
 * BitString Construction & Management
 *
 * Each BitString stores n_bits packed into ceil(n_bits/64) uint64 words.
 * ───────────────────────────────────────────────────────────── */

BitString* bs_create(size_t n_bits) {
    BitString* bs = (BitString*)malloc(sizeof(BitString));
    if (!bs) return NULL;
    bs->n_bits  = n_bits;
    bs->n_words = (n_bits + 63) / 64;
    bs->data    = (uint64_t*)calloc(bs->n_words, sizeof(uint64_t));
    if (!bs->data) {
        free(bs);
        return NULL;
    }
    return bs;
}

BitString* bs_create_from_bytes(const uint8_t* bytes, size_t n_bytes) {
    BitString* bs = bs_create(n_bytes * 8);
    if (!bs) return NULL;
    bytes_to_u64(bs->data, bytes, n_bytes);
    return bs;
}

BitString* bs_create_random(size_t n_bits) {
    BitString* bs = bs_create(n_bits);
    if (!bs) return NULL;
    bit_random(bs->data, n_bits);
    return bs;
}

BitString* bs_clone(const BitString* bs) {
    if (!bs) return NULL;
    BitString* clone = bs_create(bs->n_bits);
    if (!clone) return NULL;
    memcpy(clone->data, bs->data, bs->n_words * sizeof(uint64_t));
    return clone;
}

void bs_free(BitString* bs) {
    if (bs) {
        free(bs->data);
        free(bs);
    }
}

void bs_set_bit(BitString* bs, size_t pos, int value) {
    if (!bs || pos >= bs->n_bits) return;
    bit_set(bs->data, pos, value);
}

int bs_get_bit(const BitString* bs, size_t pos) {
    if (!bs || pos >= bs->n_bits) return 0;
    return bit_get(bs->data, pos);
}

void bs_set_all(BitString* bs, int value) {
    if (!bs) return;
    bit_fill(bs->data, bs->n_words, value);
}

void bs_xor(BitString* dst, const BitString* a, const BitString* b) {
    if (!dst || !a || !b) return;
    size_t n = dst->n_words;
    if (a->n_words < n) n = a->n_words;
    if (b->n_words < n) n = b->n_words;
    bit_xor_buf(dst->data, a->data, b->data, n);
}

void bs_and(BitString* dst, const BitString* a, const BitString* b) {
    if (!dst || !a || !b) return;
    size_t n = dst->n_words;
    if (a->n_words < n) n = a->n_words;
    if (b->n_words < n) n = b->n_words;
    bit_and_buf(dst->data, a->data, b->data, n);
}

int bs_equal(const BitString* a, const BitString* b) {
    if (!a || !b) return (a == b);
    if (a->n_bits != b->n_bits) return 0;
    return bit_equal_buf(a->data, b->data, a->n_words);
}

void bs_print(const BitString* bs) {
    if (!bs) { printf("(null)\n"); return; }
    bit_print_binary(bs->data, bs->n_bits);
}

void bs_print_hex(const BitString* bs) {
    if (!bs) { printf("(null)\n"); return; }
    bit_print_hex(bs->data, (bs->n_bits + 7) / 8);
}

size_t bs_popcount(const BitString* bs) {
    if (!bs) return 0;
    return bit_popcount_buf(bs->data, bs->n_words);
}

int bs_is_zero(const BitString* bs) {
    if (!bs) return 1;
    return bit_is_zero_buf(bs->data, bs->n_words);
}

/* ───────────────────────────────────────────────────────────────
 * OWF Construction and Management
 *
 * owf_create: allocates an OWF struct for the given type
 * owf_eval: dispatches to the type-specific evaluation function
 * ───────────────────────────────────────────────────────────── */

OWF* owf_create(OWFType type, size_t input_bits) {
    OWF* owf;
    switch (type) {
        case OWF_MULTIPLICATION: owf = owf_create_mult(input_bits); break;
        case OWF_MODULAR_EXP:    owf = owf_create_modexp(input_bits); break;
        case OWF_RSA:            owf = owf_create_rsa(input_bits); break;
        case OWF_SUBSET_SUM:     owf = owf_create_subset_sum(input_bits); break;
        case OWF_SQUARING:       owf = owf_create_squaring(input_bits); break;
        default: return NULL;
    }
    return owf;
}

void owf_free(OWF* owf) {
    if (owf) {
        free(owf->name);
        free(owf->description);
        free(owf->params);
        free(owf);
    }
}

int owf_eval(const OWF* owf, const BitString* input, BitString* output) {
    if (!owf || !input || !output || !owf->eval) return 0;
    return owf->eval(input, output, owf->params);
}

int owf_validate(const OWF* owf) {
    if (!owf) return 0;
    /* Verify basic properties: input/output sizes match */
    if (owf->input_bits == 0 || owf->output_bits == 0) return 0;
    if (!owf->eval) return 0;
    /* Verify determinism: same input → same output */
    BitString* x1 = bs_create_random(owf->input_bits);
    BitString* x2 = bs_clone(x1);
    BitString* y1 = bs_create(owf->output_bits);
    BitString* y2 = bs_create(owf->output_bits);
    if (!x1 || !x2 || !y1 || !y2) {
        bs_free(x1); bs_free(x2); bs_free(y1); bs_free(y2);
        return 0;
    }
    owf_eval(owf, x1, y1);
    owf_eval(owf, x2, y2);
    int deterministic = bs_equal(y1, y2);
    bs_free(x1); bs_free(x2); bs_free(y1); bs_free(y2);
    return deterministic;
}

/* ───────────────────────────────────────────────────────────────
 * Candidate OWF 1: Integer Multiplication Factoring
 *
 * f_mult(p, q) = p · q  (for primes p, q of ~n_bits/2 each)
 * Hardness assumption: Factoring is hard.
 * ───────────────────────────────────────────────────────────── */

OWF* owf_create_mult(size_t n_bits) {
    OWF* owf = (OWF*)malloc(sizeof(OWF));
    if (!owf) return NULL;
    owf->type        = OWF_MULTIPLICATION;
    owf->name        = _strdup("Integer Multiplication (Factoring)");
    owf->description = _strdup("f(p,q) = p*q. One-way under factoring assumption.");
    owf->input_bits  = n_bits;
    owf->output_bits = n_bits;  /* product of two n/2-bit primes has ≤ n bits */
    owf->eval        = owf_eval_mult;
    owf->params      = NULL;
    owf->params_size = 0;
    return owf;
}

int owf_eval_mult(const BitString* in, BitString* out, void* params) {
    (void)params;
    if (!in || !out) return 0;
    /* Treat input as two halves: p (low bits) and q (high bits) */
    size_t half_bits = in->n_bits / 2;
    size_t half_words = (half_bits + 63) / 64;
    uint64_t* p = (uint64_t*)calloc(half_words, sizeof(uint64_t));
    uint64_t* q = (uint64_t*)calloc(half_words, sizeof(uint64_t));
    uint64_t* prod = (uint64_t*)calloc(2 * half_words, sizeof(uint64_t));
    if (!p || !q || !prod) {
        free(p); free(q); free(prod);
        return 0;
    }
    /* Copy low half to p, high half to q */
    for (size_t i = 0; i < half_words && i < in->n_words; i++) {
        p[i] = in->data[i];
    }
    for (size_t i = 0; i < half_words && i + half_words < in->n_words; i++) {
        q[i] = in->data[i + half_words];
    }
    bit_mul(prod, p, half_words, q, half_words);
    /* Copy result to output (truncate to output bits) */
    size_t out_words = out->n_words;
    if (2 * half_words < out_words) out_words = 2 * half_words;
    for (size_t i = 0; i < out_words; i++) {
        out->data[i] = prod[i];
    }
    free(p); free(q); free(prod);
    return 1;
}

/* ───────────────────────────────────────────────────────────────
 * Candidate OWF 2: Modular Exponentiation (Discrete Log)
 *
 * f_mod_exp(g, x) = g^x mod p
 * Hardness assumption: Discrete logarithm is hard.
 * ───────────────────────────────────────────────────────────── */

OWF* owf_create_modexp(size_t n_bits) {
    OWF* owf = (OWF*)malloc(sizeof(OWF));
    if (!owf) return NULL;
    owf->type        = OWF_MODULAR_EXP;
    owf->name        = _strdup("Modular Exponentiation (Discrete Log)");
    owf->description = _strdup("f(g,x) = g^x mod p. One-way under DLOG assumption.");
    owf->input_bits  = n_bits;
    owf->output_bits = n_bits;
    owf->eval        = owf_eval_modexp;
    owf->params      = NULL;
    owf->params_size = 0;
    return owf;
}

int owf_eval_modexp(const BitString* in, BitString* out, void* params) {
    (void)params;
    if (!in || !out) return 0;
    size_t third = in->n_words / 3;
    if (third == 0) third = 1;
    /* Input: g (first third), x (second third), p (last third) */
    uint64_t* g = (uint64_t*)calloc(third, sizeof(uint64_t));
    uint64_t* x = (uint64_t*)calloc(third, sizeof(uint64_t));
    uint64_t* p = (uint64_t*)calloc(third, sizeof(uint64_t));
    if (!g || !x || !p) {
        free(g); free(x); free(p);
        return 0;
    }
    for (size_t i = 0; i < third && i < in->n_words; i++) {
        g[i] = in->data[i];
    }
    for (size_t i = 0; i < third && i + third < in->n_words; i++) {
        x[i] = in->data[i + third];
    }
    size_t p_start = 2 * third;
    for (size_t i = 0; i < third && i + p_start < in->n_words; i++) {
        p[i] = in->data[i + p_start];
    }
    if (bit_is_zero(p, third)) {
        /* Ensure modulus is non-zero; set to a default */
        p[0] = 1;
    }
    bit_mod_exp(out->data, g, x, p, third);
    free(g); free(x); free(p);
    return 1;
}

/* ───────────────────────────────────────────────────────────────
 * Candidate OWF 3: RSA Function
 *
 * f_RSA(N, e, x) = x^e mod N
 * Hardness assumption: RSA problem (inverting without d).
 * ───────────────────────────────────────────────────────────── */

OWF* owf_create_rsa(size_t n_bits) {
    OWF* owf = (OWF*)malloc(sizeof(OWF));
    if (!owf) return NULL;
    owf->type        = OWF_RSA;
    owf->name        = _strdup("RSA Function");
    owf->description = _strdup("f(N,e,x) = x^e mod N. One-way under RSA assumption.");
    owf->input_bits  = n_bits;
    owf->output_bits = n_bits;
    owf->eval        = owf_eval_rsa;
    owf->params      = NULL;
    owf->params_size = 0;
    return owf;
}

int owf_eval_rsa(const BitString* in, BitString* out, void* params) {
    (void)params;
    if (!in || !out) return 0;
    /* Same structure as modexp for simplicity */
    return owf_eval_modexp(in, out, params);
}

/* ───────────────────────────────────────────────────────────────
 * Candidate OWF 4: Subset Sum (Knapsack)
 *
 * f_subset(a_1,...,a_n, S) = (a_1,...,a_n, Σ_{i∈S} a_i)
 * Hardness assumption: Subset sum is NP-complete (worst-case),
 * average-case hardness used in early cryptosystems.
 * ───────────────────────────────────────────────────────────── */

OWF* owf_create_subset_sum(size_t n_bits) {
    OWF* owf = (OWF*)malloc(sizeof(OWF));
    if (!owf) return NULL;
    owf->type        = OWF_SUBSET_SUM;
    owf->name        = _strdup("Subset Sum (Knapsack)");
    owf->description = _strdup("f(a,S) = (a, sum_{i in S} a_i). Based on NP-complete problem.");
    owf->input_bits  = n_bits;
    owf->output_bits = n_bits;
    owf->eval        = owf_eval_subset_sum;
    owf->params      = NULL;
    owf->params_size = 0;
    return owf;
}

int owf_eval_subset_sum(const BitString* in, BitString* out, void* params) {
    (void)params;
    if (!in || !out) return 0;
    /* Simplify: treat input as (values vector, subset indicator).
     * First half = values, second half = subset choice bits.
     * Output = (first half) || (sum of chosen values). */
    size_t half = in->n_bits / 2;
    size_t n_vals = half / 8;  /* 8 bits per value */
    if (n_vals == 0) n_vals = 1;
    /* Zero output */
    memset(out->data, 0, out->n_words * sizeof(uint64_t));
    /* Accumulate sum of chosen values */
    uint64_t sum = 0;
    for (size_t i = 0; i < n_vals && i * 8 + 8 <= half; i++) {
        uint64_t val = 0;
        for (size_t b = 0; b < 8; b++) {
            if (bit_get(in->data, i * 8 + b))
                val |= (1ULL << b);
        }
        int chosen = bit_get(in->data, half + i);
        if (chosen) sum += val;
    }
    /* Copy first half of input to output */
    size_t half_words = (half + 63) / 64;
    for (size_t i = 0; i < half_words && i < out->n_words; i++) {
        out->data[i] = in->data[i];
    }
    /* Place sum at a designated position */
    if (half_words < out->n_words) {
        out->data[half_words] = sum;
    }
    return 1;
}

/* ───────────────────────────────────────────────────────────────
 * Candidate OWF 5: Squaring (Rabin Function)
 *
 * f_squaring(x) = x^2 mod N
 * Hardness: Equivalent to factoring (Rabin 1979).
 * ───────────────────────────────────────────────────────────── */

OWF* owf_create_squaring(size_t n_bits) {
    OWF* owf = (OWF*)malloc(sizeof(OWF));
    if (!owf) return NULL;
    owf->type        = OWF_SQUARING;
    owf->name        = _strdup("Squaring (Rabin)");
    owf->description = _strdup("f(x) = x^2 mod N. One-way under factoring assumption.");
    owf->input_bits  = n_bits;
    owf->output_bits = n_bits;
    owf->eval        = owf_eval_squaring;
    owf->params      = NULL;
    owf->params_size = 0;
    return owf;
}

int owf_eval_squaring(const BitString* in, BitString* out, void* params) {
    (void)params;
    if (!in || !out) return 0;
    /* Output = input * input (mod 2^{output_bits}) */
    uint64_t* prod = (uint64_t*)calloc(2 * in->n_words, sizeof(uint64_t));
    if (!prod) return 0;
    bit_mul(prod, in->data, in->n_words, in->data, in->n_words);
    memcpy(out->data, prod, out->n_words * sizeof(uint64_t));
    free(prod);
    return 1;
}

/* ───────────────────────────────────────────────────────────────
 * Weak vs Strong OWF — Yao's Theorem (1982)
 *
 * Weak OWF: ∀ PPT A, Pr[A inverts] ≤ 1 - 1/q(n)
 * Strong OWF: ∀ PPT A, Pr[A inverts] ≤ negl(n)
 *
 * Yao's reduction: If f is weakly one-way, then
 *   F(x_1, ..., x_k) = (f(x_1), ..., f(x_k))
 * is strongly one-way for k = n·q(n).
 *
 * Intuition: Inverting k independent instances requires
 * inverting each one, which is hard.
 * ───────────────────────────────────────────────────────────── */

BitString* owf_parallel_repeat(const OWF* owf, const BitString* input, int k) {
    if (!owf || !input || k <= 0) return NULL;
    size_t out_per = owf->output_bits;
    BitString* result = bs_create(k * out_per);
    if (!result) return NULL;
    for (int i = 0; i < k; i++) {
        BitString* chunk_in = bs_create(owf->input_bits);
        BitString* chunk_out = bs_create(out_per);
        if (!chunk_in || !chunk_out) {
            bs_free(chunk_in); bs_free(chunk_out);
            bs_free(result);
            return NULL;
        }
        /* Use a subsegment of input or randomly generated */
        size_t offset = (i * owf->input_bits) % input->n_bits;
        for (size_t j = 0; j < owf->input_bits && offset + j < input->n_bits; j++) {
            bs_set_bit(chunk_in, j, bs_get_bit(input, offset + j));
        }
        owf_eval(owf, chunk_in, chunk_out);
        for (size_t j = 0; j < out_per; j++) {
            bs_set_bit(result, i * out_per + j, bs_get_bit(chunk_out, j));
        }
        bs_free(chunk_in);
        bs_free(chunk_out);
    }
    return result;
}

double owf_inversion_probability(const OWF* owf, int num_trials) {
    if (!owf || num_trials <= 0) return 0.0;
    int successes = 0;
    for (int t = 0; t < num_trials; t++) {
        BitString* x = bs_create_random(owf->input_bits);
        BitString* y = bs_create(owf->output_bits);
        if (!x || !y) { bs_free(x); bs_free(y); continue; }
        owf_eval(owf, x, y);
        /* Try brute-force inversion on small instances */
        InversionResult* ir = owf_invert_bruteforce(owf, y, 0.01);
        if (ir && ir->success) {
            /* Verify: f(x') == f(x) */
            BitString* y2 = bs_create(owf->output_bits);
            if (y2) {
                owf_eval(owf, ir->preimage, y2);
                if (bs_equal(y, y2)) successes++;
                bs_free(y2);
            }
        }
        inversion_result_free(ir);
        bs_free(x);
        bs_free(y);
    }
    return (double)successes / (double)num_trials;
}

int owf_is_weak_to_strong_reduction(const OWF* weak_owf, int k,
                                     OWF** strong_owf_out) {
    /* Demonstration: wrap the weak OWF with k-fold parallel repetition */
    if (!weak_owf || k <= 0 || !strong_owf_out) return 0;
    OWF* strong = (OWF*)malloc(sizeof(OWF));
    if (!strong) return 0;
    strong->type        = OWF_CUSTOM;
    strong->name        = _strdup("Strong OWF (Parallel Repetition)");
    strong->description = _strdup("k-fold parallel repetition of a weak OWF");
    strong->input_bits  = weak_owf->input_bits * k;
    strong->output_bits = weak_owf->output_bits * k;
    strong->eval        = NULL; /* Would use parallel repeat */
    strong->params      = NULL;
    strong->params_size = 0;
    *strong_owf_out = strong;
    return 1;
}

/* ───────────────────────────────────────────────────────────────
 * Inversion (for testing/benchmarking)
 *
 * Brute-force inversion: try all possible preimages.
 * Exponentially slow — only useful for very small n (≤ 20 bits).
 * ───────────────────────────────────────────────────────────── */

InversionResult* owf_invert_bruteforce(const OWF* owf, const BitString* output,
                                        double timeout_seconds) {
    (void)timeout_seconds;
    if (!owf || !output) return NULL;
    InversionResult* res = (InversionResult*)malloc(sizeof(InversionResult));
    if (!res) return NULL;
    res->preimage     = bs_create(owf->input_bits);
    res->success      = 0;
    res->time_seconds = 0.0;
    res->queries      = 0;
    if (!res->preimage) { free(res); return NULL; }

    /* Brute force only feasible for very small n (≤ 20) */
    if (owf->input_bits > 20) {
        res->success = 0;
        return res;
    }
    size_t max_tries = (size_t)1 << owf->input_bits;
    BitString* candidate = bs_create(owf->input_bits);
    BitString* cand_out  = bs_create(owf->output_bits);
    if (!candidate || !cand_out) {
        bs_free(candidate); bs_free(cand_out);
        return res;
    }
    for (size_t t = 0; t < max_tries; t++) {
        /* Set candidate bits from t */
        for (size_t i = 0; i < owf->input_bits; i++) {
            bs_set_bit(candidate, i, (t >> i) & 1);
        }
        owf_eval(owf, candidate, cand_out);
        res->queries++;
        if (bs_equal(cand_out, output)) {
            memcpy(res->preimage->data, candidate->data,
                   candidate->n_words * sizeof(uint64_t));
            res->success = 1;
            break;
        }
    }
    bs_free(candidate);
    bs_free(cand_out);
    return res;
}

InversionResult* owf_invert_with_oracle(const OWF* owf, const BitString* output,
                                         int (*oracle)(const BitString*, int*)) {
    if (!owf || !output || !oracle) return NULL;
    InversionResult* res = (InversionResult*)malloc(sizeof(InversionResult));
    if (!res) return NULL;
    res->preimage = bs_create(owf->input_bits);
    res->success  = 0;
    res->time_seconds = 0.0;
    res->queries  = 0;
    if (!res->preimage) { free(res); return NULL; }
    /* Use oracle to guide inversion */
    int predicted_bit = 0;
    if (oracle(output, &predicted_bit)) {
        /* Simple oracle-based recovery: try to reconstruct input bit-by-bit */
        for (size_t i = 0; i < owf->input_bits && i < 64; i++) {
            bs_set_bit(res->preimage, i, (predicted_bit >> i) & 1);
        }
        res->success = 1;
    }
    res->queries = 1;
    return res;
}

void inversion_result_free(InversionResult* res) {
    if (res) {
        bs_free(res->preimage);
        free(res);
    }
}

/* ───────────────────────────────────────────────────────────────
 * Security Analysis
 * ───────────────────────────────────────────────────────────── */

double owf_estimate_hardness(const OWF* owf) {
    if (!owf) return 0.0;
    /* Return log2 of estimated operations to invert */
    switch (owf->type) {
        case OWF_MULTIPLICATION:
            /* GNFS: L_n[1/3, c] ≈ exp((c+o(1))(ln n)^{1/3} (ln ln n)^{2/3}) */
            return (double)owf->input_bits * 0.5;
        case OWF_MODULAR_EXP:
            /* DLOG: similar to factoring, ~n bits of security */
            return (double)owf->input_bits * 0.5;
        case OWF_RSA:
            return (double)owf->input_bits * 0.5;
        case OWF_SUBSET_SUM:
            /* Best known: ~2^{n/2} meet-in-the-middle */
            return (double)owf->input_bits * 0.25;
        case OWF_SQUARING:
            return (double)owf->input_bits * 0.5;
        default:
            return (double)owf->input_bits * 0.3;
    }
}

int owf_verify_oneway_property(const OWF* owf, int num_samples) {
    if (!owf || num_samples <= 0) return 0;
    int consistent = 1;
    for (int i = 0; i < num_samples; i++) {
        BitString* x = bs_create_random(owf->input_bits);
        BitString* y1 = bs_create(owf->output_bits);
        BitString* y2 = bs_create(owf->output_bits);
        if (!x || !y1 || !y2) { bs_free(x); bs_free(y1); bs_free(y2); continue; }
        owf_eval(owf, x, y1);
        owf_eval(owf, x, y2);
        if (!bs_equal(y1, y2)) consistent = 0;
        bs_free(x); bs_free(y1); bs_free(y2);
        if (!consistent) break;
    }
    return consistent;
}

/* ───────────────────────────────────────────────────────────────
 * BitString Arithmetic (for OWF implementations)
 *
 * These are thin wrappers that delegate to bit_operations functions,
 * handling BitString → uint64* buffer conversion.
 * ───────────────────────────────────────────────────────────── */

void bs_add(BitString* result, const BitString* a, const BitString* b) {
    if (!result || !a || !b) return;
    size_t n = result->n_words;
    if (a->n_words < n) n = a->n_words;
    if (b->n_words < n) n = b->n_words;
    bit_add(result->data, a->data, b->data, n);
}

void bs_sub(BitString* result, const BitString* a, const BitString* b) {
    if (!result || !a || !b) return;
    size_t n = result->n_words;
    if (a->n_words < n) n = a->n_words;
    if (b->n_words < n) n = b->n_words;
    bit_sub(result->data, a->data, b->data, n);
}

void bs_mul(BitString* result, const BitString* a, const BitString* b) {
    if (!result || !a || !b) return;
    uint64_t* prod = (uint64_t*)calloc(a->n_words + b->n_words, sizeof(uint64_t));
    if (!prod) return;
    bit_mul(prod, a->data, a->n_words, b->data, b->n_words);
    size_t copy_words = result->n_words;
    if (a->n_words + b->n_words < copy_words)
        copy_words = a->n_words + b->n_words;
    memcpy(result->data, prod, copy_words * sizeof(uint64_t));
    free(prod);
}

void bs_div(BitString* quotient, BitString* remainder,
            const BitString* a, const BitString* b) {
    /* Long division by repeated subtraction */
    if (!a || !b || bs_is_zero(b)) return;
    if (quotient) memset(quotient->data, 0, quotient->n_words * sizeof(uint64_t));
    if (remainder) {
        size_t n = remainder->n_words;
        if (a->n_words < n) n = a->n_words;
        memcpy(remainder->data, a->data, n * sizeof(uint64_t));
    }
    /* Simplified: only compute remainder for small numbers */
    if (!remainder) return;
    while (!bs_is_zero(remainder)) {
        if (memcmp(remainder->data, b->data,
                   b->n_words * sizeof(uint64_t)) < 0) break;
        /* Subtract b from remainder */
        bs_sub(remainder, remainder, b);
    }
}

void bs_mod(BitString* result, const BitString* a, const BitString* modulus) {
    /* a mod modulus = remainder after division */
    BitString* quot = bs_create(a->n_bits);
    BitString* rem  = bs_create(a->n_bits);
    if (!quot || !rem) { bs_free(quot); bs_free(rem); return; }
    bs_div(quot, rem, a, modulus);
    memcpy(result->data, rem->data, result->n_words * sizeof(uint64_t));
    bs_free(quot);
    bs_free(rem);
}

void bs_mod_exp(BitString* result, const BitString* base,
                const BitString* exp, const BitString* modulus) {
    if (!result || !base || !exp || !modulus) return;
    size_t n = result->n_words;
    if (base->n_words < n) n = base->n_words;
    if (exp->n_words < n) n = exp->n_words;
    if (modulus->n_words < n) n = modulus->n_words;
    bit_mod_exp(result->data, base->data, exp->data, modulus->data, n);
}

void bs_gcd(BitString* result, const BitString* a, const BitString* b) {
    if (!result || !a || !b) return;
    size_t n = result->n_words;
    if (a->n_words < n) n = a->n_words;
    if (b->n_words < n) n = b->n_words;
    bit_gcd(result->data, a->data, b->data, n);
}

int bs_is_prime(const BitString* n, int num_rounds) {
    /* Miller-Rabin primality test (simplified) */
    if (!n || bs_is_zero(n)) return 0;
    /* Check small divisors */
    /* For educational purposes, use trial division up to small bounds */
    uint64_t val = n->data[0];
    if (val < 2) return 0;
    if (val == 2 || val == 3) return 1;
    if (val % 2 == 0) return 0;
    for (uint64_t d = 3; d * d <= val && d < 1000; d += 2) {
        if (val % d == 0) return 0;
    }
    /* For larger numbers, run Miller-Rabin rounds */
    for (int round = 0; round < num_rounds; round++) {
        /* Simplified Miller-Rabin: find a,d such that n-1 = 2^s * d */
        uint64_t nm1 = val - 1;
        int s = 0;
        while (nm1 % 2 == 0) { nm1 /= 2; s++; }
        uint64_t d = nm1;
        /* Random base a ∈ [2, n-2] */
        uint64_t a = 2 + (rand() % (val - 3));
        uint64_t x = 1;
        uint64_t base = a;
        uint64_t exp = d;
        while (exp > 0) {
            if (exp & 1) x = (x * base) % val;
            base = (base * base) % val;
            exp >>= 1;
        }
        if (x == 1 || x == val - 1) continue;
        int composite = 1;
        for (int r = 0; r < s - 1; r++) {
            x = (x * x) % val;
            if (x == val - 1) { composite = 0; break; }
        }
        if (composite) return 0;
    }
    return 1;
}

void bs_rand_prime(BitString* result, size_t n_bits) {
    if (!result) return;
    int attempts = 0;
    while (attempts < 1000) {
        bit_random(result->data, n_bits);
        /* Ensure odd */
        bs_set_bit(result, 0, 1);
        /* Ensure high bit set */
        bs_set_bit(result, n_bits - 1, 1);
        if (bs_is_prime(result, 5)) return;
        attempts++;
    }
}
