/*
 * prg_construction.h -- PRG Constructions from One-Way Functions
 *
 * L4 Fundamental Theorems:
 *   OWP + Hardcore ? PRG (Yao 1982):
 *     Given OWP f: {0,1}^n ? {0,1}^n and hardcore predicate B,
 *     define G(s) = f(s) || B(s), giving stretch 1.
 *
 *   Iterated PRG (Blum-Micali / Yao):
 *     Given PRG G with stretch 1, iterate to get arbitrary stretch:
 *       G_k(s_0) = b_1 b_2 ... b_k
 *       where (s_i, b_i) = G(s_{i-1}) with f(s) as new seed, B(s) as output.
 *
 *   PRG from any OWF (HILL 1999, Hastad-Impagliazzo-Levin-Luby):
 *     If any one-way function exists, then a PRG exists.
 *     This is the most general result, but highly non-constructive.
 *
 * L5 Algorithms:
 *   Single-bit stretch PRG from OWP + hardcore
 *   Iterated PRG (composition to get larger stretch)
 *   Simplified PRG from specific OWPs
 *
 * Reference: Yao (1982), Goldreich (2001) Vol 1, Chapter 3
 *            HILL (1999), Goldreich-Levin (1989)
 *            Goldreich-Goldwasser-Micali (1986) ? GGM PRF from PRG
 *
 * Courses: MIT 6.876, Stanford CS255, Berkeley CS276, Princeton COS 551
 */

#ifndef PRG_CONSTRUCTION_H
#define PRG_CONSTRUCTION_H

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include "prg_crypto.h"
#include "hardcore_bit.h"

/* ================================================================
 * PRG from One-Way Permutation
 * ================================================================ */

/*
 * PRG_with_stretch_1: G(s) = (f(s), B(s))
 * Input:  s ? {0,1}^n
 * Output: G(s) ? {0,1}^{n+1}
 *
 * Given:
 *   - OWP f: {0,1}^n ? {0,1}^n (length-preserving permutation)
 *   - Hardcore predicate B: {0,1}^n ? {0,1} for f
 *
 * Security: If f is a OWP and B is hardcore for f, then G is a secure PRG.
 * Proof intuition: f(s) looks random (OWP), B(s) is unpredictable given f(s)
 * (hardcore), so f(s)||B(s) is indistinguishable from n+1 random bits.
 */
typedef struct {
    OWP* owp;                     /* one-way permutation */
    HardcorePredicate* hc;        /* hardcore predicate */
    size_t n;                     /* security parameter (bits) */
    size_t output_bits;           /* n + 1 */
} PRGFromOWP;

/* Create PRG from OWP + hardcore predicate */
PRGFromOWP* prg_owp_create(OWP* owp, HardcorePredicate* hc);

/* Initialize with seed s (n bits) */
int prg_owp_init(PRGFromOWP* prg, const uint8_t* seed, size_t seed_bytes);

/* Generate the next output (n+1 bits ? bytes) */
int prg_owp_next(PRGFromOWP* prg, uint8_t* output, size_t output_capacity);

/* Free PRG from OWP */
void prg_owp_free(PRGFromOWP* prg);

/* ================================================================
 * Iterated PRG (PRG Composition)
 * ================================================================ */

/*
 * Given a PRG G with stretch 1 (n ? n+1 bits), construct a PRG G_k
 * with stretch k (n ? n+k bits).
 *
 * Algorithm (Blum-Micali iteration):
 *   Input: seed s_0 ? {0,1}^n
 *   For i = 1 to k:
 *     (s_i, b_i) ? G(s_{i-1})   // s_i = first n bits, b_i = last bit
 *   Output: b_1 b_2 ... b_k
 *
 * The output b_1...b_k is pseudorandom if the underlying G is secure.
 * This is proven via the hybrid argument.
 *
 * This construction is also used in:
 *   - Blum-Micali: iterate g^x mod p, output MSB each step
 *   - Blum-Blum-Shub: iterate x^2 mod N, output LSB each step
 *   - GGM PRF: tree-based iteration for PRF construction
 */
typedef struct {
    PRGFromOWP* base_prg;         /* underlying PRG with stretch 1 */
    size_t n;                     /* security parameter */
    size_t k;                     /* total output bits (stretch) */
    size_t bits_emitted;          /* how many bits output so far */
    uint8_t* current_seed;        /* current s_i (n bits packed) */
} IteratedPRG;

/* Create iterated PRG from base PRG with stretch-1 */
IteratedPRG* iterated_prg_create(PRGFromOWP* base_prg, size_t k);

/* Initialize with seed */
int iterated_prg_init(IteratedPRG* iprg, const uint8_t* seed, size_t seed_bytes);

/* Generate next bit (0/1, or -1 on error) */
int iterated_prg_next_bit(IteratedPRG* iprg);

/* Generate next byte */
int iterated_prg_next_byte(IteratedPRG* iprg);

/* Generate n_bits of output */
size_t iterated_prg_generate_bits(IteratedPRG* iprg, uint8_t* buffer, size_t n_bits);

/* Free iterated PRG */
void iterated_prg_free(IteratedPRG* iprg);

/* ================================================================
 * PRG from General One-Way Function (Overview)
 * ================================================================ */

/*
 * HILL (1999) / HILL-Impaliazzo (1989):
 *   OWF exists ? PRG exists
 *
 * Construction outline:
 *   1. OWF f ? OWF f' that is "regular" (via hashing)
 *   2. GL hardcore bit ? PRG with stretch 1
 *   3. PRG stretch 1 ? PRG with arbitrary stretch (iteration)
 *
 * We do not implement the full HILL construction (which requires
 * pairwise independent hashing, leftover hash lemma, etc.)
 * but provide the conceptual structure and simplified versions.
 */

/*
 * Simplified: f'(x, h, r) = (f(x), h, r, h(x), ?x, r? mod 2)
 * where h is from a pairwise independent hash family.
 *
 * This is a building block toward the full HILL reduction.
 */
typedef struct {
    size_t n;                     /* security parameter */
    size_t m;                     /* OWF output length */
    size_t hash_key_bits;         /* description length of hash function */
    OWF* owf;                     /* underlying one-way function */
} PRGFromOWFOutline;

/* Create outline structure */
PRGFromOWFOutline* prg_owf_outline_create(OWF* owf);

/* Free outline */
void prg_owf_outline_free(PRGFromOWFOutline* outline);

/*
 * Pairwise independent hash function family H = {h_a: {0,1}^n ? {0,1}^m}
 * where h_a,b(x) = (a?x + b) mod p for prime p > 2^n.
 *
 * This is used in the HILL construction for entropy smoothing.
 */
typedef struct {
    uint64_t a;    /* multiplier (nonzero mod p) */
    uint64_t b;    /* additive constant */
    uint64_t p;    /* prime > 2^n */
} PairwiseHash;

/* Create a random pairwise independent hash function */
PairwiseHash pairwise_hash_create(uint64_t prime);

/* Evaluate h(x) = (a?x + b) mod p (mapping to bits) */
uint64_t pairwise_hash_eval(const PairwiseHash* h, uint64_t x);

/* ================================================================
 * PRG from Specific Assumptions (Concrete Constructions)
 * ================================================================ */

/*
 * We provide three concrete PRG constructions:
 *
 * 1. Blum-Micali PRG:  based on Discrete Log hardcore (MSB of g^x mod p)
 * 2. Blum-Blum-Shub PRG: based on Quadratic Residuosity (LSB of x^2 mod N)
 * 3. RSA-based PRG:     based on RSA hardcore (LSB of x^e mod N)
 *
 * Each is an instantiation of the iterated PRG pattern with a
 * specific OWP and hardcore predicate.
 */

/* Type enumeration for PRG construction */
typedef enum {
    PRG_TYPE_BLUM_MICALI,
    PRG_TYPE_BLUM_BLUM_SHUB,
    PRG_TYPE_OWP_GENERIC,
    PRG_TYPE_COUNT
} PRGConstructionType;

/* Get human-readable name for PRG type */
const char* prg_type_name(PRGConstructionType type);

/* ================================================================
 * PRG Output Quality Metrics
 * ================================================================ */

/*
 * Metrics for evaluating PRG output quality (for testing/demo).
 * Note: these are statistical tests only ? passing them does NOT
 * guarantee cryptographic security.
 */

/* Frequency (monobit) test: count 1's in bit sequence */
typedef struct {
    size_t n_bits;
    size_t n_ones;
    double frequency;        /* n_ones / n_bits */
    double p_value;          /* chi-squared p-value vs uniform */
} FrequencyTest;

/* Run frequency test on byte buffer */
FrequencyTest frequency_test_run(const uint8_t* data, size_t n_bytes);

/* Runs test: count runs of consecutive identical bits */
typedef struct {
    size_t n_runs;
    size_t n_bits;
    double expected_runs;    /* (2*n_ones*n_zeros)/n_bits + 1 */
    double p_value;
} RunsTest;

/* Run runs test on byte buffer */
RunsTest runs_test_run(const uint8_t* data, size_t n_bytes);

/* Serial correlation test */
typedef struct {
    size_t n_bits;
    double autocorrelation_lag1;
    double autocorrelation_lag2;
} SerialCorrelationTest;

/* Run serial correlation test */
SerialCorrelationTest serial_correlation_run(const uint8_t* data, size_t n_bytes);

/*
 * Diehard-like battery (simplified):
 * Runs frequency + runs + autocorrelation tests.
 * Returns 1 if all pass at ?=0.01 significance.
 */
int statistical_test_battery(const uint8_t* data, size_t n_bytes);

#endif /* PRG_CONSTRUCTION_H */
