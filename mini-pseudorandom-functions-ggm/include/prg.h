/*
 * prg.h - Pseudorandom Generator (PRG) Definitions and Operations
 *
 * L1 Definition
 *   A pseudorandom generator is a deterministic polynomial-time algorithm G
 *   that stretches a short uniformly random seed s in {0,1}^n into a longer
 *   "pseudorandom" output G(s) in {0,1}^{l(n)} where l(n) > n.
 *
 *   Formally: G is a PRG if for every PPT distinguisher D,
 *       |Pr[D(G(U_n)) = 1] - Pr[D(U_{l(n)}) = 1]| <= negl(n)
 *
 * L3 Mathematical Structure
 *   G : {0,1}^n -> {0,1}^{l(n)} deterministic, polynomial-time
 *
 * Key Properties:
 *   - Expansion: l(n) > n (output longer than seed)
 *   - Pseudorandomness: computationally indistinguishable from uniform
 *   - Deterministic: G(s) always produces same output for same s
 *
 * Length-doubling PRG (crucial for GGM):
 *   G : {0,1}^n -> {0,1}^{2n}  -- maps n bits to 2n bits
 *
 * Reference:
 *   Blum, Micali (1984) -- first PRG from discrete log assumption
 *   Yao (1982) -- PRG definition, next-bit unpredictability
 *   Goldreich-Goldwasser-Micali (1986) -- PRG -> PRF
 *   Arora-Barak section 9.2.1 -- modern treatment
 *
 * Courses: Princeton COS 522, MIT 6.875, Stanford CS255
 */

#ifndef PRG_H
#define PRG_H

#include <stddef.h>
#include <stdint.h>

/* ================================================================
 * Bit-String Operations for Cryptographic Primitives
 * ================================================================ */

/*
 * BitString: A sequence of bits (0/1) stored as uint8_t array.
 * Used for cryptographic keys, seeds, and PRG outputs.
 */
typedef struct {
    uint8_t* bits;      /* bit data (packed, 8 bits per byte) */
    int      length;    /* number of meaningful bits */
    int      capacity;  /* allocated bytes */
} BitString;

/* Create/destroy bit strings */
BitString* bs_create(int length);
BitString* bs_create_random(int length, uint64_t seed);
BitString* bs_create_zeros(int length);
BitString* bs_clone(const BitString* src);
void       bs_free(BitString* bs);

/* Bit access */
int  bs_get_bit(const BitString* bs, int pos);
void bs_set_bit(BitString* bs, int pos, int value);

/* String comparison and utilities */
int  bs_equal(const BitString* a, const BitString* b);
int  bs_compare(const BitString* a, const BitString* b);
void bs_print(const BitString* bs);
void bs_print_bits(const BitString* bs);
void bs_copy_bits_to(const BitString* src, BitString* dst, int offset);

/* Concatenation and splitting */
BitString* bs_concat(const BitString* a, const BitString* b);
BitString* bs_prefix(const BitString* src, int n_bits);
BitString* bs_suffix(const BitString* src, int n_bits);
void       bs_split(const BitString* src, BitString** left, BitString** right);

/* ================================================================
 * PRG Definition (L1)
 * ================================================================ */

/*
 * PRG: maps n bits -> l(n) = n + s bits (s = stretch)
 * A PRG is length-doubling when l(n) = 2n.
 */
typedef struct PRG_impl PRG;

struct PRG_impl {
    int  seed_len;              /* n - input length in bits */
    int  output_len;            /* l(n) - output length in bits */
    int  stretch;               /* l(n) - n - additional pseudorandom bits */
    int  is_length_doubling;    /* 1 if output_len == 2*seed_len */

    /* PRG evaluation function (deterministic) */
    BitString* (*evaluate)(const PRG* prg, const BitString* seed);

    /* Internal state for specific implementations */
    void* state;
};

/* PRG lifecycle */
PRG* prg_create_length_doubling(int seed_len);
PRG* prg_create_general(int seed_len, int output_len);
void prg_free(PRG* prg);

/* Core evaluation: PRG(seed) -> output */
BitString* prg_evaluate(const PRG* prg, const BitString* seed);

/* Verify that PRG satisfies length property: |G(seed)| > |seed| */
int prg_is_expanding(const PRG* prg);

/* ================================================================
 * Length-doubling PRG Helpers for GGM
 * ================================================================ */

/*
 * For a length-doubling PRG G : {0,1}^n -> {0,1}^{2n},
 *   G(s) = G_0(s) || G_1(s)
 * G_0(s) = first n bits of G(s)     -- used when bit = 0 in GGM tree
 * G_1(s) = last n bits of G(s)      -- used when bit = 1 in GGM tree
 */

/* Evaluate left half: G_0(seed) - first n bits */
BitString* prg_evaluate_left(const PRG* prg, const BitString* seed);

/* Evaluate right half: G_1(seed) - last n bits */
BitString* prg_evaluate_right(const PRG* prg, const BitString* seed);

/*
 * Sequential walk: Given seed and input x (bit sequence),
 * walk the GGM tree depth-first. Returns the leaf value.
 * For length-doubling PRG G:
 *   F_k(x_1 x_2 ... x_m) = G_{x_m}(G_{x_{m-1}}(... G_{x_1}(k)...))
 */
BitString* prg_sequential_eval(const PRG* prg,
                                const BitString* seed,
                                const BitString* input_bits);

/* ================================================================
 * PRG Security Properties (L2)
 * ================================================================ */

/*
 * PRG Advantage: The maximum distinguishing advantage over all
 * PPT distinguishers.
 * Advantage eps(n) = max_D |Pr_{s<-{0,1}^n}[D(G(s)) = 1]
 *                          - Pr_{r<-{0,1}^{l(n)}}[D(r) = 1]|
 */
typedef struct {
    double advantage;
    int    seed_length;
    int    num_trials;
} PRGAdvantage;

/* Run a distinguisher against the PRG */
PRGAdvantage prg_measure_advantage(const PRG* prg,
                                   int (*distinguisher)(const BitString*),
                                   int num_trials);

/* ================================================================
 * Practical PRG Constructions (for demonstration)
 * ================================================================ */

/* Toy PRG: Uses iterated hash for demonstration. NOT cryptographically secure. */
PRG* prg_create_toy_length_doubling(int seed_len);

/* AES-CTR-based PRG (demonstration): G(k) = AES_k(0) || AES_k(1) */
PRG* prg_create_aes_ctr_prg(int seed_len);

/* ================================================================
 * Statistical Tests for Pseudorandomness
 * ================================================================ */

/* Monobit test: Check if proportion of 1s approx 0.5 */
double prg_statistical_monobit(const BitString* output);

/* Runs test: Count number of runs (consecutive 0s or 1s) */
double prg_statistical_runs(const BitString* output);

/* Serial test: Check transition frequencies (00, 01, 10, 11) */
double prg_statistical_serial(const BitString* output);

/* Poker test: Block frequency (NIST SP 800-22 style) */
double prg_statistical_poker(const BitString* output, int block_size);

/* Full NIST-lite battery (returns 1 if all pass at alpha=0.01) */
int prg_statistical_battery(const BitString* output, double alpha);

#endif /* PRG_H */
