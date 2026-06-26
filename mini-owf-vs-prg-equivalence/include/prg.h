/*
 * prg.h — Pseudorandom Generators: Definitions and Constructions
 *
 * L1 Definition:
 *   A deterministic polynomial-time algorithm G: {0,1}^n → {0,1}^{l(n)}
 *   with l(n) > n (stretch) is a pseudorandom generator if for every
 *   PPT distinguisher D, the advantage
 *     |Pr[D(G(U_n)) = 1] - Pr[D(U_{l(n)}) = 1]|
 *   is negligible in n.
 *
 * L2 Core Concepts:
 *   - Stretch: l(n) - n (how many extra bits generated)
 *   - Seed: random n-bit input to G
 *   - Computational indistinguishability from uniform
 *   - PRG implies OWF (easy direction: G is itself a OWF)
 *   - PRG iteration for arbitrary polynomial stretch
 *
 * L7 Applications:
 *   - Stream ciphers (PRG as keystream generator)
 *   - Private-key encryption from PRG
 *   - Derandomization (BPP ⊆ P/poly under PRG assumptions)
 *
 * The equivalence OWF ⇔ PRG is the main theorem of this module:
 *   OWF ⇒ PRG: Håstad, Impagliazzo, Levin, Luby (HILL 1999)
 *   PRG ⇒ OWF: trivial (if PRG exists, G is a one-way function)
 *
 * Reference:
 *   Blum & Micali (1984) — How to Generate Cryptographically Strong Sequences
 *   Yao (1982) — Theory and Applications of Trapdoor Functions
 *   HILL (1999) — A Pseudorandom Generator from any One-way Function
 *   Goldreich (2001) — Foundations of Cryptography, Vol 1, Ch 3
 *
 * Courses: MIT 6.875, Stanford CS255, Berkeley CS276, Princeton COS 522
 */

#ifndef PRG_H
#define PRG_H

#include "owf.h"
#include <stdint.h>
#include <stddef.h>

/* ================================================================
 * L1: PRG Type Definition
 * ================================================================ */

/*
 * Pseudorandom Generator descriptor.
 * G: {0,1}^n → {0,1}^{l(n)} with l(n) > n
 */
typedef struct PRG PRG;
typedef int (*PRGEvalFunc)(const PRG *prg, const BitString *seed, BitString *output);

struct PRG {
    SecurityParam n;            /* Seed length (security parameter) */
    size_t        output_len;   /* l(n): output length in bits */
    PRGEvalFunc   eval;         /* G(seed) = output */
    void         *params;       /* Construction-specific parameters */
    char          name[64];
};

/* Create/destroy PRG instances */
PRG  *prg_create(SecurityParam n, size_t output_len, PRGEvalFunc eval,
                 void *params, const char *name);
void  prg_free(PRG *prg);
int   prg_eval(const PRG *prg, const BitString *seed, BitString *output);

/* ================================================================
 * L1: PRG Distinguishing Experiment
 * ================================================================ */

/*
 * PRG Distinguishing Experiment (Exp_{D,G}^{prg}(n)):
 *   1. Choose b ← {0,1} uniformly
 *   2. If b = 0: choose r ← {0,1}^{l(n)} uniformly (truly random)
 *      If b = 1: choose s ← {0,1}^n uniformly, r = G(s)
 *   3. Run D on r, get guess b'
 *   4. Output 1 if b' = b, else 0
 *
 * Advantage: Adv_{D,G}^{prg}(n) = |Pr[Exp=1] - 1/2|
 */
typedef struct {
    int   n_trials;
    int   n_correct;
    double advantage;
} PRGDistinguishingResult;

/* Distinguisher function: returns 0 (random) or 1 (pseudorandom) guess */
typedef int (*PRGDistinguisherFunc)(const BitString *challenge, size_t n);

PRGDistinguishingResult prg_distinguishing_experiment(const PRG *prg, int n_trials,
                                                       PRGDistinguisherFunc D);

/* ================================================================
 * L2: Blum-Micali PRG Construction (from hardcore bit)
 * ================================================================ */

/*
 * Blum-Micali Construction (1984):
 *   Given: permutation f on {0,1}^n, hardcore predicate b: {0,1}^n → {0,1}
 *   Define G(s) = (f(s), b(s))  — stretches by 1 bit
 *
 * For arbitrary stretch l:
 *   s_0 = seed
 *   For i = 1..l: s_i = f(s_{i-1}), output b(s_{i-1})
 *   Output: b(s_0) || b(s_1) || ... || b(s_{l-1})
 */
typedef struct {
    OWF        *f;              /* Underlying one-way permutation */
    int       (*hardcore)(const BitString *x);  /* Hardcore predicate b(x) */
    size_t      stretch;        /* Number of extra bits to output */
    int         is_blum_micali; /* Flag for the iterated construction */
} BlumMicaliParams;

int   blum_micali_prg_eval(const PRG *prg, const BitString *seed, BitString *output);
void *blum_micali_params_create(OWF *f, int (*hc)(const BitString *x), size_t stretch);

/* ================================================================
 * L2: PRG from OWF via HILL (sketch / black-box)
 * ================================================================ */

/*
 * HILL Construction (1999):
 *   Given any OWF f, construct PRG G.
 *   Main steps:
 *     1. Goldreich-Levin: extract hardcore bit h(x,r) = <x,r>
 *     2. Hash-iterate: use pairwise-independent hash to condense entropy
 *     3. Assemble into PRG via iterated extraction
 *
 * This header declares the high-level interface; the full construction
 * is in reduction_owf_prg.c.
 */
typedef struct {
    OWF        *owf;             /* Underlying one-way function */
    size_t      output_len;      /* Target output length */
    int         n_hashes;        /* Number of hash families used */
    /* Internal state for the iterative extraction process */
    BitString  *current_state;
    int         bits_extracted;
    int         bits_remaining;
} HILLParams;

int   hill_prg_eval(const PRG *prg, const BitString *seed, BitString *output);
void *hill_params_create(OWF *owf, size_t output_len);

/* ================================================================
 * L5: PRG Iteration (Arbitrary Stretch)
 * ================================================================ */

/*
 * Given a PRG G with 1-bit stretch: G: {0,1}^n → {0,1}^{n+1}
 * Construct G_l: {0,1}^n → {0,1}^{n+l} as follows:
 *
 * Let G(s) = (G_core(s), G_bit(s)) where G_core is n bits, G_bit is 1 bit.
 *   s_0 = seed
 *   s_{i+1} = G_core(s_i)     [next seed]
 *   out_i = G_bit(s_i)         [output bit]
 *   Output: out_0 || out_1 || ... || out_{l-1}
 *
 * This is the Blum-Micali length-expansion technique, generalized.
 */
typedef struct {
    PRG   *base_prg;       /* G with 1-bit stretch: n → n+1 */
    size_t output_bits;    /* l: total output bits desired */
} PRGIteration;

int   prg_iterate_eval(const PRG *prg, const BitString *seed, BitString *output);
void *prg_iterate_params_create(PRG *base_prg, size_t output_bits);

/* ================================================================
 * L7: PRG as Stream Cipher
 * ================================================================ */

/*
 * Stream cipher from PRG:
 *   Key = seed s ∈ {0,1}^n
 *   Keystream = G(s) (concatenated PRG outputs)
 *   Ciphertext = plaintext XOR keystream
 *
 * This is the standard construction for symmetric encryption from PRG.
 */
int   prg_stream_encrypt(const PRG *prg, const BitString *key,
                         const BitString *plaintext, BitString *ciphertext);
int   prg_stream_decrypt(const PRG *prg, const BitString *key,
                         const BitString *ciphertext, BitString *plaintext);

/* ================================================================
 * L7: PRG for Derandomization (Nisan-Wigderson style)
 * ================================================================ */

/*
 * Using PRG to derandomize BPP algorithms:
 *   Instead of using l(n) random bits, enumerate all n-bit seeds,
 *   run G on each, and take majority vote.
 *
 * If PRG exists, then BPP ⊆ P/poly (requires non-uniform advice).
 */
int   prg_derandomize_bpp(const PRG *prg, int (*bpp_algo)(const BitString *input,
                           const BitString *random), const BitString *input, int *result);

#endif /* PRG_H */
