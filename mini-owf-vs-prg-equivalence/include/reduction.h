/*
 * reduction.h ? OWF => PRG Reduction (HILL Construction)
 *
 * L4 Fundamental Theorem (HILL, 1999):
 *   If one-way functions exist, then pseudorandom generators exist.
 *
 * Equivalently (combined with trivial PRG => OWF direction):
 *   OWF exist <=> PRG exist
 *
 * The HILL construction proceeds in several stages:
 *   Stage 1: OWF => OWF with known hardcore bit (Goldreich-Levin)
 *            g(x,r) = (f(x), r),  hc(x,r) = <x,r>
 *   Stage 2: OWF + hardcore => PRG with 1-bit stretch
 *            G(s) = (f(s), hc(s))
 *   Stage 3: PRG with 1-bit stretch => PRG with arbitrary stretch
 *            Iterate: use core part as next seed, output bit
 *
 * Key proof techniques:
 *   - Goldreich-Levin theorem for hardcore bit extraction
 *   - Pairwise independent hashing for entropy preservation
 *   - Hybrid argument for stretch amplification
 *   - Leftover hash lemma for extracting pseudorandom bits
 *
 * L2 Core Concepts:
 *   - Entropy: min-entropy, pseudoentropy
 *   - Pseudorandomness from computational hardness
 *   - Black-box vs non-black-box reductions
 *   - Security reduction tightness
 *
 * Reference:
 *   HILL (1999) ? A Pseudorandom Generator from any One-way Function
 *   Goldreich (2001) ? Foundations of Cryptography, Vol 1, Sec 3.4-3.5
 *   Vadhan (2012) ? Pseudorandomness, Sec 6
 *   Arora & Barak (2009) ? Computational Complexity, Ch 20
 *
 * Courses: MIT 6.875, Stanford CS255, Berkeley CS276
 */

#ifndef REDUCTION_H
#define REDUCTION_H

#include "owf.h"
#include "prg.h"
#include "hardcore_bit.h"
#include "indistinguish.h"

/* ================================================================
 * L4: OWF => PRG Main Reduction
 * ================================================================ */

/*
 * Full HILL construction: given any OWF f, construct a PRG G.
 *
 * Stage 1: Build g(x,r) = (f(x), r) ? augmented OWF
 * Stage 2: Extract hardcore bit h(x,r) = <x,r>
 * Stage 3: Construct 1-bit stretch PRG: G_1(s) = (g(s), h(s))
 * Stage 4: Iterate G_1 to get arbitrary stretch
 */

/*
 * Stage 1+2: Given OWF f, construct OWF g with hardcore bit.
 * g(x, r) = (f(x), r),  hc(x, r) = sum x_i * r_i (mod 2)
 */
typedef struct {
    OWF            *f;          /* Original OWF */
    OWF            *g;          /* Augmented OWF g(x,r) = (f(x), r) */
    HardcorePred    hc;         /* Hardcore bit for g */
    int             input_len;  /* |x| = |r| */
} OWFWithHardcoreBit;

/*
 * Construct the Goldreich-Levin augmented OWF from any OWF.
 * Returns a descriptor with g and the hardcore predicate.
 */
OWFWithHardcoreBit *owf_add_hardcore_bit(OWF *f);

/*
 * Stage 3: Construct PRG with 1-bit stretch from OWF with hardcore.
 * G(s) = (g(s), hc(s))  where s = (x, r)
 * Output: n+1 bits from n-bit input (stretch = 1 bit)
 */
PRG *prg_one_bit_stretch(const OWFWithHardcoreBit *owf_hc);

/*
 * Stage 4: Given PRG with 1-bit stretch, construct PRG with
 * arbitrary polynomial stretch l(n).
 * G_l(s) iteratively applies G_1, using core bits as next seed
 * and outputting the extra bit each time.
 */
PRG *prg_arbitrary_stretch(PRG *prg_one_bit, size_t total_output_len);

/*
 * Full HILL reduction: OWF => PRG with arbitrary stretch.
 * Combines all stages into a single function call.
 */
PRG *hill_owf_to_prg(OWF *owf, size_t output_len);

/* ================================================================
 * L4: PRG => OWF Direction (Easy / Trivial)
 * ================================================================ */

/*
 * Theorem: If PRG G: {0,1}^n -> {0,1}^{2n} exists,
 * then G itself is a one-way function.
 *
 * Proof sketch:
 *   Suppose not: exists inverter A that given y = G(x),
 *   finds x' such that G(x') = y with noticeable probability.
 *   Then we can distinguish G(U_n) from U_{2n}:
 *     Given challenge z:
 *       x' = A(z)
 *       If G(x') = z: output 1 (pseudorandom, since inversion worked)
 *       Else: output 0 (random, since random strings have few preimages)
 *
 * Because G outputs 2n bits from n-bit inputs, a random string
 * is in the image of G with probability <= 2^n / 2^{2n} = 2^{-n},
 * which is negligible.
 */
OWF *prg_to_owf(PRG *prg);

/* ================================================================
 * L5: Entropy and Pseudoentropy
 * ================================================================ */

/*
 * Min-entropy of a distribution X:
 *   H_{inf}(X) = -log(max_x Pr[X = x])
 *
 * Pseudoentropy: A distribution X has pseudoentropy >= k if
 * there exists a distribution Y with H_{inf}(Y) >= k such that
 * X and Y are computationally indistinguishable.
 *
 * The HILL construction works by showing that (f(x), r, <x,r>)
 * has pseudoentropy at least n+1 when f is a OWF.
 */

typedef struct {
    double min_entropy;
    double collision_entropy;   /* -log(sum_x Pr[X=x]^2) */
    double shannon_entropy;     /* -sum_x Pr[X=x] * log(Pr[X=x]) */
    double pseudo_min_entropy;  /* Min-entropy of indistinguishable distribution */
} EntropyProfile;

/*
 * Estimate entropy profile from samples.
 */
EntropyProfile entropy_from_samples(const DistEnsemble *X);

/*
 * Leftover Hash Lemma (Impagliazzo-Levin-Luby, 1989):
 * If H is a universal hash family from {0,1}^n to {0,1}^m, and
 * X has min-entropy >= m + 2*log(1/epsilon), then:
 *   Delta( (H, H(X)), (H, U_m) ) <= epsilon/2
 *
 * This is used in HILL to extract pseudorandom bits.
 */
double leftover_hash_lemma(const DistEnsemble *X, int m,
                           const GF2HashFunc *hash, int n_samples);

/* ================================================================
 * L5: Reduction Tightness Analysis
 * ================================================================ */

/*
 * Measure the security loss in the OWF => PRG reduction.
 *
 * Given an adversary A that breaks the PRG with advantage epsilon,
 * construct an inverter B for the underlying OWF.
 *
 * Tightness ratio: epsilon_A / epsilon_B
 * HILL: epsilon_A = O(epsilon_B^3 / n) ? cubic loss in security
 * Holenstein (2006): epsilon_A = O(epsilon_B^2 / n) ? quadratic
 * Haitner-Reingold-Vadhan (2010): epsilon_A = O(epsilon_B) ? linear
 */
typedef struct {
    double adv_prg;           /* Adversary advantage against PRG */
    double adv_owf;           /* Resulting inverter advantage against OWF */
    double tightness_ratio;   /* adv_prg / adv_owf */
    int    n_queries;         /* Number of OWF queries by inverter */
    char   construction[64];  /* Name of the reduction variant */
} ReductionTightness;

ReductionTightness measure_reduction_tightness(OWF *owf, PRG *prg,
                                                int n_trials,
                                                PRGDistinguisherFunc D,
                                                OWFAdversaryFunc A);

/* ================================================================
 * L8: Advanced Reduction Variants
 * ================================================================ */

/*
 * Randomized iterate construction:
 * Instead of deterministic iteration, use randomized encodings
 * to improve security and stretch efficiency.
 */

/*
 * Pseudoentropy generator from OWF:
 * Output (f(x), h_1(x), ..., h_k(x)) where h_i are from
 * a pairwise independent hash family. By leftover hash lemma,
 * this has pseudoentropy >= H_{inf}(x|f(x)) - O(log n).
 */
typedef struct {
    OWF         *owf;
    GF2HashFunc *hashes;
    int          n_hashes;
    int          bits_per_hash;
} PseudoentropyGen;

PseudoentropyGen *pseudoentropy_gen_create(OWF *owf, int n_hashes,
                                            int bits_per_hash);
void              pseudoentropy_gen_free(PseudoentropyGen *peg);

#endif /* REDUCTION_H */
