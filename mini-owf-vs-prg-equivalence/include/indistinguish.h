/*
 * indistinguish.h ? Computational Indistinguishability and Hybrid Arguments
 *
 * L1 Definition:
 *   Two distribution ensembles {X_n} and {Y_n} are computationally
 *   indistinguishable if for every PPT distinguisher D,
 *     |Pr[D(X_n, 1^n) = 1] - Pr[D(Y_n, 1^n) = 1]| < negl(n)
 *
 * L4 Fundamental Theorem (Yao, 1982):
 *   Next-bit unpredictability <=> pseudorandomness.
 *   A distribution is pseudorandom iff no PPT algorithm can predict
 *   the next bit given previous bits with advantage > negl(n).
 *
 * L4 Hybrid Argument:
 *   If distributions D_0, D_1, ..., D_k are such that D_i and D_{i+1}
 *   are computationally indistinguishable for all i, then D_0 and D_k
 *   are computationally indistinguishable (loss k in reduction).
 *
 * L3 Mathematical Structures:
 *   - Total variation distance (statistical distance)
 *   - Distribution ensembles over {0,1}^*
 *   - Hybrid distributions for modular proofs
 *
 * These are the core proof techniques used throughout cryptography,
 * especially in proving OWF => PRG via HILL.
 *
 * Reference:
 *   Yao (1982) ? Theory and Applications of Trapdoor Functions
 *   Goldreich (2001) ? Foundations of Cryptography, Vol 1, Ch 3
 *   Arora & Barak (2009) ? Computational Complexity, Ch 9
 */

#ifndef INDISTINGUISH_H
#define INDISTINGUISH_H

#include "owf.h"
#include "prg.h"
#include <stdint.h>
#include <stddef.h>

/* ================================================================
 * L1: Distribution Ensemble
 * ================================================================ */

typedef struct {
    BitString *samples;     /* Array of sample bit strings */
    int        n_samples;   /* Number of samples in ensemble */
    int        capacity;    /* Allocated capacity */
    size_t     sample_len;  /* Length of each sample (bits) */
} DistEnsemble;

DistEnsemble *dist_ensemble_create(size_t sample_len);
void          dist_ensemble_free(DistEnsemble *de);
void          dist_ensemble_add(DistEnsemble *de, const BitString *sample);
void          dist_ensemble_randomize(DistEnsemble *de, int n_samples);

/* ================================================================
 * L3: Statistical Distance
 * ================================================================ */

/*
 * Statistical (total variation) distance between two distributions:
 *   Delta(X, Y) = 1/2 * sum_{v} |Pr[X=v] - Pr[Y=v]|
 *
 * For sample-based estimation:
 *   Delta_hat = 1/2 * sum_{v} |count_X(v)/N_X - count_Y(v)/N_Y|
 */
double stat_distance_from_samples(const DistEnsemble *X, const DistEnsemble *Y);

/*
 * Compute exact statistical distance for small domains (enumeration).
 * Domain: all bitstrings of the given length up to max_len.
 * f_X(v) = Pr[X=v], f_Y(v) = Pr[Y=v]
 */
typedef double (*ProbMassFunc)(const BitString *v, void *ctx);
double stat_distance_exact(size_t max_len, ProbMassFunc f_X, ProbMassFunc f_Y,
                           void *ctx_X, void *ctx_Y);

/* ================================================================
 * L2: Computational Indistinguishability
 * ================================================================ */

/*
 * Distinguisher function: takes a sample and returns 0 or 1.
 * Context can hold state between calls.
 */
typedef int (*Distinguisher)(const BitString *sample, void *ctx);

/*
 * Computational indistinguishability experiment:
 *   1. Flip coin b in {0,1}
 *   2. If b=0: sample from X, else sample from Y
 *   3. Run D on sample, get guess b'
 *   4. D succeeds if b' = b
 *
 * Advantage = |2 * Pr[success] - 1|
 */
typedef struct {
    int    n_trials;
    int    n_correct;
    double advantage;
} CompIndistResult;

/*
 * Run computational indistinguishability experiment.
 * X, Y: two distribution ensembles
 * D: distinguisher
 */
CompIndistResult comp_indist_experiment(const DistEnsemble *X, const DistEnsemble *Y,
                                         int n_trials, Distinguisher D, void *ctx);

/* ================================================================
 * L4: Hybrid Argument
 * ================================================================ */

/*
 * Hybrid Lemma:
 *   Let H_0, H_1, ..., H_k be k+1 hybrid distributions.
 *   If for every i, H_i and H_{i+1} are computationally indistinguishable
 *   with advantage at most epsilon(n), then H_0 and H_k are
 *   computationally indistinguishable with advantage at most k * epsilon(n).
 *
 * This is the fundamental proof technique for:
 *   - PRG => PRG with arbitrary stretch (iterate 1-bit stretch)
 *   - OWF => PRG (HILL: chain of entropy-preserving transformations)
 *   - Encryption security (IND-CPA from PRG)
 */

typedef struct {
    DistEnsemble **hybrids;  /* H_0, ..., H_k */
    int            k;         /* Number of hybrids (k+1 distributions) */
    size_t         n_bits;    /* Sample length */
} HybridChain;

HybridChain *hybrid_chain_create(int k, size_t n_bits);
void         hybrid_chain_free(HybridChain *hc);

/*
 * Verify the hybrid lemma by testing each adjacent pair.
 * Returns the maximum advantage across all adjacent pairs.
 */
double hybrid_lemma_verify(const HybridChain *hc, int n_trials,
                           Distinguisher D, void *ctx);

/*
 * Create a hybrid chain for PRG iteration proof:
 * H_i = (G_output_first_i_bits || uniform_last_l-i_bits)
 * H_0 = all uniform, H_l = all G output
 */
HybridChain *prg_hybrid_chain(const PRG *prg, int l);

/* ================================================================
 * L4: Next-Bit Unpredictability <=> Pseudorandomness
 * ================================================================ */

/*
 * Yao's Theorem (1982): A distribution ensemble {X_n} is pseudorandom
 * iff it is next-bit unpredictable.
 *
 * Next-bit predictor: given first i bits, predict bit i+1.
 *   adv = |Pr[P(x_1,...,x_i) = x_{i+1}] - 1/2|
 */

typedef int (*NextBitPredictor)(const BitString *prefix, int prefix_len, void *ctx);

/*
 * Measure next-bit unpredictability of a distribution.
 * For each position i, test if predictor can predict bit i+1
 * given bits 1..i with advantage > negl(n).
 */
typedef struct {
    double *advantages;    /* adv[i] for each position i */
    int     n_positions;   /* Number of positions checked */
    double  max_advantage; /* Maximum advantage across all positions */
} NextBitUnpredResult;

NextBitUnpredResult next_bit_unpred_test(const DistEnsemble *X,
                                          NextBitPredictor P, void *ctx);

/*
 * Yao's theorem constructive direction:
 * Given a next-bit predictor with advantage epsilon,
 * construct a distinguisher with advantage epsilon/l.
 */
Distinguisher yao_predictor_to_distinguisher(NextBitPredictor P, int l);

/*
 * Yao's theorem converse:
 * Given a distinguisher with advantage epsilon,
 * construct a next-bit predictor with advantage epsilon/l.
 */
NextBitPredictor yao_distinguisher_to_predictor(Distinguisher D, int l);

/* ================================================================
 * L7: Application ? Encryption from PRG
 * ================================================================ */

/*
 * IND-CPA security via hybrid argument:
 *   Game 0 (real): C = G(k) XOR m
 *   Game 1 (hybrid): C = random XOR m
 *   Game 0 ?_c Game 1 by PRG security
 *
 * The hybrid argument shows that breaking the encryption
 * implies breaking the PRG.
 */
int  indist_encrypt(const PRG *prg, const BitString *key,
                    const BitString *msg, BitString *cipher);
int  indist_decrypt(const PRG *prg, const BitString *key,
                    const BitString *cipher, BitString *msg);

#endif /* INDISTINGUISH_H */
