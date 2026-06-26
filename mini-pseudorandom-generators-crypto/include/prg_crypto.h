/*
 * prg_crypto.h ? Cryptographic Pseudorandom Generator Definitions
 *
 * L1 Definitions:
 *   Pseudorandom Generator (PRG): A deterministic polynomial-time algorithm G
 *     that on input a short random seed s in {0,1}^n outputs a longer
 *     "pseudorandom" string G(s) in {0,1}^{l(n)} where l(n) > n.
 *     G is secure if no polynomial-time distinguisher can tell G(U_n) from U_{l(n)}.
 *
 *   Computational Indistinguishability: Two ensembles {X_n} and {Y_n} are
 *     computationally indistinguishable (X ?_c Y) if for every PPT
 *     distinguisher D, |Pr[D(X_n)=1] - Pr[D(Y_n)=1]| ? negl(n).
 *
 *   Statistical (Total Variation) Distance: ?(X, Y) = (1/2) ?_x |Pr[X=x] - Pr[Y=x]|
 *
 *   Next-bit Unpredictability: For all i, Pr[A(G(s)_{1..i-1}) = G(s)_i] ? 1/2 + negl(n)
 *
 * L2 Core Concepts:
 *   PRG = Deterministic expansion + Computational indistinguishability
 *   Advantage: Adv_{G,D}(n) = |Pr[D(G(U_n))=1] - Pr[D(U_{l(n)})=1]|
 *   Expansion factor / Stretch: l(n) - n bits of expansion
 *
 * L4 Fundamental Theorems:
 *   Yao (1982): PRG ? Next-bit unpredictability
 *
 * Reference: Goldreich (2008), Arora-Barak (2009) Chapter 9, Katz-Lindell (2015)
 * Courses: MIT 6.875, Stanford CS255, Princeton COS 551, Berkeley CS276, CMU 15-859
 */

#ifndef PRG_CRYPTO_H
#define PRG_CRYPTO_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

/* ================================================================
 * Basic PRG Configuration
 * ================================================================ */

#define PRG_MAX_SEED_BITS    512
#define PRG_MAX_OUTPUT_BITS  8192
#define PRG_BYTES(nbits)     (((nbits) + 7) / 8)

/*
 * PRG parameters: seed length and output length in bits.
 * l(n) > n for any nontrivial PRG (expansion required).
 */
typedef struct {
    size_t seed_bits;
    size_t output_bits;
    size_t stretch_bits;
} PRGParams;

typedef struct PRG PRG;
typedef int (*PRGInitFunc)(PRG* prg, const uint8_t* seed, size_t seed_bytes);
typedef int (*PRGNextFunc)(PRG* prg, uint8_t* output, size_t output_bytes);
typedef void (*PRGFreeFunc)(PRG* prg);

struct PRG {
    PRGParams params;
    uint8_t state[PRG_BYTES(PRG_MAX_SEED_BITS) * 4];
    size_t state_len;
    size_t bits_produced;
    PRGInitFunc init;
    PRGNextFunc next;
    PRGFreeFunc free_ctx;
    void* priv;
};

PRG* prg_create(size_t seed_bits, size_t output_bits);
int prg_init(PRG* prg, const uint8_t* seed, size_t seed_bytes);
int prg_generate(PRG* prg, uint8_t* output, size_t output_bytes);
int prg_fill(PRG* prg, uint8_t* buffer, size_t buffer_bytes);
void prg_free(PRG* prg);

/* ================================================================
 * Computational Indistinguishability Framework
 * ================================================================ */

typedef struct {
    size_t domain_size;
    double* probs_a;
    double* probs_b;
} DistributionPair;

double stat_distance(const DistributionPair* dp);
double max_advantage_from_distance(double stat_dist);

typedef struct {
    size_t input_bits;
    size_t queries;
    double* advantage_log;
    double cumulative_advantage;
} Distinguisher;

void distinguisher_init(Distinguisher* d, size_t input_bits);
void distinguisher_record_guess(Distinguisher* d, int guess, int actual);
double distinguisher_advantage(const Distinguisher* d);
void distinguisher_reset(Distinguisher* d);

/* ================================================================
 * PRG Security Game
 * ================================================================ */

typedef struct {
    size_t n;
    size_t l;
    size_t trials;
    size_t successes_given_prg;
    size_t total_prg_trials;
    size_t successes_given_random;
    size_t total_random_trials;
    double estimated_advantage;
} PRGSecurityGame;

void prg_security_game_init(PRGSecurityGame* game, size_t n, size_t l);
int prg_security_game_trial(PRGSecurityGame* game, const uint8_t* sample,
                            int distinguisher_guess, int is_prg_output);
double prg_security_game_advantage(const PRGSecurityGame* game);
int prg_advantage_is_negligible(double advantage, size_t n, double poly_degree);

/* ================================================================
 * Next-bit Unpredictability Framework
 * ================================================================ */

typedef struct {
    size_t seed_bits;
    size_t output_bits;
    size_t position;
    double base_rate;
    size_t correct_guesses;
    size_t total_guesses;
    double observed_advantage;
} NextBitPredictor;

void nbp_init(NextBitPredictor* nbp, size_t n, size_t l, size_t position);
void nbp_record(NextBitPredictor* nbp, int prediction, int actual_bit);
double nbp_advantage(const NextBitPredictor* nbp);

/* ================================================================
 * Utility: Bit Manipulation for PRG Output
 * ================================================================ */

void bytes_to_bits(const uint8_t* bytes, size_t byte_len,
                   int* bits, size_t bit_len);
void bits_to_bytes(const int* bits, size_t bit_len,
                   uint8_t* bytes, size_t byte_capacity);
void xor_bytes(uint8_t* dst, const uint8_t* a, const uint8_t* b, size_t len);
int ct_memcmp(const uint8_t* a, const uint8_t* b, size_t len);

/* ================================================================
 * Utility: Test Randomness (non-cryptographic, for simulation/testing)
 * ================================================================ */

void prg_test_srand(uint64_t seed);
uint64_t prg_test_rand(void);
void prg_fill_random(uint8_t* buffer, size_t n_bytes);
int prg_random_bit(void);

#endif /* PRG_CRYPTO_H */
