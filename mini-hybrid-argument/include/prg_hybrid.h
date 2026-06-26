/*
 * prg_hybrid.h - PRG Security via the Hybrid Argument
 *
 * A pseudorandom generator (PRG) G: {0,1}^n -> {0,1}^{l(n)} with
 * l(n) > n is a deterministic polynomial-time algorithm whose output
 * is computationally indistinguishable from uniform.
 *
 * The hybrid argument is the standard technique for proving that a
 * PRG with 1-bit stretch implies a PRG with arbitrary polynomial
 * stretch. This "PRG Length Extension" theorem (Blum-Micali-Yao)
 * is one of the most important applications of the hybrid argument.
 *
 * L1 Definitions: PRG, stretch function, PRG security
 * L4 Fundamental Laws: PRG Length Extension theorem
 * L5 Algorithms: BMY iteration, hybrid sequence construction
 * L6 Canonical Problems: PRG distinguishing game
 * L7 Applications: Stream ciphers, key derivation
 *
 * The BMY Construction:
 *   Base PRG G_1: {0,1}^n -> {0,1}^{n+1} (1-bit stretch)
 *   Extended PRG G_k: {0,1}^n -> {0,1}^{n+k} via iteration:
 *     s_0 = seed
 *     For i = 1..k: (s_i, b_i) = G_1(s_{i-1})  [|s_i|=n, b_i in {0,1}]
 *     Output b_1 || b_2 || ... || b_k || s_k
 *
 * Hybrid Sequence for the Proof:
 *   H_i = (R_i || G_{k-i}(s_i))  where
 *     R_i = i truly random bits
 *     s_i = state after i iterations starting from random seed
 *   H_0 = G_k(U_n)    (all pseudorandom)
 *   H_k = U_{n+k}     (all random)
 *   H_i ~=~ H_{i+1} by security of one application of G_1
 *   Therefore H_0 ~=~ H_k with advantage <= k * epsilon(n)
 *
 * Reference:
 *   Blum & Micali (1984) "How to Generate Cryptographically Strong
 *                        Sequences of Pseudorandom Bits"
 *   Yao (1982) "Theory and Applications of Trapdoor Functions"
 *   Goldreich (2001) Foundations of Cryptography, Section 3.3
 *   Arora & Barak (2009) Section 9.3
 *
 * Courses: MIT 6.875, Stanford CS355, Berkeley CS276, Princeton COS 522
 */

#ifndef PRG_HYBRID_H
#define PRG_HYBRID_H

#include "hybrid_argument.h"

/* ================================================================
 * PRG Core Types
 * ================================================================ */

/*
 * A PRG is a deterministic function G: {0,1}^n -> {0,1}^{l(n)}.
 *   - seed: input randomness (n bits)
 *   - output: pseudorandom bits (l(n) bits, l(n) > n)
 *   - stretch: l(n) - n, the number of extra bits produced
 *
 * The PRG must be computable in poly(n) time.
 */
typedef struct PRG PRG;

typedef void (*prg_eval_fn)(const PRG* g,
                             const uint8_t* seed, size_t seed_bits,
                             uint8_t* output, size_t* output_bits);

struct PRG {
    char*        name;
    size_t       (*stretch)(size_t seed_bits);
    prg_eval_fn  evaluate;
    void*        state;
};

PRG* prg_create(const char* name,
                 size_t (*stretch_fn)(size_t seed_bits),
                 prg_eval_fn eval_fn,
                 void* state);
void prg_free(PRG* g);
void prg_evaluate(const PRG* g,
                   const uint8_t* seed, size_t seed_bits,
                   uint8_t* output, size_t* output_bits);

/* ================================================================
 * PRG Security Game
 * ================================================================ */

/*
 * The PRG distinguishing experiment PrivK^{prg}_{A,G}(n):
 *   1. Challenger chooses b <- {0,1} uniformly.
 *   2. If b=0: sample r <- U_{l(n)}, send r to adversary.
 *      If b=1: sample s <- U_n, compute y = G(s), send y.
 *   3. Adversary outputs b' in {0,1}.
 *   4. Adversary succeeds if b' = b.
 *
 * Advantage: |Pr[b'=1 | b=1] - Pr[b'=1 | b=0]|
 */
typedef struct {
    int     challenger_bit;
    int     adversary_guess;
    int     correct;
    double  advantage;
    int     num_trials;
} PRGSecurityGame;

PRGSecurityGame prg_security_game_run(const PRG* g,
                                       const Distinguisher* adv,
                                       security_param_t n,
                                       int num_trials);
void prg_security_game_print(const PRGSecurityGame* game);

/* ================================================================
 * PRG Length Extension: BMY Construction
 * ================================================================ */

/*
 * BMY iteration: given a base PRG G_1 with 1-bit stretch, construct
 * G_k with k-bit stretch. This is the constructive part of the
 * "1-bit stretch PRG => arbitrary polynomial stretch PRG" theorem.
 *
 * Parameters:
 *   base_prg: G_1 with stretch 1 (outputs n+1 bits from n-bit seed)
 *   k: desired extra output bits (k = poly(n))
 *
 * Returns: G_k with stretch k (outputs n+k bits)
 *
 * Complexity: O(k * T_G) where T_G is the time to evaluate G_1.
 */
PRG* prg_bmy_extend(const PRG* base_prg, size_t k);

/*
 * Build the hybrid sequence for the BMY security proof.
 * Creates k+1 hybrid distributions H_0, ..., H_k as described above.
 * Each hybrid is represented as a DistributionEnsemble.
 *
 * Parameters:
 *   base_prg: G_1, the base PRG
 *   n: security parameter
 *   k: number of hybrid steps (= number of extra bits)
 *
 * Returns: HybridSequence with k+1 elements
 */
HybridSequence* prg_bmy_hybrid_sequence(const PRG* base_prg,
                                          security_param_t n, size_t k);

/*
 * Verify empirically that the hybrid argument bound holds.
 * Estimates advantages between adjacent hybrids via Monte Carlo
 * and checks: measured_total <= k * max(pairwise_advantages).
 */
HybridArgumentResult* prg_bmy_verify_hybrid(const PRG* base_prg,
                                              security_param_t n,
                                              size_t k,
                                              int num_trials);

/* ================================================================
 * Concrete PRG Implementations (for demonstration)
 * ================================================================ */

/*
 * LCG-based "PRG": X_{i+1} = (a * X_i + c) mod m.
 * NOT cryptographically secure. Used only to demonstrate the
 * hybrid argument structure and how advantages accumulate.
 * Parameters: multiplier a, increment c, modulus m.
 */
PRG* prg_create_lcg(uint64_t multiplier, uint64_t increment, uint64_t modulus);

/*
 * Hash-chain PRG: G(s) = H(s) || H(s+1) || ... || H(s+k-1)
 * where H is modeled as a random oracle (using a simple hash here).
 * Produces k blocks of pseudorandom output.
 * Cryptographic in the random oracle model.
 */
PRG* prg_create_hash_chain(size_t num_blocks);

/*
 * Trivial PRG: G(s) = s || ~s (seed followed by its complement).
 * Obviously insecure -- serves as a pedagogical baseline to show
 * what a distinguisher can exploit (the complement pattern).
 */
PRG* prg_create_trivial(void);

/*
 * XOR-shift PRG: a simple but non-cryptographic PRG based on
 * xorshift operations. Fast and good statistical properties,
 * but predictable given enough output.
 */
PRG* prg_create_xorshift(uint64_t initial_state);

/* Stream cipher from PRG (L7 Application) */
void prg_stream_xor(const PRG* g,
                     const uint8_t* key, size_t key_bits,
                     const uint8_t* input, size_t input_bits,
                     uint8_t* output);

/* Key derivation function (L7 Application) */
int prg_kdf_derive(const PRG* g,
                    const uint8_t* mk, size_t mk_bits,
                    const uint8_t* salt, size_t salt_bits,
                    uint8_t* sub_key, size_t sub_key_bits);

/* PRG output statistical analysis */
typedef struct {
    double mean_bit_fraction;
    size_t num_runs;
    double entropy_estimate;
    size_t output_bits;
} PRGStatistics;

PRGStatistics prg_analyze_output(const PRG* g,
                                  const uint8_t* seed, size_t seed_bits);

#endif /* PRG_HYBRID_H */