/*
 * black_box_separation.h ? Black-Box Separation Results
 *
 * L4 Fundamental Laws / L8 Advanced Topics:
 * Not all cryptographic primitives are equivalent. Black-box separation
 * results establish that some primitives require strictly stronger
 * assumptions than others, even if both could exist.
 *
 * The central result: OWF ? OT (Impagliazzo-Rudich 1989)
 * This proved that public-key cryptography requires assumptions beyond
 * those needed for symmetric cryptography.
 *
 * Also covers:
 *   - Simon (1998): OWF ? CRHF
 *   - Gertner, Malkin, Reingold (2001): TDP ? OT (is actually: DK ? OT
 *     requires more than TDP)
 *   - Hsiao, Reyzin (2004): PRF ? PKE
 *   - Lindell, Omri, Zarosim (2014): OT constructions from OWF impossible
 *
 * The RTV framework (Reingold, Trevisan, Vadhan 2004) provides a
 * systematic taxonomy of black-box reductions.
 *
 * Reference:
 *   Impagliazzo, Rudich, "Limits on the Provable Consequences of
 *     One-Way Permutations" (STOC 1989)
 *   Reingold, Trevisan, Vadhan, "Notions of Reducibility between
 *     Cryptographic Primitives" (TCC 2004)
 *   Simon, "Finding Collisions on a One-Way Street" (Eurocrypt 1998)
 */

#ifndef BLACK_BOX_SEPARATION_H
#define BLACK_BOX_SEPARATION_H

#include "minimal_assumptions.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * L1: Definitions ? Reduction Types
 * ================================================================ */

/*
 * A black-box reduction from primitive Q to primitive P means:
 * There exists an oracle machine M such that for every implementation
 * ? of P, M^? is an implementation of Q.
 * Formally: ?? (? implements P) ? (M^? implements Q)
 *
 * Types of black-box constructions (RTV taxonomy):
 */
typedef enum {
    BB_FULL,        /* Fully black-box: construction + security proof use oracle */
    BB_SEMI,        /* Semi black-box: construction uses oracle, proof is non-BB */
    BB_WEAKLY,      /* Weakly black-box: only security proof uses oracle */
    NON_BB          /* Non black-box: neither uses oracle */
} BBReductionType;

const char* bb_reduction_type_name(BBReductionType t);

/*
 * Separating oracle O:
 * A distribution on oracles such that:
 *   - P exists relative to O (with high probability)
 *   - Q does NOT exist relative to O
 * This proves no black-box reduction Q ? P exists.
 */
typedef struct {
    CryptoPrimitive from;    /* P: the assumed primitive */
    CryptoPrimitive to;      /* Q: the target primitive */
    BBReductionType type;
    int is_separated;        /* 1 = separation proven */
    int is_open;             /* 1 = open problem */
    const char* result_name;
    const char* reference;
} SeparationResult;

/* ================================================================
 * L2: Core Separation Results Database
 * ================================================================ */

/*
 * Known separations and their status as of 2026:
 */
typedef enum {
    SEP_IR89,          /* OWF ? OT (Impagliazzo-Rudich 1989) */
    SEP_SIMON98,       /* OWF ? CRHF (Simon 1998) */
    SEP_GGKT05,        /* TDP ? OT (Gertner et al.: actually they showed
                          TDP ? non-interactive key agreement) */
    SEP_HR04,          /* PRF ? PKE (Hsiao-Reyzin 2004) */
    SEP_MMP08,         /* OWF ? IBE (Boneh et al. 2008: requires TDP
                          and specific assumptions) */
    SEP_LOZ14,         /* No fully BB construction of OT from OWF
                          (Lindell, Omri, Zarosim 2014 ? strengthening IR89) */
    SEP_NUM
} SeparationID;

SeparationResult get_separation(SeparationID id);
void print_all_separations(void);

/* ================================================================
 * L3: Oracle Models for Separation
 * ================================================================ */

/*
 * Random Oracle Model: O is a truly random function R: {0,1}^n ? {0,1}^n.
 *
 * Properties:
 *   - R is one-way (PSPACE can invert, but PPT cannot)
 *   - R is not a permutation (with overwhelming probability)
 *   - In this model: OWF exist, CRHF do NOT exist
 */
typedef struct {
    uint8_t** table;      /* table[i] = R(i), stored as n/8 bytes each */
    size_t    input_bits;
    size_t    entries;    /* 2^input_bits */
    int       is_permutation;
} RandomOracle;

RandomOracle* ro_create(size_t n_bits, int as_permutation);
void ro_free(RandomOracle* ro);
void ro_eval(const RandomOracle* ro, const uint8_t* x, uint8_t* y, size_t len);
void ro_pspace_invert(const RandomOracle* ro, const uint8_t* y,
                       uint8_t* x, size_t len);

/*
 * PSPACE Oracle: Provides a PSPACE-complete solver.
 * Any specific inversion query can be answered by exhaustive search.
 * This models the adversary's computational power.
 */
typedef struct {
    RandomOracle* ro;
    uint8_t* queries_made;
    size_t n_queries;
    double success_count;
    double total_attempts;
} PSPACEAdversary;

PSPACEAdversary* pspace_adversary_create(RandomOracle* ro);
void pspace_adversary_attack(PSPACEAdversary* adv,
                              const uint8_t* target, size_t len);
void pspace_adversary_free(PSPACEAdversary* adv);

/* ================================================================
 * L4: The Impagliazzo-Rudich Oracle Construction
 * ================================================================ */

/*
 * The IR Oracle (P, O) where:
 *   P = random length-preserving function (? OWF)
 *   O = PSPACE oracle for inverting P
 *
 * Claim: In this relativized world:
 *   1. OWF exist (P is a OWF relative to O)
 *   2. No BB construction of OT from P exists
 *
 * Proof Outline:
 *   1. Any BB-OT protocol makes poly(n) queries to P
 *   2. With O access, PSPACE can answer ALL P-queries
 *   3. The protocol's security reduces to information-theoretic bounds
 *   4. OT requires PKE-type asymmetry, but O makes everything invertible
 */
typedef struct {
    RandomOracle*   random_func;   /* P: random oracle */
    PSPACEAdversary* pspace_oracle; /* O: PSPACE inverter */
    double           sec_param;
    int              ot_protocol_exists;
} IR_OracleWorld;

IR_OracleWorld* ir_oracle_create(size_t n_bits);
void ir_oracle_free(IR_OracleWorld* ir);
int  ir_oracle_prove_separation(IR_OracleWorld* ir, int n_protocols_to_test);

/*
 * Simulate possible BB-OT protocols and show they all fail.
 * Each protocol attempt reduces to a transcript game that
 * the PSPACE adversary can break.
 */
int ir_test_ot_protocol(IR_OracleWorld* ir, int protocol_id);

/* ================================================================
 * L5: Algorithms ? Separation Testing
 * ================================================================ */

/*
 * Generic separation testing framework:
 * For a given pair (from_primitive, to_primitive), generate
 * candidate BB constructions and test them against the
 * separating oracle.
 */
typedef struct {
    CryptoPrimitive from;
    CryptoPrimitive to;
    int n_constructions_tested;
    int n_constructions_broken;
    double break_rate;
    const char* verdict;  /* "SEPARATED" or "OPEN" or "EQUIVALENT" */
} SeparationTest;

SeparationTest separation_test_run(CryptoPrimitive from, CryptoPrimitive to,
                                    int n_candidates);

/* ================================================================
 * L6: Canonical Question ? Minicrypt vs Cryptomania
 * ================================================================ */

/*
 * The boundary between Minicrypt and Cryptomania is OWF ? OT.
 * Resolving this (even in BB model) took from 1976 to 1989.
 *
 * If we could prove OWF ? OT, then Minicrypt = Cryptomania.
 * The IR89 result shows this is NOT possible via BB reduction.
 *
 * Open question: Can a NON-BB construction bridge the gap?
 *   - Gentry's FHE (2009) used non-BB techniques
 *   - iO (2013-) may bridge some gaps
 *   - But OWF ? OT remains open in non-BB model too
 */
void print_minicrypt_cryptomania_boundary(void);

/*
 * The Post-Quantum boundary:
 * Factoring/DLog-based TDP ? quantum broken
 * LWE ? quantum resistant
 * Is OWF ? OT possible with LWE but not with factoring?
 *   - LWE gives PKE directly (Regev 2005)
 *   - OWF ? PKE was never known even classically
 *   - So LWE is a STRONGER assumption than OWF
 */
void print_post_quantum_boundary(void);

/* ================================================================
 * L7: Application ? Cryptographic Policy
 * ================================================================ */

/*
 * Given the separation results, advise on minimal assumptions
 * needed for various cryptographic deployments.
 */
typedef struct {
    CryptoPrimitive needed_primitive;
    int security_bits;
    CryptoAssumption minimal_assumption;
    const char* recommendation;
} CryptoDeploymentAdvice;

CryptoDeploymentAdvice advise_deployment(CryptoPrimitive target, int security_bits);
void print_deployment_advice(const CryptoDeploymentAdvice* advice);

#ifdef __cplusplus
}
#endif

#endif /* BLACK_BOX_SEPARATION_H */
