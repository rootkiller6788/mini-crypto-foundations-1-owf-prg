/*
 * impagliazzo_worlds.h ? Impagliazzo's Five Worlds Formalization
 *
 * L2 Core Concept: The five possible "worlds" of computational complexity
 * and their cryptographic implications.
 *
 * Reference:
 *   Impagliazzo, "A Personal View of Average-Case Complexity" (STOC 1995)
 *   Goldreich, "Foundations of Cryptography", Vol 1, Section 2.7
 *
 * The Five Worlds form a chain of increasing cryptographic power:
 *
 *   Algorithmica ? Heuristica ? Pessiland ? Minicrypt ? Cryptomania
 *
 * Each transition corresponds to a fundamental barrier or assumption.
 * The central research objective: determine which world we live in.
 */

#ifndef IMPAGLIAZZO_WORLDS_H
#define IMPAGLIAZZO_WORLDS_H

#include "minimal_assumptions.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * L1: World Formal Definition
 * ================================================================ */

/*
 * Each world is defined by a set of axioms about computational complexity:
 *
 * Algorithmica (A1): P = NP
 *   Consequence: all of NP is easy. No cryptography possible.
 *
 * Heuristica (H1-H2):
 *   H1: P ? NP
 *   H2: DistNP ? AvgP (all NP problems are easy on average)
 *   Consequence: NP-complete problems are hard in worst-case,
 *   but every efficiently samplable distribution has an efficient
 *   algorithm that solves the problem with high probability.
 *   Still no OWF.
 *
 * Pessiland (P1-P3):
 *   P1: P ? NP
 *   P2: DistNP ? AvgP (some NP problems hard on average)
 *   P3: No OWF exists
 *   Consequence: Hard-on-average problems exist, but no cryptography.
 *   This world seemed unlikely after HILL, but was historically important.
 *
 * Minicrypt (M1-M2):
 *   M1: OWF exist
 *   M2: No TDP exists
 *   Consequence: Symmetric cryptography possible. No public-key crypto
 *   (under black-box reductions, given Impagliazzo-Rudich separation).
 *
 * Cryptomania (C1):
 *   C1: TDP exist (or equivalently, PKE possible)
 *   Consequence: Full public-key cryptography, including PKE, digital
 *   signatures, secure multi-party computation, FHE.
 */

typedef struct {
    int p_eq_np;              /* Axiom: P = NP */
    int distnp_in_avgp;       /* Axiom: DistNP ? AvgP */
    int owf_exists;           /* Axiom: ? OWF */
    int tdp_exists;           /* Axiom: ? TDP */
} WorldAxioms;

/* Standard axiom sets for each world */
WorldAxioms algorithmica_axioms(void);
WorldAxioms heuristica_axioms(void);
WorldAxioms pessiland_axioms(void);
WorldAxioms minicrypt_axioms(void);
WorldAxioms cryptomania_axioms(void);

/*
 * World Resolution Engine:
 * Given real-world evidence (crypto schemes, hardness results),
 * compute posterior likelihood of each world.
 */
typedef struct {
    double p_algorithmica;    /* Pr[Algorithmica | evidence] */
    double p_heuristica;
    double p_pessiland;
    double p_minicrypt;
    double p_cryptomania;
    double p_unknown;         /* Pr[unclassified] */
} WorldBelief;

WorldBelief world_belief_init(void);
void world_belief_update(WorldBelief* belief, const char* evidence);
ImpagliazzoWorld world_belief_map(const WorldBelief* belief);
void world_belief_print(const WorldBelief* belief);

/* ================================================================
 * L2: Evidence Accumulation ? What we know
 * ================================================================ */

/*
 * Evidence types that shift our beliefs about which world we inhabit.
 */
typedef enum {
    EVID_RSA_STILL_STANDING,     /* RSA not broken after decades */
    EVID_PKE_DEPLOYED,           /* TLS, PGP widely deployed */
    EVID_FACTORING_NO_PROGRESS,  /* No poly-time factoring discovered */
    EVID_SHA3_COMPETITION,       /* Hash functions remain secure */
    EVID_MPC_FEASIBLE,           /* Secure MPC implemented */
    EVID_BITCOIN_SECURE,         /* Bitcoin's proof-of-work holds */
    EVID_NO_P_NP_PROOF,          /* P vs NP remains open */
    EVID_QUANTUM_THREAT,         /* Shor's algorithm threatens factoring */
    EVID_IO_CANDIDATE,           /* Indistinguishability Obfuscation candidate */
    EVID_NUM
} Evidence;

const char* evidence_name(Evidence e);
double evidence_log_likelihood(Evidence e, ImpagliazzoWorld w);

/* ================================================================
 * L3: Cryptographic Landscape Per World
 * ================================================================ */

typedef struct {
    ImpagliazzoWorld world;
    int has_owf;
    int has_prg;
    int has_prf;
    int has_uowhf;
    int has_crhf;
    int has_ske;
    int has_mac;
    int has_bit_commit;
    int has_tdp;
    int has_owp;
    int has_pke;
    int has_ds;
    int has_ot;
    int has_mpc;
    int has_zk;
    int has_fhe;
    int has_io;
} WorldCapabilities;

WorldCapabilities world_capabilities(ImpagliazzoWorld w);
void world_capabilities_print(ImpagliazzoWorld w);

/* ================================================================
 * L4: Theorems about World Transitions
 * ================================================================ */

/*
 * Theorem (HILL 1999): Heuristica ? Minicrypt transition
 * If OWF exists, we are at least in Minicrypt.
 * OWF is equivalent to PRG, PRF, SKE, MAC, BitCommit.
 */
int theorem_hill_world_transition(void);

/*
 * Theorem (Impagliazzo-Rudich 1989): Minicrypt ? Cryptomania
 * Under black-box reductions, OWF does not imply OT (and thus PKE).
 */
int theorem_ir_separation(void);

/*
 * Theorem (Rompel 1990): OWF ? UOWHF (at least Minicrypt)
 * If OWF exist, universal one-way hash functions exist.
 */
int theorem_rompel_uowhf(void);

/*
 * Theorem (Naor 1991): OWF ? Bit Commitment
 */
int theorem_naor_bitcommit(void);

/* ================================================================
 * L5: World Testing / Oracle Construction
 * ================================================================ */

/*
 * Construct a relativized world (oracle model) where OWF exist
 * but TDP do not. This is the Impagliazzo-Rudich oracle.
 */
typedef struct {
    uint8_t* oracle_table;     /* random function values */
    size_t   input_size;       /* input bits per entry */
    size_t   table_entries;    /* total entries */
    int      is_permutation;   /* OWP vs OWF distinction */
} RelativizedWorld;

RelativizedWorld* rw_create(size_t input_bits, int as_permutation);
void rw_free(RelativizedWorld* rw);
int rw_eval(const RelativizedWorld* rw, const uint8_t* x, uint8_t* y);
int rw_invert_pspace(const RelativizedWorld* rw, const uint8_t* y,
                      uint8_t* x, size_t xlen);

/*
 * Prove: in a random oracle model, OWF exists but OT cannot be
 * constructed in a black-box manner from it.
 */
int rw_demonstrate_separation(RelativizedWorld* rw);

/* ================================================================
 * L6: Canonical Question: Which World Do We Live In?
 * ================================================================ */

/*
 * The current consensus (2026):
 *   - Algorithmica: nearly ruled out (P ? NP likely)
 *   - Heuristica: unlikely (crypto seems to work)
 *   - Pessiland: unlikely (OWF candidates exist)
 *   - Minicrypt: possible (if factoring is hard but LWE broken)
 *   - Cryptomania: most likely (factoring, DLog, LWE all seem hard)
 */
void print_current_consensus(void);

/*
 * The Post-Quantum update:
 * Shor's algorithm rules out factoring/DLog based TDP.
 * LWE-based crypto is quantum-resistant.
 * If LWE is secure, we remain in Cryptomania even post-quantum.
 */
void print_post_quantum_analysis(void);

#ifdef __cplusplus
}
#endif

#endif /* IMPAGLIAZZO_WORLDS_H */
