/*
 * minimal_assumptions.h ? Cryptographic Minimal Assumptions Framework
 *
 * The central question of cryptographic foundations:
 *   "What is the weakest assumption under which cryptography is possible?"
 *
 * This module formalizes Impagliazzo's Five Worlds (1995) and the
 * hierarchy of cryptographic assumptions from weak (OWF) to strong (TDP,
 * PKE, OT), along with hardness amplification and black-box separation
 * results that rigorously establish which assumptions are truly minimal.
 *
 * Core Theorems:
 *   T1: OWF ? PRG (H?stad-Impagliazzo-Levin-Luby 1999)
 *   T2: OWF ? UOWHF (Rompel 1990)
 *   T3: OWF ? symmetric encryption, MAC, bit commitment
 *   T4: OWF ? OT (black-box separation, Impagliazzo-Rudich 1989)
 *   T5: OWF ? PRF (Goldreich-Goldwasser-Micali 1986)
 *   T6: Yao's XOR Lemma: if f is (1-?)-hard then f^{?k} is (1/2+?)-hard
 *
 * Reference:
 *   Goldreich, "Foundations of Cryptography: Basic Tools" (2001)
 *   Katz & Lindell, "Introduction to Modern Cryptography" (3rd ed, 2020)
 *   Impagliazzo, "A Personal View of Average-Case Complexity" (1995)
 *   Arora-Barak, "Computational Complexity: A Modern Approach" (2009)
 *
 * Course Mapping:
 *   MIT 6.875: Cryptography and Cryptanalysis
 *   Stanford CS255: Introduction to Cryptography
 *   Princeton COS 433: Cryptography
 *   ETH 263-4660: Foundations of Cryptography
 */

#ifndef MINIMAL_ASSUMPTIONS_H
#define MINIMAL_ASSUMPTIONS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * L1: Core Definitions ? Cryptographic Primitives
 * ================================================================ */

/*
 * Security parameter ? ? ?.
 * All cryptographic constructions are parameterized by ?.
 * Running times are measured as functions of ?.
 */
typedef uint64_t security_param_t;

/*
 * Negligible function ?: ? ? [0,1]
 * ?(?) = ?^{-?(1)} ? decays faster than any inverse polynomial.
 * Formal: ?c>0 ??? ??>??: ?(?) < ?^{-c}
 */
typedef double negligible_t;
int is_negligible(negligible_t (*nu)(security_param_t), security_param_t lambda);

/* Standard negligible functions for testing */
double negligible_exp(security_param_t n);
double negligible_superpoly(security_param_t n);

/*
 * One-Way Function (OWF) f: {0,1}* ? {0,1}*
 * - Easy to compute: ? poly-time A computing f(x)
 * - Hard to invert: ? PPT A, Pr[A(f(x),1^n) ? f^{-1}(f(x))] = ?(n)
 */
typedef struct {
    size_t in_len;
    size_t out_len;
    double hardness;
} OWFParams;

/*
 * Pseudorandom Generator (PRG) G: {0,1}^n ? {0,1}^{?(n)}, ?(n) > n
 * The output is computationally indistinguishable from uniform.
 */
typedef struct {
    size_t seed_len;
    size_t output_len;
    double stretch;
} PRGParams;

/*
 * Trapdoor Permutation (TDP):
 * A family of permutations {f_i} with trapdoor t_i enabling inversion.
 */
typedef struct {
    int has_trapdoor;
    size_t domain_bits;
    uint8_t* public_key;
    uint8_t* trapdoor;
    size_t pk_len, td_len;
} TDPParams;

/*
 * Oblivious Transfer (OT): Sender has (m0,m1), Receiver has b?{0,1}.
 */
typedef enum {
    OT_RABIN,
    OT_CHOICE,
    OT_STRING
} OTType;

/* ================================================================
 * L2: Core Concepts ? Impagliazzo's Five Worlds
 * ================================================================ */

/*
 * Impagliazzo's Five Worlds (1995)
 * Each "world" is a conjecture about the relationship between
 * worst-case complexity, average-case complexity, and cryptography.
 */
typedef enum {
    ALGORITHMICA,   /* P = NP ? no crypto possible */
    HEURISTICA,     /* P ? NP, NP hard on average but no OWF */
    PESSILAND,      /* OWF exist, but no TDP */
    MINICRYPT,      /* OWF exist ? symmetric crypto possible */
    CRYPTOMANIA     /* TDP exist ? public-key crypto possible */
} ImpagliazzoWorld;

const char* world_name(ImpagliazzoWorld w);
int world_has_owf(ImpagliazzoWorld w);
int world_has_prg(ImpagliazzoWorld w);
int world_has_prf(ImpagliazzoWorld w);
int world_has_ske(ImpagliazzoWorld w);
int world_has_mac(ImpagliazzoWorld w);
int world_has_bit_commitment(ImpagliazzoWorld w);
int world_has_tdp(ImpagliazzoWorld w);
int world_has_pke(ImpagliazzoWorld w);
int world_has_digital_signature(ImpagliazzoWorld w);
int world_has_ot(ImpagliazzoWorld w);
int world_has_fhe(ImpagliazzoWorld w);
int world_has_mpc(ImpagliazzoWorld w);

/* ================================================================
 * L2: Primitive Enumeration
 * ================================================================ */

typedef enum {
    PRIM_OWF,           /* One-Way Function */
    PRIM_OWP,           /* One-Way Permutation */
    PRIM_TDP,           /* Trapdoor Permutation */
    PRIM_PRG,           /* Pseudorandom Generator */
    PRIM_PRF,           /* Pseudorandom Function */
    PRIM_PRP,           /* Pseudorandom Permutation */
    PRIM_UOWHF,         /* Universal One-Way Hash Function */
    PRIM_CRHF,          /* Collision-Resistant Hash Function */
    PRIM_SKE,           /* Symmetric Key Encryption */
    PRIM_MAC,           /* Message Authentication Code */
    PRIM_BIT_COMMIT,    /* Bit Commitment */
    PRIM_STR_COMMIT,    /* String Commitment */
    PRIM_PKE,           /* Public Key Encryption */
    PRIM_DS,            /* Digital Signatures */
    PRIM_OT,            /* Oblivious Transfer */
    PRIM_FHE,           /* Fully Homomorphic Encryption */
    PRIM_MPC,           /* Multi-Party Computation */
    PRIM_ZK,            /* Zero-Knowledge Proofs */
    PRIM_NIZK,          /* Non-Interactive ZK */
    PRIM_NUM            /* sentinel */
} CryptoPrimitive;

const char* prim_name(CryptoPrimitive p);
const char* prim_description(CryptoPrimitive p);

/* ================================================================
 * L2: Assumption Types
 * ================================================================ */

typedef enum {
    ASSUME_NONE,
    ASSUME_OWF_EXISTS,
    ASSUME_OWP_EXISTS,
    ASSUME_TDP_EXISTS,
    ASSUME_FACTORING,
    ASSUME_DLOG,
    ASSUME_DDH,
    ASSUME_LWE,
    ASSUME_SVP,
    ASSUME_QR,
    ASSUME_RSA,
    ASSUME_NUM
} CryptoAssumption;

const char* assumption_name(CryptoAssumption a);
int assumption_implies(CryptoAssumption a, CryptoPrimitive p);

/* ================================================================
 * L3: Mathematical Structures ? Assumption Hierarchy
 * ================================================================ */

typedef struct {
    CryptoPrimitive from;
    CryptoPrimitive to;
    int is_black_box;
    int is_separation;
    const char* reference;
} ReductionEdge;

typedef struct {
    int n_primitives;
    int n_edges;
    ReductionEdge* edges;
    int* adj_matrix;
    int* transitive_closure;
} AssumptionHierarchy;

AssumptionHierarchy* ah_create(void);
void ah_free(AssumptionHierarchy* ah);
int ah_reducible(const AssumptionHierarchy* ah, CryptoPrimitive from, CryptoPrimitive to);
int ah_is_minimal_for(const AssumptionHierarchy* ah, CryptoPrimitive target,
                      CryptoPrimitive* candidates, int n_candidates);
void ah_print_hierarchy(const AssumptionHierarchy* ah);
void ah_print_minimal_assumptions(const AssumptionHierarchy* ah);

/* ================================================================
 * L4: Fundamental Laws
 * ================================================================ */

/*
 * Theorem (HILL 1999): OWF ? PRG
 * Construction: hardcore bit extraction ? 1-bit stretch ? iteration
 */
int owf_implies_prg_construction(double hardness_leak);

/*
 * Theorem (Rompel 1990): OWF ? UOWHF
 */
int owf_implies_uowhf_construction(void);

/*
 * Theorem (Impagliazzo-Rudich 1989): OWF ? OT in black-box model
 */
typedef struct {
    int n_queries;
    int query_log[1024];
    double success_prob;
    const char* conclusion;
} IR_SeparationResult;

IR_SeparationResult impagliazzo_rudich_separation(int n_iterations);

/* ================================================================
 * L4: Hardness Amplification ? Yao's XOR Lemma
 * ================================================================ */

/*
 * Yao's XOR Lemma (1982): If f is ?-hard, then XOR of k independent
 * copies is (1/2 + ?)-hard with ? ? (1-?)^k ? poly(n)/s.
 */
double yao_xor_bound(double delta, int k, double circuit_size, double input_size);

/*
 * Direct Product Theorem: If f is ?-hard, computing all k copies
 * correctly is exponentially small in k.
 */
double direct_product_bound(double delta, int k);

/*
 * Goldreich-Levin Hardcore Bit:
 * B(x,r) = ?x,r? mod 2 is a hardcore bit for g(x,r) = (f(x), r).
 */
int goldreich_levin_hardcore_bit(const uint8_t* x, size_t xlen,
                                  const uint8_t* r, size_t rlen);

int goldreich_levin_list_decode(const uint8_t* fx, size_t fxlen,
                                 const uint8_t** r_list, int n_r,
                                 uint8_t* recovered, size_t xlen);

/* ================================================================
 * L5: Algorithms ? Construction Methods
 * ================================================================ */

typedef struct {
    uint8_t* seed;
    size_t seed_len;
    uint8_t* output;
} OneBitPRG;

int hill_prg_stretch(size_t seed_len, size_t target_len, double security);

typedef struct {
    size_t key_len;
    size_t input_len;
    size_t output_len;
    uint8_t* key;
} GGMPRF;

GGMPRF* ggm_prf_init(const uint8_t* key, size_t key_len,
                      size_t input_len, size_t output_len);
void ggm_prf_eval(GGMPRF* prf, const uint8_t* input, uint8_t* output);
void ggm_prf_free(GGMPRF* prf);

/* ================================================================
 * L6: Canonical Problems
 * ================================================================ */

int check_minicrypt_vs_cryptomania(void);
int check_bitcommit_from_owf(void);

typedef struct {
    uint8_t* tm_description;
    size_t    tm_len;
    uint8_t* input;
    size_t    input_len;
    uint64_t  time_bound;
} UniversalOWFInput;

int universal_owf_eval(const UniversalOWFInput* in,
                        uint8_t* output, size_t* out_len);

/* ================================================================
 * L7: Applications
 * ================================================================ */

double pow_security_estimate(double hash_rate, double target_time);
void tls_cipher_recommendation(ImpagliazzoWorld world, char* out, size_t out_len);
int is_post_quantum_secure(CryptoAssumption assumption);

/* ================================================================
 * L8: Advanced Topics
 * ================================================================ */

typedef enum {
    BB_CONSTRUCTION,
    NON_BB_CONSTRUCTION
} ConstructionType;

/*
 * RTV Framework (Reingold-Trevisan-Vadhan 2004):
 * Systematic study of limitations of black-box reductions.
 */
typedef struct {
    ConstructionType type;
    CryptoPrimitive from_prim;
    CryptoPrimitive to_prim;
    int is_possible;
    int is_impossible;
    const char* reference;
} RTVEntry;

RTVEntry rtv_query(CryptoPrimitive from, CryptoPrimitive to);
void meta_complexity_perspective(void);

#ifdef __cplusplus
}
#endif

#endif /* MINIMAL_ASSUMPTIONS_H */
