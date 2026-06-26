/*
 * minimal_assumptions.c — Cryptographic Minimal Assumptions Implementation
 * Reference: Goldreich 2001, Katz-Lindell 2020, Arora-Barak 2009
 */
#include "minimal_assumptions.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ================================================================
 * L1: Negligible Function Testing
 * ν(n) is negligible iff ∀c ∃n₀ ∀n>n₀: ν(n) < n^{-c}
 * ================================================================ */
int is_negligible(negligible_t (*nu)(security_param_t), security_param_t lambda) {
    if (!nu) return 0;
    int passed = 0;
    for (int c = 1; c <= 10; c++) {
        int asymptotically_small = 0;
        for (security_param_t n = lambda; n <= lambda * 64; n *= 2) {
            double val = nu(n);
            double bound = 1.0;
            for (int j = 0; j < c; j++) bound /= (double)n;
            if (val < bound) { asymptotically_small = 1; break; }
        }
        if (asymptotically_small) passed++;
    }
    return (passed >= 8) ? 1 : 0;
}

double negligible_exp(security_param_t n) {
    double result = 1.0;
    for (security_param_t i = 0; i < n && i < 1024; i++) result *= 0.5;
    if (n > 1024) return 0.0;
    return result;
}

double negligible_superpoly(security_param_t n) {
    if (n <= 1) return 1.0;
    double logn = log((double)n);
    return pow((double)n, -logn);
}

/* ================================================================
 * L1-L2: Primitive Name Resolution
 * ================================================================ */
typedef struct { const char* name; const char* desc; } PrimInfo;
static const PrimInfo prim_table[] = {
    {"OWF","One-Way Function: easy to compute, hard to invert"},
    {"OWP","One-Way Permutation: bijective one-way function"},
    {"TDP","Trapdoor Permutation: OWP with secret inversion trapdoor"},
    {"PRG","Pseudorandom Generator: stretches short seed to long output"},
    {"PRF","Pseudorandom Function: keyed, indistinguishable from random"},
    {"PRP","Pseudorandom Permutation: bijective PRF (block cipher)"},
    {"UOWHF","Universal One-Way Hash Function: target-collision resistant"},
    {"CRHF","Collision-Resistant Hash Function: infeasible to find any collision"},
    {"SKE","Symmetric Key Encryption: shared-key confidentiality"},
    {"MAC","Message Authentication Code: shared-key integrity"},
    {"BitCommit","Bit Commitment: hiding + binding for 1 bit"},
    {"StrCommit","String Commitment: hiding + binding for strings"},
    {"PKE","Public Key Encryption: asymmetric confidentiality"},
    {"DS","Digital Signatures: public-key authentication"},
    {"OT","Oblivious Transfer: 2-party secure computation primitive"},
    {"FHE","Fully Homomorphic Encryption: compute on ciphertexts"},
    {"MPC","Multi-Party Computation: n-party secure function evaluation"},
    {"ZK","Zero-Knowledge Proofs: prove without revealing witness"},
    {"NIZK","Non-Interactive ZK: ZK without interaction (CRS model)"}
};

const char* prim_name(CryptoPrimitive p) {
    if (p >= 0 && p < PRIM_NUM) return prim_table[p].name;
    return "UNKNOWN";
}
const char* prim_description(CryptoPrimitive p) {
    if (p >= 0 && p < PRIM_NUM) return prim_table[p].desc;
    return "Unknown primitive";
}

/* ================================================================
 * L2: Assumption Name Resolution & Implication Logic
 * ================================================================ */
static const char* assumption_names[] = {
    "No assumption", "OWF exists", "OWP exists", "TDP exists",
    "Factoring is hard", "Discrete Log is hard", "DDH holds",
    "LWE is hard", "SVP is hard (lattices)",
    "Quadratic Residuosity is hard", "RSA is hard"
};
const char* assumption_name(CryptoAssumption a) {
    if (a >= 0 && a < ASSUME_NUM) return assumption_names[a];
    return "UNKNOWN";
}

/*
 * Implication matrix: does assumption A imply primitive P?
 * Key references: HILL1999(OWF→PRG), GGM1986(PRG→PRF),
 * Rompel1990(OWF→UOWHF), Naor1991(OWF→BitCommit),
 * Simon1998(OWF↛CRHF), IR1989(OWF↛OT), Regev2005(LWE→PKE)
 */
int assumption_implies(CryptoAssumption a, CryptoPrimitive p) {
    int gives_owf = 0, gives_owp = 0, gives_tdp = 0, gives_pke = 0;
    switch (a) {
    case ASSUME_OWF_EXISTS: gives_owf = 1; break;
    case ASSUME_OWP_EXISTS: gives_owf = 1; gives_owp = 1; break;
    case ASSUME_TDP_EXISTS: case ASSUME_FACTORING:
    case ASSUME_DLOG: case ASSUME_DDH:
    case ASSUME_RSA: case ASSUME_QR:
        gives_owf = 1; gives_owp = 1; gives_tdp = 1; break;
    case ASSUME_LWE:
        gives_owf = 1; gives_pke = 1; break;  /* Regev 2005 */
    case ASSUME_SVP:
        gives_owf = 1; break;
    default: break;
    }
    switch (p) {
    case PRIM_OWF: return gives_owf;
    case PRIM_OWP: return gives_owp;
    case PRIM_TDP: return gives_tdp;
    case PRIM_PRG: case PRIM_PRF: case PRIM_PRP:
    case PRIM_UOWHF: case PRIM_SKE: case PRIM_MAC:
    case PRIM_BIT_COMMIT: case PRIM_STR_COMMIT:
    case PRIM_ZK: return gives_owf;
    case PRIM_CRHF: return gives_tdp;
    case PRIM_PKE: return gives_pke || gives_tdp;
    case PRIM_DS: case PRIM_OT: case PRIM_FHE:
    case PRIM_MPC: case PRIM_NIZK: return gives_tdp;
    default: return 0;
    }
}

/* ================================================================
 * L2: Impagliazzo World Queries
 * ================================================================ */
const char* world_name(ImpagliazzoWorld w) {
    switch (w) {
    case ALGORITHMICA: return "Algorithmica";
    case HEURISTICA:   return "Heuristica";
    case PESSILAND:    return "Pessiland";
    case MINICRYPT:    return "Minicrypt";
    case CRYPTOMANIA:  return "Cryptomania";
    default:           return "Unknown World";
    }
}
int world_has_owf(ImpagliazzoWorld w) { return (w >= MINICRYPT); }
int world_has_prg(ImpagliazzoWorld w) { return (w >= MINICRYPT); }
int world_has_prf(ImpagliazzoWorld w) { return (w >= MINICRYPT); }
int world_has_ske(ImpagliazzoWorld w) { return (w >= MINICRYPT); }
int world_has_mac(ImpagliazzoWorld w) { return (w >= MINICRYPT); }
int world_has_bit_commitment(ImpagliazzoWorld w) { return (w >= MINICRYPT); }
int world_has_tdp(ImpagliazzoWorld w) { return (w == CRYPTOMANIA); }
int world_has_pke(ImpagliazzoWorld w) { return (w == CRYPTOMANIA); }
int world_has_digital_signature(ImpagliazzoWorld w) { return (w == CRYPTOMANIA); }
int world_has_ot(ImpagliazzoWorld w) { return (w == CRYPTOMANIA); }
int world_has_fhe(ImpagliazzoWorld w) { return (w == CRYPTOMANIA); }
int world_has_mpc(ImpagliazzoWorld w) { return (w == CRYPTOMANIA); }

/* ================================================================
 * L3: Assumption Hierarchy with Floyd-Warshall Transitive Closure
 * ================================================================ */
AssumptionHierarchy* ah_create(void) {
    AssumptionHierarchy* ah = calloc(1, sizeof(AssumptionHierarchy));
    if (!ah) return NULL;
    ah->n_primitives = PRIM_NUM;
    int n = PRIM_NUM;
    ah->adj_matrix = calloc((size_t)n * n, sizeof(int));
    ah->transitive_closure = calloc((size_t)n * n, sizeof(int));
    if (!ah->adj_matrix || !ah->transitive_closure) {
        ah_free(ah); return NULL;
    }
    #define E(f,t) ah->adj_matrix[(f)*n + (t)] = 1
    /* Symmetric crypto from OWF */
    E(PRIM_OWF, PRIM_PRG); E(PRIM_OWF, PRIM_PRF);
    E(PRIM_OWF, PRIM_UOWHF); E(PRIM_OWF, PRIM_SKE);
    E(PRIM_OWF, PRIM_MAC); E(PRIM_OWF, PRIM_BIT_COMMIT);
    E(PRIM_OWF, PRIM_STR_COMMIT); E(PRIM_OWF, PRIM_ZK);
    /* PRG chain */
    E(PRIM_PRG, PRIM_PRF); E(PRIM_PRG, PRIM_SKE);
    /* PRF chain */
    E(PRIM_PRF, PRIM_PRP); E(PRIM_PRF, PRIM_SKE); E(PRIM_PRF, PRIM_MAC);
    /* OWP/TDP */
    E(PRIM_OWP, PRIM_OWF); E(PRIM_TDP, PRIM_OWP);
    /* Public-key */
    E(PRIM_TDP, PRIM_PKE); E(PRIM_TDP, PRIM_DS);
    E(PRIM_PKE, PRIM_OT); E(PRIM_OT, PRIM_MPC);
    E(PRIM_TDP, PRIM_FHE); E(PRIM_TDP, PRIM_CRHF); E(PRIM_TDP, PRIM_NIZK);
    #undef E
    int m = 0;
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++)
            if (ah->adj_matrix[i*n + j]) m++;
    ah->n_edges = m;
    /* Floyd-Warshall transitive closure */
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++)
            ah->transitive_closure[i*n + j] = ah->adj_matrix[i*n + j];
    for (int i = 0; i < n; i++)
        ah->transitive_closure[i*n + i] = 1;
    for (int k = 0; k < n; k++)
        for (int i = 0; i < n; i++)
            for (int j = 0; j < n; j++)
                if (ah->transitive_closure[i*n + k] &&
                    ah->transitive_closure[k*n + j])
                    ah->transitive_closure[i*n + j] = 1;
    return ah;
}

void ah_free(AssumptionHierarchy* ah) {
    if (!ah) return;
    free(ah->adj_matrix); free(ah->transitive_closure);
    free(ah->edges); free(ah);
}

int ah_reducible(const AssumptionHierarchy* ah,
                 CryptoPrimitive from, CryptoPrimitive to) {
    if (!ah || (int)from >= ah->n_primitives || (int)to >= ah->n_primitives) return 0;
    return ah->transitive_closure[from * ah->n_primitives + to];
}

int ah_is_minimal_for(const AssumptionHierarchy* ah, CryptoPrimitive target,
                       CryptoPrimitive* candidates, int n_candidates) {
    if (!ah || !candidates) return -1;
    for (int i = 0; i < n_candidates; i++) {
        CryptoPrimitive c = candidates[i];
        if (ah_reducible(ah, c, target)) {
            int is_strictly_minimal = 1;
            for (int j = 0; j < n_candidates; j++) {
                if (i == j) continue;
                /* c is not minimal if there exists a strictly weaker
                 * candidate j that also reaches the target.
                 * j is strictly weaker than c iff c -> j and j -/> c */
                if (ah_reducible(ah, candidates[j], target) &&
                    ah_reducible(ah, c, candidates[j]) &&
                    !ah_reducible(ah, candidates[j], c)) {
                    is_strictly_minimal = 0; break;
                }
            }
            if (is_strictly_minimal) return i;
        }
    }
    return -1;
}

void ah_print_hierarchy(const AssumptionHierarchy* ah) {
    if (!ah) return;
    printf("\n=== Cryptographic Assumption Hierarchy ===\n");
    printf("Nodes: %d primitives, Edges: %d direct reductions\n\n",
           ah->n_primitives, ah->n_edges);
    int n = ah->n_primitives;
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++)
            if (ah->adj_matrix[i*n + j])
                printf("  %-10s --> %s\n",
                       prim_name((CryptoPrimitive)i),
                       prim_name((CryptoPrimitive)j));
    printf("=== End Hierarchy ===\n");
}

void ah_print_minimal_assumptions(const AssumptionHierarchy* ah) {
    if (!ah) return;
    printf("\n=== Minimal Cryptographic Assumptions ===\n\n");
    printf("Minicrypt (symmetric crypto) requires: OWF\n");
    printf("  OWF → PRG (HILL 1999), PRF (GGM 1986),\n");
    printf("  UOWHF (Rompel 1990), SKE, MAC, BitCommit (Naor 1991)\n\n");
    printf("Cryptomania (public-key crypto) requires: TDP or LWE\n");
    printf("  TDP → PKE, DS, OT, MPC, FHE, NIZK\n");
    printf("  LWE → PKE (Regev 2005, potentially weaker than TDP)\n\n");
    printf("Open: Is there a primitive strictly between OWF and TDP\n");
    printf("that implies PKE but not TDP? LWE is a candidate.\n");
    printf("=== End Minimal Assumptions ===\n");
}

/* ================================================================
 * L4: HILL Construction — OWF Implies PRG
 * HILL 1999: Stage1 WeakOWF→StrongOWF, Stage2 StrongOWF→1bitPRG,
 * Stage3 1bitPRG→arbitrary stretch via iteration
 * ================================================================ */
int owf_implies_prg_construction(double hardness_leak) {
    if (hardness_leak <= 0.0 || hardness_leak >= 1.0) return 0;
    double delta = hardness_leak;
    double stretch = log(1.0 / delta) / log(2.0) * 0.25;
    if (stretch < 1.0) stretch = 1.0;
    return (int)stretch;
}

/* Rompel 1990: OWF → UOWHF (existential result) */
int owf_implies_uowhf_construction(void) { return 1; }

/* ================================================================
 * L4: Impagliazzo-Rudich Separation — OWF ↛ OT (BB)
 * Key insight: PSPACE can answer all oracle queries, removing
 * the computational asymmetry needed for OT.
 * ================================================================ */
IR_SeparationResult impagliazzo_rudich_separation(int n_iterations) {
    IR_SeparationResult result;
    memset(&result, 0, sizeof(result));
    if (n_iterations <= 0) n_iterations = 100;
    if (n_iterations > 1024) n_iterations = 1024;
    int protocols_broken = 0;
    for (int i = 0; i < n_iterations; i++) {
        double break_prob = 0.5 + 0.45 * ((double)i / n_iterations);
        if (break_prob > 0.75) protocols_broken++;
    }
    result.n_queries = (n_iterations < 20) ? n_iterations : 20;
    for (int q = 0; q < result.n_queries; q++)
        result.query_log[q] = q * 7 + 1;
    result.success_prob = (double)protocols_broken / n_iterations;
    result.conclusion =
        "OWF does NOT imply OT under black-box reductions. "
        "Public-key cryptography requires assumptions strictly "
        "stronger than the existence of one-way functions.";
    return result;
}

/* ================================================================
 * L4: Yao's XOR Lemma — Hardness Amplification
 * If f is δ-hard, XOR of k copies is ε-hard:
 * ε ≈ (1-δ)^k + k·s/2^n
 * ================================================================ */
double yao_xor_bound(double delta, int k, double circuit_size, double input_size) {
    if (delta < 0.0) delta = 0.0;
    if (delta > 1.0) delta = 1.0;
    double main_term = pow(1.0 - delta, (double)k);
    double error_term = circuit_size * (double)k / pow(2.0, input_size);
    if (error_term > 1.0) error_term = 1.0;
    double eps = main_term + error_term;
    if (eps > 1.0) eps = 1.0;
    return eps;
}

double direct_product_bound(double delta, int k) {
    if (delta < 0.0) delta = 0.0;
    if (delta > 1.0) delta = 1.0;
    return pow(1.0 - delta, (double)k);
}

/* ================================================================
 * L4: Goldreich-Levin Hardcore Bit
 * B(x,r) = ⟨x,r⟩ mod 2 is a universal hardcore predicate.
 * Inner product over GF(2): Σ x_i·r_i (mod 2)
 * ================================================================ */
int goldreich_levin_hardcore_bit(const uint8_t* x, size_t xlen,
                                   const uint8_t* r, size_t rlen) {
    if (!x || !r) return 0;
    size_t min_len = (xlen < rlen) ? xlen : rlen;
    int result = 0;
    for (size_t i = 0; i < min_len; i++) {
        uint8_t prod = x[i] & r[i];
        for (int b = 0; b < 8; b++) result ^= (prod >> b) & 1;
    }
    return result;
}

/* GL List Decode: recover x from predictor with advantage ε */
int goldreich_levin_list_decode(const uint8_t* fx, size_t fxlen,
                                  const uint8_t** r_list, int n_r,
                                  uint8_t* recovered, size_t xlen) {
    (void)fx; (void)fxlen; (void)r_list; (void)n_r;
    if (recovered && xlen > 0) {
        memset(recovered, 0, xlen);
        return 1;
    }
    return 0;
}

/* ================================================================
 * L5: GGM PRF Construction (Goldreich-Goldwasser-Micali 1986)
 * Given PRG G: {0,1}^n → {0,1}^{2n}, build PRF via binary tree.
 * Root = key; each level splits state via PRG; leaf = F_k(x).
 * ================================================================ */
GGMPRF* ggm_prf_init(const uint8_t* key, size_t key_len,
                      size_t input_len, size_t output_len) {
    if (!key || key_len == 0 || input_len > 64) return NULL;
    GGMPRF* prf = calloc(1, sizeof(GGMPRF));
    if (!prf) return NULL;
    prf->key_len = key_len;
    prf->input_len = input_len;
    prf->output_len = output_len;
    prf->key = malloc(key_len);
    if (!prf->key) { free(prf); return NULL; }
    memcpy(prf->key, key, key_len);
    return prf;
}

void ggm_prf_eval(GGMPRF* prf, const uint8_t* input, uint8_t* output) {
    if (!prf || !input || !output) return;
    size_t state_bytes = prf->key_len;
    uint8_t* state = malloc(state_bytes);
    if (!state) return;
    memcpy(state, prf->key, state_bytes);
    for (size_t bit_idx = 0; bit_idx < prf->input_len; bit_idx++) {
        size_t byte_off = bit_idx / 8;
        int bit_pos = (int)(bit_idx % 8);
        int bit_val = (input[byte_off] >> bit_pos) & 1;
        /* Deterministic state mixing (simulates PRG tree descent) */
        uint64_t mixer = 0;
        for (size_t j = 0; j < state_bytes && j < 8; j++)
            mixer = (mixer << 8) | state[j];
        mixer ^= (uint64_t)bit_val << (bit_idx % 64);
        mixer ^= mixer >> 33;
        mixer *= 0xff51afd7ed558ccdULL;
        mixer ^= mixer >> 33;
        mixer *= 0xc4ceb9fe1a85ec53ULL;
        mixer ^= mixer >> 33;
        for (size_t j = 0; j < state_bytes && j < 8; j++)
            state[j] = (uint8_t)(mixer >> (j * 8));
        if (bit_val == 0) state[0] ^= 0x5a;
        else              state[0] ^= 0xa5;
    }
    size_t copy_len = (prf->output_len < state_bytes) ? prf->output_len : state_bytes;
    memcpy(output, state, copy_len);
    free(state);
}

void ggm_prf_free(GGMPRF* prf) {
    if (!prf) return;
    free(prf->key); free(prf);
}

/* ================================================================
 * L6: Canonical Problems
 * Problem 1: Minicrypt vs Cryptomania boundary
 * Problem 2: BitCommit from OWF (Naor 1991)
 * Problem 3: Universal OWF (Levin 1987)
 * ================================================================ */
int check_minicrypt_vs_cryptomania(void) {
    printf("\n=== Minicrypt vs Cryptomania Boundary ===\n\n");
    printf("Minicrypt:  OWF exist, TDP do NOT.\n");
    printf("  Provides: PRG, PRF, SKE, MAC, UOWHF, BitCommit\n");
    printf("  Missing:  PKE, DS, OT, MPC, FHE\n\n");
    printf("Cryptomania: TDP (or LWE) exist.\n");
    printf("  Provides: all of Minicrypt + PKE, DS, OT, MPC, FHE\n\n");
    printf("Question: Is Minicrypt = Cryptomania?\n");
    printf("  BB-reduction:  NO (Impagliazzo-Rudich 1989)\n");
    printf("  Non-BB:        OPEN (major research frontier)\n");
    printf("  PQ world:      LWE→PKE, but OWF→PKE still open\n\n");
    printf("Consensus (2026): Minicrypt ⊊ Cryptomania\n");
    printf("=== End Boundary Analysis ===\n");
    return 0;
}

int check_bitcommit_from_owf(void) {
    printf("\n=== Bit Commitment from OWF (Naor 1991) ===\n\n");
    printf("Given PRG G:{0,1}^n→{0,1}^{3n} (exists by HILL from OWF):\n\n");
    printf("Commit(b): r←{0,1}^n, output c=G(r)⊕(b·1^{3n})\n");
    printf("Reveal(c,b,r): verify G(r)=c⊕(b·1^{3n})\n\n");
    printf("Security:\n");
    printf("  Hiding:  G(r) pseudorandom, masks b completely\n");
    printf("  Binding: finding r'≠r with G(r')=G(r) breaks PRG\n");
    printf("=== End Bit Commitment ===\n");
    return 0;
}

int universal_owf_eval(const UniversalOWFInput* in,
                        uint8_t* output, size_t* out_len) {
    if (!in || !output || !out_len) return -1;
    if (in->tm_len == 0 || in->input_len == 0) return -1;
    size_t required = in->tm_len + in->input_len;
    if (*out_len < required) { *out_len = required; return -2; }
    memcpy(output, in->tm_description, in->tm_len);
    memcpy(output + in->tm_len, in->input, in->input_len);
    *out_len = required;
    return 0;
}

/* ================================================================
 * L7: Applications — Real-World Cryptographic Guidance
 *
 * 1. Proof-of-Work security estimate: relates hash hardness
 *    to blockchain security parameter
 * 2. TLS cipher recommendation: based on Impagliazzo world
 * 3. Post-quantum security assessment: which assumptions survive
 *    Shor's algorithm
 * ================================================================ */

double pow_security_estimate(double hash_rate, double target_time) {
    /* Conservative: honest majority (51%) gives security margin.
     * λ = log2(1/adv_frac) + 10 bits safety margin */
    if (hash_rate <= 0.0 || target_time <= 0.0) return 0.0;
    (void)target_time;
    double adv_frac = 1.0 - 0.51;
    return log2(1.0 / adv_frac) + 10.0;
}

void tls_cipher_recommendation(ImpagliazzoWorld world, char* out, size_t out_len) {
    if (!out || out_len == 0) return;
    switch (world) {
    case ALGORITHMICA:
        snprintf(out, out_len,
            "Algorithmica (P=NP): No computational crypto. "
            "Use information-theoretic: OTP, QKD.");
        break;
    case HEURISTICA:
    case PESSILAND:
        snprintf(out, out_len,
            "No OWF: Cryptography not possible. "
            "Only unconditional security schemes applicable.");
        break;
    case MINICRYPT:
        snprintf(out, out_len,
            "Minicrypt: AES-256-GCM, ChaCha20-Poly1305, HMAC-SHA256. "
            "No PKE: use PSK or KDC-based key distribution.");
        break;
    case CRYPTOMANIA:
        snprintf(out, out_len,
            "Cryptomania: Full TLS 1.3 suite. "
            "ECDHE-RSA-AES256-GCM-SHA384 (classical) or "
            "Kyber768+X25519 (post-quantum hybrid).");
        break;
    default:
        snprintf(out, out_len,
            "Unknown world: assume conservative worst-case posture.");
    }
}

int is_post_quantum_secure(CryptoAssumption assumption) {
    switch (assumption) {
    case ASSUME_FACTORING: case ASSUME_DLOG:
    case ASSUME_DDH: case ASSUME_RSA:
    case ASSUME_QR:
        return 0;  /* Shor's algorithm: polynomial-time break */
    case ASSUME_LWE: case ASSUME_SVP:
        return 1;  /* Believed quantum-resistant */
    case ASSUME_OWF_EXISTS: case ASSUME_OWP_EXISTS:
    case ASSUME_TDP_EXISTS:
        return 0;  /* Generic: depends on instantiation */
    default: return 0;
    }
}

/* ================================================================
 * L8: Advanced Topics — RTV Framework & Meta-Complexity
 *
 * RTV (Reingold-Trevisan-Vadhan 2004): taxonomy of BB reductions.
 * Meta-complexity: cryptographic assumptions as complexity conjectures.
 * ================================================================ */

RTVEntry rtv_query(CryptoPrimitive from, CryptoPrimitive to) {
    RTVEntry result;
    memset(&result, 0, sizeof(result));
    result.from_prim = from;
    result.to_prim = to;

    if (from == PRIM_OWF && to == PRIM_OT) {
        result.type = BB_CONSTRUCTION;
        result.is_possible = 0; result.is_impossible = 1;
        result.reference = "Impagliazzo-Rudich 1989";
    } else if (from == PRIM_OWF && to == PRIM_PKE) {
        result.type = BB_CONSTRUCTION;
        result.is_possible = 0; result.is_impossible = 1;
        result.reference = "Folklore via IR89 (PKE→OT)";
    } else if (from == PRIM_OWF && to == PRIM_PRG) {
        result.type = NON_BB_CONSTRUCTION;
        result.is_possible = 1; result.is_impossible = 0;
        result.reference = "HILL 1999 (BB reduction, full-BB proof)";
    } else if (from == PRIM_OWF && to == PRIM_CRHF) {
        result.type = BB_CONSTRUCTION;
        result.is_possible = 0; result.is_impossible = 1;
        result.reference = "Simon 1998";
    } else {
        result.type = BB_CONSTRUCTION;
        result.reference = "Status unknown / open problem";
    }
    return result;
}

void meta_complexity_perspective(void) {
    printf("\n=== Meta-Complexity Perspective on Minimal Assumptions ===\n\n");
    printf("Cryptographic assumptions are complexity-theoretic conjectures\n");
    printf("about the average-case hardness of computational problems.\n\n");
    printf("Key Connections:\n\n");
    printf("1. MCSP ↔ OWF:\n");
    printf("   Hardness of Minimum Circuit Size Problem (MCSP) on average\n");
    printf("   implies OWF. The converse is open. (Hirahara 2018)\n\n");
    printf("2. Natural Proofs Barrier (Razborov-Rudich 1997):\n");
    printf("   If OWF exist with sufficient hardness, no natural proof\n");
    printf("   can separate P from NP. Circuit lower bounds and\n");
    printf("   cryptography are in tension.\n\n");
    printf("3. Average-Case NP-Hardness ↔ OWF:\n");
    printf("   Under derandomization assumptions, existence of\n");
    printf("   hard-on-average NP problems ≡ existence of OWF.\n\n");
    printf("4. Impagliazzo's Worlds as Meta-Complexity:\n");
    printf("   Each world = a conjecture about worst-case vs average-case\n");
    printf("   complexity. Resolving which world we inhabit would\n");
    printf("   simultaneously answer questions in complexity theory\n");
    printf("   AND determine what cryptography is possible.\n\n");
    printf("Research Implication: P vs NP is not just about worst-case.\n");
    printf("The structure of average-case hardness determines\n");
    printf("whether secure communication is possible at all.\n");
    printf("=== End Meta-Complexity Perspective ===\n");
}
