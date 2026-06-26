/*
 * ggm.h - Goldreich-Goldwasser-Micali (GGM) PRF Construction
 *
 * L4 Fundamental Law (GGM Theorem):
 *   If length-doubling pseudorandom generators exist,
 *   then pseudorandom functions exist.
 *   PRG => PRF  (existential equivalence)
 *
 * The GGM Construction:
 *   Given PRG G: {0,1}^n -> {0,1}^{2n}, construct PRF
 *     F: {0,1}^n x {0,1}^m -> {0,1}^n
 *   as a binary tree of depth m:
 *     F_k(x_1 x_2 ... x_m) = G_{x_m}(G_{x_{m-1}}(... G_{x_1}(k)...))
 *   where G_0(s) = left half of G(s), G_1(s) = right half of G(s).
 *
 * Security Proof (Hybrid Argument):
 *   For any PPT adversary A making q queries, there exists a
 *   distinguisher D for G such that:
 *     Adv^{PRF}_A <= m * q * Adv^{PRG}_D
 *   Intuition: m hybrids replace tree levels one-by-one with random.
 *
 * Remark: The GGM construction is NOT practical (2^m possible inputs
 *   but evaluation is linear in m). However, it is THEORETICALLY
 *   fundamental �� it shows OWF => PRG => PRF.
 *
 * Reference:
 *   Goldreich, Goldwasser, Micali (STOC 1984, JACM 1986)
 *   "How to Construct Random Functions"
 *   Arora-Barak section 9.3.1
 *   Katz-Lindell section 7.5
 *
 * Courses:
 *   MIT 6.875, Princeton COS 522, Stanford CS255
 */

#ifndef GGM_H
#define GGM_H

#include "prg.h"
#include "prf.h"

/* ================================================================
 * GGM Binary Tree Data Structure (L3)
 * ================================================================ */

/*
 * GGMNode: A node in the GGM binary evaluation tree.
 * Each node holds an n-bit label derived from PRG.
 * The root (level 0) holds the secret key k.
 * A leaf (level m) holds the PRF output f_k(x).
 */
typedef struct GGMNode_impl GGMNode;

struct GGMNode_impl {
    int        level;         /* depth from root (0 = root, m = leaf) */
    int        bit_path;      /* path bit at this node (0 or 1, -1 for root) */
    BitString* label;         /* n-bit PRG output label */
    GGMNode*   left;          /* G_0 (bit=0) subtree */
    GGMNode*   right;         /* G_1 (bit=1) subtree */
};

/*
 * GGMTree: Full binary tree representation (for small m).
 * For large m, lazy evaluation is used (see GGMEvaluator).
 */
typedef struct {
    int        depth;         /* m = input length in bits */
    int        label_len;     /* n = seed/key length in bits */
    GGMNode*   root;          /* root node with key k */
    int        node_count;
} GGMTree;

/* ================================================================
 * GGM Construction (L5)
 * ================================================================ */

/*
 * Create a GGM PRF family from a length-doubling PRG.
 *
 * Parameters:
 *   prg:       length-doubling PRG G: {0,1}^n -> {0,1}^{2n}
 *   input_len: m (number of bits in input x)
 *
 * Result: PRF family F = {f_k}_{k in {0,1}^n}
 *         f_k: {0,1}^m -> {0,1}^n
 */
PRF_Family* ggm_create_prf_family(const PRG* prg, int input_len);

/*
 * Core GGM evaluation: F_k(x)
 *
 * Algorithm: Tree walk
 *   1. Set y_0 = k
 *   2. For i = 1 to m:
 *        y_i = G_{x_i}(y_{i-1})
 *      where x_i is the i-th bit of x
 *   3. Output y_m
 *
 * Complexity: O(m * T_G) where T_G = PRG evaluation time
 * Security:    Adv^{PRF}_A <= m * q * Adv^{PRG}
 */
BitString* ggm_evaluate(const PRG* prg,
                         const BitString* key,
                         const BitString* input);

/*
 * Complete GGM tree evaluation: compute all 2^m leaves.
 * Only feasible for small m (<= 20).
 * Returns the full tree structure.
 */
GGMTree* ggm_build_full_tree(const PRG* prg, const BitString* key, int depth);

/*
 * Free GGM tree and all nodes.
 */
void ggm_tree_free(GGMTree* tree);
void ggm_node_free(GGMNode* node);

/* ================================================================
 * GGM Tree Traversal Utilities
 * ================================================================ */

/* Print the GGM tree structure (labels as hex) */
void ggm_tree_print(const GGMTree* tree);

/* Print a single path from root to the leaf for input x */
void ggm_print_path(const PRG* prg, const BitString* key,
                    const BitString* input);

/* Collect all leaf labels (PRF outputs for all 2^m inputs) */
BitString** ggm_collect_leaves(const GGMTree* tree, int* out_count);

/* Verify tree consistency: every non-leaf node label produces
 * left/right children via PRG that match stored children */
int ggm_verify_tree_consistency(const GGMTree* tree, const PRG* prg);

/* ================================================================
 * GGM with Non-length-doubling PRG (Extension)
 * ================================================================ */

/*
 * If PRG has output l(n) != 2n, truncate or iterate.
 *
 * For l(n) > 2n: truncate to 2n bits.
 * For l(n) < 2n but l(n) > n: use iterative stretching.
 */
PRF_Family* ggm_create_from_general_prg(const PRG* prg, int input_len);

/* ================================================================
 * GGM Security (L4) - Hybrid Argument
 * ================================================================ */

/*
 * Hybrid distibutions (for the security proof):
 *
 * Hybrid H_i (0 <= i <= m):
 *   First i levels of the tree use truly random bits,
 *   remaining m-i levels use the real PRG.
 *
 * H_0 = real PRF (all PRG)
 * H_m = truly random function (all random)
 *
 * Distinguishing H_{i-1} from H_i reduces to
 * distinguishing PRG output from random.
 */

typedef struct {
    int    m;               /* tree depth */
    int    current_hybrid;  /* 0..m */
    PRG*   prg_ref;         /* reference PRG */
    int    n;               /* seed length */
} GGMHybrid;

GGMHybrid* ggm_hybrid_create(const PRG* prg, int m);
void       ggm_hybrid_free(GGMHybrid* h);

/*
 * Evaluate H_i(x) for a given hybrid level i and input x.
 * Uses real PRG for levels > i, random bits for levels <= i.
 */
BitString* ggm_hybrid_evaluate(GGMHybrid* h, int i,
                                const BitString* key,
                                const BitString* input);

/*
 * Simulate the hybrid argument: for each adjacent pair of hybrids,
 * the advantage difference is bounded by PRG advantage.
 */
double ggm_hybrid_bound_advantage(int m, int q, double prg_advantage);

/* ================================================================
 * GGM Security Proof Components
 * ================================================================ */

/*
 * Security reduction:
 *   Given a PRF adversary A making q queries with advantage eps,
 *   construct a PRG distinguisher D with advantage >= eps/(m*q).
 *
 * Returns the constructed PRG distinguisher advantage.
 */
double ggm_security_reduction(double prf_advantage, int m, int q);

/*
 * Complete GGM security proof:
 *   For all PPT A, Adv^{PRF}_A(n) <= m(n)*q(n)*Adv^{PRG}(n)
 */
typedef struct {
    int    m;                  /* input length parameter */
    int    q;                  /* number of oracle queries */
    double prg_advantage;      /* Adv^{PRG} */
    double prf_advantage_bound; /* computed bound */
    double actual_advantage;   /* measured advantage */
    int    bound_holds;        /* 1 if actual <= bound */
} GGMSecurityProof;

/*
 * Run the full security experiment:
 *  1. Generate PRF key and random function
 *  2. Run distinguisher with adaptive queries
 *  3. Compute advantage and bound
 */
GGMSecurityProof* ggm_run_security_experiment(const PRG* prg, int m,
                                               int max_queries,
                                               int num_trials);

void ggm_security_proof_free(GGMSecurityProof* proof);
void ggm_security_proof_print(const GGMSecurityProof* proof);

/* ================================================================
 * Key Derivation Function (KDF) from GGM
 * ================================================================ */

/*
 * Use GGM-PRF as a key derivation function:
 *   KDF(salt, context) = F_{master_key}(salt || context)
 */
BitString* ggm_kdf_derive(const PRF_Family* ggm_family,
                           const BitString* master_key,
                           const BitString* salt,
                           const BitString* context);

/* ================================================================
 * GGM Variants and Optimizations
 * ================================================================ */

/*
 * Pipelined GGM: Evaluate all prefixes of x simultaneously.
 * Useful when computing F_k(x^{(1)}), F_k(x^{(2)}), ..., F_k(x^{(q)})
 * where x^{(i)} share common prefixes.
 */
BitString** ggm_pipelined_eval(const PRG* prg,
                                const BitString* key,
                                const BitString** inputs,
                                int num_inputs);

/*
 * GGM with truncated output: only output first t bits of leaf.
 * Still secure for any t <= n by the GGM theorem.
 */
BitString* ggm_evaluate_truncated(const PRG* prg,
                                   const BitString* key,
                                   const BitString* input,
                                   int output_bits);

/*
 * Incremental GGM: Given F_k(x), compute F_k(x') for adjacent x'.
 * For inputs differing in bits i+1..m, we can reuse parts of the path.
 */
BitString* ggm_incremental_update(const PRG* prg,
                                   const BitString* key,
                                   const BitString* prev_input,
                                   const BitString* prev_output,
                                   const BitString* new_input);

double ggm_collision_probability(const PRG* prg,
                                  int key_len, int input_len,
                                  int num_samples);

#endif /* GGM_H */
