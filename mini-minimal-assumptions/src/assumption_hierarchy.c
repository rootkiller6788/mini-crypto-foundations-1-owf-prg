/*
 * assumption_hierarchy.c — Cryptographic Landscape & Primitive Graph
 * Implements directed graph of cryptographic primitives with
 * minimality analysis and consistency checking.
 */
#include "assumption_hierarchy.h"
#include "minimal_assumptions.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

CryptoLandscape* cl_create(void) {
    CryptoLandscape* cl = calloc(1, sizeof(CryptoLandscape));
    if (!cl) return NULL;
    AssumptionHierarchy* ah = ah_create();
    if (!ah) { free(cl); return NULL; }
    cl->n_nodes = PRIM_NUM;
    cl->nodes = calloc(PRIM_NUM, sizeof(PrimitiveNode));
    if (!cl->nodes) { ah_free(ah); free(cl); return NULL; }
    for (int i = 0; i < PRIM_NUM; i++) {
        cl->nodes[i].prim = (CryptoPrimitive)i;
        int has_incoming = 0;
        int n = ah->n_primitives;
        for (int j = 0; j < n; j++)
            if (i != j && ah->adj_matrix[j * n + i]) { has_incoming = 1; break; }
        cl->nodes[i].is_minimal = !has_incoming;
        cl->nodes[i].standard_construction = "none";
        switch (i) {
        case PRIM_OWF:
            cl->nodes[i].standard_construction =
                "SHA-256 preimage, factoring (RSA), discrete log (DSA)";
            break;
        case PRIM_PRG:
            cl->nodes[i].standard_construction =
                "HILL: OWF -> PRG via hardcore bit + iteration";
            break;
        case PRIM_PRF:
            cl->nodes[i].standard_construction =
                "GGM: PRG -> PRF via binary tree";
            break;
        case PRIM_UOWHF:
            cl->nodes[i].standard_construction =
                "Rompel: OWF -> UOWHF via tree hashing";
            break;
        case PRIM_TDP:
            cl->nodes[i].standard_construction =
                "Candidate: RSA trapdoor permutation";
            break;
        case PRIM_PKE:
            cl->nodes[i].standard_construction =
                "RSA-OAEP (factoring), ElGamal (DDH), Regev (LWE)";
            break;
        }
    }
    cl->n_reductions = ah->n_edges;
    cl->reductions = calloc(ah->n_edges, sizeof(ReductionEdge));
    if (cl->reductions) {
        int n = ah->n_primitives;
        int ei = 0;
        for (int i = 0; i < n && ei < ah->n_edges; i++)
            for (int j = 0; j < n && ei < ah->n_edges; j++)
                if (ah->adj_matrix[i * n + j]) {
                    cl->reductions[ei].from = (CryptoPrimitive)i;
                    cl->reductions[ei].to = (CryptoPrimitive)j;
                    cl->reductions[ei].is_black_box = 1;
                    cl->reductions[ei].is_separation = 0;
                    cl->reductions[ei].reference = "standard";
                    ei++;
                }
        cl->n_reductions = ei;
    }
    ah_free(ah);
    return cl;
}

void cl_free(CryptoLandscape* cl) {
    if (!cl) return;
    free(cl->nodes); free(cl->reductions);
    free(cl->separations); free(cl);
}

int cl_is_minimal(const CryptoLandscape* cl, CryptoPrimitive p) {
    if (!cl || (int)p >= cl->n_nodes) return 0;
    return cl->nodes[p].is_minimal;
}

int cl_find_minimal_for(const CryptoLandscape* cl, CryptoPrimitive target,
                        CryptoPrimitive** result, int* n_result) {
    if (!cl || !result || !n_result) return 0;
    int* reaches = calloc(PRIM_NUM, sizeof(int));
    int count = 0;
    AssumptionHierarchy* ah = ah_create();
    if (!ah) { free(reaches); return 0; }
    for (int i = 0; i < PRIM_NUM; i++)
        if (ah_reducible(ah, (CryptoPrimitive)i, target))
            reaches[count++] = i;
    int* min_idx = calloc(count, sizeof(int));
    int n_min = 0;
    for (int i = 0; i < count; i++) {
        int is_min = 1;
        for (int j = 0; j < count && is_min; j++) {
            if (i == j) continue;
            if (ah_reducible(ah, (CryptoPrimitive)reaches[j],
                             (CryptoPrimitive)reaches[i])) is_min = 0;
        }
        if (is_min) min_idx[n_min++] = reaches[i];
    }
    *n_result = n_min;
    *result = calloc(n_min, sizeof(CryptoPrimitive));
    for (int i = 0; i < n_min; i++)
        (*result)[i] = (CryptoPrimitive)min_idx[i];
    ah_free(ah); free(reaches); free(min_idx);
    return n_min;
}

void cl_print_hierarchy(const CryptoLandscape* cl) {
    if (!cl) return;
    printf("\n=== Cryptographic Primitive Landscape ===\n");
    printf("Primitives: %d, Reductions: %d\n\n",
           cl->n_nodes, cl->n_reductions);
    for (int i = 0; i < cl->n_nodes; i++)
        printf("  %-10s [%s] %s\n",
               prim_name(cl->nodes[i].prim),
               cl->nodes[i].is_minimal ? "MINIMAL" : "derived",
               cl->nodes[i].standard_construction);
    printf("=== End Landscape ===\n");
}

void cl_print_minimality_proof(const CryptoLandscape* cl, CryptoPrimitive p) {
    if (!cl) return;
    printf("\n=== Minimality Proof for %s ===\n", prim_name(p));
    AssumptionHierarchy* ah = ah_create();
    if (!ah) return;
    int n = ah->n_primitives;
    int n_deps = 0;
    for (int j = 0; j < n; j++)
        if (j != (int)p && ah_reducible(ah, p, (CryptoPrimitive)j)) n_deps++;
    printf("Reachable from %s: %d primitives\n", prim_name(p), n_deps);
    printf("Direct reductions:\n");
    for (int j = 0; j < n; j++)
        if (j != (int)p && ah->adj_matrix[p * n + j])
            printf("  %s -> %s\n", prim_name(p),
                   prim_name((CryptoPrimitive)j));
    int n_src = 0;
    for (int i = 0; i < n; i++)
        if (i != (int)p && ah_reducible(ah, (CryptoPrimitive)i, p)) n_src++;
    if (n_src == 0)
        printf("Verdict: %s IS minimal (no weaker construction known)\n",
               prim_name(p));
    else
        printf("Verdict: %s is NOT minimal (%d weaker primitives imply it)\n",
               prim_name(p), n_src);
    ah_free(ah);
    printf("=== End Minimality Proof ===\n");
}

double cl_hierarchy_depth(const CryptoLandscape* cl) {
    if (!cl) return 0.0;
    int n = cl->n_nodes;
    double* depth = calloc(n, sizeof(double));
    int changed = 1, iters = 0;
    while (changed && iters < n * n) {
        changed = 0;
        for (int i = 0; i < cl->n_reductions; i++) {
            int f = cl->reductions[i].from;
            int t = cl->reductions[i].to;
            if (depth[f] + 1.0 > depth[t]) {
                depth[t] = depth[f] + 1.0;
                changed = 1;
            }
        }
        iters++;
    }
    double max_d = 0.0;
    for (int i = 0; i < n; i++)
        if (depth[i] > max_d) max_d = depth[i];
    free(depth);
    return max_d;
}

int cl_primitive_rank(const CryptoLandscape* cl, CryptoPrimitive p) {
    if (!cl) return -1;
    AssumptionHierarchy* ah = ah_create();
    if (!ah) return -1;
    int reachable = 0;
    int n = ah->n_primitives;
    for (int j = 0; j < n; j++)
        if (ah_reducible(ah, p, (CryptoPrimitive)j)) reachable++;
    ah_free(ah);
    return reachable;
}

void cl_check_consistency(const CryptoLandscape* cl) {
    if (!cl) return;
    printf("\n=== Hierarchy Consistency Check ===\n");
    int issues = 0;
    for (int i = 0; i < cl->n_reductions; i++) {
        if (cl->reductions[i].from == cl->reductions[i].to) {
            printf("WARNING: Self-loop at %s\n",
                   prim_name(cl->reductions[i].from));
            issues++;
        }
    }
    AssumptionHierarchy* ah = ah_create();
    if (ah) {
        CryptoPrimitive sep_from[] = { PRIM_OWF, PRIM_OWF, PRIM_OWF };
        CryptoPrimitive sep_to[]   = { PRIM_OT,  PRIM_PKE, PRIM_CRHF };
        int n_seps = 3;
        for (int i = 0; i < n_seps; i++) {
            if (ah_reducible(ah, sep_from[i], sep_to[i])) {
                printf("WARNING: %s -> %s exists but is BB-separated!\n",
                       prim_name(sep_from[i]), prim_name(sep_to[i]));
                issues++;
            }
        }
        ah_free(ah);
    }
    printf("Issues found: %d\n", issues);
    if (issues == 0) printf("Hierarchy is internally consistent.\n");
    printf("=== End Consistency Check ===\n");
}
