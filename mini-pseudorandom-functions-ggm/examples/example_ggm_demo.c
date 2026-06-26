/*
 * example_ggm_demo.c - Complete GGM PRF Construction Demonstration
 *
 * This example demonstrates:
 *   L1: PRG and PRF definitions
 *   L4: GGM Theorem (PRG => PRF)
 *   L5: GGM PRF evaluation, tree construction
 *   L6: Canonical problem: building a PRF from a PRG
 *
 * It walks through the entire GGM construction:
 *   1. Create a length-doubling PRG
 *   2. Create a GGM PRF family from it
 *   3. Generate keys and evaluate the PRF
 *   4. Build and verify the full GGM tree (small m)
 *   5. Test security properties
 */

#include "ggm.h"
#include "prf.h"
#include "prg.h"
#include "crypto_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    printf("=== GGM PRF Construction Demo ===\n\n");

    /* Step 1: Create a length-doubling PRG G: {0,1}^32 -> {0,1}^64 */
    printf("Step 1: Create length-doubling PRG\n");
    PRG* prg = prg_create_toy_length_doubling(32);
    printf("  PRG: seed_len=%d, output_len=%d, expanding=%s\n",
           prg->seed_len, prg->output_len,
           prg_is_expanding(prg) ? "yes" : "no");

    /* Test PRG: show example output */
    BitString* seed = bs_create_random(32, 42);
    BitString* prg_out = prg_evaluate(prg, seed);
    printf("  PRG(seed) = ");
    bs_print_bits(prg_out);
    printf("\n");

    /* Step 2: Create GGM PRF family F: {0,1}^32 x {0,1}^5 -> {0,1}^32 */
    printf("Step 2: Create GGM PRF Family (m=5 input bits)\n");
    PRF_Family* fam = ggm_create_prf_family(prg, 5);
    printf("  PRF: key_len=%d, input_len=%d, output_len=%d\n",
           fam->key_len, fam->input_len, fam->output_len);
    printf("  Key space size: 2^%d = %lld\n",
           fam->key_len, (long long)fam->key_space);

    /* Step 3: Generate random key and evaluate PRF on sample inputs */
    printf("\nStep 3: PRF Evaluation\n");
    BitString* key = bs_create_random(32, 100);
    printf("  Key: ");
    bs_print_bits(key);

    /* Evaluate on several inputs */
    const char* test_inputs[] = {"00000", "11111", "01010", "10101"};
    for (int i = 0; i < 4; i++) {
        BitString* input = bs_create(5);
        for (int j = 0; j < 5; j++) {
            bs_set_bit(input, j, test_inputs[i][j] - '0');
        }
        BitString* output = ggm_evaluate(prg, key, input);
        printf("  F_k(%s) = ", test_inputs[i]);
        bs_print_bits(output);
        bs_free(input);
        bs_free(output);
    }

    /* Step 4: Build full GGM tree (depth=3, 15 nodes) */
    printf("\nStep 4: Build Full GGM Tree (depth=3)\n");
    GGMTree* tree = ggm_build_full_tree(prg, key, 3);
    printf("  Tree: depth=%d, nodes=%d, label_len=%d\n",
           tree->depth, tree->node_count, tree->label_len);

    /* Collect all leaves (8 possible outputs for 3-bit input) */
    int n_leaves;
    BitString** leaves = ggm_collect_leaves(tree, &n_leaves);
    printf("  Leaves collected: %d\n", n_leaves);
    for (int i = 0; i < n_leaves; i++) {
        printf("    F_k(%03d) = ", (i & 4) ? 1:0);
        printf("%d%d%d = ", (i>>2)&1, (i>>1)&1, i&1);
        bs_print_bits(leaves[i]);
        bs_free(leaves[i]);
    }
    free(leaves);

    /* Step 5: Verify tree consistency */
    printf("\nStep 5: Verify Tree Consistency\n");
    int consistent = ggm_verify_tree_consistency(tree, prg);
    printf("  Tree is %s\n", consistent ? "CONSISTENT" : "INCONSISTENT");

    /* Step 6: Collision probability test */
    printf("\nStep 6: Collision Probability\n");
    double cp = ggm_collision_probability(prg, 32, 5, 30);
    printf("  Collision prob (30 samples): %.6f\n", cp);
    printf("  Expected for truly random: %.6f\n", 1.0 / (1LL << 32));

    /* Step 7: Show path visualization */
    printf("\nStep 7: Path Visualization for input 01010\n");
    BitString* path_input = bs_create(5);
    bs_set_bit(path_input, 1, 1);
    bs_set_bit(path_input, 3, 1);
    ggm_print_path(prg, key, path_input);
    bs_free(path_input);

    /* Cleanup */
    ggm_tree_free(tree);
    bs_free(key);
    bs_free(seed);
    bs_free(prg_out);
    free(fam);
    prg_free(prg);

    printf("\n=== GGM Demo Complete ===\n");
    return 0;
}
