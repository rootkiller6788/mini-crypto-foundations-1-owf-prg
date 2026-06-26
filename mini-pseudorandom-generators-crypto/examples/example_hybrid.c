/*
 * example_hybrid.c -- End-to-End Hybrid Argument Simulation
 *
 * L6 Canonical Problem: Simulating the hybrid argument that proves
 * PRG security is equivalent to next-bit unpredictability.
 *
 * This example constructs a series of hybrid distributions and
 * verifies the triangle inequality decomposition numerically.
 */
#include "prg_hybrid.h"
#include "prg_crypto.h"
#include "prg_construction.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

int main(void) {
    printf("=== Hybrid Argument Simulation ===\n\n");

    prg_test_srand(777);

    /* Create a hybrid game with l=20 bits */
    size_t l = 20;
    printf("Setting up %zu-bit hybrid argument:\n", l);
    printf("  H_0  = U_l  (truly random)\n");
    printf("  H_i  = G(s)[1..i] || U_{l-i}\n");
    printf("  H_l  = G(s)  (fully pseudorandom)\n\n");

    HybridConfig cfg = hybrid_config_create(l, 1);
    printf("Config: l=%zu, block_size=%zu, n_blocks=%zu\n\n",
           cfg.l, cfg.block_size, cfg.n_blocks);

    /* Simulate a distinguisher with linearly increasing success */
    HybridAnalysis* ha = hybrid_analysis_create(l);
    if (!ha) { printf("Failed to create analysis\n"); return 1; }

    printf("Simulating distinguisher with growing advantage:\n");
    for (size_t i = 0; i <= l; i++) {
        /* Simulated: distinguisher gets better as more PRG bits appear */
        double prob = 0.5 + 0.02 * (double)i; /* from 0.5 to 0.9 */
        hybrid_analysis_record(ha, i, prob);
        printf("  H_%-2zu: Pr[D=1] = %.4f\n", i, prob);
    }

    hybrid_analysis_compute(ha);

    printf("\nHybrid gap analysis:\n");
    printf("  Total gap:  %.6f\n", ha->total_gap);
    printf("  Max adjacent gap: %.6f at position %zu\n",
           ha->max_adjacent_gap, ha->max_gap_index);

    /* Verify triangle inequality */
    double sum_gaps = 0.0;
    for (size_t i = 0; i < ha->l; i++) sum_gaps += ha->adjacent_gap[i];
    printf("  Sum of adjacent gaps: %.6f\n", sum_gaps);
    printf("  Triangle inequality holds: %s\n",
           (ha->total_gap <= sum_gaps + 1e-10) ? "YES" : "NO");

    /* Yao reduction */
    printf("\nYao reduction (hybrid => NBU predictor):\n");
    double pred_adv = yao_reverse_predictor_advantage(ha->max_adjacent_gap, l);
    printf("  Max adjacent advantage: %.6f\n", ha->max_adjacent_gap);
    printf("  Implied predictor advantage: %.6f\n", pred_adv);
    printf("  Interpretation: if any distinguisher has advantage epsilon,\n");
    printf("    then some bit can be predicted with advantage >= epsilon/%zu.\n", l);

    /* Verify self-consistency */
    printf("\nSelf-consistency checks:\n");
    printf("  Triangle inequality: %s\n",
           hybrid_verify_triangle_inequality(ha) ? "PASS" : "FAIL");
    printf("  Yao reduction: %s\n",
           hybrid_verify_yao_reduction(ha, 0.01) ? "PASS" : "FAIL");

    /* Negligibility check */
    printf("\nNegligibility preservation under polynomial composition:\n");
    int negl_check = hybrid_advantage_still_negligible(1e-6, 1000, 128, 2.0);
    printf("  indiv_adv * k = 1e-6 * 1000 = %.4f\n", 1e-6 * 1000.0);
    printf("  vs threshold 1/n^2 = %.6f\n", 1.0/pow(128.0, 2.0));
    printf("  Still negligible: %s\n", negl_check ? "YES" : "NO");

    hybrid_analysis_free(ha);

    /* Generic hybrid game framework demo */
    printf("\nGeneric Hybrid Game demonstration (k=3, l=128):\n");
    HybridGame* game = hybrid_game_create(3, 128);
    if (game) {
        printf("  Created hybrid game with k=%zu steps, l=%zu bits\n", game->k, game->l);
        printf("  States: ");
        for (size_t i = 0; i <= game->k; i++) {
            printf("H_%zu%s", i, (i < game->k) ? " -> " : "\n");
        }
        hybrid_game_free(game);
    }

    printf("\n=== Hybrid Argument Simulation Complete ===\n");
    return 0;
}
