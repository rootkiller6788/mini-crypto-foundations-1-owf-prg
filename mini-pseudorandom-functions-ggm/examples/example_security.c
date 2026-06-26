/*
 * example_security.c - GGM Security Proof Demonstration (L4)
 *
 * Demonstrates the GGM security proof using the hybrid argument:
 *
 *   Theorem (GGM): If PRG is secure, then GGM-PRF is secure.
 *   Bound: Adv^{PRF}_A <= m * q * Adv^{PRG}
 *
 * This example:
 *   1. Runs the security experiment (real vs random PRF)
 *   2. Computes the theoretical bound
 *   3. Verifies the bound holds for toy parameters
 *   4. Demonstrates the hybrid distributions H_0 ... H_m
 *
 * L4: Fundamental Theorem - GGM security proof
 * L6: Canonical problem: proving PRF security from PRG security
 *
 * Reference:
 *   Goldreich-Goldwasser-Micali (1986), "How to Construct Random Functions"
 *   Arora-Barak section 9.3.1
 */

#include "ggm.h"
#include "prf.h"
#include "prg.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

int main(void) {
    printf("=== GGM Security Proof Demonstration ===\n\n");

    /* Setup: Create PRG and derive PRF */
    int n = 32;   /* security parameter */
    int m = 5;    /* input length */
    int q = 8;    /* max queries */
    int trials = 50;

    printf("Parameters: n=%d, m=%d, q=%d, trials=%d\n", n, m, q, trials);

    PRG* prg = prg_create_toy_length_doubling(n);
    printf("PRG created: %d -> %d bits\n", n, 2 * n);

    /* Run security experiment */
    printf("\n--- Security Experiment ---\n");
    GGMSecurityProof* proof = ggm_run_security_experiment(prg, m, q, trials);
    if (!proof) {
        printf("  Experiment failed!\n");
        prg_free(prg);
        return 1;
    }

    ggm_security_proof_print(proof);

    /* Explain the bound */
    printf("\n--- Theoretical Bound Derivation ---\n");
    printf("  The GGM security proof uses a hybrid argument:\n");
    printf("  - H_0: real PRF (all levels use PRG)\n");
    printf("  - H_1: level 1 random, levels 2..m use PRG\n");
    printf("  - ...\n");
    printf("  - H_m: truly random (all levels random)\n\n");

    printf("  For any efficient adversary A:\n");
    printf("  |Pr[A(H_{i-1}) = 1] - Pr[A(H_i) = 1]| <= Adv^{PRG}(n)\n");
    printf("  Therefore:\n");
    printf("  Adv^{PRF}_A(n) = |Pr[A(H_0)=1] - Pr[A(H_m)=1]|\n");
    printf("                  <= sum_i |Pr[A(H_{i-1})=1] - Pr[A(H_i)=1]|\n");
    printf("                  <= m * Adv^{PRG}(n)           (for 1 query)\n");
    printf("                  <= m * q * Adv^{PRG}(n)       (for q queries)\n\n");

    printf("  With m=%d, q=%d, our bound is:\n", m, q);
    printf("  Adv^{PRF} <= %d * %d * Adv^{PRG}\n", m, q);

    /* Demonstrate hybrid distributions */
    printf("\n--- Hybrid Distribution Demonstration ---\n");
    GGMHybrid* hybrid = ggm_hybrid_create(prg, m);

    BitString* key = bs_create_random(n, 99999);
    BitString* input = bs_create(m);
    for (int i = 0; i < m; i++) bs_set_bit(input, i, (i * 7 + 3) % 2);

    printf("  Input: ");
    bs_print(input);

    for (int i = 0; i <= m; i++) {
        BitString* hi_out = ggm_hybrid_evaluate(hybrid, i, key, input);
        printf("  H_%d: ", i);
        if (hi_out) {
            bs_print_bits(hi_out);
            bs_free(hi_out);
        } else {
            printf("(null)\n");
        }
    }

    /* Compute hybrid bound explicitly */
    double prg_adv = 1.0 / (double)(1ULL << (n / 2));
    printf("\n--- Explicit Bound Calculation ---\n");
    printf("  Estimated PRG advantage: Adv^PRG = 1/2^{%d} = %.6g\n",
           n/2, prg_adv);
    printf("  PRF security bound: %d * %d * %.6g = %.6g\n",
           m, q, prg_adv, ggm_hybrid_bound_advantage(m, q, prg_adv));

    /* Security reduction */
    printf("\n--- Security Reduction ---\n");
    printf("  Given PRF distinguisher with advantage eps,\n");
    printf("  we construct PRG distinguisher with advantage eps / (m*q).\n");
    printf("  eps=0.01 => PRG advantage needed: %.6g\n",
           ggm_security_reduction(0.01, m, q));
    printf("  eps=0.0001 => PRG advantage needed: %.6g\n",
           ggm_security_reduction(0.0001, m, q));

    /* Cleanup */
    bs_free(key);
    bs_free(input);
    ggm_hybrid_free(hybrid);
    ggm_security_proof_free(proof);
    prg_free(prg);

    printf("\n=== Security Proof Demo Complete ===\n");
    return 0;
}
