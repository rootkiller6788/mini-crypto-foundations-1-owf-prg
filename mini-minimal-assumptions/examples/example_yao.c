/*
 * example_yao.c — Yao's XOR Lemma Hardness Amplification Demo
 *
 * Demonstrates how weak hardness (δ = 0.01) can be amplified
 * to strong hardness (ε ≈ negl) via XOR composition.
 *
 * This is THE fundamental technique that enables basing
 * cryptography on minimal assumptions: we only need to
 * assume a WEAK one-way function, and hardness amplification
 * converts it to a STRONG one-way function.
 */
#include "hardness_amplification.h"
#include "minimal_assumptions.h"
#include <stdio.h>
#include <math.h>

int main(void) {
    printf("============================================\n");
    printf("  Yao's XOR Lemma — Hardness Amplification\n");
    printf("============================================\n\n");

    printf("Core idea: If f is weakly hard (adversary has small\n");
    printf("advantage δ), then XOR of k copies makes it strongly\n");
    printf("hard (adversary advantage ε ≈ negl).\n\n");

    double base_delta = 0.01;  /* 1% advantage (very weak!) */
    int n_bits = 64;
    double circuit_size = 1e6;  /* 1 million gate circuits */

    printf("Base parameters:\n");
    printf("  Input size n = %d bits\n", n_bits);
    printf("  Base hardness δ = %.4f (adversary has %.1f%% advantage)\n",
           base_delta, base_delta * 100);
    printf("  Circuit budget s = %.0f gates\n", circuit_size);
    printf("\n");

    printf("k | ε (XOR)       |  (1-δ)^k     | Verdict\n");
    printf("--+---------------+---------------+--------\n");

    for (int k = 1; k <= 20; k++) {
        double eps = yao_xor_bound(base_delta, k, circuit_size, (double)n_bits);
        double dp = direct_product_bound(base_delta, k);
        const char* verdict;
        if (eps < 1e-6) verdict = "NEGLIGIBLE (perfect!)";
        else if (eps < 0.001) verdict = "STRONG";
        else if (eps < 0.01) verdict = "MODERATE";
        else if (eps < 0.1) verdict = "WEAK";
        else verdict = "VERY WEAK";
        printf("%2d | %13.6e | %13.6e | %s\n", k, eps, dp, verdict);
    }

    printf("\n--- Optimal k computation ---\n");
    double target = 1e-6;  /* negl */
    int k_opt = yao_xor_optimal_k(base_delta, target, n_bits);
    printf("Target ε = %.1e => k* = %d XOR copies\n", target, k_opt);
    printf("Input expansion: %d * %d = %d bits total\n",
           k_opt, n_bits, k_opt * n_bits);

    printf("\n--- Goldreich-Levin Hardcore Bit ---\n");
    uint8_t x[] = {0xAA, 0x55, 0xAA, 0x55};  /* alternating bits */
    uint8_t r[] = {0xFF, 0xFF, 0xFF, 0xFF};  /* all ones */
    int hc = goldreich_levin_hardcore_bit(x, 4, r, 4);
    printf("B(x,r) = <x,r> mod 2 = parity of x = %d\n", hc);
    printf("(x has 16 ones -> parity = 0)\n");

    printf("\n--- Full Pipeline Demo ---\n");
    HardnessAmplificationPipeline* hap = ha_pipeline_create(0.05, 32);
    ha_pipeline_execute(hap);
    printf("Result: weak δ=%.3f -> strong δ=%.6e (k=%d)\n",
           hap->weak_delta, hap->strong_delta, hap->k);
    ha_pipeline_free(hap);

    printf("\n============================================\n");
    printf("  Demo Complete\n");
    printf("============================================\n");
    return 0;
}
