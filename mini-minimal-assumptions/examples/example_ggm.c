/*
 * example_ggm.c — GGM PRF Construction Demo
 *
 * Demonstrates the Goldreich-Goldwasser-Micali (1986) construction
 * of a pseudorandom function from a pseudorandom generator.
 *
 * The PRF is built as a binary tree: starting from the root key,
 * each input bit selects either the left or right child obtained
 * by applying the PRG to the current node.
 */
#include "minimal_assumptions.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    printf("============================================\n");
    printf("  GGM Pseudorandom Function Construction\n");
    printf("============================================\n\n");

    uint8_t key[8] = {0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE};

    printf("Key: DEADBEEFCAFEBABE (64 bits)\n");
    printf("PRF: {0,1}^8 × {0,1}^8 -> {0,1}^8\n\n");

    GGMPRF* prf = ggm_prf_init(key, 8, 8, 8);
    if (!prf) {
        printf("ERROR: Failed to initialize PRF\n");
        return 1;
    }

    printf("PRF Evaluation Table (8-bit input -> 8-bit output):\n\n");
    printf("  Input    Output\n");
    printf("  -------- --------\n");

    for (int i = 0; i < 16; i++) {
        uint8_t input[1] = { (uint8_t)i };
        uint8_t output[8];
        memset(output, 0, 8);
        ggm_prf_eval(prf, input, output);
        printf("  0x%02X     ", i);
        for (int j = 0; j < 8; j++) printf("%02X", output[j]);
        printf("\n");
    }

    printf("\n--- Pseudorandomness Check ---\n");
    printf("Count of 1-bits in first 16 outputs:\n");
    int ones = 0, total_bits = 16 * 8;
    for (int i = 0; i < 16; i++) {
        uint8_t input[1] = { (uint8_t)i };
        uint8_t output[8];
        ggm_prf_eval(prf, input, output);
        for (int j = 0; j < 8; j++)
            for (int b = 0; b < 8; b++)
                ones += (output[j] >> b) & 1;
    }
    printf("  %d ones out of %d bits = %.1f%%\n",
           ones, total_bits, 100.0 * ones / total_bits);
    printf("  (Expected: ~50%% for truly random function)\n");

    printf("\n--- Determinism Check ---\n");
    uint8_t in_test[1] = { 0x2A };
    uint8_t out1[8], out2[8];
    ggm_prf_eval(prf, in_test, out1);
    ggm_prf_eval(prf, in_test, out2);
    printf("F_k(0x2A) evaluated twice: %s\n",
           memcmp(out1, out2, 8) == 0 ? "IDENTICAL ✓" : "DIFFERENT ✗");

    printf("\n--- Avalanche Effect ---\n");
    uint8_t in_a[1] = { 0x55 };
    uint8_t in_b[1] = { 0x54 };  /* 1 bit difference */
    uint8_t out_a[8], out_b[8];
    ggm_prf_eval(prf, in_a, out_a);
    ggm_prf_eval(prf, in_b, out_b);
    int diff_bits = 0;
    for (int j = 0; j < 8; j++) {
        uint8_t diff = out_a[j] ^ out_b[j];
        for (int b = 0; b < 8; b++) diff_bits += (diff >> b) & 1;
    }
    printf("1-bit input change -> %d/%d output bits changed\n",
           diff_bits, 64);

    ggm_prf_free(prf);

    printf("\n============================================\n");
    printf("  Demo Complete\n");
    printf("============================================\n");
    return 0;
}
