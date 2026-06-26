/*
 * example_bm.c -- End-to-End Blum-Micali PRG Demonstration
 *
 * L6 Canonical Problem: Generating cryptographically pseudorandom bits
 * using the Blum-Micali construction based on discrete logarithm hardness.
 *
 * Demonstrates: safe prime generation, generator finding, bit generation,
 * simultaneous hardcore bits, and modular exponentiation visualization.
 */
#include "blum_micali.h"
#include "prg_crypto.h"
#include "prg_construction.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    printf("=== Blum-Micali PRG Demo ===\n\n");

    prg_test_srand(99);

    BMState* bm = bm_keygen(16);
    if (!bm) {
        printf("BM keygen failed (try different seed/range)\n");
        return 1;
    }

    printf("Prime p = %llu (safe prime)\n", (unsigned long long)bm->p);
    printf("Generator g = %llu\n", (unsigned long long)bm->g);
    printf("Seed x0 = %llu\n", (unsigned long long)bm->seed);

    /* Verify g generates Z_p^* */
    if (bm_verify_generator(bm->p, bm->g)) {
        printf("  g is a valid generator of Z_%llu^*\n", (unsigned long long)bm->p);
    }
    printf("\n");

    /* Generate 32 bytes of output */
    uint8_t output[32];
    memset(output, 0, 32);
    size_t gen = bm_generate_bytes(bm, output, 32);
    printf("Generated %zu bytes via Blum-Micali (MSB extraction):\n", gen);
    for (size_t i = 0; i < 8 && i < gen; i++) {
        printf("  byte[%zu] = 0x%02X\n", i, output[i]);
    }
    if (gen > 8) printf("  ... (%zu bytes total)\n", gen);

    /* Statistical quality */
    printf("\nStatistical tests:\n");
    FrequencyTest ft = frequency_test_run(output, gen);
    printf("  Frequency: %.4f\n", ft.frequency);

    /* Simultaneous hardcore demo */
    printf("\nSimultaneous hardcore bits (MSB extraction at multiple positions):\n");
    BMState* bm2 = bm_keygen(16);
    if (bm2) {
        uint8_t sim_out[4];
        memset(sim_out, 0, 4);
        size_t sgen = bm_next_bits_simultaneous(bm2, sim_out, 16);
        printf("  Generated %zu bits via simultaneous hardcore\n", sgen);
        printf("  Output: ");
        for (size_t i = 0; i < (sgen + 7) / 8 && i < 4; i++)
            printf("%02X ", sim_out[i]);
        printf("\n");
        bm_free(bm2);
    }

    /* Iterated PRG style demonstration */
    printf("\nBM iteration trace (first 16 bits):\n");
    BMState* bm3 = (BMState*)calloc(1, sizeof(BMState));
    if (bm3 && bm_init(bm3, bm->p, bm->g, bm->seed) == 0) {
        printf("  ");
        for (int i = 0; i < 16; i++) {
            int bit = bm_next_bit(bm3);
            if (bit >= 0) printf("%d", bit);
        }
        printf("\n");
        bm_free(bm3);
    }

    bm_free(bm);
    printf("\n=== BM Demo Complete ===\n");
    return 0;
}
