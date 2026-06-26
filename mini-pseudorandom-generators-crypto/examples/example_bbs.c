/*
 * example_bbs.c -- End-to-End Blum-Blum-Shub PRG Demonstration
 *
 * L6 Canonical Problem: Generating cryptographically pseudorandom bits
 * using the BBS construction from number-theoretic assumptions.
 *
 * Demonstrates: key generation, bit generation, output verification,
 * PRG interface wrapping, and statistical quality checks.
 */
#include "blum_blum_shub.h"
#include "prg_crypto.h"
#include "prg_construction.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    printf("=== Blum-Blum-Shub PRG Demo ===\n\n");

    prg_test_srand(42);
    BBSState* bbs = bbs_keygen(32);
    if (!bbs) {
        printf("BBS keygen failed (try different random seed)\n");
        return 1;
    }

    printf("Blum integer N = %llu = %llu * %llu\n",
           (unsigned long long)bbs->blum.n,
           (unsigned long long)bbs->blum.p,
           (unsigned long long)bbs->blum.q);
    printf("Seed x0 = %llu\n\n", (unsigned long long)bbs->seed);

    /* Generate 64 bytes of PRG output */
    uint8_t output[64];
    memset(output, 0, 64);
    size_t gen = bbs_generate_bytes(bbs, output, 64);
    printf("Generated %zu bytes via BBS (LSB extraction):\n", gen);

    for (size_t i = 0; i < 8 && i < gen; i++) {
        printf("  byte[%zu] = 0x%02X\n", i, output[i]);
    }
    if (gen > 8) printf("  ... (%zu bytes total)\n", gen);

    /* Run statistical tests */
    printf("\nStatistical quality tests:\n");
    FrequencyTest ft = frequency_test_run(output, gen);
    printf("  Frequency (1's ratio): %.4f (ideal: 0.5000)\n", ft.frequency);

    RunsTest rt = runs_test_run(output, gen);
    printf("  Runs: %zu (expected ~%.1f)\n", rt.n_runs, rt.expected_runs);

    int battery = statistical_test_battery(output, gen);
    printf("  Test battery: %s\n", battery ? "PASS" : "FAIL (may be OK for small N)");

    /* Wrap as generic PRG and do a second generation */
    printf("\nWrapping BBS as generic PRG...\n");
    BBSState* bbs2 = bbs_keygen(32);
    if (bbs2) {
        PRG* prg = bbs_to_prg(bbs2);
        if (prg) {
            uint8_t seed_bytes[8];
            prg_fill_random(seed_bytes, 4);
            prg_init(prg, seed_bytes, 4);
            uint8_t prg_out[32];
            memset(prg_out, 0, 32);
            prg_fill(prg, prg_out, 32);
            printf("  PRG wrapper output bytes: ");
            for (int i = 0; i < 8; i++) printf("%02X ", prg_out[i]);
            printf("\n");
            prg_free(prg);
        }
    }

    /* CRT-accelerated demo */
    printf("\nCRT-accelerated BBS demo:\n");
    BBSState* bbs3 = (BBSState*)calloc(1, sizeof(BBSState));
    if (bbs3 && bbs_init(bbs3, 11, 19, 3) == 0) {
        bbs_crt_init(bbs3);
        uint8_t crt_out[8];
        memset(crt_out, 0, 8);
        bbs_crt_generate_bytes(bbs3, crt_out, 8);
        printf("  CRT output: ");
        for (int i = 0; i < 8; i++) printf("%02X ", crt_out[i]);
        printf("\n");
        bbs_free(bbs3);
    }

    bbs_free(bbs);
    printf("\n=== BBS Demo Complete ===\n");
    return 0;
}
