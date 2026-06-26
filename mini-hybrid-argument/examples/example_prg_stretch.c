/*
 * example_prg_stretch.c - Demo: PRG Length Extension via BMY
 *
 * Demonstrates the Blum-Micali-Yao construction for extending a
 * PRG with 1-bit stretch to arbitrary polynomial stretch.
 * Uses the hybrid argument to verify security.
 */
#include "distinguisher.h"
#include "prg_hybrid.h"
#include <stdio.h>
#include <string.h>
#include <math.h>

int main(void) {
    printf("=== PRG Length Extension Demo ===\n\n");
    rand_seed(42);

    uint8_t seed[4] = {0xAA, 0x55, 0xAA, 0x55};
    uint8_t out[128];
    size_t ob = 0;

    /* 1. Trivial PRG */
    printf("--- Trivial PRG ---\n");
    PRG* g = prg_create_trivial();
    if (g) {
        prg_evaluate(g, seed, 32, out, &ob);
        printf("Trivial: %zu bits output, first byte=0x%02X\n", ob, out[0]);
        prg_free(g);
    }

    /* 2. XorShift PRG */
    printf("\n--- XorShift PRG ---\n");
    g = prg_create_xorshift(42ULL);
    if (g) {
        prg_evaluate(g, seed, 32, out, &ob);
        printf("XorShift: %zu bits output\n", ob);

        PRGStatistics stats = prg_analyze_output(g, seed, 32);
        printf("  Mean bit: %.4f, Runs: %zu, Entropy: %.4f\n",
               stats.mean_bit_fraction, stats.num_runs, stats.entropy_estimate);

        /* Stream cipher */
        uint8_t pt[] = "HELLO";
        uint8_t ct[8], dt[8];
        prg_stream_xor(g, seed, 32, pt, 40, ct);
        prg_stream_xor(g, seed, 32, ct, 40, dt);
        printf("  Stream cipher: '%s' -> encrypted -> '%s'\n", pt, dt);

        /* KDF */
        uint8_t sub[8];
        prg_kdf_derive(g, seed, 32, (uint8_t*)"salt", 32, sub, 64);
        printf("  KDF: derived key = 0x");
        for (int i = 0; i < 4; i++) printf("%02X", sub[i]);
        printf("...\n");

        prg_free(g);
    }

    /* 3. HashChain PRG */
    printf("\n--- HashChain PRG ---\n");
    g = prg_create_hash_chain(4);
    if (g) {
        prg_evaluate(g, seed, 32, out, &ob);
        printf("HashChain: %zu bits output\n", ob);
        prg_free(g);
    }

    /* 4. LCG PRG */
    printf("\n--- LCG PRG ---\n");
    g = prg_create_lcg(1103515245ULL, 12345ULL, 2147483648ULL);
    if (g) {
        prg_evaluate(g, seed, 32, out, &ob);
        printf("LCG: %zu bits output\n", ob);
        prg_free(g);
    }

    /* 5. PRG Security Game */
    printf("\n--- PRG Security Game ---\n");
    g = prg_create_xorshift(99ULL);
    Distinguisher* adv = dist_create_first_k_zero(8);
    if (g && adv) {
        PRGSecurityGame game = prg_security_game_run(g, adv, 32, 200);
        printf("XorShift vs first-k-zero: advantage=%.4f\n", game.advantage);
    }
    prg_free(g);
    dist_free_with_state(adv);

    /* 6. Hybrid Sequence */
    printf("\n--- Hybrid Sequence ---\n");
    HybridSequence* hs = hseq_create(5);
    printf("Capacity: 5, Length: %d\n", hseq_length(hs));
    hseq_free(hs);

    printf("\n=== Demo Complete ===\n");
    return 0;
}
