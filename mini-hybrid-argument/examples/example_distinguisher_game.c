/*
 * example_distinguisher_game.c - Demo: PRG Distinguishing Game
 *
 * Simulates the PRG security game with different distinguishers
 * against different PRG constructions.
 */
#include "prg_hybrid.h"
#include "distinguisher.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    printf("=== PRG Distinguishing Game ===\n\n");
    rand_seed(12345);

    /* Create three different PRGs */
    PRG* trivial = prg_create_trivial();
    PRG* xorshift = prg_create_xorshift(42ULL);
    PRG* hashchain = prg_create_hash_chain(4);

    /* Create various distinguishers */
    Distinguisher* d_trivial = dist_create_trivial(0);
    Distinguisher* d_firstzero = dist_create_first_k_zero(8);
    Distinguisher* d_bitcount = dist_create_bit_count_threshold(64, 0.1);

    printf("--- PRG: Trivial (s||~s) ---\n");
    printf("Against trivial distinguisher:\n");
    PRGSecurityGame g1 = prg_security_game_run(trivial, d_trivial, 16, 200);
    prg_security_game_print(&g1);

    printf("\nAgainst first-k-zero distinguisher:\n");
    PRGSecurityGame g2 = prg_security_game_run(trivial, d_firstzero, 16, 200);
    prg_security_game_print(&g2);

    printf("\n--- PRG: XorShift ---\n");
    printf("Against bit-count distinguisher:\n");
    PRGSecurityGame g3 = prg_security_game_run(xorshift, d_bitcount, 16, 200);
    prg_security_game_print(&g3);

    printf("\n--- PRG: HashChain ---\n");
    printf("Against first-k-zero distinguisher:\n");
    PRGSecurityGame g4 = prg_security_game_run(hashchain, d_firstzero, 16, 200);
    prg_security_game_print(&g4);

    /* Cleanup */
    prg_free(trivial);
    prg_free(xorshift);
    prg_free(hashchain);
    dist_free_with_state(d_trivial);
    dist_free_with_state(d_firstzero);
    dist_free_with_state(d_bitcount);

    printf("\n=== Demo Complete ===\n");
    return 0;
}
