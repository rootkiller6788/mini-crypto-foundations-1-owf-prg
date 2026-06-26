/*
 * example_worlds.c — Impagliazzo's Five Worlds Demo
 *
 * Demonstrates: world belief updating based on evidence,
 * world capability enumeration, and cryptographic deployment advice.
 */
#include "minimal_assumptions.h"
#include "impagliazzo_worlds.h"
#include "black_box_separation.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    printf("============================================\n");
    printf("  Impagliazzo's Five Worlds — Live Demo\n");
    printf("============================================\n\n");

    /* Start with uniform belief over five worlds */
    WorldBelief belief = world_belief_init();
    printf("Initial belief (uniform prior):\n");
    world_belief_print(&belief);

    /* Feed in real-world evidence */
    printf("\n--- Updating with real-world evidence ---\n\n");

    printf("[1] RSA still standing after 40+ years\n");
    world_belief_update(&belief, "RSA still standing");
    world_belief_print(&belief);

    printf("\n[2] P vs NP remains open after decades\n");
    world_belief_update(&belief, "P vs NP unresolved");
    world_belief_print(&belief);

    printf("\n[3] TLS/PGP widely deployed, no catastrophic breaks\n");
    world_belief_update(&belief, "PKE and TLS widely deployed and secure");
    world_belief_print(&belief);

    printf("\n[4] Post-quantum: LWE-based candidates look promising\n");
    world_belief_update(&belief, "LWE post-quantum candidates secure");
    world_belief_print(&belief);

    /* Show capabilities of each world */
    printf("\n============================================\n");
    printf("  World Capabilities Overview\n");
    printf("============================================\n");
    world_capabilities_print(ALGORITHMICA);
    world_capabilities_print(MINICRYPT);
    world_capabilities_print(CRYPTOMANIA);

    /* MAP estimate */
    ImpagliazzoWorld best = world_belief_map(&belief);
    printf("\nMAP Estimate: We live in %s\n", world_name(best));

    /* Deployment advice based on belief */
    printf("\n============================================\n");
    printf("  Deployment Recommendations\n");
    printf("============================================\n");
    CryptoDeploymentAdvice adv_ske = advise_deployment(PRIM_SKE, 128);
    CryptoDeploymentAdvice adv_pke = advise_deployment(PRIM_PKE, 128);
    print_deployment_advice(&adv_ske);
    print_deployment_advice(&adv_pke);

    /* TLS recommendation */
    char tls_buf[256];
    tls_cipher_recommendation(best, tls_buf, sizeof(tls_buf));
    printf("\nTLS Recommendation: %s\n", tls_buf);

    printf("\n============================================\n");
    printf("  Demo Complete\n");
    printf("============================================\n");
    return 0;
}
