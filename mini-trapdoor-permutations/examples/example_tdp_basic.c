/**
 * example_tdp_basic.c -- Basic TDP Operations Demo
 *
 * Demonstrates:
 *   1. TDP key generation
 *   2. Domain sampling
 *   3. Forward evaluation (easy direction)
 *   4. Inverse evaluation (hard direction, with trapdoor)
 *   5. Permutation property verification
 *   6. Brute-force inversion attempt (shows why trapdoor is essential)
 *
 * This example shows the core abstraction of trapdoor permutations
 * before specializing to the RSA construction.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "tdp_core.h"
#include "modular_math.h"
#include "rsa.h"
#include "rsa_keygen.h"
#include "tdp_pke.h"

int main(void) {
    printf("========================================\n");
    printf("  Trapdoor Permutation Basic Demo\n");
    printf("========================================\n\n");

    /* Step 1: Generate an RSA key pair (concrete TDP instantiation) */
    printf("[1] Generating RSA-64 key pair...\n");
    rsa_keypair_t rsa_key;
    tdp_status_t status = rsa_generate_keypair(&rsa_key, 64, 42);
    if (status != TDP_SUCCESS) {
        printf("Key generation failed!\n");
        return 1;
    }
    printf("    Modulus n (%u bits):\n", rsa_key.params.nbits);
    bigint_print_hex("    n = ", &rsa_key.params.n);
    bigint_print_hex("    e = ", &rsa_key.params.e);
    bigint_print_hex("    d = ", &rsa_key.params.d);
    printf("\n");

    /* Build TDP public key and trapdoor from RSA key */
    tdp_public_key_t pk;
    pk.modulus = rsa_key.params.n;
    pk.exponent = rsa_key.params.e;
    pk.nbits = rsa_key.params.nbits;

    tdp_trapdoor_t td;
    td.prime_p = rsa_key.params.p;
    td.prime_q = rsa_key.params.q;
    td.private_exp = rsa_key.params.d;
    td.totient = rsa_key.params.phi_n;
    td.d_p = rsa_key.d_p;
    td.d_q = rsa_key.d_q;
    td.q_inv = rsa_key.q_inv;

    /* Step 2: Sample a domain element */
    printf("[2] Sampling domain element...\n");
    tdp_domain_elem_t x = tdp_sample_domain(&pk);
    if (!x.in_domain) {
        printf("Failed to sample domain element (may need larger key).\n");
        printf("Using x = 2 instead.\n");
        bigint_t two;
        bigint_set_one(&two); bigint_inc(&two);
        x.value = two;
        x.in_domain = tdp_check_domain_membership(&pk, &x.value);
    }
    bigint_print_hex("    x = ", &x.value);
    printf("    in_domain = %s\n\n", x.in_domain ? "true" : "false");
    if (!x.in_domain) {
        printf("Domain element not valid -- exiting.\n");
        return 1;
    }

    /* Step 3: Forward evaluation (easy -- no trapdoor needed) */
    printf("[3] Forward evaluation: y = f(x)...\n");
    tdp_eval_result_t y = tdp_eval_forward(&pk, &x);
    if (y.valid) {
        bigint_print_hex("    y = f(x) = ", &y.value);
    } else {
        printf("Forward evaluation failed.\n");
        return 1;
    }
    printf("\n");

    /* Step 4: Inverse evaluation (hard -- requires trapdoor) */
    printf("[4] Inverse evaluation: x' = f^{-1}(y) with trapdoor...\n");
    tdp_domain_elem_t x_recovered = tdp_eval_inverse(&pk, &td, &y);
    if (x_recovered.in_domain) {
        bigint_print_hex("    x' = ", &x_recovered.value);
        printf("    Roundtrip: %s\n",
               bigint_compare(&x_recovered.value, &x.value) == 0 ? "SUCCESS" : "FAILURE");
    } else {
        printf("Inverse evaluation failed.\n");
    }
    printf("\n");

    /* Step 5: Verify permutation property */
    printf("[5] Verifying permutation property...\n");
    bool is_perm = tdp_verify_permutation_property(&pk, &td, &x);
    printf("    f^{-1}(f(x)) == x? %s\n", is_perm ? "YES" : "NO");
    printf("\n");

    /* Step 6: Attempt brute-force inversion (demonstrates why trapdoor matters) */
    printf("[6] Simulating brute-force attack (10000 attempts)...\n");
    printf("    Without the trapdoor, the best strategy is to try\n");
    printf("    random domain elements until f(x') matches y.\n");
    printf("    Domain size ~ 2^%u, so exhaustive search is infeasible.\n\n", pk.nbits);

    uint32_t attempts = simulate_tdp_brute_force(&pk, &y, 10000);
    printf("    Attempts: %u / 10000\n", attempts);
    printf("    Success: %s\n", (attempts < 10000) ? "Found (unlikely for large keys)!"
                                                     : "Failed (expected)");
    printf("    This shows why trapdoor knowledge is essential.\n");
    printf("\n");

    /* Step 7: Security analysis */
    printf("[7] Security analysis:\n");
    printf("    Security parameter lambda = 64 (DEMO ONLY -- use >= 2048 in practice)\n");
    printf("    Negligible threshold 2^{-64} = %.2e\n", pow(2.0, -64));
    printf("    Is 2^{-80} negligible? %s\n",
           tdp_is_negligible(pow(2.0, -80), 64) ? "Yes" : "No");
    printf("    One-way advantage at 1/10000 = %.4f\n",
           tdp_one_way_advantage(1, 10000, 64));
    printf("    Is this advantage significant? %s\n",
           tdp_advantage_is_significant(0.0001, 64) ? "Yes (breaks security)" : "No");

    printf("\n========================================\n");
    printf("  Demo Complete\n");
    printf("========================================\n");
    return 0;
}
