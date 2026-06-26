/*
 * example_hybrid_proof.c - Demo: Hybrid Argument Proof Structure
 *
 * Demonstrates the hybrid argument structure by constructing a simple
 * sequence of 5 hybrid distributions and showing how the pairwise
 * advantages sum to bound the total advantage.
 *
 * This is a pedagogical example of the proof technique used in:
 *   - PRG length extension (BMY)
 *   - Encryption scheme composition
 *   - Zero-knowledge proof composition
 */
#include "hybrid_argument.h"
#include <stdio.h>
#include <math.h>

/* Simple ensemble: always outputs constant bytes */
static size_t const_out_len(security_param_t n) { (void)n; return 128; }
static void const_sampler(const DistributionEnsemble* ens,
                           security_param_t n, DistributionSample* out) {
    (void)n;
    uint8_t val = ens->aux_data ? *(uint8_t*)ens->aux_data : 0;
    memset(out->data, val, out->byte_length);
}

int main(void) {
    printf("=== Hybrid Argument Proof Demo ===\n\n");
    rand_seed(12345);

    /* Create 5 hybrid ensembles with different constant byte values */
    /* H_0: all 0x00, H_1: all 0x01, ..., H_4: all 0x04 */
    /* Adjacent differ in exactly one byte value (the "swap") */

    uint8_t vals[5] = {0x00, 0x33, 0x66, 0x99, 0xCC};
    HybridSequence* hs = hseq_create(5);

    for (int i = 0; i < 5; i++) {
        uint8_t* val_ptr = (uint8_t*)malloc(sizeof(uint8_t));
        *val_ptr = vals[i];
        char name[16];
        snprintf(name, sizeof(name), "H_%d", i);
        DistributionEnsemble* ens = dens_create(name, const_out_len,
                                                  const_sampler, val_ptr);
        if (ens) hseq_add(hs, ens);
    }

    printf("Created %d hybrid distributions:\n", hseq_length(hs));
    for (int i = 0; i < hseq_length(hs); i++) {
        printf("  H_%d: all bytes = 0x%02X\n",
               i, *(uint8_t*)hseq_get(hs, i)->aux_data);
    }

    /* Run the hybrid argument verification */
    HybridArgumentResult* result = hybrid_arg_verify(hs, 128, 200, 0.1);
    if (result) {
        hybrid_arg_result_print(result);
        printf("\nTheoretical: Adv(H_0,H_4) <= 4 * epsilon = %.4f\n",
               4.0 * 0.1);
        printf("Measured:   Adv(H_0,H_4) = %.4f\n", result->measured_total);
        printf("Bound holds: %s\n",
               result->measured_total <= 4.0 * 0.1 ? "YES" : "NO");
        hybrid_arg_result_free(result);
    }

    /* Cleanup */
    for (int i = 0; i < hseq_length(hs); i++) {
        DistributionEnsemble* e = hseq_get(hs, i);
        if (e) {
            free(e->aux_data);
            dens_free(e);
        }
    }
    hseq_free(hs);

    printf("\n=== Demo Complete ===\n");
    return 0;
}
