/*
 * example_prg_construction.c — PRG from OWF via Goldreich-Levin
 *
 * Demonstrates the full chain:
 *   OWF → Hardcore Bit → PRG → Statistical Tests
 *
 * This example shows:
 *   - OWF instantiation (L1, L3)
 *   - Hardcore bit extraction (L4)
 *   - Blum-Micali PRG construction (L5)
 *   - Statistical tests for pseudorandomness (L6)
 *   - PRG applications (L7)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include "../include/owf.h"
#include "../include/hardcore_bit.h"
#include "../include/bit_operations.h"
#include "../include/security_params.h"

/* Declarations from prg_from_owf.c */
typedef struct {
    OWF*     owf;
    size_t   seed_bits;
    size_t   output_bits;
    size_t   stretch;
} PRGFromOWF;

PRGFromOWF* prg_create(OWF* owf, size_t stretch);
void        prg_free(PRGFromOWF* prg);
int         prg_evaluate(const PRGFromOWF* prg, const BitString* seed,
                          BitString* output);

/* Statistical test functions */
static double bias_test(const BitString* sample) {
    if (!sample || sample->n_bits == 0) return 0.5;
    double frac = (double)bs_popcount(sample) / (double)sample->n_bits;
    double bias = frac - 0.5;
    return bias < 0 ? -bias : bias;
}

static size_t runs_test(const BitString* sample) {
    if (!sample || sample->n_bits <= 1) return 0;
    size_t runs = 1;
    for (size_t i = 1; i < sample->n_bits; i++) {
        if (bs_get_bit(sample, i) != bs_get_bit(sample, i - 1)) runs++;
    }
    return runs;
}

static size_t longest_run(const BitString* sample) {
    if (!sample || sample->n_bits == 0) return 0;
    size_t longest = 1, current = 1;
    for (size_t i = 1; i < sample->n_bits; i++) {
        if (bs_get_bit(sample, i) == bs_get_bit(sample, i - 1)) {
            current++;
            if (current > longest) longest = current;
        } else {
            current = 1;
        }
    }
    return longest;
}

int main(void) {
    srand((unsigned int)time(NULL));
    printf("=== PRG from OWF via Goldreich-Levin Hardcore Bit ===\n\n");

    /* ── Step 1: Create the underlying OWF ─────────────────── */
    printf("Step 1: Creating OWF (RSA-style, n=32 bits)\n");
    size_t n = 32;
    OWF* owf = owf_create(OWF_SQUARING, n);
    if (!owf) { printf("Failed to create OWF.\n"); return 1; }
    printf("  OWF type: %s\n", owf->name);
    printf("  Input bits: %zu, Output bits: %zu\n",
           owf->input_bits, owf->output_bits);

    /* ── Step 2: Demonstrate the hardcore bit ──────────────── */
    printf("\nStep 2: Goldreich-Levin hardcore bit\n");
    BitString* secret = bs_create_random(n);
    BitString* witness = bs_create_random(n);
    int hc = hc_inner_product(secret, witness, NULL);
    printf("  Secret x = "); bs_print_hex(secret);
    printf("  Witness r = "); bs_print_hex(witness);
    printf("  hc(x, r) = ⟨x, r⟩ mod 2 = %d\n", hc);

    /* ── Step 3: Build the PRG ─────────────────────────────── */
    printf("\nStep 3: Building Blum-Micali style PRG\n");
    size_t stretch = 64;  /* expand 32 → 96 bits */
    PRGFromOWF* prg = prg_create(owf, stretch);
    if (!prg) { printf("Failed to create PRG.\n"); owf_free(owf); return 1; }
    printf("  Seed bits:     %zu\n", prg->seed_bits);
    printf("  Stretch:       %zu\n", prg->stretch);
    printf("  Output bits:   %zu\n", prg->output_bits);
    printf("  Expansion:     %.1fx\n", (double)prg->output_bits / prg->seed_bits);

    /* ── Step 4: Generate PRG output ───────────────────────── */
    printf("\nStep 4: Generating PRG output from random seed\n");
    BitString* seed = bs_create_random(n);
    BitString* output = bs_create(prg->output_bits);

    prg_evaluate(prg, seed, output);
    printf("  Seed:   "); bs_print_hex(seed);
    printf("  Output: "); bs_print_hex(output);

    /* ── Step 5: Statistical Tests ─────────────────────────── */
    printf("\nStep 5: Statistical tests for pseudorandomness\n");

    /* Test 1: Bias */
    double bias = bias_test(output);
    printf("  Bias (|frac_1 - 0.5|): %.4f  %s\n", bias,
           bias < 0.1 ? "[PASS]" : "[SUSPICIOUS]");

    /* Test 2: Runs test */
    size_t runs = runs_test(output);
    double exp_runs = (double)output->n_bits / 2.0;
    printf("  Runs: %zu (expected ~%.1f)  %s\n", runs, exp_runs,
           (double)runs > exp_runs * 0.5 && (double)runs < exp_runs * 1.5
           ? "[PASS]" : "[SUSPICIOUS]");

    /* Test 3: Longest run */
    size_t lr = longest_run(output);
    double exp_lr = log2((double)output->n_bits);
    printf("  Longest run: %zu (expected ~%.1f)  %s\n", lr, exp_lr,
           (double)lr < exp_lr * 2.0 ? "[PASS]" : "[SUSPICIOUS]");

    /* ── Step 6: Forward Security ──────────────────────────── */
    printf("\nStep 6: Forward security demonstration\n");
    BitString* state = bs_clone(seed);
    printf("  Initial state:  "); bs_print_hex(state);

    int bits[8];
    for (int i = 0; i < 8; i++) {
        BitString* r = bs_create_random(n);
        bits[i] = hc_inner_product(state, r, NULL);
        bs_free(r);

        BitString* next = bs_create(owf->output_bits);
        owf_eval(owf, state, next);
        memcpy(state->data, next->data,
               state->n_words * sizeof(uint64_t));
        bs_free(next);
    }
    printf("  Output bits:    ");
    for (int i = 0; i < 8; i++) printf("%d", bits[i]);
    printf("\n");
    printf("  Final state:    "); bs_print_hex(state);
    printf("  (Knowing final state doesn't reveal output bits — OWF security)\n");

    /* ── Step 7: Security Parameter Estimation ─────────────── */
    printf("\nStep 7: Security estimation\n");
    double hardness = owf_estimate_hardness(owf);
    printf("  OWF hardness: ~%.0f bits\n", hardness);
    SecurityLevel sl = estimate_security_level((size_t)hardness, 0.0);
    printf("  Recommended parameters:\n");
    keylen_print_recommendation(sl);

    /* ── Step 8: Comparison with True Random ───────────────── */
    printf("\nStep 8: Comparison with true random\n");
    BitString* random = bs_create_random(output->n_bits);
    printf("  PRG bias:     %.4f\n", bias_test(output));
    printf("  Random bias:  %.4f\n", bias_test(random));
    printf("  PRG runs:     %zu\n", runs_test(output));
    printf("  Random runs:  %zu\n", runs_test(random));
    bs_free(random);

    /* ── Cleanup ───────────────────────────────────────────── */
    bs_free(secret); bs_free(witness); bs_free(seed);
    bs_free(output); bs_free(state);
    prg_free(prg);
    owf_free(owf);

    printf("\n=== PRG Construction Demonstration Complete ===\n");
    return 0;
}
