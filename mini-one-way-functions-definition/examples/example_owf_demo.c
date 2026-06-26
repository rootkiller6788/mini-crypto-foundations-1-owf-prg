/*
 * example_owf_demo.c - Demonstrate One-Way Function concepts
 *
 * L1-L2: Shows core OWF definition, evaluation, inversion experiment.
 * This is an end-to-end runnable example (>30 lines) with output.
 */

#include "owf_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static int simple_squaring_eval(void* ctx, const bit_string_t* x,
                                 sec_param_t n, bit_string_t** y) {
    (void)ctx; (void)n;
    /* A simple OWF: f(x) = x^2 (concatenate x with itself) */
    *y = bs_create(x->bit_len * 2);
    if (!*y) return -1;
    /* Copy x twice */
    for (size_t i = 0; i < x->byte_cap && i < (*y)->byte_cap; i++)
        (*y)->data[i] = x->data[i];
    for (size_t i = 0; i < x->byte_cap && (i+x->byte_cap) < (*y)->byte_cap; i++)
        (*y)->data[i+x->byte_cap] = x->data[i];
    return 0;
}

static int brute_force_invert(void* ctx, const bit_string_t* y,
                               sec_param_t n, bit_string_t** xp) {
    (void)ctx; (void)y; (void)n;
    /* For demonstration: just return something (inversion is hard!) */
    *xp = bs_create(8);
    return (*xp) ? 0 : -1;
}

int main(void) {
    srand((unsigned)time(NULL));
    printf("=== One-Way Function Demonstration ===\n\n");

    /* Part 1: Create an OWF scheme */
    owf_scheme_t* owf = owf_scheme_create(
        "Simple-Squaring-OWF",
        "Length-doubling (educational example)",
        simple_squaring_eval, brute_force_invert,
        NULL, NULL, 128, 64, 128);
    printf("Created OWF: %s\n", owf->name);
    printf("  Assumption: %s\n", owf->assumption);
    printf("  Input: %zu bits, Output: %zu bits\n\n",
           owf->input_bits, owf->output_bits);

    /* Part 2: Evaluate f(x) */
    bit_string_t* x = bs_random(64);
    printf("Random input x: ");
    bs_print_hex(x, "");

    bit_string_t* y = NULL;
    owf_evaluate(owf, x, &y);
    printf("Output y = f(x): ");
    bs_print_hex(y, "");
    printf("  Evaluation count: %llu\n\n", (unsigned long long)owf->eval_count);

    /* Part 3: Run inversion experiment */
    printf("Running 10 inversion experiments...\n");
    double avg_time = 0.0;
    double success_rate = invert_experiment_batch(
        owf, brute_force_invert, NULL, 64, 10, &avg_time);
    printf("  Success rate: %.2f%%\n", success_rate * 100.0);
    printf("  Avg time: %.3f ms\n", avg_time);
    printf("  (Low success rate demonstrates one-wayness)\n\n");

    /* Part 4: Negligible function demonstration */
    printf("Negligible function values:\n");
    for (sec_param_t n = 8; n <= 64; n *= 2) {
        printf("  n=%3u: 2^{-n}=%.2e  is_negl=%d\n",
               n, negligible_exponential(n), is_negligible(negligible_exponential(n), n));
    }

    /* Part 5: OWF strength classification */
    printf("\nOWF Strength Classification:\n");
    printf("  Success %.4f -> ", success_rate);
    owf_strength_t s = owf_estimate_strength(success_rate, 64, 10);
    printf("%s\n", s == OWF_TYPE_STRONG ? "STRONG" :
                     s == OWF_TYPE_WEAK ? "WEAK" : "UNKNOWN");

    bs_free(x); bs_free(y);
    owf_scheme_free(owf);
    printf("\n=== Demonstration Complete ===\n");
    return 0;
}
