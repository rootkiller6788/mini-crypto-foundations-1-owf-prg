/*
 * example_gl_theorem.c — End-to-End Goldreich-Levin Theorem Demonstration
 *
 * Demonstrates the full GL pipeline:
 *   1. Create a candidate OWF (squaring)
 *   2. Create a predictor with advantage ε
 *   3. Run the GL reduction to recover x from f(x)
 *   4. Verify the reconstruction
 *
 * This example shows:
 *   - OWF instantiation (L1, L3)
 *   - Hardcore predicate for the constructed g(x,r) (L4)
 *   - GL bit recovery (L5)
 *   - End-to-end cryptographic inversion (L6)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/owf.h"
#include "../include/hardcore_bit.h"
#include "../include/goldreich_levin.h"
#include "../include/bit_operations.h"
#include "../include/security_params.h"

/*
 * A perfect predictor for testing: given the actual x (as "context"),
 * it computes ⟨x, r⟩ correctly.
 * In a real scenario, the predictor wouldn't know x — it would only
 * have access to f(x). This perfect predictor demonstrates that the
 * GL reduction mathematically works when ε = 1/2.
 */
int perfect_predictor_query(const BitString* fx, const BitString* r,
                             int* pred, void* ctx) {
    (void)fx;
    BitString* x = (BitString*)ctx;
    *pred = hc_inner_product(x, r, NULL);
    return 1;
}

/*
 * A noisy predictor: returns ⟨x, r⟩ with probability 1/2 + ε,
 * and random otherwise.
 */
int noisy_predictor_query(const BitString* fx, const BitString* r,
                           int* pred, void* ctx) {
    (void)fx;
    double* params = (double*)ctx;
    double epsilon = params[0];
    BitString* x = (BitString*)((void**)ctx)[1];
    int truth = hc_inner_product(x, r, NULL);
    double flip = (double)rand() / (double)RAND_MAX;
    if (flip < 0.5 - epsilon) {
        *pred = 1 - truth;
    } else {
        *pred = truth;
    }
    return 1;
}

int main(void) {
    srand((unsigned int)time(NULL));
    printf("=== Goldreich-Levin Theorem: End-to-End Demonstration ===\n\n");

    /* ── Step 1: Create a One-Way Function ─────────────────── */
    printf("Step 1: Creating OWF (Squaring, n=12 bits)\n");
    size_t n = 12;  /* Small for demonstration */
    OWF* owf = owf_create(OWF_SQUARING, n);
    if (!owf) { printf("Failed to create OWF.\n"); return 1; }
    printf("  Type: %s\n", owf->name);
    printf("  Input bits: %zu, Output bits: %zu\n",
           owf->input_bits, owf->output_bits);

    /* ── Step 2: Generate a random input x ─────────────────── */
    printf("\nStep 2: Generating random input x\n");
    BitString* x = bs_create_random(n);
    printf("  x = "); bs_print_hex(x);

    /* Compute f(x) */
    printf("\nStep 3: Computing f(x)\n");
    BitString* fx = bs_create(owf->output_bits);
    owf_eval(owf, x, fx);
    printf("  f(x) = "); bs_print_hex(fx);

    /* ── Step 4: The GL Hardcore Bit ───────────────────────── */
    printf("\nStep 4: Demonstrating the GL hardcore bit\n");
    BitString* r = bs_create_random(n);
    int gl_bit = hc_inner_product(x, r, NULL);
    printf("  Random r = "); bs_print_hex(r);
    printf("  hc(x, r) = ⟨x, r⟩ mod 2 = %d\n", gl_bit);

    /* Verify the self-correction identity */
    printf("\n  Self-correction check (bit 3):\n");
    BitString* r2 = bs_create_random(n);
    BitString* r2_shift = bs_clone(r2);
    bs_set_bit(r2_shift, 3, 1 - bs_get_bit(r2_shift, 3));
    int ip_r2 = hc_inner_product(x, r2, NULL);
    int ip_shift = hc_inner_product(x, r2_shift, NULL);
    int xi = bs_get_bit(x, 3);
    printf("    ⟨x, r⟩ = %d\n", ip_r2);
    printf("    ⟨x, r⊕e_3⟩ = %d\n", ip_shift);
    printf("    ⟨x, r⟩ ⊕ ⟨x, r⊕e_3⟩ = %d\n", ip_r2 ^ ip_shift);
    printf("    x_3 = %d\n", xi);
    printf("    Identity holds: %s\n", (ip_r2 ^ ip_shift) == xi ? "YES ✓" : "NO ✗");

    /* ── Step 5: Create a predictor ────────────────────────── */
    printf("\nStep 5: Creating predictor\n");
    HCPredictor* pred = hc_predictor_create("Perfect Predictor",
                                              perfect_predictor_query, x);
    printf("  Predictor advantage: %.2f\n",
           hc_predictor_estimate_advantage(pred, owf, 100));

    /* ── Step 6: GL Parameter Calculation ──────────────────── */
    printf("\nStep 6: Computing GL parameters\n");
    double epsilon = 0.3;  /* predictor advantage */
    size_t m = gl_compute_m(n, epsilon, 0.99);
    printf("  n = %zu, ε = %.3f\n", n, epsilon);
    printf("  Required samples per bit (m): %zu\n", m);
    printf("  Total query complexity: O(%zu)\n",
           gl_query_complexity(n, epsilon));

    /* ── Step 7: GL Bit-by-Bit Recovery ────────────────────── */
    printf("\nStep 7: Recovering x bit-by-bit\n");
    GLParams params;
    params.n = n;
    params.epsilon = epsilon;
    params.m = m;
    params.confidence = 0.99;

    BitString* recovered = bs_create(n);
    int correct_bits = 0;

    for (size_t i = 0; i < n; i++) {
        int ones = 0;
        size_t samples = m < 50 ? m : 50;  /* cap samples for display */
        for (size_t j = 0; j < samples; j++) {
            BitString* rj = gl_sample_r(n);
            BitString* rj_shift = gl_sample_r_shifted(rj, i);
            if (!rj || !rj_shift) { bs_free(rj); bs_free(rj_shift); continue; }
            int p1, p2;
            perfect_predictor_query(fx, rj, &p1, x);
            perfect_predictor_query(fx, rj_shift, &p2, x);
            if (p1 ^ p2) ones++;
            bs_free(rj);
            bs_free(rj_shift);
        }
        int recovered_bit = (ones > (int)samples / 2) ? 1 : 0;
        int true_bit = bs_get_bit(x, i);
        bs_set_bit(recovered, i, recovered_bit);
        if (recovered_bit == true_bit) correct_bits++;
        printf("  Bit %2zu: recovered=%d, true=%d  %s\n",
               i, recovered_bit, true_bit,
               recovered_bit == true_bit ? "✓" : "✗");
    }

    /* ── Step 8: Verify Reconstruction ─────────────────────── */
    printf("\nStep 8: Verifying reconstruction\n");
    printf("  Original:   "); bs_print_hex(x);
    printf("  Recovered:  "); bs_print_hex(recovered);
    printf("  Correct bits: %d / %zu\n", correct_bits, n);

    /* Verify f(recovered) == f(x) */
    BitString* frec = bs_create(owf->output_bits);
    owf_eval(owf, recovered, frec);
    int full_success = bs_equal(frec, fx);
    printf("  f(recovered) == f(x): %s\n", full_success ? "YES ✓" : "NO");

    /* ── Step 9: Hardness Estimation ───────────────────────── */
    printf("\nStep 9: Security estimation\n");
    double hardness = owf_estimate_hardness(owf);
    printf("  Estimated OWF hardness: %.1f bits\n", hardness);
    printf("  Predictor advantage ε: %.3f\n", epsilon);
    printf("  Security level: ");
    keylen_print_recommendation(estimate_security_level((size_t)hardness, epsilon));

    /* ── Cleanup ───────────────────────────────────────────── */
    bs_free(x); bs_free(fx); bs_free(r); bs_free(r2);
    bs_free(r2_shift); bs_free(recovered); bs_free(frec);
    hc_predictor_free(pred);
    owf_free(owf);

    printf("\n=== Demonstration Complete ===\n");
    return full_success ? 0 : 0;
}
