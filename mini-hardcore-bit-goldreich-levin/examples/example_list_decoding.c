/*
 * example_list_decoding.c — Hadamard Code List Decoding Demonstration
 *
 * Demonstrates the list decoding of the Hadamard code, which is
 * the core combinatorial structure underlying Goldreich-Levin.
 *
 * This example shows:
 *   - Hadamard code encoding (L1, L3)
 *   - Walsh-Hadamard transform (L5)
 *   - List decoding of noisy codewords (L5)
 *   - Fourier analysis over the Boolean cube (L8)
 *
 * Reference: Goldreich-Levin STOC 1989; Arora-Barak §19.4
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include "../include/owf.h"
#include "../include/list_decoding.h"
#include "../include/bit_operations.h"

/*
 * Noisy oracle: returns correct Hadamard symbol with probability
 * 1/2 + epsilon, random otherwise.
 */
int noisy_hadamard_oracle(const BitString* r, void* ctx) {
    void** ctx_arr = (void**)ctx;
    BitString* x = (BitString*)ctx_arr[0];
    double epsilon = *(double*)ctx_arr[1];
    int truth = 0;
    size_t n = x->n_words < r->n_words ? x->n_words : r->n_words;
    truth = bit_inner_product(x->data, r->data, n);
    if ((double)rand() / RAND_MAX < 0.5 - epsilon) {
        return 1 - truth;
    }
    return truth;
}

int main(void) {
    srand((unsigned int)time(NULL));
    printf("=== Hadamard Code List Decoding Demonstration ===\n\n");

    /* ── Step 1: Create Hadamard code ──────────────────────── */
    size_t n = 4;  /* small for demo */
    printf("Step 1: Creating Hadamard code RM(1, %zu)\n", n);
    HadamardCode* code = hadamard_create(n);
    if (!code) { printf("Failed to create code.\n"); return 1; }
    printf("  Message length: %zu bits\n", code->n);
    printf("  Codeword length: %zu bits (2^%zu)\n", code->code_len, code->n);
    printf("  Rate: %.4f\n", hadamard_rate(n));
    printf("  Min relative distance: %.1f\n", hadamard_min_distance(n));

    /* ── Step 2: Encode a message ──────────────────────────── */
    printf("\nStep 2: Encoding a test message\n");
    BitString* msg = bs_create(n);
    bs_set_bit(msg, 0, 1);  /* x = 1001 */
    bs_set_bit(msg, 3, 1);
    printf("  Message x = "); bs_print(msg);

    HadamardCodeword* cw = hadamard_encode(code, msg);
    printf("  Codeword (truth table of <x,r>):\n");
    printf("  r=0: %d, r=1: %d, r=2: %d, r=3: %d\n",
           cw->symbols[0], cw->symbols[1], cw->symbols[2], cw->symbols[3]);
    printf("  r=4: %d, r=5: %d, r=6: %d, r=7: %d\n",
           cw->symbols[4], cw->symbols[5], cw->symbols[6], cw->symbols[7]);
    printf("  r=8: %d, r=9: %d, r=10: %d, r=11: %d\n",
           cw->symbols[8], cw->symbols[9], cw->symbols[10], cw->symbols[11]);
    printf("  r=12: %d, r=13: %d, r=14: %d, r=15: %d\n",
           cw->symbols[12], cw->symbols[13], cw->symbols[14], cw->symbols[15]);

    /* Verify distance property: any two codewords differ at exactly half */
    printf("\nStep 3: Distance property verification\n");
    BitString* msg2 = bs_create(n);
    bs_set_bit(msg2, 2, 1);  /* different message */
    HadamardCodeword* cw2 = hadamard_encode(code, msg2);
    int diff = 0;
    for (size_t i = 0; i < code->code_len; i++) {
        if (cw->symbols[i] != cw2->symbols[i]) diff++;
    }
    printf("  Differences between two codewords: %d / %zu (%.1f%%)\n",
           diff, code->code_len, 100.0 * diff / code->code_len);

    /* ── Step 4: Walsh-Hadamard Transform ──────────────────── */
    printf("\nStep 4: Fast Walsh-Hadamard Transform\n");
    size_t N = (size_t)1 << n;
    int* data = (int*)malloc(N * sizeof(int));
    for (size_t i = 0; i < N; i++) data[i] = cw->symbols[i];
    hadamard_transform(data, n);
    printf("  After FWHT (inverse = original message):\n");
    printf("  [");
    for (size_t i = 0; i < N; i++) {
        printf("%d%s", data[i], i < N - 1 ? ", " : "");
    }
    printf("]\n");
    free(data);

    /* ── Step 5: List Decoding with Noise ──────────────────── */
    printf("\nStep 5: List decoding a noisy codeword\n");
    double epsilon = 0.2;
    void* ctx_arr[2];
    ctx_arr[0] = msg;
    ctx_arr[1] = &epsilon;

    ListDecodingResult* lst = hadamard_list_decode(
        noisy_hadamard_oracle, ctx_arr, n, epsilon, 10);
    if (lst) {
        printf("  List size: %zu candidates\n", lst->list_size);
        printf("  Queries used: %zu\n", lst->queries);

        /* Check if original message is in list */
        int found = list_contains(lst, msg);
        printf("  Original message in list: %s\n", found ? "YES ✓" : "NO");

        list_decode_result_print(lst);
        list_decode_result_free(lst);
    }

    /* ── Step 6: Self-Correction Demonstration ─────────────── */
    printf("\nStep 6: Hadamard self-correction\n");
    BitString* target_r = bs_create(n);
    bs_set_bit(target_r, 1, 1);  /* want ⟨x, r=(0,1,0,0)⟩ */
    int corrected = hadamard_self_correct(noisy_hadamard_oracle,
                                           ctx_arr, target_r, n, 50);
    int true_val = bit_inner_product(msg->data, target_r->data,
                                      msg->n_words);
    printf("  Target: ⟨x, (0,1,0,0)⟩ = %d\n", true_val);
    printf("  Self-corrected: %d  %s\n", corrected,
           corrected == true_val ? "✓" : "✗");

    /* ── Step 7: Fourier Analysis ──────────────────────────── */
    printf("\nStep 7: Fourier coefficient analysis\n");
    int* truth_table = (int*)malloc(N * sizeof(int));
    for (size_t i = 0; i < N; i++) truth_table[i] = cw->symbols[i];
    double* coeffs = (double*)malloc(N * sizeof(double));
    fourier_transform(truth_table, n, coeffs);
    printf("  Largest Fourier coefficient magnitude:\n");
    double max_coeff = 0.0;
    int max_idx = 0;
    for (size_t i = 0; i < N; i++) {
        double mag = coeffs[i] > 0 ? coeffs[i] : -coeffs[i];
        if (mag > max_coeff) { max_coeff = mag; max_idx = (int)i; }
    }
    printf("  Index: %zu, Magnitude: %.4f\n", (size_t)max_idx, max_coeff);
    free(truth_table); free(coeffs);

    /* ── Step 8: List Size Bounds ──────────────────────────── */
    printf("\nStep 8: List size bounds\n");
    printf("  Johnson bound (ε=%.1f): %zu\n", epsilon,
           hadamard_list_size_bound(epsilon));
    printf("  GL bound (ε=%.1f, n=%zu): %zu\n", epsilon, n,
           gl_list_size_bound(n, epsilon));

    /* ── Cleanup ───────────────────────────────────────────── */
    hadamard_codeword_free(cw);
    hadamard_codeword_free(cw2);
    hadamard_free(code);
    bs_free(msg); bs_free(msg2); bs_free(target_r);

    printf("\n=== List Decoding Demonstration Complete ===\n");
    return 0;
}
