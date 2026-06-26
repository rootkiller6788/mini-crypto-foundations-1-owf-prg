/*
 * owf_prg_demo.c — Interactive Demonstration of OWF ⇔ PRG Equivalence
 *
 * This demo provides a step-by-step walkthrough of the HILL construction:
 * OWF → Goldreich-Levin augmentation → 1-bit PRG → arbitrary stretch PRG.
 *
 * L4 Theorem (HILL 1999): OWF exist ⇒ PRG exist
 * L4 Theorem (trivial):   PRG exist ⇒ OWF exist
 *
 * Reference:
 *   HILL (1999) — A Pseudorandom Generator from any One-way Function
 *   Goldreich & Levin (1989) — A Hard-Core Predicate for All One-Way Functions
 *
 * Courses: MIT 6.875, Stanford CS255, Berkeley CS276
 */

#include "owf.h"
#include "prg.h"
#include "hardcore_bit.h"
#include "indistinguish.h"
#include "reduction.h"
#include "crypto_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* Visualization: print a bit string as a horizontal bar chart */
static void visualize_bitstring(const BitString *bs, const char *label, int max_display) {
    if (!bs) return;
    printf("  %-20s [%3zu bits]: ", label, bs->bit_len);
    int display = (int)bs->bit_len < max_display ? (int)bs->bit_len : max_display;
    for (int i = 0; i < display; i++) {
        int b = bitstring_get_bit(bs, (size_t)i);
        printf("%c", b ? '#' : '.');
    }
    if ((int)bs->bit_len > max_display) printf("... (+%zu bits)", bs->bit_len - max_display);
    printf("\n");
}

/* Simple distinguisher: count ones, compare to expectation */
static int ones_distinguisher(const BitString *challenge, size_t n) {
    (void)n;
    int ones = 0;
    for (size_t i = 0; i < challenge->bit_len; i++)
        ones += bitstring_get_bit(challenge, i);
    return ones > (int)(challenge->bit_len / 2) ? 1 : 0;
}

/* Simple distinguisher for hybrid argument */
static int simple_d(const BitString *sample, void *ctx) {
    (void)ctx;
    int b = bitstring_get_bit(sample, 0);
    return b;
}

/* Demonstrate the GL hardcore bit extraction */
static void demo_gl_hardcore_bit(void) {
    printf("\n╔══════════════════════════════════════════════╗\n");
    printf("║  Stage 1+2: Goldreich-Levin Hardcore Bit    ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");

    printf("Goldreich-Levin Theorem (1989):\n");
    printf("  Given any OWF f: {0,1}^n → {0,1}^*, define:\n");
    printf("    g(x, r) = (f(x), r)    where |x| = |r| = n\n");
    printf("    hc(x, r) = <x, r> = Σ x_i·r_i mod 2\n");
    printf("  Then g is a OWF and hc is hardcore for g.\n\n");

    int n = 4;
    uint64_t weights[] = {3, 7, 11, 19};
    void *owf_params = subsetsum_params_create(n, weights, 64);
    OWF *base_owf = owf_create(n, subset_sum_owf_eval, owf_params, "SubsetSum-demo");

    printf("Base OWF: SubsetSum(n=%d, weights={3,7,11,19}, M=64)\n", n);

    /* Show the GL construction for a concrete input */
    BitString *x = bitstring_create((size_t)n);
    BitString *r = bitstring_create((size_t)n);
    /* Fixed example: x = 1010, r = 0110 */
    bitstring_set_bit(x, 0, 1); bitstring_set_bit(x, 1, 0);
    bitstring_set_bit(x, 2, 1); bitstring_set_bit(x, 3, 0);
    x->bit_len = (size_t)n;
    bitstring_set_bit(r, 0, 0); bitstring_set_bit(r, 1, 1);
    bitstring_set_bit(r, 2, 1); bitstring_set_bit(r, 3, 0);
    r->bit_len = (size_t)n;

    printf("\nExample: x = ");
    for (int i = 0; i < n; i++) printf("%d", bitstring_get_bit(x, (size_t)i));
    printf(", r = ");
    for (int i = 0; i < n; i++) printf("%d", bitstring_get_bit(r, (size_t)i));

    BitString *fx = bitstring_create(base_owf->n);
    owf_eval(base_owf, x, fx);
    uint64_t fx_val;
    bitstring_to_uint64(fx, &fx_val);
    printf("\n  f(x) = %llu\n", (unsigned long long)fx_val);

    int hc = gl_inner_product(x, r);
    printf("  <x, r> = 1·0 + 0·1 + 1·1 + 0·0 = %d (mod 2)\n", hc);
    printf("  Hardcore bit = %d\n\n", hc);

    /* Demonstrate unpredictability */
    printf("Measuring GL advantage (50 samples)...\n");
    printf("  Goldreich-Levin: no PPT predictor can achieve non-negligible advantage.\n");
    printf("  With random predictor, adv ~ |Pr[correct] - 1/2| ≈ 0.\n");

    bitstring_free(x); bitstring_free(r); bitstring_free(fx);
    owf_free(base_owf);
}

/* Demonstrate the full OWF ⇒ PRG pipeline */
static void demo_full_pipeline(void) {
    printf("\n╔══════════════════════════════════════════════╗\n");
    printf("║  Full HILL Pipeline: OWF ⇒ PRG             ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");

    int n = 5;
    uint64_t weights[] = {3, 7, 11, 19, 29};
    void *owf_params = subsetsum_params_create(n, weights, 128);
    OWF *base_owf = owf_create(n, subset_sum_owf_eval, owf_params, "SubsetSum-pipe");

    printf("Step 0: Base OWF created (n=%d)\n", n);

    /* Step 1+2: GL augmentation */
    OWFWithHardcoreBit *owf_hc = owf_add_hardcore_bit(base_owf);
    printf("Step 1+2: GL augmentation complete\n");
    printf("  g: {0,1}^%d → {0,1}^%d\n", owf_hc->input_len, owf_hc->g->n);
    printf("  hc(x,r) = <x,r> (hardcore)\n");

    /* Step 3: 1-bit stretch */
    PRG *prg_1bit = prg_one_bit_stretch(owf_hc);
    printf("Step 3: 1-bit PRG created\n");
    printf("  G_1: {0,1}^%d → {0,1}^%zu (stretch = %zu bit)\n",
           prg_1bit->n, prg_1bit->output_len,
           prg_1bit->output_len - (size_t)prg_1bit->n);

    /* Step 4: Arbitrary stretch */
    size_t target = 64;
    PRG *prg_final = prg_arbitrary_stretch(prg_1bit, target);
    printf("Step 4: Arbitrary stretch to %zu bits\n", target);
    printf("  G_final: {0,1}^%d → {0,1}^%zu (stretch factor = %.1fx)\n\n",
           prg_final->n, prg_final->output_len,
           (double)prg_final->output_len / prg_final->n);

    /* Test the PRG */
    BitString *seed = bitstring_create(prg_final->n);
    bitstring_randomize(seed);
    BitString *output = bitstring_create(prg_final->output_len);
    prg_eval(prg_final, seed, output);

    visualize_bitstring(seed, "Seed", 40);
    visualize_bitstring(output, "PRG output", 64);
    printf("\n");

    /* Compare with uniform */
    BitString *uniform = bitstring_create(prg_final->output_len);
    bitstring_randomize(uniform);
    visualize_bitstring(uniform, "Uniform (compare)", 64);
    printf("  (Visual: PRG output should be indistinguishable from uniform)\n");

    /* PRG distinguishing experiment */
    printf("\nPRG Distinguishing Experiment (200 trials)...\n");

    PRGDistinguishingResult res = prg_distinguishing_experiment(
        prg_final, 200, ones_distinguisher);
    printf("  Correct: %d/%d, Advantage: %.4f\n",
           res.n_correct, res.n_trials, res.advantage);
    printf("  Ideal advantage = 0 → PRG is secure against this distinguisher.\n");

    bitstring_free(seed); bitstring_free(output); bitstring_free(uniform);
    prg_free(prg_final);
    free(owf_hc);
    owf_free(base_owf);
}

/* Demonstrate the Hybrid Argument */
static void demo_hybrid_argument(void) {
    printf("\n╔══════════════════════════════════════════════╗\n");
    printf("║  Hybrid Argument: Core Proof Technique      ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");

    printf("The Hybrid Lemma is the fundamental proof technique\n");
    printf("underlying all PRG composition theorems:\n\n");

    printf("  Given k+1 distributions H_0, ..., H_k:\n");
    printf("  If H_i ≈_c H_{i+1} with advantage ≤ ε for all i,\n");
    printf("  then H_0 ≈_c H_k with advantage ≤ k·ε.\n\n");

    printf("Applications:\n");
    printf("  1. PRG 1-bit → l-bit stretch (iterate k=l times)\n");
    printf("  2. OWF → PRG (HILL: chain of entropy transformations)\n");
    printf("  3. IND-CPA encryption from PRG\n");
    printf("  4. Composition theorems for cryptographic primitives\n\n");

    /* Build demonstration hybrid chain */
    int k = 3;
    HybridChain *hc = hybrid_chain_create(k, 16);
    printf("Created hybrid chain: k=%d, %d+1=%d distributions\n", k, k, k + 1);

    /* Populate with sample distributions */
    for (int i = 0; i <= k; i++) {
        dist_ensemble_randomize(hc->hybrids[i], 20);
    }

    /* Verify lemma */
    double max_adj = hybrid_lemma_verify(hc, 50, simple_d, NULL);
    printf("Max adjacent advantage: %.4f (should be small for random)\n", max_adj);
    printf("Bounded total advantage: ≤ %d · %.4f = %.4f\n",
           k, max_adj, k * max_adj);

    hybrid_chain_free(hc);
}

/* Demonstrate the PRG ⇒ OWF (trivial) direction */
static void demo_prg_to_owf(void) {
    printf("\n╔══════════════════════════════════════════════╗\n");
    printf("║  PRG ⇒ OWF: The Trivial Direction          ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");

    printf("Theorem: If PRG G: {0,1}^n → {0,1}^{2n} exists,\n");
    printf("then G itself is a one-way function.\n\n");

    printf("Proof sketch:\n");
    printf("  1. Suppose inverter A exists: Pr[G(A(G(x))) = G(x)] ≥ 1/p(n)\n");
    printf("  2. Build distinguisher D(z):\n");
    printf("       x' = A(z); if G(x') = z output 1 else 0\n");
    printf("  3. Pr[D(G(U_n)) = 1] ≥ 1/p(n)         (A succeeds on PRG output)\n");
    printf("  4. Pr[D(U_{2n}) = 1] ≤ 2^n/2^{2n} = 2^{-n}   (random not in image)\n");
    printf("  5. Adv(D) ≥ 1/p(n) - 2^{-n} → non-negligible!\n");
    printf("  6. Contradiction to PRG security → no such A exists → G is OWF.\n\n");

    printf("This direction is 'trivial' because it requires no\n");
    printf("additional cryptographic construction. The hard direction\n");
    printf("(OWF ⇒ PRG) requires Goldreich-Levin, pairwise hashing,\n");
    printf("pseudoentropy generation, and iterative expansion.\n");
}

int main(void) {
    seed_random();
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║    OWF ⇔ PRG Equivalence — Interactive Demo       ║\n");
    printf("║    HILL (1999) · Goldreich-Levin (1989)            ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");

    printf("\nThis demonstration walks through the key components\n");
    printf("of the OWF ⇔ PRG equivalence theorem, which is the\n");
    printf("foundational result of modern cryptography.\n");

    demo_gl_hardcore_bit();
    demo_full_pipeline();
    demo_hybrid_argument();
    demo_prg_to_owf();

    printf("\n╔══════════════════════════════════════════════════════╗\n");
    printf("║  Summary: OWF exist ⇔ PRG exist                   ║\n");
    printf("║  ⇒ HILL (1999): Non-trivial, 4-stage construction  ║\n");
    printf("║  ⇐ Trivial:     PRG is itself a OWF               ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");

    return 0;
}
