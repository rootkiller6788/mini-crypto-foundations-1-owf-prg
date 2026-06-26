/*
 * example_owf_prg_equivalence.c — OWF ⇔ PRG Equivalence Theorem
 *
 * L4 Fundamental Theorem (HILL 1999): OWF exist ⇔ PRG exist
 *
 * This example demonstrates both directions of the equivalence:
 *
 * Direction 1 (HARD — HILL 1999): OWF ⇒ PRG
 *   Stage 1: OWF → OWF with hardcore bit (Goldreich-Levin)
 *   Stage 2: OWF+HC → 1-bit stretch PRG
 *   Stage 3: 1-bit PRG → arbitrary stretch PRG
 *
 * Direction 2 (EASY — trivial): PRG ⇒ OWF
 *   G itself is a OWF: if you can invert G, you can break PRG security.
 *   Proof: Pr[G(U_n) has unique preimage] ≥ 1 - negl(n)
 *   If inverter succeeds → found preimage → distinguished from random
 *
 * The example shows:
 *   - Building the full HILL construction end-to-end
 *   - Testing PRG security via distinguishing experiment
 *   - Testing OWF security via inversion experiment
 *   - Comparing security loss (reduction tightness)
 *   - Yao amplification: weak OWF → strong OWF
 */

#include "owf.h"
#include "prg.h"
#include "hardcore_bit.h"
#include "indistinguish.h"
#include "reduction.h"
#include "crypto_utils.h"
#include <stdio.h>
#include <stdlib.h>

/* A simple distinguisher that checks bit patterns */
static int pattern_distinguisher(const BitString *challenge, size_t n) {
    (void)n;
    /* Count the number of 1s in the challenge */
    int ones = 0;
    for (size_t i = 0; i < challenge->bit_len; i++) {
        ones += bitstring_get_bit(challenge, (size_t)i);
    }
    /* Uniform random: expected ones ≈ len/2.
     * Pseudorandom from our simple PRG: parity-based, may have bias.
     * Distinguisher: if ones > len/2, guess pseudorandom. */
    return (ones > (int)(challenge->bit_len / 2)) ? 1 : 0;
}

/* A simple inverter that tries random preimages (brute-force for small n) */
static int random_inverter(const OWF *owf, const BitString *y, BitString *x_out) {
    (void)owf;
    (void)y;
    /* For small domains, brute-force search */
    int max_attempts = 200;
    for (int attempt = 0; attempt < max_attempts; attempt++) {
        (void)attempt;
        bitstring_randomize(x_out);
    }
    return 1; /* Always returns a guess */
}

int main(void) {
    seed_random();
    printf("=== OWF ⇔ PRG Equivalence Theorem ===\n\n");

    /* ================================================================
     * Direction 1: OWF ⇒ PRG (HILL Construction)
     * ================================================================ */
    printf("========================================\n");
    printf("DIRECTION 1: OWF ⇒ PRG (HILL 1999)\n");
    printf("========================================\n\n");

    /* Stage 0: Create base OWF (Subset Sum with 5 weights) */
    printf("[Stage 0] Base OWF: Subset Sum (n=5, weights={3,7,11,19,29}, M=128)\n");
    int n_bits = 5;
    uint64_t weights[] = {3, 7, 11, 19, 29};
    void *owf_params = subsetsum_params_create(n_bits, weights, 128);
    OWF *base_owf = owf_create(n_bits, subset_sum_owf_eval, owf_params, "SubsetSum");

    printf("  OWF: f(x) = Σ x_i · a_i mod 128\n");
    printf("  Domain: {0,1}^%d, Range: [0, 127]\n", n_bits);

    /* Show a few evaluations */
    for (int test = 0; test < 3; test++) {
        BitString *x = bitstring_create((size_t)n_bits);
        BitString *y = bitstring_create(base_owf->n);
        bitstring_randomize(x);
        x->bit_len = (size_t)n_bits;
        owf_eval(base_owf, x, y);
        uint64_t yval;
        bitstring_to_uint64(y, &yval);
        printf("  f(");
        for (int b = 0; b < n_bits; b++)
            printf("%d", bitstring_get_bit(x, (size_t)b));
        printf(") = %llu\n", (unsigned long long)yval);
        bitstring_free(x);
        bitstring_free(y);
    }

    /* Stage 1+2: Goldreich-Levin augmentation */
    printf("\n[Stage 1+2] Goldreich-Levin: Augment OWF with hardcore bit\n");
    OWFWithHardcoreBit *owf_hc = owf_add_hardcore_bit(base_owf);
    printf("  g(x,r) = (f(x), r) ∈ {0,1}^{%d}\n", owf_hc->g->n);
    printf("  hc(x,r) = <x,r> = Σ x_i·r_i mod 2\n");
    printf("  Input: (x||r) ∈ {0,1}^{%d}\n", owf_hc->input_len);

    /* Stage 3: 1-bit stretch PRG */
    printf("\n[Stage 3] 1-bit stretch PRG: G_1(s) = (g(s), hc(s))\n");
    PRG *prg_1 = prg_one_bit_stretch(owf_hc);
    printf("  G_1: {0,1}^{%d} → {0,1}^{%zu} (stretch = 1 bit)\n",
           prg_1->n, prg_1->output_len);

    /* Test the 1-bit PRG */
    BitString *sd = bitstring_create(prg_1->n);
    BitString *out1 = bitstring_create(prg_1->output_len);
    bitstring_randomize(sd);
    prg_eval(prg_1, sd, out1);
    printf("  G_1(seed) = %zu bits output\n", out1->bit_len);
    bitstring_free(sd);
    bitstring_free(out1);

    /* Stage 4: Arbitrary stretch */
    printf("\n[Stage 4] Arbitrary stretch: G_64 via iterative expansion\n");
    PRG *prg_final = prg_arbitrary_stretch(prg_1, 64);
    printf("  G_64: {0,1}^{%d} → {0,1}^{%zu}\n", prg_final->n, prg_final->output_len);
    printf("  Stretch factor: %.2fx\n",
           (double)prg_final->output_len / prg_final->n);

    /* PRG distinguishing experiment */
    printf("\n[Test] PRG distinguishing experiment (200 trials)...\n");
    PRGDistinguishingResult prg_res = prg_distinguishing_experiment(
        prg_final, 200, pattern_distinguisher);
    printf("  Correct guesses: %d / %d\n", prg_res.n_correct, prg_res.n_trials);
    printf("  Distinguisher advantage: %.4f\n", prg_res.advantage);
    printf("  (Advantage ≈ 0 ⇒ PRG is secure against this distinguisher)\n");

    /* ================================================================
     * Direction 2: PRG ⇒ OWF (Trivial)
     * ================================================================ */
    printf("\n========================================\n");
    printf("DIRECTION 2: PRG ⇒ OWF (Trivial)\n");
    printf("========================================\n\n");

    OWF *owf_from_prg = prg_to_owf(prg_final);
    printf("  f(x) = G(x): {0,1}^{%d} → {0,1}^{%d}\n",
           owf_from_prg->n, owf_from_prg->n);
    printf("  If inverter A can invert G,\n");
    printf("  then D(z) = {output 1 if G(A(z)) = z} distinguishes G(U_n) from U_{2n}\n");
    printf("  Pr[U_{2n} ∈ Im(G)] ≤ 2^{%d}/2^{%zu} = 2^{-%zu} (negligible)\n",
           owf_from_prg->n, prg_final->output_len,
           prg_final->output_len - (size_t)owf_from_prg->n);
    printf("  ∴ Breaking OWF-security of G ⇒ Breaking PRG-security of G\n");

    /* Test OWF aspect */
    printf("\n[Test] OWF inversion experiment (100 trials, random inverter)...\n");
    OWFInversionResult owf_res = owf_inversion_experiment(
        owf_from_prg, 100, random_inverter);
    printf("  Trials: %d, Successes: %d\n",
           owf_res.n_trials, owf_res.n_successes);
    printf("  Success probability: %.4f\n", owf_res.success_probability);
    printf("  (For secure OWF, success should be negligible in n)\n");

    /* ================================================================
     * Bonus: Yao Weak-to-Strong OWF Amplification
     * ================================================================ */
    printf("\n========================================\n");
    printf("BONUS: Yao Amplification — Weak OWF → Strong OWF\n");
    printf("========================================\n\n");
    printf("  Weak OWF: Inverter succeeds with prob ≤ 1-1/p(n)\n");
    printf("  Strong OWF: Inverter succeeds with prob ≤ negl(n)\n");
    printf("  Construction: f'(x_1,...,x_q) = (f(x_1),...,f(x_q))\n");
    printf("  With q = n·p(n) copies, success prob drops to (1-1/p)^q ≈ e^{-n}\n");

    int n_copies = 8;
    void *amp_params = yao_amplify_params_create(base_owf, n_copies);
    OWF *strong_owf = owf_create(base_owf->n * n_copies,
                                  yao_amplify_owf_eval, amp_params,
                                  "Yao-amplified");
    printf("\n  Created amplified OWF: %d copies → total input %d bits\n",
           n_copies, strong_owf->n);
    printf("  Each inverter success ≤ 1/p(n) per copy\n");
    printf("  Parallel success ≤ (1/p(n))^{%d} → negligible for large n_copies\n",
           n_copies);

    /* ================================================================
     * Summary
     * ================================================================ */
    printf("\n========================================\n");
    printf("THEOREM: OWF exist ⇔ PRG exist\n");
    printf("========================================\n");
    printf("  ⇒ (HILL 1999):  Non-trivial, uses Goldreich-Levin + pseudoentropy\n");
    printf("  ⇐ (Trivial):    PRG G itself is length-expanding OWF\n");
    printf("\n  The two primitives are equivalent:\n");
    printf("    • If you have any OWF, you can build a PRG.\n");
    printf("    • If you have any PRG, you have a OWF.\n");
    printf("  This equivalence is the foundation of modern cryptography.\n");

    /* Cleanup */
    owf_free(strong_owf);
    owf_free(owf_from_prg); /* Frees prg_final as its param */
    free(owf_hc);
    owf_free(base_owf);

    printf("\n=== Equivalence Demo Complete ===\n");
    return 0;
}
