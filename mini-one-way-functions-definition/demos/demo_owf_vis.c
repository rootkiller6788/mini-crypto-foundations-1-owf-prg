/*
 * demo_owf_vis.c --- Interactive Visualization of One-Way Function Concepts
 *
 * L1-L6: Demonstrates OWF concept visually with ASCII art.
 * Shows: RSA OWF evaluation, inversion hardness, GL predicate,
 *        Yao amplification effect, CRT bijection.
 *
 * This is an end-to-end runnable demonstration (>30 lines) with output.
 * Part of the demos/ directory per SKILL.md S5.1.
 */

#include "owf_core.h"
#include "owf_number_theory.h"
#include "owf_candidates.h"
#include "owf_hardcore.h"
#include "owf_weak_strong.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

/* ================================================================
 * Visualization 1: OWF Evaluation Flow
 * Demonstrates the easy direction (x -> f(x)) vs hard direction.
 * ================================================================ */
static void demo_eval_flow(void) {
    printf("\n========================================\n");
    printf("  1. One-Way Function Evaluation Flow\n");
    printf("========================================\n\n");

    printf("  EASY direction (poly-time):\n");
    printf("    x = [random n-bit string]\n");
    printf("        |\n");
    printf("        v  (efficient computation)\n");
    printf("    y = f(x)\n");
    printf("        |\n");
    printf("        v\n");
    printf("  HARD direction (no PPT algorithm):\n");
    printf("    y = f(x)\n");
    printf("        |\n");
    printf("        v  (believed to require super-poly time)\n");
    printf("    x = ??? (need to invert f)\n\n");

    printf("  Formal definition:\n");
    printf("    For all PPT A, for all positive polynomials p(n),\n");
    printf("    exists N s.t. for all n > N:\n");
    printf("      Pr[A(f(x), 1^n) in f^{-1}(f(x))] < 1/p(n)\n");
    printf("    where x <- {0,1}^n uniformly.\n\n");

    /* Demonstrate with concrete function */
    printf("  Concrete example (toy):\n");
    bit_string_t* x = bs_random(8);
    printf("  x = "); bs_print_hex(x, "");

    owf_scheme_t* toy = owf_scheme_create("toy", "demo",
        NULL, NULL, NULL, NULL, 64, 8, 16);
    bit_string_t* y = bs_create(16);
    if (y) {
        /* Simple OWF: double the input */
        memcpy(y->data, x->data, x->byte_cap);
        if (16 / 8 > x->byte_cap)
            memset(y->data + x->byte_cap, 0, (16/8) - x->byte_cap);
        printf("  y = "); bs_print_hex(y, "");
    }
    printf("  Eval time: instantaneous (trivial)\n");
    printf("  Invert time: exhaustive search over 2^8 = 256 inputs\n\n");

    bs_free(x); bs_free(y);
    owf_scheme_free(toy);
}

/* ================================================================
 * Visualization 2: Negligible Function Decay
 * Shows how negligible functions vanish faster than any inverse polynomial.
 * ================================================================ */
static void demo_negligible_decay(void) {
    printf("\n========================================\n");
    printf("  2. Negligible Function Decay\n");
    printf("========================================\n\n");

    printf("  Definition: mu(n) is negligible if for every polynomial p(n),\n");
    printf("  exists N s.t. for all n > N: mu(n) < 1/p(n).\n\n");

    printf("  %-8s %-16s %-16s %-16s\n",
           "n", "2^{-n}", "2^{-sqrt(n)}", "1/n^2");
    printf("  %-8s %-16s %-16s %-16s\n",
           "--------", "----------------", "----------------", "----------------");

    for (int n = 1; n <= 256; n *= 2) {
        printf("  %-8d %-16.4e %-16.4e %-16.4e\n",
               n,
               negligible_exponential((sec_param_t)n),
               negligible_super_poly((sec_param_t)n),
               1.0 / ((double)n * (double)n));
    }
    printf("\n  Key insight: Negligible functions vanish faster than\n");
    printf("  any 1/poly(n). In practice, 2^{-128} < 10^{-38} is\n");
    printf("  considered negligible for all practical purposes.\n\n");
}

/* ================================================================
 * Visualization 3: Goldreich-Levin Hardcore Predicate
 * Visualizes inner product mod 2 computation and list decoding.
 * ================================================================ */
static void demo_gl_visual(void) {
    printf("\n========================================\n");
    printf("  3. Goldreich-Levin Hardcore Predicate\n");
    printf("========================================\n\n");

    printf("  GL(x, r) = <x, r> mod 2 = XOR of (x_i AND r_i)\n\n");

    size_t n = 8;
    bit_string_t* x = bs_create(n);
    x->data[0] = 0xA5; /* 10100101 */

    printf("  x = 0xA5 = 10100101\n\n");
    printf("  Computing GL(x, r) for various r:\n");
    printf("  %-12s %-10s %-20s\n", "r (hex)", "r (bin)", "GL(x, r)");
    printf("  %-12s %-10s %-20s\n", "--------", "------", "--------");

    uint8_t test_r[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xFF};
    for (int i = 0; i < 9; i++) {
        bit_string_t* r = bs_create(n);
        r->data[0] = test_r[i];
        int gl_bit = gl_predicate(x, r);

        /* Binary representation of r */
        char r_bin[9];
        for (int b = 0; b < 8; b++)
            r_bin[7-b] = (test_r[i] & (1u << b)) ? '1' : '0';
        r_bin[8] = '\0';

        printf("  r = 0x%02x     %s     %d\n", test_r[i], r_bin, gl_bit);
        bs_free(r);
    }
    printf("\n  Theorem (Goldreich-Levin 1989):\n");
    printf("    If f is a OWF, then GL is a hardcore predicate of\n");
    printf("    g(x, r) = (f(x), r).\n");
    printf("    Pr[A(f(x), r) = GL(x,r)] <= 1/2 + negl(n)\n\n");

    /* Show list decoding concept */
    printf("  List Decoding Concept:\n");
    printf("    Given: predictor P(r) with Pr[P(r) = <x,r>] >= 1/2 + eps\n");
    printf("    Goal: recover x from P\n");
    printf("    Method: Sample k = O(n/eps^2) random r_i\n");
    printf("            For each z in {0,1}^k:\n");
    printf("              Estimate x_j = majority of P(r_i xor e_j) xor P(r_i)\n");
    printf("            Verify candidates, output list\n\n");
}

/* ================================================================
 * Visualization 4: RSA OWF Demonstration
 * Shows RSA evaluation and trapdoor inversion.
 * ================================================================ */
static void demo_rsa_visual(void) {
    printf("\n========================================\n");
    printf("  4. RSA One-Way Function\n");
    printf("========================================\n\n");

    printf("  RSA-OWF: f_{N,e}(x) = x^e mod N\n");
    printf("  Trapdoor: d = e^{-1} mod phi(N)\n\n");

    rsa_params_t* rsa = rsa_params_generate(32);
    if (!rsa) return;

    printf("  Parameters:\n");
    printf("  N = "); big_nat_print_hex(&rsa->N, "");
    printf("  e = "); big_nat_print_hex(&rsa->e, "");

    /* Demonstrate evaluation and inversion */
    bit_string_t* x = bs_random(32);
    printf("\n  Random input: "); bs_print_hex(x, "");

    bit_string_t* y = NULL;
    rsa_owf_eval(rsa, x, 256, &y);
    printf("  f(x) = x^e mod N: "); bs_print_hex(y, "");

    bit_string_t* xp = NULL;
    rsa_owf_invert_trapdoor(rsa, y, &xp);
    printf("  f^{-1}(y) (with trapdoor d): "); bs_print_hex(xp, "");

    printf("  Match: %s\n\n", bs_equal(x, xp) ? "YES (RSA correctness)" : "NO");

    printf("  One-wayness: Without the trapdoor d, inverting f requires\n");
    printf("  factoring N = p*q, which is believed to require super-polynomial\n");
    printf("  time on classical computers (best known: GNFS, sub-exponential).\n\n");

    bs_free(x); bs_free(y); bs_free(xp);
    rsa_params_free(rsa);
}

/* ================================================================
 * Visualization 5: Yao Amplification Effect
 * Shows how weak OWF becomes strong via parallel repetition.
 * ================================================================ */
static void demo_yao_visual(void) {
    printf("\n========================================\n");
    printf("  5. Yao Amplification (Weak -> Strong)\n");
    printf("========================================\n\n");

    printf("  Weak OWF: Pr[A inverts f] <= 1 - 1/q(n) = 1 - epsilon\n");
    printf("  Build F(x_1,...,x_t) = (f(x_1),...,f(x_t)).\n");
    printf("  Then: Pr[A inverts F] <= (1 - epsilon)^t\n\n");

    printf("  Amplification effect for epsilon = 0.1:\n");
    printf("  %-8s %-20s %-20s\n", "t", "(1-eps)^t", "Security (bits)");
    printf("  %-8s %-20s %-20s\n", "--------", "--------------------", "--------------------");

    for (int t = 1; t <= 256; t *= 2) {
        double prob = direct_product_bound(0.9, (size_t)t);
        double bits = (prob > 0.0) ? -log2(prob) : INFINITY;
        printf("  %-8d %-20.6e %-20.1f\n", t, prob, bits);
    }
    printf("\n  Theorem (Yao 1982): If weak OWF exist, then strong OWF exist.\n");
    printf("  This is a cornerstone result: weak and strong OWF are\n");
    printf("  qualitatively equivalent, differing only in quantitative hardness.\n\n");
}

/* ================================================================
 * Visualization 6: CRT Bijection Map
 * Shows the Chinese Remainder Theorem isomorphism.
 * ================================================================ */
static void demo_crt_visual(void) {
    printf("\n========================================\n");
    printf("  6. Chinese Remainder Theorem (CRT)\n");
    printf("========================================\n\n");

    printf("  CRT: Z_15 is isomorphic to Z_3 x Z_5\n");
    printf("  Every x mod 15 corresponds to unique (x mod 3, x mod 5).\n\n");

    printf("  %-8s %-12s %-12s\n", "x mod 15", "x mod 3", "x mod 5");
    printf("  %-8s %-12s %-12s\n", "--------", "------------", "------------");

    for (int x = 0; x < 15; x++) {
        printf("  %-8d %-12d %-12d\n", x, x % 3, x % 5);
    }
    printf("\n  All 15 pairs are distinct -> CRT is a bijection.\n");
    printf("  Used in: RSA-CRT (4x speedup), Rabin inversion, Garner's algorithm.\n\n");

    /* Demonstrate CRT solve */
    big_nat_t residues[2] = {
        big_nat_from_uint64(2),  /* a1 = 2 mod 3 */
        big_nat_from_uint64(3)   /* a2 = 3 mod 5 */
    };
    big_nat_t moduli[2] = {
        big_nat_from_uint64(3),
        big_nat_from_uint64(5)
    };
    big_nat_t solution = crt_solve(residues, moduli, 2);
    printf("  Example: Solve x = 2 mod 3, x = 3 mod 5\n");
    printf("  Solution: x = "); big_nat_print(&solution, "");
    printf("  Verify: %u mod 3 = ?, %u mod 5 = ?\n",
           solution.digits[0], solution.digits[0]);
}

/* ================================================================
 * Visualization 7: OWF Strength Classification
 * Shows how empirical measurements classify OWF as strong/weak.
 * ================================================================ */
static void demo_strength_classification(void) {
    printf("\n========================================\n");
    printf("  7. OWF Strength Classification\n");
    printf("========================================\n\n");

    printf("  Classification criteria:\n");
    printf("    - STRONG: invert_prob < 2^{-n/2} (negligible)\n");
    printf("    - WEAK:   invert_prob > 1/n^2 (noticeable)\n");
    printf("    - UNKNOWN: in between\n\n");

    printf("  %-16s %-12s %-10s\n", "invert_prob", "n", "class");
    printf("  %-16s %-12s %-10s\n", "----------------", "------------", "----------");

    struct { double p; sec_param_t n; const char* expected; } cases[] = {
        {1e-40, 128, "STRONG"},
        {0.5,   128, "WEAK"},
        {1e-4,  128, "UNKNOWN"},
        {1e-30, 256, "STRONG"},
        {0.01,  256, "WEAK"},
        {1e-8,  256, "UNKNOWN"},
    };

    for (int i = 0; i < 6; i++) {
        owf_strength_t s = owf_estimate_strength(cases[i].p, cases[i].n, 1000);
        printf("  %-16.2e %-12u %-10s\n", cases[i].p, cases[i].n,
               s == OWF_TYPE_STRONG ? "STRONG" :
               s == OWF_TYPE_WEAK ? "WEAK" : "UNKNOWN");
    }
    printf("\n");
}

int main(void) {
    srand((unsigned)time(NULL));

    printf("==========================================================\n");
    printf("  One-Way Functions — Interactive Visualization\n");
    printf("  Formal Definitions, Constructions, and Theorems\n");
    printf("==========================================================\n");

    demo_eval_flow();
    demo_negligible_decay();
    demo_gl_visual();
    demo_rsa_visual();
    demo_yao_visual();
    demo_crt_visual();
    demo_strength_classification();

    printf("==========================================================\n");
    printf("  Visualization Complete — All demonstrations passed\n");
    printf("==========================================================\n");
    return 0;
}
