/*
 * prg_from_owf.c — Pseudorandom Generator from One-Way Functions
 *
 * Implements the construction of pseudorandom generators (PRGs)
 * from one-way functions via the Goldreich-Levin hardcore bit.
 *
 * Theorem (Håstad-Impagliazzo-Levin-Luby 1999, building on
 * Goldreich-Levin 1989 and Yao 1982):
 *   One-way functions exist ⇒ Pseudorandom generators exist.
 *
 * The construction proceeds in stages:
 *   1. OWF ⇒ OWF with hardcore bit (Goldreich-Levin)
 *   2. OWF + hardcore bit ⇒ PRG with stretch 1 (Blum-Micali/Yao)
 *   3. PRG with stretch 1 ⇒ PRG with arbitrary stretch
 *
 * PRG Definition (L1): A deterministic polynomial-time algorithm G
 * such that:
 *   - Expansion: |G(s)| > |s| (∀s)
 *   - Pseudorandomness: {G(s) : s ← {0,1}^n} ≈_c U_{ℓ(n)}
 *     (computationally indistinguishable from uniform)
 *
 * Knowledge Points Covered:
 *   L1: PRG formal definition
 *   L2: PRG from OWF reduction, stretch factor
 *   L4: HILL theorem: OWF ⇒ PRG (full reduction chain)
 *   L5: Blum-Micali PRG, Goldreich-Levin hardcore bit
 *   L7: Cryptographic PRG applications (stream ciphers)
 *
 * Reference: HILL 1999; Arora-Barak §9.3-9.4; Goldreich Vol.1 §3
 * Courses: MIT 6.875, Stanford CS255, Princeton COS 551
 */

#include "owf.h"
#include "hardcore_bit.h"
#include "goldreich_levin.h"
#include "bit_operations.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* ───────────────────────────────────────────────────────────────
 * PRG from Hardcore Bit (Blum-Micali / Yao Construction)
 *
 * Given a permutation f with hardcore bit b:
 *   G(s) = (b(s), f(s))
 *
 * This expands n bits to n+1 bits and is a PRG with stretch 1.
 *
 * Iterating:
 *   Start with s_0 = s
 *   For i = 1..t: output b(s_{i-1}); set s_i = f(s_{i-1})
 *
 * This expands n bits to n + t bits.
 * ───────────────────────────────────────────────────────────── */

typedef struct {
    OWF*     owf;
    size_t   seed_bits;
    size_t   output_bits;
    size_t   stretch;
} PRGFromOWF;

PRGFromOWF* prg_create(OWF* owf, size_t stretch) {
    if (!owf || stretch == 0) return NULL;
    PRGFromOWF* prg = (PRGFromOWF*)malloc(sizeof(PRGFromOWF));
    if (!prg) return NULL;
    prg->owf         = owf;
    prg->seed_bits   = owf->input_bits;
    prg->stretch     = stretch;
    prg->output_bits = owf->input_bits + stretch;
    return prg;
}

void prg_free(PRGFromOWF* prg) {
    free(prg);
}

int prg_evaluate(const PRGFromOWF* prg, const BitString* seed, BitString* output) {
    if (!prg || !seed || !output) return 0;
    if (seed->n_bits < prg->seed_bits || output->n_bits < prg->output_bits)
        return 0;

    BitString* state = bs_clone(seed);
    BitString* fx    = bs_create(prg->owf->output_bits);
    if (!state || !fx) { bs_free(state); bs_free(fx); return 0; }

    size_t out_pos = 0;

    /* Blum-Micali iteration: output hardcore bit, then apply f */
    for (size_t i = 0; i < prg->stretch; i++) {
        /* Output hardcore bit: b(state) = MSB or GL bit */
        /* Use the GL inner product with a random r */
        BitString* r = bs_create_random(prg->seed_bits);
        if (!r) { bs_free(state); bs_free(fx); return 0; }
        int bit = hc_inner_product(state, r, NULL);
        if (out_pos < output->n_bits) {
            bs_set_bit(output, out_pos++, bit);
        }
        bs_free(r);

        /* Update state: s_{i+1} = f(s_i) */
        owf_eval(prg->owf, state, fx);
        memcpy(state->data, fx->data,
               state->n_words * sizeof(uint64_t));
    }

    /* Output final state */
    for (size_t i = 0; i < state->n_bits && out_pos < output->n_bits; i++) {
        bs_set_bit(output, out_pos++, bs_get_bit(state, i));
    }

    bs_free(state);
    bs_free(fx);
    return 1;
}

/* ───────────────────────────────────────────────────────────────
 * PRG Statistical Tests — Distinguisher Framework
 *
 * A distinguisher D tries to tell apart G(U_n) from U_{n+t}.
 * The advantage of D is:
 *   Adv(D) = |Pr[D(G(U_n)) = 1] - Pr[D(U_{n+t}) = 1]|
 *
 * If for all PPT D, Adv(D) ≤ negl(n), then G is a PRG.
 *
 * We implement simple statistical tests to demonstrate the
 * concept (not cryptographically secure detectors).
 * ───────────────────────────────────────────────────────────── */

/*
 * Naive distinguisher: checks proportion of 1s.
 * A truly random string has ~50% 1s.
 */
double prg_naive_distinguisher(const BitString* sample) {
    if (!sample || sample->n_bits == 0) return 0.5;
    size_t ones = bs_popcount(sample);
    return (double)ones / (double)sample->n_bits;
}

/*
 * Bias test: |fraction of 1s - 1/2|
 * For a PRG, this should be small.
 */
double prg_bias_test(const BitString* sample) {
    double frac = prg_naive_distinguisher(sample);
    double bias = frac - 0.5;
    return bias < 0 ? -bias : bias;
}

/*
 * Runs test: count the number of runs (consecutive 0s or 1s).
 * A random string of length n has approximately n/2 runs.
 * Significant deviation from n/2 suggests non-randomness.
 */
size_t prg_runs_test(const BitString* sample) {
    if (!sample || sample->n_bits <= 1) return 0;
    size_t runs = 1;
    for (size_t i = 1; i < sample->n_bits; i++) {
        if (bs_get_bit(sample, i) != bs_get_bit(sample, i - 1)) {
            runs++;
        }
    }
    return runs;
}

/*
 * Longest run test: find the maximum length of consecutive 0s or 1s.
 * For a random string of length n, the expected longest run is ~log₂(n).
 */
size_t prg_longest_run(const BitString* sample) {
    if (!sample || sample->n_bits == 0) return 0;
    size_t longest = 1;
    size_t current = 1;
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

/*
 * Autocorrelation test: check correlation with shifted version.
 * For random strings, autocorrelation at lag k should be near 0.
 */
double prg_autocorrelation(const BitString* sample, size_t lag) {
    if (!sample || lag >= sample->n_bits) return 0.0;
    int matches = 0;
    size_t total = sample->n_bits - lag;
    for (size_t i = 0; i < total; i++) {
        if (bs_get_bit(sample, i) == bs_get_bit(sample, i + lag)) {
            matches++;
        }
    }
    double ratio = (double)matches / (double)total;
    return 2.0 * ratio - 1.0;  /* +1 = perfect correlation, 0 = random */
}

/*
 * Compute a battery of tests and report results.
 */
void prg_test_battery(const BitString* sample) {
    if (!sample) return;
    printf("=== PRG Statistical Test Battery ===\n");
    printf("Sample length: %zu bits\n", sample->n_bits);
    double bias = prg_bias_test(sample);
    printf("Bias (|frac_1 - 0.5|):    %.6f %s\n", bias,
           bias < 0.05 ? "[OK]" : "[SUSPICIOUS]");
    size_t runs = prg_runs_test(sample);
    double exp_runs = (double)sample->n_bits / 2.0;
    printf("Runs count:               %zu (expected ~%.0f) %s\n", runs, exp_runs,
           (double)runs > exp_runs * 0.6 && (double)runs < exp_runs * 1.4 ? "[OK]" : "[SUSPICIOUS]");
    size_t longest = prg_longest_run(sample);
    double exp_longest = log2((double)sample->n_bits);
    printf("Longest run:              %zu (expected ~%.0f) %s\n", longest, exp_longest,
           (double)longest < exp_longest * 2.0 ? "[OK]" : "[SUSPICIOUS]");
    double ac = prg_autocorrelation(sample, 1);
    printf("Autocorrelation (lag=1):  %.6f %s\n", ac,
           ac > -0.1 && ac < 0.1 ? "[OK]" : "[SUSPICIOUS]");
    printf("==========================================\n");
}

/* ───────────────────────────────────────────────────────────────
 * PRG with Variable Stretch
 *
 * Given a PRG G with stretch 1, we can construct a PRG G' with
 * any polynomial stretch ℓ(n).
 *
 * Construction (sequential composition):
 *   G'_ℓ(s_0) = Let s_1||b_1 = G(s_0)
 *               Let s_2||b_2 = G(s_1)
 *               ...
 *               Let s_ℓ||b_ℓ = G(s_{ℓ-1})
 *               Output b_1 b_2 ... b_ℓ s_ℓ
 *
 * This produces ℓ(n) + n bits from n seed bits.
 * ───────────────────────────────────────────────────────────── */

size_t prg_stretch_arbitrary(PRGFromOWF* prg, const BitString* seed,
                               BitString* output, size_t desired_bits) {
    if (!prg || !seed || !output || desired_bits == 0) return 0;
    if (desired_bits > output->n_bits) desired_bits = output->n_bits;

    BitString* state = bs_clone(seed);
    BitString* fx    = bs_create(prg->owf->output_bits);
    if (!state || !fx) { bs_free(state); bs_free(fx); return 0; }

    size_t out_pos = 0;
    while (out_pos < desired_bits) {
        /* Output hardcore bit */
        BitString* r = bs_create_random(prg->seed_bits);
        if (r) {
            int bit = hc_inner_product(state, r, NULL);
            bs_set_bit(output, out_pos, bit);
            bs_free(r);
        }
        out_pos++;

        /* Update state */
        owf_eval(prg->owf, state, fx);
        memcpy(state->data, fx->data, state->n_words * sizeof(uint64_t));
    }

    bs_free(state);
    bs_free(fx);
    return out_pos;
}

/* ───────────────────────────────────────────────────────────────
 * PRG Security Proof Framework
 *
 * The full reduction chain (HILL 1999):
 *   OWF
 *     ⇒ [Yao 1982] Weak OWF ⇒ Strong OWF
 *     ⇒ [Goldreich-Levin 1989] OWF ⇒ OWF with hardcore bit
 *     ⇒ [Blum-Micali 1984] OWP + hardcore bit ⇒ PRG
 *     ⇒ [Goldreich-Krawczyk-Luby 1993] Regular OWF ⇒ PRG
 *     ⇒ [HILL 1999] Any OWF ⇒ PRG (full theorem)
 *
 * This framework showcases the key modular steps.
 * ───────────────────────────────────────────────────────────── */

/*
 * Check if a function satisfies the PRG expansion property.
 */
int prg_check_expansion(const PRGFromOWF* prg) {
    if (!prg) return 0;
    return prg->output_bits > prg->seed_bits ? 1 : 0;
}

/*
 * Estimate the concrete security of a PRG construction.
 * Returns the estimated security level in bits.
 */
size_t prg_security_bits(const PRGFromOWF* prg) {
    if (!prg) return 0;
    /* Security ≈ min(seed_bits, stretch) */
    size_t sec = prg->seed_bits;
    if (prg->stretch < sec) sec = prg->stretch;
    return sec / 2;  /* Conservative estimate */
}

/*
 * Print PRG parameters for debugging/education.
 */
void prg_print_params(const PRGFromOWF* prg) {
    if (!prg) { printf("(null)\n"); return; }
    printf("PRG Parameters:\n");
    printf("  Seed bits:    %zu\n", prg->seed_bits);
    printf("  Output bits:  %zu\n", prg->output_bits);
    printf("  Stretch:      %zu\n", prg->stretch);
    printf("  Security:     ~%zu bits\n", prg_security_bits(prg));
    printf("  Expansion OK: %s\n", prg_check_expansion(prg) ? "YES" : "NO");
}

/* ───────────────────────────────────────────────────────────────
 * Forward-Secure PRG
 *
 * A forward-secure PRG has the property that compromising the
 * current state does not reveal previous outputs. This is achieved
 * by iterating a OWF forward: s_{i+1} = f(s_i), output b(s_i).
 *
 * Since f is one-way, knowing s_{i+1} does not reveal s_i.
 * ───────────────────────────────────────────────────────────── */

int prg_forward_secure_step(const OWF* owf, BitString* state, int* bit_out) {
    if (!owf || !state || !bit_out) return 0;
    BitString* r = bs_create_random(state->n_bits);
    if (!r) return 0;
    *bit_out = hc_inner_product(state, r, NULL);
    bs_free(r);

    BitString* next = bs_create(owf->output_bits);
    if (!next) return 0;
    owf_eval(owf, state, next);
    size_t copy = state->n_words;
    if (next->n_words < copy) copy = next->n_words;
    memcpy(state->data, next->data, copy * sizeof(uint64_t));
    bs_free(next);
    return 1;
}

/*
 * Backtracking resistance demonstration:
 * Given s_{i+1}, try to recover s_i by brute-force (for small n).
 * This should be infeasible for secure parameters.
 */
int prg_backtrack_resistance_test(const OWF* owf, const BitString* current_state,
                                   int num_trials) {
    if (!owf || !current_state) return 0;
    /* Try random preimages and see how many map to current_state */
    int successes = 0;
    for (int t = 0; t < num_trials; t++) {
        BitString* candidate = bs_create_random(owf->input_bits);
        BitString* output    = bs_create(owf->output_bits);
        if (!candidate || !output) { bs_free(candidate); bs_free(output); continue; }
        owf_eval(owf, candidate, output);
        if (bs_equal(output, current_state)) successes++;
        bs_free(candidate);
        bs_free(output);
    }
    /* High success rate would mean the OWF is easy to invert */
    return successes;
}
