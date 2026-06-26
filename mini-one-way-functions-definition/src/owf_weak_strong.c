/*
 * owf_weak_strong.c - Weak OWF -> Strong OWF (Yao Amplification)
 *
 * L4 Fundamental Law (Yao 1982): If weak one-way functions exist,
 * then strong one-way functions exist.
 *
 * L2 Core Concept:
 *   Weak OWF: exists polynomial q(.) s.t. for all PPT A,
 *              Pr[A(f(x)) not in f^{-1}(f(x))] > 1/q(n)
 *   Strong OWF: for all PPT A, Pr[A(f(x)) in f^{-1}(f(x))] < negl(n)
 *
 * Construction: F(x_1,...,x_t) = (f(x_1),...,f(x_t)) where t = n*q(n).
 *   Intuition: To invert F, must invert f on ALL t independent instances.
 *   Success prob for F <= (1 - 1/q(n))^t ~ e^{-n} which is negligible.
 *
 * L5 Algorithms/Methods:
 *   - Parallel repetition construction
 *   - Quantitative security amplification analysis
 *   - Direct product theorem (foundation of amplification)
 *
 * Reference:
 *   Yao, "Theory and Applications of Trapdoor Functions" (FOCS 1982)
 *   Goldreich Vol 1 Sec 2.3; Katz-Lindell Sec 7.4.2
 *   Goldreich-Impagliazzo-Levin-Venkatesan-Zuckerman (1990)
 */

#include "owf_weak_strong.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* ================================================================
 * Yao Amplification Construction (L4)
 *
 * F(x_1,...,x_t) = (f(x_1), f(x_2), ..., f(x_t))
 *
 * Each x_i is an independent n-bit input to the base OWF f.
 * Total input: t*n bits. Total output: t * |f(.)| bits.
 * ================================================================ */

yao_amplification_t* yao_amp_create(owf_scheme_t* base_owf,
                                     size_t t, double weak_bound) {
    if (!base_owf || t == 0) return NULL;

    yao_amplification_t* amp = (yao_amplification_t*)calloc(1, sizeof(yao_amplification_t));
    if (!amp) return NULL;

    amp->base_owf    = base_owf;
    amp->t           = t;
    amp->sec_param   = base_owf->sec_param;
    amp->input_bits  = t * base_owf->input_bits;
    amp->output_bits = t * base_owf->output_bits;
    amp->weak_bound  = weak_bound;

    /* Strong bound: (1 - weak_bound)^t */
    /* If weak_bound = 1/q(n) = noticeable inversion prob,
     * then 1 - weak_bound = failure prob for single copy,
     * and (1-weak_bound)^t = failure prob for all copies */
    amp->strong_bound = pow(1.0 - weak_bound, (double)t);

    return amp;
}

void yao_amp_free(yao_amplification_t* amp) {
    free(amp);
}

void yao_amp_print(const yao_amplification_t* amp) {
    if (!amp) { printf("Yao Amplification: NULL\n"); return; }
    printf("=== Yao Amplification ===\n");
    printf("  Base OWF: %s\n", amp->base_owf ? amp->base_owf->name : "unknown");
    printf("  Repetitions t: %zu\n", amp->t);
    printf("  Input bits: %zu (t * %zu)\n", amp->input_bits, amp->base_owf->input_bits);
    printf("  Output bits: %zu\n", amp->output_bits);
    printf("  Weak bound (1/q): %.6f\n", amp->weak_bound);
    printf("  Strong bound ((1-1/q)^t): %.6e\n", amp->strong_bound);
}

/* ================================================================
 * Yao Amplification Evaluation
 *
 * Splits input into t blocks, evaluates f on each, concatenates.
 * ================================================================ */

int yao_amp_eval(void* ctx, const bit_string_t* x,
                 sec_param_t n, bit_string_t** y) {
    (void)n;
    if (!ctx || !x || !y) return -1;

    yao_amplification_t* amp = (yao_amplification_t*)ctx;
    size_t block_bits  = amp->base_owf->input_bits;
    /* block_bytes used explicitly below */

    /* Prepare output: t * output_bits */
    size_t out_block_bits  = amp->base_owf->output_bits;
    size_t out_block_bytes = (out_block_bits + 7) / 8;
    /* total_out_bytes used implicitly via total_out_bits */
    size_t total_out_bits  = amp->t * out_block_bits;

    *y = bs_create(total_out_bits);
    if (!*y) return -1;

    for (size_t i = 0; i < amp->t; i++) {
        /* Extract i-th input block */
        bit_string_t* xi = bs_create(block_bits);
        if (!xi) { bs_free(*y); *y = NULL; return -1; }

        for (size_t b = 0; b < block_bits; b++) {
            size_t global_bit = i * block_bits + b;
            size_t g_byte = global_bit / 8, g_bit = global_bit % 8;
            if (g_byte < x->byte_cap) {
                int val = (x->data[g_byte] >> g_bit) & 1;
                if (val) {
                    size_t l_byte = b / 8, l_bit = b % 8;
                    if (l_byte < xi->byte_cap) xi->data[l_byte] |= (1u << l_bit);
                }
            }
        }

        /* Evaluate f(x_i) */
        bit_string_t* yi = NULL;
        owf_evaluate(amp->base_owf, xi, &yi);
        bs_free(xi);

        if (!yi) { bs_free(*y); *y = NULL; return -1; }

        /* Copy yi into output at position i */
        size_t offset_bytes = i * out_block_bytes;
        size_t copy_bytes = yi->byte_cap < out_block_bytes ? yi->byte_cap : out_block_bytes;
        memcpy((*y)->data + offset_bytes, yi->data, copy_bytes);
        bs_free(yi);
    }

    return 0;
}

/* ================================================================
 * Yao Amplification Inversion
 *
 * To invert F, must invert f on each block independently.
 * Success probability for F = product of per-block success probs.
 *
 * If base inverter succeeds with prob p, amplified inverter
 * succeeds with prob p^t (negligible for large t).
 * ================================================================ */

int yao_amp_invert(void* ctx, const bit_string_t* y,
                   sec_param_t n, bit_string_t** x_prime) {
    (void)n;
    if (!ctx || !y || !x_prime) return -1;

    yao_amplification_t* amp = (yao_amplification_t*)ctx;
    size_t out_block_bits  = amp->base_owf->output_bits;
    size_t out_block_bytes = (out_block_bits + 7) / 8;
    size_t in_block_bits   = amp->base_owf->input_bits;
    /* in_block_bytes computed for clarity */

    size_t total_in_bits = amp->t * in_block_bits;
    *x_prime = bs_create(total_in_bits);
    if (!*x_prime) return -1;

    for (size_t i = 0; i < amp->t; i++) {
        /* Extract i-th output block */
        size_t start_bytes = i * out_block_bytes;
        bit_string_t* yi = bs_create(out_block_bits);
        if (!yi) { bs_free(*x_prime); *x_prime = NULL; return -1; }

        size_t copy_len = out_block_bytes;
        if (start_bytes + copy_len > y->byte_cap)
            copy_len = y->byte_cap - start_bytes;
        memcpy(yi->data, y->data + start_bytes, copy_len);

        /* Attempt to invert f on this block */
        bit_string_t* xi = NULL;
        owf_attempt_invert(amp->base_owf, yi, &xi);
        bs_free(yi);

        if (!xi) {
            /* Default: zero block */
            xi = bs_create(in_block_bits);
        }

        /* Copy xi into output at the right position */
        for (size_t b = 0; b < in_block_bits && xi && b < xi->bit_len; b++) {
            size_t global_bit = i * in_block_bits + b;
            size_t g_byte = global_bit / 8, g_bit = global_bit % 8;
            size_t l_byte = b / 8, l_bit = b % 8;
            if (g_byte < (*x_prime)->byte_cap && l_byte < xi->byte_cap) {
                int val = (xi->data[l_byte] >> l_bit) & 1;
                if (val) (*x_prime)->data[g_byte] |= (1u << g_bit);
            }
        }
        bs_free(xi);
    }

    return 0;
}

owf_scheme_t* yao_amp_as_owf(yao_amplification_t* amp) {
    if (!amp) return NULL;
    return owf_scheme_create(
        "Yao-Amplified-OWF",
        "Weak OWF amplified to Strong OWF (Yao 1982)",
        yao_amp_eval, yao_amp_invert, NULL,
        amp,
        amp->sec_param,
        amp->input_bits,
        amp->output_bits
    );
}


/* ================================================================
 * Quantitative Security Analysis (L5)
 *
 * Given weak inversion probability p_invert:
 *   t = target_bits / (-log2(p_invert))
 * ensures amplified inversion prob < 2^{-target_bits}.
 *
 * This computes concrete security parameters for the amplification.
 * ================================================================ */

size_t yao_compute_t(double weak_invert_prob, int target_bits) {
    if (weak_invert_prob <= 0.0 || weak_invert_prob >= 1.0) return 1;
    if (target_bits <= 0) return 1;

    /* t >= target_bits / (-log2(p)) */
    double log2_p = log2(weak_invert_prob);
    if (log2_p >= 0.0) return 1;  /* p >= 1, degenerate */

    double t_needed = (double)target_bits / (-log2_p);
    size_t t = (size_t)ceil(t_needed);
    if (t < 1) t = 1;
    return t;
}

yao_security_analysis_t* yao_analyze_security(double weak_invert_prob,
                                               size_t t, int target_bits) {
    yao_security_analysis_t* analysis = (yao_security_analysis_t*)calloc(
        1, sizeof(yao_security_analysis_t));
    if (!analysis) return NULL;

    analysis->base_invert_prob  = weak_invert_prob;
    analysis->base_failure_prob = 1.0 - weak_invert_prob;
    analysis->repetitions_t     = t;
    analysis->amplified_invert_prob = pow(weak_invert_prob, (double)t);
    analysis->target_bits  = target_bits;

    /* Achieved security: -log2(amplified_invert_prob) */
    if (analysis->amplified_invert_prob > 0.0)
        analysis->achieved_bits = (int)(-log2(analysis->amplified_invert_prob));
    else
        analysis->achieved_bits = 999;  /* effectively infinite */

    return analysis;
}

void yao_security_analysis_print(const yao_security_analysis_t* analysis) {
    if (!analysis) { printf("Security Analysis: NULL\n"); return; }
    printf("=== Yao Security Analysis ===\n");
    printf("  Base invert prob: %.6f\n", analysis->base_invert_prob);
    printf("  Base failure prob (epsilon): %.6f\n", analysis->base_failure_prob);
    printf("  Repetitions t: %zu\n", analysis->repetitions_t);
    printf("  Amplified invert prob: %.6e\n", analysis->amplified_invert_prob);
    printf("  Target security: %d bits\n", analysis->target_bits);
    printf("  Achieved security: %d bits\n", analysis->achieved_bits);
}

/* ================================================================
 * Direct Product Theorem (L4)
 *
 * Informal: If computing f on ONE random input is hard, then
 * computing f on MANY independent inputs is MUCH harder.
 *
 * Formally: If Pr[A inverts f] <= delta, then
 *   Pr[A inverts all t copies] <= delta^t.
 *
 * This is the foundational lemma behind Yao amplification.
 * ================================================================ */

double direct_product_bound(double single_invert_prob, size_t t) {
    if (single_invert_prob < 0.0) single_invert_prob = 0.0;
    if (single_invert_prob > 1.0) single_invert_prob = 1.0;
    return pow(single_invert_prob, (double)t);
}

/* ================================================================
 * Amplification Experiment (L5)
 *
 * Empirically verify Yao amplification:
 *   1. Run inversion on base OWF t times (base_success_rate)
 *   2. Run inversion on amplified OWF (amp_success_rate)
 *   3. Compare: amp_success_rate should be <= base_success_rate^t
 * ================================================================ */

amp_experiment_t* amp_experiment_run(yao_amplification_t* amp,
                                      int num_trials) {
    if (!amp || num_trials <= 0) return NULL;

    amp_experiment_t* exp = (amp_experiment_t*)calloc(1, sizeof(amp_experiment_t));
    if (!exp) return NULL;

    exp->amp = amp;
    exp->num_trials = num_trials;

    /* Run inversion experiments on base OWF */
    for (int i = 0; i < num_trials; i++) {
        bit_string_t* x = bs_random(amp->base_owf->input_bits);
        if (!x) continue;

        bit_string_t* y = NULL;
        owf_evaluate(amp->base_owf, x, &y);

        if (y && amp->base_owf->invert) {
            bit_string_t* xp = NULL;
            int ret = owf_attempt_invert(amp->base_owf, y, &xp);
            if (ret == 0 && xp) {
                exp->base_successes++;
                bs_free(xp);
            }
        }
        bs_free(x); bs_free(y);
    }

    /* Run inversion experiments on amplified OWF */
    owf_scheme_t* amp_owf = yao_amp_as_owf(amp);
    for (int i = 0; i < num_trials; i++) {
        bit_string_t* x = bs_random(amp->input_bits);
        if (!x) continue;

        bit_string_t* y = NULL;
        owf_evaluate(amp_owf, x, &y);

        if (y && amp_owf->invert) {
            bit_string_t* xp = NULL;
            int ret = owf_attempt_invert(amp_owf, y, &xp);
            if (ret == 0 && xp) {
                exp->amp_successes++;
                bs_free(xp);
            }
        }
        bs_free(x); bs_free(y);
    }
    owf_scheme_free(amp_owf);

    exp->base_success_rate = (double)exp->base_successes / (double)num_trials;
    exp->amp_success_rate  = (double)exp->amp_successes / (double)num_trials;
    exp->predicted_amp_rate = direct_product_bound(
        exp->base_success_rate, amp->t);
    if (exp->base_success_rate > 0.0 && exp->amp_success_rate > 0.0)
        exp->amplification_factor = exp->base_success_rate / exp->amp_success_rate;
    else
        exp->amplification_factor = INFINITY;

    return exp;
}

void amp_experiment_free(amp_experiment_t* exp) {
    free(exp);
}

void amp_experiment_print(const amp_experiment_t* exp) {
    if (!exp) { printf("Amplification Experiment: NULL\n"); return; }
    printf("=== Amplification Experiment ===\n");
    printf("  Trials: %d\n", exp->num_trials);
    printf("  Base successes: %d (%.4f%%)\n",
           exp->base_successes, exp->base_success_rate * 100.0);
    printf("  Amp successes: %d (%.4f%%)\n",
           exp->amp_successes, exp->amp_success_rate * 100.0);
    printf("  Predicted amp rate: %.6e\n", exp->predicted_amp_rate);
    printf("  Amplification factor: %.2f\n", exp->amplification_factor);
}
