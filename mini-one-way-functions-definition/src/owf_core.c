/*
 * owf_core.c — Core One-Way Function Implementation
 *
 * L1 Definitions: OWF, security parameter, negligible function,
 *                 inversion experiment, strong vs weak OWF
 *
 * L2 Concepts: One-wayness, inversion probability, PPT formalization
 *
 * Every function implements a specific knowledge point from the
 * formal definition of one-way functions.
 *
 * Reference: Goldreich Vol 1 §2.1-2.4, Katz-Lindell §7, Arora-Barak §9
 */

#include "owf_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

/* ================================================================
 * Negligible Functions
 *
 * L1: A function μ: N → [0,1] is negligible if ∀ positive
 * polynomial p(·), ∃ N s.t. ∀ n > N: μ(n) < 1/p(n).
 * ================================================================ */

double negligible_exponential(sec_param_t n) {
    /* μ(n) = 2^{-n} — standard cryptographic negligible function */
    if (n > 1024) return 0.0; /* underflows double */
    return pow(2.0, -(double)n);
}

double negligible_super_poly(sec_param_t n) {
    /* μ(n) = 2^{-sqrt(n)} — weaker but still negligible */
    double sqrt_n = sqrt((double)n);
    if (sqrt_n > 1024) return 0.0;
    return pow(2.0, -sqrt_n);
}

double negligible_neglog(sec_param_t n) {
    /* μ(n) = n^{-log n} — super-polynomial but still negligible */
    if (n <= 1) return 1.0;
    double log_n = log2((double)n);
    return pow((double)n, -log_n);
}

int is_negligible(double value, sec_param_t n) {
    /* Check if value < 2^{-n/2}, a conservative negligible threshold */
    if (value <= 0.0) return 1;
    double threshold = pow(2.0, -(double)n / 2.0);
    return value < threshold;
}

/* ================================================================
 * Bit String Operations
 *
 * L3: Fundamental data type for OWF inputs/outputs.
 * bit_string_t represents arbitrary-length binary strings
 * that are the domain/range of one-way functions.
 * ================================================================ */

bit_string_t* bs_create(size_t bit_len) {
    bit_string_t* bs = (bit_string_t*)calloc(1, sizeof(bit_string_t));
    if (!bs) return NULL;

    bs->bit_len = bit_len;
    bs->byte_cap = (bit_len + 7) / 8;
    if (bs->byte_cap == 0) bs->byte_cap = 1;
    bs->data = (uint8_t*)calloc(bs->byte_cap, 1);
    if (!bs->data) {
        free(bs);
        return NULL;
    }
    return bs;
}

bit_string_t* bs_from_bytes(const uint8_t* bytes, size_t byte_len) {
    if (!bytes || byte_len == 0) return NULL;

    bit_string_t* bs = (bit_string_t*)calloc(1, sizeof(bit_string_t));
    if (!bs) return NULL;

    bs->bit_len = byte_len * 8;
    bs->byte_cap = byte_len;
    bs->data = (uint8_t*)malloc(byte_len);
    if (!bs->data) {
        free(bs);
        return NULL;
    }
    memcpy(bs->data, bytes, byte_len);
    return bs;
}

bit_string_t* bs_random(size_t bit_len) {
    bit_string_t* bs = bs_create(bit_len);
    if (!bs) return NULL;

    /* Use system randomness */
    for (size_t i = 0; i < bs->byte_cap; i++) {
        bs->data[i] = (uint8_t)(rand() & 0xFF);
    }

    /* Mask off excess bits in last byte */
    size_t excess = (bs->byte_cap * 8) - bit_len;
    if (excess > 0 && bs->byte_cap > 0) {
        bs->data[bs->byte_cap - 1] &= (uint8_t)(0xFF >> excess);
    }
    return bs;
}

bit_string_t* bs_clone(const bit_string_t* bs) {
    if (!bs) return NULL;
    bit_string_t* clone = bs_create(bs->bit_len);
    if (!clone) return NULL;
    memcpy(clone->data, bs->data, bs->byte_cap);
    return clone;
}

void bs_free(bit_string_t* bs) {
    if (bs) {
        free(bs->data);
        free(bs);
    }
}

int bs_equal(const bit_string_t* a, const bit_string_t* b) {
    if (!a || !b) return 0;
    if (a->bit_len != b->bit_len) return 0;
    return memcmp(a->data, b->data, a->byte_cap) == 0;
}

void bs_print_hex(const bit_string_t* bs, const char* label) {
    if (label) printf("%s", label);
    if (!bs) {
        printf("[null]\n");
        return;
    }
    size_t byte_len = bs->byte_cap;
    if (byte_len > 32) byte_len = 32; /* truncate long output */
    for (size_t i = 0; i < byte_len; i++) {
        printf("%02x", bs->data[i]);
    }
    if (bs->byte_cap > 32) printf("...");
    printf(" (%zu bits)\n", bs->bit_len);
}

/* ================================================================
 * OWF Scheme Management
 *
 * L1: An OWF scheme is the complete formal description of a
 * (candidate) one-way function including evaluation algorithm,
 * domain/range, security parameter, and metadata.
 * ================================================================ */

owf_scheme_t* owf_scheme_create(const char* name, const char* assumption,
                                owf_eval_fn eval, owf_invert_fn invert,
                                owf_keygen_fn keygen, void* ctx,
                                sec_param_t n, size_t in_bits, size_t out_bits) {
    owf_scheme_t* owf = (owf_scheme_t*)calloc(1, sizeof(owf_scheme_t));
    if (!owf) return NULL;

    owf->name       = name ? strdup(name) : NULL;
    owf->assumption = assumption ? strdup(assumption) : NULL;
    owf->eval       = eval;
    owf->invert     = invert;
    owf->keygen     = keygen;
    owf->ctx        = ctx;
    owf->sec_param  = n;
    owf->input_bits = in_bits;
    owf->output_bits = out_bits;
    owf->eval_count   = 0;
    owf->invert_count = 0;
    owf->success_count = 0;

    return owf;
}

void owf_scheme_free(owf_scheme_t* owf) {
    if (owf) {
        free(owf->name);
        free(owf->assumption);
        free(owf);
    }
}

int owf_evaluate(owf_scheme_t* owf, const bit_string_t* x, bit_string_t** y) {
    if (!owf || !owf->eval || !x || !y) return -1;
    owf->eval_count++;
    return owf->eval(owf->ctx, x, owf->sec_param, y);
}

int owf_attempt_invert(owf_scheme_t* owf, const bit_string_t* y,
                       bit_string_t** x_prime) {
    if (!owf || !owf->invert || !y || !x_prime) return -1;
    owf->invert_count++;

    int ret = owf->invert(owf->ctx, y, owf->sec_param, x_prime);
    if (ret == 0 && *x_prime) {
        /* Verify: check if f(x') == y */
        bit_string_t* y_check = NULL;
        owf->eval(owf->ctx, *x_prime, owf->sec_param, &y_check);
        if (y_check && bs_equal(y_check, y)) {
            owf->success_count++;
            bs_free(y_check);
        } else {
            bs_free(y_check);
            /* Inversion claimed success but verification failed */
            bs_free(*x_prime);
            *x_prime = NULL;
            return -1;
        }
    }
    return ret;
}

/* ================================================================
 * Inversion Experiment
 *
 * L2: The inversion experiment formalizes the security game
 * between a challenger and an adversary trying to invert f.
 *
 * Game: Pick x ← {0,1}^n, y = f(x). Adversary gets (y, 1^n).
 *       Adversary wins if it outputs x' s.t. f(x') = y.
 * ================================================================ */

invert_experiment_t* invert_experiment_run(owf_scheme_t* owf, owf_invert_fn A,
                                            void* adv_ctx, sec_param_t n) {
    invert_experiment_t* exp = (invert_experiment_t*)calloc(1, sizeof(invert_experiment_t));
    if (!exp) return NULL;

    exp->owf = owf;

    /* Step 1: Choose x ← {0,1}^n uniformly */
    exp->challenge_x = bs_random(n);
    if (!exp->challenge_x) {
        free(exp);
        return NULL;
    }

    /* Step 2: Compute y = f(x) */
    if (owf_evaluate(owf, exp->challenge_x, &exp->challenge_y) != 0) {
        invert_experiment_free(exp);
        return NULL;
    }

    /* Step 3: Adversary outputs x' */
    if (A(adv_ctx, exp->challenge_y, n, &exp->adversary_output) != 0) {
        exp->success = 0;
    } else if (exp->adversary_output) {
        /* Step 4: Check if f(x') == y */
        bit_string_t* y_check = NULL;
        if (owf_evaluate(owf, exp->adversary_output, &y_check) == 0 && y_check) {
            exp->success = bs_equal(y_check, exp->challenge_y);
            bs_free(y_check);
        } else {
            exp->success = 0;
        }
    } else {
        exp->success = 0;
    }

    /* Advantage: Pr[success] - baseline */
    exp->advantage = exp->success ? 1.0 : 0.0;
    /* Subtract probability of random guess: 1/2^{|x|} */
    double baseline = 1.0 / pow(2.0, (double)(owf->input_bits));
    exp->advantage -= baseline;
    if (exp->advantage < 0.0) exp->advantage = 0.0;

    return exp;
}

void invert_experiment_free(invert_experiment_t* exp) {
    if (exp) {
        bs_free(exp->challenge_x);
        bs_free(exp->challenge_y);
        bs_free(exp->adversary_output);
        free(exp);
    }
}

void invert_experiment_print(const invert_experiment_t* exp) {
    if (!exp) {
        printf("Experiment: NULL\n");
        return;
    }
    printf("=== Inversion Experiment ===\n");
    printf("  OWF: %s\n", exp->owf ? exp->owf->name : "unknown");
    printf("  Security param: %u\n", exp->owf ? exp->owf->sec_param : 0);
    printf("  Challenge x: ");
    bs_print_hex(exp->challenge_x, NULL);
    printf("  Challenge y: ");
    bs_print_hex(exp->challenge_y, NULL);
    printf("  Adversary x': ");
    bs_print_hex(exp->adversary_output, NULL);
    printf("  Success: %s\n", exp->success ? "YES" : "NO");
    printf("  Advantage: %.6f\n", exp->advantage);
}

double invert_experiment_batch(owf_scheme_t* owf, owf_invert_fn A,
                               void* adv_ctx, sec_param_t n, int K,
                               double* avg_time_ms) {
    if (!owf || !A || K <= 0) return 0.0;

    int successes = 0;
    clock_t total_time = 0;

    for (int i = 0; i < K; i++) {
        clock_t t0 = clock();
        invert_experiment_t* exp = invert_experiment_run(owf, A, adv_ctx, n);
        clock_t t1 = clock();

        if (exp) {
            if (exp->success) successes++;
            total_time += (t1 - t0);
            invert_experiment_free(exp);
        }
    }

    if (avg_time_ms) {
        *avg_time_ms = (double)total_time / (double)K * 1000.0 / (double)CLOCKS_PER_SEC;
    }

    return (double)successes / (double)K;
}

/* ================================================================
 * Strong vs Weak OWF Classification
 *
 * L2: Weak OWF has noticeable inversion failure probability.
 * Strong OWF has negligible inversion success probability.
 *
 * Yao's theorem (L4) shows they are equivalent.
 * ================================================================ */

owf_strength_t owf_estimate_strength(double invert_prob, sec_param_t n,
                                      int num_samples) {
    /*
     * Heuristic classification:
     *   - If invert_prob is clearly negligible (< 2^{-n/2}), classify as STRONG
     *   - If invert_prob is clearly noticeable (> n^{-2}), classify as WEAK
     *   - Otherwise: CANDIDATE_UNKNOWN
     */
    double negl_threshold = pow(2.0, -(double)n / 2.0);
    double notice_threshold = 1.0 / ((double)n * (double)n);

    /* With small sample sizes, add statistical noise consideration */
    double sample_adjustment = 1.0 / sqrt((double)num_samples);
    double adjusted_notice = notice_threshold - sample_adjustment;
    if (adjusted_notice < 0.01) adjusted_notice = 0.01;

    if (invert_prob < negl_threshold) {
        return OWF_TYPE_STRONG;
    } else if (invert_prob > adjusted_notice) {
        return OWF_TYPE_WEAK;
    } else {
        return OWF_TYPE_CANDIDATE_UNKNOWN;
    }
}

/* ================================================================
 * OWF Family
 *
 * L3: A family of OWFs F = {f_k} indexed by keys k ∈ K.
 * Key generation, domain sampling, and evaluation are the
 * three algorithms that define the family.
 * ================================================================ */

owf_family_t* owf_family_create(sec_param_t n, size_t capacity) {
    owf_family_t* family = (owf_family_t*)calloc(1, sizeof(owf_family_t));
    if (!family) return NULL;

    family->sec_param = n;
    family->capacity  = capacity;
    family->count     = 0;
    family->functions = (owf_scheme_t**)calloc(capacity, sizeof(owf_scheme_t*));
    if (!family->functions) {
        free(family);
        return NULL;
    }
    return family;
}

void owf_family_free(owf_family_t* family) {
    if (family) {
        for (size_t i = 0; i < family->count; i++) {
            owf_scheme_free(family->functions[i]);
        }
        free(family->functions);
        free(family);
    }
}

int owf_family_add(owf_family_t* family, owf_scheme_t* owf) {
    if (!family || !owf) return -1;
    if (family->count >= family->capacity) return -1;

    family->functions[family->count++] = owf;
    return 0;
}

owf_scheme_t* owf_family_sample(owf_family_t* family) {
    if (!family || family->count == 0) return NULL;

    size_t idx = (size_t)rand() % family->count;
    return family->functions[idx];
}

/* ================================================================
 * Utility: Random Number Generation
 *
 * L2: Randomness is essential for cryptographic definitions.
 * In practice, we use CSPRNG; here we seed from time for
 * demonstration purposes.
 * ================================================================ */

int random_bytes(uint8_t* buf, size_t len) {
    if (!buf) return -1;

    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(rand() & 0xFF);
    }
    return 0;
}

uint64_t random_uint64_below(uint64_t max_val) {
    if (max_val <= 1) return 0;

    /* Simple rejection sampling for uniform distribution */
    uint64_t mask = 1;
    while (mask < max_val) mask = (mask << 1) | 1;

    uint64_t val;
    do {
        val = 0;
        for (int i = 0; i < 8; i++) {
            val = (val << 8) | (rand() & 0xFF);
        }
        val &= mask;
    } while (val >= max_val);

    return val;
}
