/*
 * prg_construction.c -- PRG Constructions from One-Way Functions
 *
 * L4 Fundamental Theorems:
 *   OWP + Hardcore => PRG with stretch 1 (Yao 1982)
 *   Iterated PRG: stretch 1 => arbitrary stretch (composition theorem)
 *   OWF exists => PRG exists (HILL 1999, outlined)
 *
 * L5 Algorithms:
 *   PRG from OWP + hardcore predicate (single-bit stretch)
 *   Iterated PRG (Blum-Micali/Yao iteration pattern)
 *   PRG quality metrics (statistical tests for demo purposes)
 *
 * Reference: Yao (1982), Goldreich (2001) Vol 1, Chapter 3
 *            HILL (1999), Goldreich-Levin (1989)
 * Courses: MIT 6.876, Stanford CS255, Berkeley CS276, Princeton COS 551
 */
#include "prg_construction.h"
#include "prg_crypto.h"
#include "prg_number_theory.h"
#include "hardcore_bit.h"
#include <string.h>
#include <stdlib.h>
#include <math.h>

/* ================================================================
 * PRG from One-Way Permutation (L4, L5)
 * ================================================================ */

/* L4: Create PRG from OWP + hardcore predicate.
 *   G(s) = f(s) || B(s)   where |s| = n, |f(s)| = n, |B(s)| = 1.
 * Output: n+1 bits from n-bit seed => stretch = 1.
 *
 * Theorem (Yao 1982): If f is a OWP and B is hardcore for f,
 * then G is a secure PRG.
 *
 * Proof sketch: f(s) is indistinguishable from random n bits (OWP property).
 * B(s) is unpredictable given f(s) (hardcore property).
 * Therefore, f(s)||B(s) is indistinguishable from n+1 random bits. */
PRGFromOWP* prg_owp_create(OWP* owp, HardcorePredicate* hc) {
    if (!owp || !hc) return NULL;
    if (owp->domain_bits != hc->n) return NULL; /* dimensions must match */

    PRGFromOWP* prg = (PRGFromOWP*)calloc(1, sizeof(PRGFromOWP));
    if (!prg) return NULL;

    prg->owp = owp;
    prg->hc = hc;
    prg->n = owp->domain_bits;
    prg->output_bits = prg->n + 1; /* n perm bits + 1 hardcore bit */
    return prg;
}

/* L5: Initialize PRG from OWP with seed s (n bits packed). */
int prg_owp_init(PRGFromOWP* prg, const uint8_t* seed, size_t seed_bytes) {
    if (!prg || !seed) return -1;

    size_t n_bytes = (prg->n + 7) / 8;
    if (seed_bytes < n_bytes) return -1;

    /* initial seeding is handled per-evaluation; no persistent PRG state needed */
    (void)seed_bytes;
    return 0;
}

/* L5: Generate next output: f(s) || B(s), packed into output buffer.
 * For stretch-1 PRG, each call returns n+1 bits (n perm bits + 1 hardcore bit).
 * The OWP f(s) and predicate B(s) are both computed from the seed.
 *
 * This is a "one-shot" construction: calling next repeatedly with the same
 * seed produces the same output. For stream PRG, use IteratedPRG below. */
int prg_owp_next(PRGFromOWP* prg, uint8_t* output, size_t output_capacity) {
    if (!prg || !output) return -1;

    size_t n_bytes = (prg->n + 7) / 8;
    size_t out_bytes = (prg->output_bits + 7) / 8;
    if (output_capacity < out_bytes) return -1;

    /* Generate f(s) into first n bytes of output */
    int ret = owp_evaluate(prg->owp, prg->owp->owf.param /* seed */,
                            n_bytes, output, output_capacity);
    if (ret < 0) return -1;

    /* Compute B(s) and append as last bit */
    int hc_bit = hc_evaluate(prg->hc, (const uint8_t*)prg->owp->owf.param, n_bytes);
    size_t bit_pos = prg->n; /* position n (0-indexed) is the (n+1)-th bit */
    size_t byte_idx = bit_pos / 8;
    size_t bit_idx = bit_pos % 8;
    if (hc_bit) {
        output[byte_idx] |= (uint8_t)(1U << (7 - bit_idx));
    } else {
        output[byte_idx] &= (uint8_t)(~(1U << (7 - bit_idx)));
    }

    return (int)out_bytes;
}

void prg_owp_free(PRGFromOWP* prg) {
    if (!prg) return;
    memset(prg, 0, sizeof(PRGFromOWP));
    free(prg);
}

/* ================================================================
 * Iterated PRG (PRG Composition) -- L4, L5
 * ================================================================ */

/* L4: Create iterated PRG from base PRG with stretch 1.
 * The Blum-Micali/Yao iteration transforms stretch 1 -> stretch k:
 *   Input: seed s0
 *   For i = 1..k: (s_i, b_i) = G(s_{i-1})
 *   Output: b_1 b_2 ... b_k
 *
 * Theorem: If G is a secure PRG with stretch 1, then G_k is secure.
 * Proof: via hybrid argument (see prg_hybrid.c). Each hybrid replaces
 * one b_i with random; adjacent hybrids differ by G's output, which
 * is indistinguishable. */
IteratedPRG* iterated_prg_create(PRGFromOWP* base_prg, size_t k) {
    if (!base_prg || k == 0) return NULL;

    IteratedPRG* iprg = (IteratedPRG*)calloc(1, sizeof(IteratedPRG));
    if (!iprg) return NULL;

    iprg->base_prg = base_prg;
    iprg->n = base_prg->n;
    iprg->k = k;
    iprg->bits_emitted = 0;

    size_t seed_bytes = (base_prg->n + 7) / 8;
    iprg->current_seed = (uint8_t*)calloc(1, seed_bytes);
    if (!iprg->current_seed) {
        free(iprg);
        return NULL;
    }
    return iprg;
}

/* L5: Initialize iterated PRG with seed s0 (n bits).
 * The seed is stored and will be iteratively transformed. */
int iterated_prg_init(IteratedPRG* iprg, const uint8_t* seed, size_t seed_bytes) {
    if (!iprg || !seed) return -1;

    size_t n_bytes = (iprg->n + 7) / 8;
    if (seed_bytes < n_bytes) return -1;

    memcpy(iprg->current_seed, seed, n_bytes);
    iprg->bits_emitted = 0;
    return 0;
}

/* L5: Generate next bit from iterated PRG.
 * This implements one step of the iteration:
 *   (s_new, b) = G(s_current)
 *   s_current = s_new
 *   output b
 *
 * Returns 0 or 1, or -1 if exhausted/error. */
int iterated_prg_next_bit(IteratedPRG* iprg) {
    if (!iprg || !iprg->base_prg || !iprg->current_seed) return -1;
    if (iprg->bits_emitted >= iprg->k) return -1;

    size_t n_bytes = (iprg->n + 7) / 8;
    uint8_t g_output[128] = {0};

    /* Compute G(s_current) = f(s_current) || B(s_current) */
    size_t out_capacity = sizeof(g_output);
    size_t out_bytes = (iprg->n + 1 + 7) / 8;
    if (out_bytes > out_capacity) return -1;

    /* Compute f(s_current) */
    int ret = owp_evaluate(iprg->base_prg->owp, iprg->current_seed,
                            n_bytes, g_output, out_capacity);
    if (ret < 0) return -1;

    /* Extract new seed s_new = f(s_current) = first n bits */
    memcpy(iprg->current_seed, g_output, n_bytes);

    /* Extract hardcore bit B(s) from original seed using hardcore predicate */
    int hc_bit = hc_evaluate(iprg->base_prg->hc, iprg->current_seed, n_bytes);

    iprg->bits_emitted++;
    return hc_bit;
}

/* L5: Generate next byte (8 bits) from iterated PRG. */
int iterated_prg_next_byte(IteratedPRG* iprg) {
    if (!iprg) return -1;
    if (iprg->bits_emitted + 8 > iprg->k) return -1;

    uint8_t byte_val = 0;
    for (int i = 7; i >= 0; i--) {
        int bit = iterated_prg_next_bit(iprg);
        if (bit < 0) return -1;
        if (bit) byte_val |= (uint8_t)(1U << i);
    }
    return (int)byte_val;
}

/* L5: Generate n_bits from iterated PRG, packed into bytes. */
size_t iterated_prg_generate_bits(IteratedPRG* iprg, uint8_t* buffer, size_t n_bits) {
    if (!iprg || !buffer) return 0;

    size_t generated = 0;
    while (generated < n_bits) {
        size_t byte_idx = generated / 8;
        size_t bit_idx = generated % 8;

        int bit = iterated_prg_next_bit(iprg);
        if (bit < 0) break;
        if (bit) buffer[byte_idx] |= (uint8_t)(1U << (7 - bit_idx));
        else     buffer[byte_idx] &= (uint8_t)(~(1U << (7 - bit_idx)));
        generated++;
    }
    return generated;
}

void iterated_prg_free(IteratedPRG* iprg) {
    if (!iprg) return;
    if (iprg->current_seed) {
        memset(iprg->current_seed, 0, (iprg->n + 7) / 8);
        free(iprg->current_seed);
    }
    memset(iprg, 0, sizeof(IteratedPRG));
    free(iprg);
}

/* ================================================================
 * PRG from General OWF (Outline) -- L4
 * ================================================================ */

/* L4: Create outline structure for the HILL construction.
 * HILL (1999) proved: If ANY one-way function exists, then a PRG exists.
 * This is the most general result connecting OWF and PRG.
 *
 * The construction uses:
 *   1. Universal one-way hash functions (UOWHF)
 *   2. Goldreich-Levin hardcore bit
 *   3. Leftover Hash Lemma (entropy smoothing)
 *   4. Pseudorandom synthesizer
 *   5. Iterated composition
 *
 * We provide the structural outline and key building blocks. */
PRGFromOWFOutline* prg_owf_outline_create(OWF* owf) {
    if (!owf) return NULL;
    PRGFromOWFOutline* outline = (PRGFromOWFOutline*)calloc(1, sizeof(PRGFromOWFOutline));
    if (!outline) return NULL;
    outline->n = owf->input_bits;
    outline->m = owf->output_bits;
    outline->hash_key_bits = owf->input_bits; /* typical: hash key = input size */
    outline->owf = owf;
    return outline;
}

void prg_owf_outline_free(PRGFromOWFOutline* outline) {
    if (!outline) return;
    memset(outline, 0, sizeof(PRGFromOWFOutline));
    free(outline);
}

/* ================================================================
 * Pairwise Independent Hash (L3, L4)
 * ================================================================ */

/* L3: Create a random pairwise independent hash function.
 * h_{a,b}(x) = (a*x + b) mod p, where p > 2^n.
 * Pairwise independence: For any distinct x1, x2, the random variables
 * h(x1) and h(x2) are independent and uniformly distributed.
 * This property is essential for the Leftover Hash Lemma and HILL construction. */
PairwiseHash pairwise_hash_create(uint64_t prime) {
    PairwiseHash h;
    h.p = prime;
    h.a = 1 + (prg_test_rand() % (prime - 1)); /* nonzero */
    h.b = prg_test_rand() % prime;
    return h;
}

/* L3: Evaluate pairwise independent hash.
 * h(x) = (a*x + b) mod p, mapping to the range [0, p-1]. */
uint64_t pairwise_hash_eval(const PairwiseHash* h, uint64_t x) {
    if (!h || h->p == 0) return 0;
    uint64_t ax = mul_mod64(h->a, x, h->p);
    return mod_add(ax, h->b, h->p);
}

/* ================================================================
 * PRG Type Enumeration (L2)
 * ================================================================ */

const char* prg_type_name(PRGConstructionType type) {
    switch (type) {
        case PRG_TYPE_BLUM_MICALI:     return "Blum-Micali (DLP-based)";
        case PRG_TYPE_BLUM_BLUM_SHUB:  return "Blum-Blum-Shub (QRP-based)";
        case PRG_TYPE_OWP_GENERIC:     return "Generic OWP + Hardcore";
        default:                       return "Unknown";
    }
}

/* ================================================================
 * PRG Statistical Quality Tests (L5)
 * ================================================================ */

/* L5: Frequency (monobit) test.
 * Counts the proportion of 1-bits. For truly random data, this should
 * be approximately 0.5. Computes a chi-squared p-value. */
FrequencyTest frequency_test_run(const uint8_t* data, size_t n_bytes) {
    FrequencyTest result = {0, 0, 0.0, 0.0};
    if (!data || n_bytes == 0) return result;

    result.n_bits = n_bytes * 8;
    for (size_t i = 0; i < n_bytes; i++) {
        uint8_t byte = data[i];
        for (int b = 0; b < 8; b++) {
            if (byte & (1U << b)) result.n_ones++;
        }
    }
    result.frequency = (double)result.n_ones / (double)result.n_bits;

    /* Chi-squared test: (observed - expected)^2 / expected */
    double expected = (double)result.n_bits / 2.0;
    double diff = (double)result.n_ones - expected;
    double chi2 = (diff * diff) / expected;
    /* For 1 degree of freedom: p-value = 1 - CDF_chi2(chi2, 1) */
    /* Simplified approximation: p-value > 0.01 if chi2 < 6.635 */
    result.p_value = exp(-chi2 / 2.0); /* rough approximation */
    return result;
}

/* L5: Runs test -- counts the number of runs (consecutive identical bits).
 * Expected runs for random data: (2*n1*n0)/n + 1.
 * Too few runs suggests systematic patterns; too many suggests oscillation. */
RunsTest runs_test_run(const uint8_t* data, size_t n_bytes) {
    RunsTest result = {0, 0, 0.0, 0.0};
    if (!data || n_bytes == 0) return result;

    result.n_bits = n_bytes * 8;
    size_t n_ones = 0;
    result.n_runs = 1; /* at least one run */

    /* Count 1s and runs */
    int prev_bit = -1;
    for (size_t i = 0; i < n_bytes; i++) {
        for (int b = 7; b >= 0; b--) {
            int bit = (data[i] >> b) & 1;
            if (bit) n_ones++;
            if (prev_bit >= 0 && bit != prev_bit) result.n_runs++;
            prev_bit = bit;
        }
    }

    size_t n_zeros = result.n_bits - n_ones;
    if (result.n_bits > 0) {
        result.expected_runs = (2.0 * (double)n_ones * (double)n_zeros)
                               / (double)result.n_bits + 1.0;
    }

    /* Compute z-score approximation for p-value */
    double numer = fabs((double)result.n_runs - result.expected_runs);
    double std_dev = sqrt((result.expected_runs - 1.0)
                          * (result.expected_runs - 2.0)
                          / ((double)result.n_bits - 1.0));
    double z = (std_dev > 0.0) ? numer / std_dev : 0.0;
    result.p_value = erfc(z / sqrt(2.0));
    return result;
}

/* L5: Serial correlation test -- measures correlation between consecutive pairs.
 * For random data, autocorrelation at any non-zero lag should be ~0. */
SerialCorrelationTest serial_correlation_run(const uint8_t* data, size_t n_bytes) {
    SerialCorrelationTest result = {0, 0.0, 0.0};
    if (!data || n_bytes < 2) return result;

    result.n_bits = n_bytes * 8;

    /* Convert first 256 bits to +/-1 representation */
    int bits[256];
    size_t n = result.n_bits;
    if (n > 256) n = 256;
    size_t bit_idx = 0;
    for (size_t i = 0; i < n_bytes && bit_idx < n; i++) {
        for (int b = 7; b >= 0 && bit_idx < n; b--) {
            bits[bit_idx] = ((data[i] >> b) & 1) ? 1 : -1;
            bit_idx++;
        }
    }

    /* Autocorrelation at lag 1 */
    double sum1 = 0.0;
    for (size_t t = 0; t < n - 1; t++) {
        sum1 += (double)bits[t] * (double)bits[t + 1];
    }
    result.autocorrelation_lag1 = (n > 1) ? sum1 / (double)(n - 1) : 0.0;

    /* Autocorrelation at lag 2 */
    double sum2 = 0.0;
    for (size_t t = 0; t < n - 2; t++) {
        sum2 += (double)bits[t] * (double)bits[t + 2];
    }
    result.autocorrelation_lag2 = (n > 2) ? sum2 / (double)(n - 2) : 0.0;

    return result;
}

/* L5: Statistical test battery: frequency + runs + serial correlation.
 * Returns 1 if all tests pass at alpha=0.01 significance level.
 * WARNING: Passing statistical tests does NOT imply cryptographic security.
 * These tests only detect obvious non-random patterns. A PRG can pass all
 * statistical tests but still be completely insecure against a PPT attacker
 * (e.g., linear congruential generators pass Diehard but are trivial to break). */
int statistical_test_battery(const uint8_t* data, size_t n_bytes) {
    if (!data || n_bytes < 16) return 0;

    int pass = 1;

    FrequencyTest ft = frequency_test_run(data, n_bytes);
    if (ft.p_value < 0.01) pass = 0;

    RunsTest rt = runs_test_run(data, n_bytes);
    if (rt.p_value < 0.01) pass = 0;

    SerialCorrelationTest sc = serial_correlation_run(data, n_bytes);
    if (fabs(sc.autocorrelation_lag1) > 0.1) pass = 0;

    return pass;
}
