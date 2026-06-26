/*
 * hybrid_argument.c - Hybrid Argument: Core Framework Implementation
 *
 * Implements the fundamental data structures and algorithms for the
 * hybrid argument proof technique. The hybrid argument, pioneered by
 * Goldwasser & Micali (1984) and systematized by Goldreich (2001),
 * is the single most important proof technique in modern cryptography.
 *
 * L1: Hybrid Sequence, Hybrid Argument Lemma, Advantage, Distribution Ensemble
 * L2: Computational vs Statistical Indistinguishability
 * L3: Probability ensemble, sample spaces, distance metrics
 * L4: Hybrid Argument Lemma (telescoping sum + triangle inequality)
 * L5: Monte Carlo advantage estimation, statistical testing
 *
 * Reference: Goldreich (2001) Foundations of Cryptography Vol 1, Ch 3
 *            Arora & Barak (2009) Computational Complexity, Sec 9.2-9.3
 * Courses: MIT 6.875, Stanford CS355, Princeton COS 522, Berkeley CS276
 */

#include "hybrid_argument.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* ================================================================
 * PRNG: xorshift128+ (Vigna 2015) — for Monte Carlo experiments
 * 128-bit state, period ~2^128. Non-cryptographic.
 * ================================================================ */

static uint64_t rng_state[2];
static int rng_initialized = 0;

void rand_seed(uint64_t seed) {
    rng_state[0] = seed;
    rng_state[1] = seed ^ 0x9E3779B97F4A7C15ULL;
    rng_initialized = 1; /* MUST be set before calling rand_next to break recursion */
    for (int i = 0; i < 20; i++) rand_next();
}

uint64_t rand_next(void) {
    if (!rng_initialized) rand_seed(123456789ULL);
    uint64_t s1 = rng_state[0];
    uint64_t s0 = rng_state[1];
    rng_state[0] = s0;
    s1 ^= s1 << 23;
    rng_state[1] = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5);
    return rng_state[1] + s0;
}

uint8_t rand_bit(void) {
    return (uint8_t)(rand_next() & 1);
}

void rand_bytes(uint8_t* buf, size_t nbytes) {
    if (!buf || nbytes == 0) return;
    size_t i = 0;
    while (i < nbytes) {
        uint64_t v = rand_next();
        for (size_t j = 0; j < 8 && i < nbytes; j++, i++) {
            buf[i] = (uint8_t)(v & 0xFF);
            v >>= 8;
        }
    }
}

/* ================================================================
 * Negligible Function Evaluation
 *
 * A function mu: N -> R is negligible if for every positive
 * polynomial p, there exists N such that for all n > N:
 *   mu(n) < 1 / p(n)
 *
 * Standard families and their decay rates at n=100:
 *   EXP:       2^{-n}       -> ~7.89e-31
 *   SUPERPOLY: n^{-log n}   -> ~4.98e-14
 *   EXP_SQRT:  2^{-sqrt(n)} -> ~9.77e-04
 *   NEAR_EXP:  n * 2^{-n}   -> ~7.89e-29
 *   EXP_NEGL:  2^{-n/2}     -> ~8.88e-16
 *
 * Closure properties:
 *   1. mu + nu is negligible if both are
 *   2. mu * nu is negligible if both are
 *   3. p(n) * mu(n) is negligible for any polynomial p
 * ================================================================ */

double negl_eval(const NegligibleFunction* negl, security_param_t n) {
    if (!negl) return 0.0;
    double c = negl->coefficient;
    double dn = (double)n;
    switch (negl->type) {
        case NEGL_TYPE_EXP:
            return c * pow(2.0, -dn);
        case NEGL_TYPE_SUPERPOLY:
            if (n <= 1) return c;
            { double ln = log2(dn); return c * pow(2.0, -(ln * ln)); }
        case NEGL_TYPE_EXP_SQRT:
            return c * pow(2.0, -sqrt(dn));
        case NEGL_TYPE_NEAR_EXP:
            return c * dn * pow(2.0, -dn);
        case NEGL_TYPE_EXP_NEGL:
            return c * pow(2.0, -dn / 2.0);
        case NEGL_TYPE_CUSTOM:
            return negl->custom_fn ? c * negl->custom_fn(n) : 0.0;
        default:
            return 0.0;
    }
}

NegligibleFunction negl_exp(void) {
    NegligibleFunction nf = {NEGL_TYPE_EXP, 1.0, NULL};
    return nf;
}

NegligibleFunction negl_superpoly(void) {
    NegligibleFunction nf = {NEGL_TYPE_SUPERPOLY, 1.0, NULL};
    return nf;
}

NegligibleFunction negl_exp_sqrt(void) {
    NegligibleFunction nf = {NEGL_TYPE_EXP_SQRT, 1.0, NULL};
    return nf;
}

NegligibleFunction negl_near_exp(void) {
    NegligibleFunction nf = {NEGL_TYPE_NEAR_EXP, 1.0, NULL};
    return nf;
}

int negl_is_negligible(const NegligibleFunction* negl, security_param_t n,
                       double threshold) {
    if (!negl) return 0;
    return (negl_eval(negl, n) < threshold) ? 1 : 0;
}

const char* negl_type_name(NegligibleType t) {
    switch (t) {
        case NEGL_TYPE_EXP:       return "2^{-n}";
        case NEGL_TYPE_SUPERPOLY: return "n^{-log n}";
        case NEGL_TYPE_EXP_SQRT:  return "2^{-sqrt(n)}";
        case NEGL_TYPE_NEAR_EXP:  return "n * 2^{-n}";
        case NEGL_TYPE_EXP_NEGL:  return "2^{-n/2}";
        case NEGL_TYPE_CUSTOM:    return "custom";
        default:                  return "unknown";
    }
}

/* ================================================================
 * DistributionSample — One random draw from a distribution X_n
 *
 * For security parameter n, X_n is a distribution over {0,1}^{l(n)}.
 * A DistributionSample is a single element: data array + length info.
 * ================================================================ */

DistributionSample* dsample_create(size_t bit_length) {
    DistributionSample* s = (DistributionSample*)malloc(sizeof(DistributionSample));
    if (!s) return NULL;
    size_t bl = (bit_length + 7) / 8;
    s->data = (uint8_t*)calloc(bl, 1);
    if (!s->data) { free(s); return NULL; }
    s->length = bit_length;
    s->byte_length = bl;
    return s;
}

DistributionSample* dsample_clone(const DistributionSample* src) {
    if (!src) return NULL;
    DistributionSample* s = dsample_create(src->length);
    if (!s) return NULL;
    memcpy(s->data, src->data, src->byte_length);
    return s;
}

void dsample_free(DistributionSample* s) {
    if (s) { free(s->data); free(s); }
}

int dsample_cmp(const DistributionSample* a, const DistributionSample* b) {
    if (!a && !b) return 0;
    if (!a || !b) return 1;
    if (a->length != b->length) return 1;
    return memcmp(a->data, b->data, a->byte_length);
}

void dsample_randomize(DistributionSample* s) {
    if (!s) return;
    rand_bytes(s->data, s->byte_length);
    /* Mask stray bits in partial last byte */
    size_t rem = s->length % 8;
    if (rem != 0) {
        uint8_t mask = (uint8_t)((1 << rem) - 1);
        s->data[s->byte_length - 1] &= mask;
    }
}

void dsample_fprint(FILE* f, const DistributionSample* s) {
    if (!f || !s) return;
    fprintf(f, "Sample[%zu bits]: ", s->length);
    size_t show = (s->length < 256) ? s->length : 256;
    for (size_t i = 0; i < show; i++) {
        size_t bi = i / 8, bj = 7 - (i % 8);
        fprintf(f, "%c", (s->data[bi] >> bj) & 1 ? '1' : '0');
    }
    if (s->length > 256) fprintf(f, "...");
    fprintf(f, "\n");
}

/* ================================================================
 * DistributionEnsemble — {X_n}_{n in N}
 *
 * Each X_n is a distribution over {0,1}^{l(n)} for polynomial l.
 * The ensemble is specified by output_length(n) and sample(ens,n,out).
 *
 * This is the fundamental object in cryptographic definitions:
 * "X and Y are indistinguishable" means the ensembles {X_n} and {Y_n}
 * cannot be told apart by any PPT algorithm.
 * ================================================================ */

DistributionEnsemble* dens_create(const char* name,
                                   size_t (*output_len)(security_param_t n),
                                   ensemble_sampler_fn sample_fn,
                                   void* aux_data) {
    DistributionEnsemble* ens = (DistributionEnsemble*)
        malloc(sizeof(DistributionEnsemble));
    if (!ens) return NULL;
    ens->name = name ? _strdup(name) : NULL;
    ens->output_length = output_len;
    ens->sample = sample_fn;
    ens->aux_data = aux_data;
    return ens;
}

void dens_free(DistributionEnsemble* ens) {
    if (ens) { free(ens->name); free(ens); }
}

void dens_sample(const DistributionEnsemble* ens,
                 security_param_t n,
                 DistributionSample* out) {
    if (ens && ens->sample && out)
        ens->sample(ens, n, out);
}

/* ================================================================
 * Distinguisher — PPT algorithm D: {0,1}^* -> {0,1}
 *
 * Adv_D(X,Y) = |Pr[D(X_n)=1] - Pr[D(Y_n)=1]|
 *
 * If for all PPT D: Adv_D(X,Y) <= negl(n), then X ~=_c Y
 * (computational indistinguishability).
 *
 * The advantage is estimated via Monte Carlo:
 *   Adv_hat = |(1/T)*Sum D(x_t) - (1/T)*Sum D(y_t)|
 * With 95% confidence half-width:
 *   hw = 1.96 * sqrt(se_x^2 + se_y^2)
 * where se = sqrt(p(1-p)/T)
 * ================================================================ */

Distinguisher* dist_create(const char* name,
                            distinguisher_fn eval_fn,
                            void* state,
                            size_t time_complexity) {
    Distinguisher* D = (Distinguisher*)malloc(sizeof(Distinguisher));
    if (!D) return NULL;
    D->name = name ? _strdup(name) : NULL;
    D->evaluate = eval_fn;
    D->state = state;
    D->time_complexity = time_complexity;
    return D;
}

void dist_free(Distinguisher* D) {
    if (D) { free(D->name); free(D); }
}

int dist_evaluate(const Distinguisher* D, const DistributionSample* x) {
    if (!D || !D->evaluate || !x) return 0;
    return D->evaluate(D, x);
}

double dist_estimate_advantage(const Distinguisher* D,
                                const DistributionEnsemble* X,
                                const DistributionEnsemble* Y,
                                security_param_t n,
                                int num_trials,
                                double* confidence_half_width) {
    if (!D || !X || !Y || num_trials <= 0) {
        if (confidence_half_width) *confidence_half_width = 1.0;
        return 0.0;
    }

    size_t out_len = X->output_length ? X->output_length(n) : 256;
    DistributionSample* sample = dsample_create(out_len);
    if (!sample) {
        if (confidence_half_width) *confidence_half_width = 1.0;
        return 0.0;
    }

    /* Pr[D(X)=1] */
    double count_x = 0.0;
    for (int t = 0; t < num_trials; t++) {
        dens_sample(X, n, sample);
        if (dist_evaluate(D, sample)) count_x += 1.0;
    }
    double p_x = count_x / (double)num_trials;

    /* Pr[D(Y)=1] */
    double count_y = 0.0;
    for (int t = 0; t < num_trials; t++) {
        dens_sample(Y, n, sample);
        if (dist_evaluate(D, sample)) count_y += 1.0;
    }
    double p_y = count_y / (double)num_trials;

    double adv = fabs(p_x - p_y);

    if (confidence_half_width) {
        double se_x = sqrt(p_x * (1.0 - p_x) / (double)num_trials);
        double se_y = sqrt(p_y * (1.0 - p_y) / (double)num_trials);
        *confidence_half_width = 1.96 * sqrt(se_x * se_x + se_y * se_y);
    }

    dsample_free(sample);
    return adv;
}

/* ================================================================
 * HybridSequence — The backbone of the hybrid argument
 *
 * A sequence H_0, H_1, ..., H_m of distribution ensembles where
 * adjacent pairs differ by a single "swap" operation (e.g.,
 * replacing one PRG block with truly random bits).
 *
 * Central Lemma:
 *   If for all i: Adv_D(H_i, H_{i+1}) <= epsilon,
 *   then Adv_D(H_0, H_m) <= m * epsilon.
 *
 * Proof (by telescoping sum):
 *   Adv_D(H_0, H_m) = |Pr[D(H_0)=1] - Pr[D(H_m)=1]|
 *   = |Sum_{i=0}^{m-1} (Pr[D(H_i)=1] - Pr[D(H_{i+1})=1])|
 *   <= Sum_{i=0}^{m-1} |Pr[D(H_i)=1] - Pr[D(H_{i+1})=1]|
 *   = Sum_{i=0}^{m-1} Adv_D(H_i, H_{i+1})
 *   <= m * epsilon
 * ================================================================ */

HybridSequence* hseq_create(int capacity) {
    HybridSequence* hs = (HybridSequence*)malloc(sizeof(HybridSequence));
    if (!hs) return NULL;
    hs->hybrids = (DistributionEnsemble**)
        calloc((size_t)capacity, sizeof(DistributionEnsemble*));
    if (!hs->hybrids) { free(hs); return NULL; }
    hs->num_hybrids = 0;
    hs->capacity = capacity;
    return hs;
}

void hseq_free(HybridSequence* hs) {
    if (hs) { free(hs->hybrids); free(hs); }
}

int hseq_add(HybridSequence* hs, DistributionEnsemble* hybrid) {
    if (!hs || !hybrid) return -1;
    if (hs->num_hybrids >= hs->capacity) return -1;
    hs->hybrids[hs->num_hybrids++] = hybrid;
    return hs->num_hybrids - 1;
}

int hseq_length(const HybridSequence* hs) {
    return hs ? hs->num_hybrids : 0;
}

DistributionEnsemble* hseq_get(const HybridSequence* hs, int index) {
    if (!hs || index < 0 || index >= hs->num_hybrids) return NULL;
    return hs->hybrids[index];
}

/* ================================================================
 * HybridArgumentResult — Empirical verification of the hybrid lemma
 *
 * For each adjacent pair, estimates the advantage via Monte Carlo
 * and verifies that total <= m * epsilon.
 *
 * The statistical test used: bias detection — checks whether the
 * fraction of 1-bits deviates significantly from 0.5. If two
 * distributions differ in their bit-level bias, this test detects it.
 * ================================================================ */

HybridArgumentResult* hybrid_arg_verify(const HybridSequence* hs,
                                          security_param_t n,
                                          int num_trials,
                                          double epsilon) {
    if (!hs || hs->num_hybrids < 2 || num_trials <= 0) return NULL;

    int m = hs->num_hybrids;
    HybridArgumentResult* r = (HybridArgumentResult*)
        malloc(sizeof(HybridArgumentResult));
    if (!r) return NULL;

    r->num_hybrids = m;
    r->pairwise_epsilon = epsilon;
    r->overall_bound = (double)(m - 1) * epsilon;
    r->passes_bound = 1;
    r->measured_total = 0.0;
    r->pairwise_advantages = (double*)calloc((size_t)(m - 1), sizeof(double));
    if (!r->pairwise_advantages) { free(r); return NULL; }

    for (int i = 0; i < m - 1; i++) {
        size_t out_len = 256;
        if (hs->hybrids[i] && hs->hybrids[i]->output_length)
            out_len = hs->hybrids[i]->output_length(n);

        DistributionSample* sample = dsample_create(out_len);
        if (!sample) { r->pairwise_advantages[i] = 0.0; continue; }

        /* Bias-detection test: accept if 1-bit fraction deviates >0.1 from 0.5 */
        double cnt_i = 0.0, cnt_ip1 = 0.0;
        for (int t = 0; t < num_trials; t++) {
            if (hs->hybrids[i]) {
                dens_sample(hs->hybrids[i], n, sample);
                int ones = 0;
                for (size_t b = 0; b < out_len; b++) {
                    if ((sample->data[b/8] >> (7 - (b%8))) & 1) ones++;
                }
                if (fabs((double)ones/(double)out_len - 0.5) > 0.1) cnt_i += 1.0;
            }
            if (hs->hybrids[i+1]) {
                dens_sample(hs->hybrids[i+1], n, sample);
                int ones = 0;
                for (size_t b = 0; b < out_len; b++) {
                    if ((sample->data[b/8] >> (7 - (b%8))) & 1) ones++;
                }
                if (fabs((double)ones/(double)out_len - 0.5) > 0.1) cnt_ip1 += 1.0;
            }
        }
        double adv = fabs(cnt_i - cnt_ip1) / (double)num_trials;
        r->pairwise_advantages[i] = adv;
        r->measured_total += adv;
        if (adv > epsilon) r->passes_bound = 0;
        dsample_free(sample);
    }
    return r;
}

void hybrid_arg_result_free(HybridArgumentResult* r) {
    if (r) { free(r->pairwise_advantages); free(r); }
}

void hybrid_arg_result_print(const HybridArgumentResult* r) {
    if (!r) { printf("NULL result\n"); return; }
    printf("=== Hybrid Argument Verification ===\n");
    printf("Hybrids: %d\n", r->num_hybrids);
    printf("Epsilon bound: %.6f\n", r->pairwise_epsilon);
    printf("Overall bound (m*eps): %.6f\n", r->overall_bound);
    printf("Measured total: %.6f\n", r->measured_total);
    printf("Passes: %s\n", r->passes_bound ? "YES" : "NO");
    for (int i = 0; i < r->num_hybrids - 1; i++) {
        printf("  H_%d vs H_%d: %.6f\n", i, i+1, r->pairwise_advantages[i]);
    }
}

/* ================================================================
 * Statistical Distance (Total Variation Distance)
 *
 * For distributions P, Q over domain Omega:
 *   Delta(P,Q) = (1/2) * Sum_{w in Omega} |P(w) - Q(w)|
 *              = max_{S subset Omega} |P(S) - Q(S)|
 *
 * Properties:
 *   0 <= Delta(P,Q) <= 1
 *   Delta(P,Q) = 0 iff P = Q (identical distributions)
 *   Triangle inequality: Delta(X,Z) <= Delta(X,Y) + Delta(Y,Z)
 *
 * Relationship to distinguishing advantage:
 *   For unbounded D: max_D Adv_D(X,Y) = Delta(X,Y)
 *   For PPT D:       max_{D in PPT} Adv_D(X,Y) may be << Delta(X,Y)
 *                    This gap IS computational indistinguishability.
 * ================================================================ */

double stat_dist_estimate(const DistributionEnsemble* X,
                           const DistributionEnsemble* Y,
                           security_param_t n,
                           int num_trials) {
    if (!X || !Y || num_trials <= 0) return 1.0;

    size_t out_len = X->output_length ? X->output_length(n) : 256;
    DistributionSample* sx = dsample_create(out_len);
    DistributionSample* sy = dsample_create(out_len);
    if (!sx || !sy) { dsample_free(sx); dsample_free(sy); return 1.0; }

    /* Estimate per-bit marginal differences, then take sup norm */
    size_t check_bits = (out_len < 64) ? out_len : 64;
    double max_diff = 0.0;
    for (size_t bit = 0; bit < check_bits; bit++) {
        double c1 = 0.0, c2 = 0.0;
        size_t bi = bit / 8, bj = 7 - (bit % 8);
        for (int t = 0; t < num_trials; t++) {
            dens_sample(X, n, sx);
            if ((sx->data[bi] >> bj) & 1) c1 += 1.0;
            dens_sample(Y, n, sy);
            if ((sy->data[bi] >> bj) & 1) c2 += 1.0;
        }
        double diff = fabs(c1 - c2) / (double)num_trials;
        if (diff > max_diff) max_diff = diff;
    }
    dsample_free(sx); dsample_free(sy);
    return max_diff;
}

double stat_dist_uniform_vs_biased(double bias) {
    return fabs(0.5 - bias);
}

int stat_dist_triangle_inequality(double d_xy, double d_yz, double d_xz) {
    return (d_xz <= d_xy + d_yz + 1e-10) ? 1 : 0;
}

/* ================================================================
 * Entropy Estimation — Quantifying randomness
 *
 * Shannon entropy H(X) = -Sum Pr[X=x] log2 Pr[X=x]
 * Measures expected information content. Uniform distribution on
 * n bits has H = n (maximum). Deterministic output has H = 0.
 *
 * Min-entropy H_inf(X) = -log2(max_x Pr[X=x])
 * The worst-case predictability. Used in extractor theory and
 * leakage-resilient cryptography. If H_inf(X) >= k, then no
 * outcome occurs with probability > 2^{-k}.
 *
 * Collision entropy (Renyi-2) H_2(X) = -log2(Sum_x Pr[X=x]^2)
 * Measures collision probability. Used in leftover hash lemma.
 * ================================================================ */

double shannon_entropy_estimate(const DistributionSample** samples,
                                 int num_samples) {
    if (!samples || num_samples <= 0) return 0.0;
    size_t bins[256] = {0};
    for (int i = 0; i < num_samples; i++)
        if (samples[i] && samples[i]->byte_length > 0)
            bins[samples[i]->data[0]]++;
    double H = 0.0;
    for (int b = 0; b < 256; b++) {
        if (bins[b] > 0) {
            double p = (double)bins[b] / (double)num_samples;
            H -= p * log2(p);
        }
    }
    return H;
}

double min_entropy_estimate(const DistributionSample** samples,
                             int num_samples) {
    if (!samples || num_samples <= 0) return 0.0;
    size_t bins[256] = {0};
    for (int i = 0; i < num_samples; i++)
        if (samples[i] && samples[i]->byte_length > 0)
            bins[samples[i]->data[0]]++;
    size_t maxc = 0;
    for (int b = 0; b < 256; b++)
        if (bins[b] > maxc) maxc = bins[b];
    return -log2((double)maxc / (double)num_samples);
}

double collision_entropy_estimate(const DistributionSample** samples,
                                   int num_samples) {
    if (!samples || num_samples <= 0) return 0.0;
    size_t bins[256] = {0};
    for (int i = 0; i < num_samples; i++)
        if (samples[i] && samples[i]->byte_length > 0)
            bins[samples[i]->data[0]]++;
    double cp = 0.0;
    for (int b = 0; b < 256; b++) {
        if (bins[b] > 0) {
            double p = (double)bins[b] / (double)num_samples;
            cp += p * p;
        }
    }
    return -log2(cp);
}

/* ================================================================
 * Kolmogorov-Smirnov Two-Sample Test
 *
 * D_{n,m} = sup_x |F_n(x) - G_m(x)|
 *
 * Where F_n and G_m are empirical CDFs. The KS statistic is a
 * non-parametric test of the null hypothesis that both samples
 * come from the same distribution.
 *
 * In the hybrid argument, if KS statistic between adjacent hybrids
 * is large, then an unbounded distinguisher can tell them apart.
 * For PPT distinguishers, the advantage is bounded by but may be
 * much less than the KS statistic.
 *
 * Reference: Kolmogorov (1933), Smirnov (1948)
 * ================================================================ */

double ks_statistic(const DistributionSample** samples_a, int num_a,
                     const DistributionSample** samples_b, int num_b) {
    if (!samples_a || !samples_b || num_a <= 0 || num_b <= 0) return 0.0;
    double max_diff = 0.0;
    /* Evaluate empirical CDF at each byte value 0..255 */
    double cdf_a_at[257] = {0.0};
    double cdf_b_at[257] = {0.0};

    for (int i = 0; i < num_a; i++)
        if (samples_a[i] && samples_a[i]->byte_length > 0)
            cdf_a_at[samples_a[i]->data[0]] += 1.0;
    for (int i = 0; i < num_b; i++)
        if (samples_b[i] && samples_b[i]->byte_length > 0)
            cdf_b_at[samples_b[i]->data[0]] += 1.0;

    /* Accumulate to CDF */
    double cum_a = 0.0, cum_b = 0.0;
    for (int t = 0; t < 256; t++) {
        cum_a += cdf_a_at[t] / (double)num_a;
        cum_b += cdf_b_at[t] / (double)num_b;
        double diff = fabs(cum_a - cum_b);
        if (diff > max_diff) max_diff = diff;
    }
    return max_diff;
}

/*
 * chi_squared_two_sample: Pearson's chi-squared test for homogeneity.
 *
 * Tests the null hypothesis that two sets of samples come from the
 * same distribution. Partitions the sample space into bins and
 * computes:
 *   chi^2 = Sum_{bins} (O_i - E_i)^2 / E_i
 *
 * Large chi^2 -> reject null -> distributions are distinguishable.
 * In hybrid arguments, small chi^2 between adjacent hybrids suggests
 * they cannot be distinguished by statistical (unbounded) tests.
 *
 * Reference: Pearson (1900) "On the criterion..."
 */
double chi_squared_two_sample(const DistributionSample** samples_a, int num_a,
                               const DistributionSample** samples_b, int num_b,
                               size_t num_bins) {
    if (!samples_a || !samples_b || num_a <= 0 || num_b <= 0 || num_bins == 0)
        return 0.0;

    size_t* ha = (size_t*)calloc(num_bins, sizeof(size_t));
    size_t* hb = (size_t*)calloc(num_bins, sizeof(size_t));
    if (!ha || !hb) { free(ha); free(hb); return 0.0; }

    for (int i = 0; i < num_a; i++)
        if (samples_a[i] && samples_a[i]->byte_length > 0)
            ha[samples_a[i]->data[0] % num_bins]++;
    for (int i = 0; i < num_b; i++)
        if (samples_b[i] && samples_b[i]->byte_length > 0)
            hb[samples_b[i]->data[0] % num_bins]++;

    double chi2 = 0.0;
    double total = (double)(num_a + num_b);
    for (size_t i = 0; i < num_bins; i++) {
        double obs_a = (double)ha[i];
        double obs_b = (double)hb[i];
        double exp_a = (obs_a + obs_b) * (double)num_a / total;
        double exp_b = (obs_a + obs_b) * (double)num_b / total;
        if (exp_a > 0.0)
            chi2 += (obs_a - exp_a) * (obs_a - exp_a) / exp_a;
        if (exp_b > 0.0)
            chi2 += (obs_b - exp_b) * (obs_b - exp_b) / exp_b;
    }
    free(ha); free(hb);
    return chi2;
}

/*
 * kullback_leibler_divergence: Estimates KL(P||Q) from samples.
 *
 * KL(P||Q) = Sum_x P(x) * log(P(x)/Q(x))
 *
 * KL divergence is NOT symmetric: KL(P||Q) != KL(Q||P) in general.
 * It measures the expected extra information needed to encode samples
 * from P using a code optimized for Q.
 *
 * In cryptography, KL divergence relates to "leakage": if a PRG output
 * has low KL divergence from uniform, then it leaks little information
 * about the seed.
 */
double kullback_leibler_divergence(const DistributionSample** sam_p, int np,
                                    const DistributionSample** sam_q, int nq,
                                    size_t num_bins) {
    if (!sam_p || !sam_q || np <= 0 || nq <= 0 || num_bins == 0) return 0.0;
    size_t* hp = (size_t*)calloc(num_bins, sizeof(size_t));
    size_t* hq = (size_t*)calloc(num_bins, sizeof(size_t));
    if (!hp || !hq) { free(hp); free(hq); return 0.0; }

    for (int i = 0; i < np; i++)
        if (sam_p[i] && sam_p[i]->byte_length > 0)
            hp[sam_p[i]->data[0] % num_bins]++;
    for (int i = 0; i < nq; i++)
        if (sam_q[i] && sam_q[i]->byte_length > 0)
            hq[sam_q[i]->data[0] % num_bins]++;

    double kl = 0.0;
    for (size_t i = 0; i < num_bins; i++) {
        double p = (double)hp[i] / (double)np;
        double q = (double)hq[i] / (double)nq;
        if (p > 0.0) {
            if (q > 0.0) kl += p * log(p / q);
            else kl += p * log(p / 1e-10); /* penalty */
        }
    }
    free(hp); free(hq);
    return kl;
}

/*
 * correlation_coefficient: Pearson r between two sets of samples.
 *
 * r = Cov(X,Y) / (sigma_X * sigma_Y)
 *
 * Detects linear relationships between distributions. If adjacent
 * hybrids have high correlation, then linear distinguishers cannot
 * separate them. Low correlation suggests structural differences.
 */
double correlation_coefficient(const DistributionSample** sx,
                                const DistributionSample** sy, int n) {
    if (!sx || !sy || n <= 1) return 0.0;
    double sum_x = 0.0, sum_y = 0.0;
    for (int i = 0; i < n; i++) {
        sum_x += (sx[i] && sx[i]->byte_length > 0) ? (double)sx[i]->data[0] : 0.0;
        sum_y += (sy[i] && sy[i]->byte_length > 0) ? (double)sy[i]->data[0] : 0.0;
    }
    double mx = sum_x / (double)n, my = sum_y / (double)n;
    double cov = 0.0, vx = 0.0, vy = 0.0;
    for (int i = 0; i < n; i++) {
        double xv = (sx[i] && sx[i]->byte_length > 0) ? (double)sx[i]->data[0] : 0.0;
        double yv = (sy[i] && sy[i]->byte_length > 0) ? (double)sy[i]->data[0] : 0.0;
        double dx = xv - mx, dy = yv - my;
        cov += dx * dy;
        vx += dx * dx;
        vy += dy * dy;
    }
    if (vx == 0.0 || vy == 0.0) return 0.0;
    return cov / sqrt(vx * vy);
}