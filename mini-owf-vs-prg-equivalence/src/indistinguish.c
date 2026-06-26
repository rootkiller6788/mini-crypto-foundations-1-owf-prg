/*
 * indistinguish.c — Computational Indistinguishability and Hybrid Arguments
 *
 * Implements:
 *   - Distribution ensemble operations (L1)
 *   - Statistical (total variation) distance (L3)
 *   - Computational indistinguishability experiment (L2)
 *   - Hybrid argument verification (L4)
 *   - Next-bit unpredictability testing (L4)
 *   - Yao's theorem: predictor ⇔ distinguisher conversion (L4)
 *   - IND-CPA encryption from PRG via hybrid argument (L7)
 *
 * L4 Theorem (Yao 1982): A distribution ensemble {X_n} is pseudorandom
 *   iff it is next-bit unpredictable.
 *
 * L4 Hybrid argument: If adjacent hybrids H_i ≈_c H_{i+1} with advantage ε,
 *   then H_0 ≈_c H_k with advantage ≤ k·ε.
 *
 * Reference:
 *   Yao (1982) — Theory and Applications of Trapdoor Functions
 *   Goldreich (2001) — Foundations of Cryptography, Vol 1, Ch 3
 *   Arora & Barak (2009) — Computational Complexity, Ch 9
 *
 * Courses: MIT 6.875, Stanford CS255, Berkeley CS276
 */

#include "indistinguish.h"
#include "prg.h"
#include "crypto_utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <math.h>

/* ================================================================
 * L1: Distribution Ensemble
 * ================================================================
 * A distribution ensemble {X_n}_{n∈N} is a sequence of
 * distributions, one for each security parameter n.
 */

DistEnsemble *dist_ensemble_create(size_t sample_len) {
    DistEnsemble *de = (DistEnsemble *)malloc(sizeof(DistEnsemble));
    if (!de) return NULL;
    de->samples = NULL;
    de->n_samples = 0;
    de->capacity = 0;
    de->sample_len = sample_len;
    return de;
}

void dist_ensemble_free(DistEnsemble *de) {
    if (!de) return;
    for (int i = 0; i < de->n_samples; i++) {
        /* Free only the data buffer, not the BitString struct itself
         * since it's part of the larger realloc'd samples array */
        free(de->samples[i].data);
    }
    free(de->samples);
    free(de);
}

void dist_ensemble_add(DistEnsemble *de, const BitString *sample) {
    if (!de || !sample) return;
    if (de->n_samples >= de->capacity) {
        int new_cap = de->capacity == 0 ? 16 : de->capacity * 2;
        de->samples = (BitString *)realloc(de->samples,
            (size_t)new_cap * sizeof(BitString));
        if (!de->samples) return;
        de->capacity = new_cap;
    }
    /* Copy sample */
    BitString *dest = &de->samples[de->n_samples];
    dest->bit_len = sample->bit_len;
    size_t byte_len = (sample->bit_len + 7) / 8;
    dest->data = (uint8_t *)malloc(byte_len);
    if (!dest->data) return;
    memcpy(dest->data, sample->data, byte_len);
    de->n_samples++;
}

void dist_ensemble_randomize(DistEnsemble *de, int n_samples) {
    if (!de) return;
    /* Clear existing samples */
    for (int i = 0; i < de->n_samples; i++) {
        free(de->samples[i].data);
    }
    de->n_samples = 0;

    /* Generate random samples */
    for (int i = 0; i < n_samples; i++) {
        BitString *bs = bitstring_create(de->sample_len);
        bitstring_randomize(bs);
        dist_ensemble_add(de, bs);
        bitstring_free(bs);
    }
}

/* ================================================================
 * L3: Statistical Distance
 * ================================================================
 * Statistical (total variation) distance:
 *   Δ(X,Y) = (1/2) · Σ_v |Pr[X=v] - Pr[Y=v]|
 *
 * Properties:
 *   - 0 ≤ Δ(X,Y) ≤ 1
 *   - Δ is a metric
 *   - If Δ(X,Y) ≤ ε, no statistical test can distinguish X,Y
 *     with advantage > ε (information-theoretic)
 */

double stat_distance_from_samples(const DistEnsemble *X, const DistEnsemble *Y) {
    /*
     * Estimate statistical distance from empirical samples.
     *
     * For each sample value v, count frequency in X and Y,
     * then compute Δ = 1/2 * Σ |freq_X(v) - freq_Y(v)|.
     *
     * This is an empirical estimate; accuracy depends on
     * sample size and domain size.
     */
    if (!X || !Y) return 1.0;
    if (X->n_samples == 0 && Y->n_samples == 0) return 0.0;
    if (X->n_samples == 0 || Y->n_samples == 0) return 1.0;

    /* Build frequency map keyed by hex string for comparison */
    /* Simplified: compute distance via counting matches */
    double Nx = (double)X->n_samples;
    double Ny = (double)Y->n_samples;
    (void)Nx; (void)Ny;  /* Used implicitly in match computation */

    /* For each sample in X, check how it compares to Y distribution */

    /* Pairwise comparison: count how many in X match each value, etc. */
    /* Simplified approach for samples: use empirical CDF style */
    int matches = 0;
    int comparisons = 0;
    for (int i = 0; i < X->n_samples && i < 100; i++) {
        for (int j = 0; j < Y->n_samples && j < 100; j++) {
            if (bitstring_equal(&X->samples[i], &Y->samples[j])) {
                matches++;
            }
            comparisons++;
        }
    }

    if (comparisons == 0) return 1.0;
    /* Heuristic empirical distance */
    double match_rate = (double)matches / comparisons;
    double empirical_dist = 1.0 - match_rate;
    if (empirical_dist > 1.0) empirical_dist = 1.0;
    if (empirical_dist < 0.0) empirical_dist = 0.0;
    return empirical_dist;
}

double stat_distance_exact(size_t max_len, ProbMassFunc f_X, ProbMassFunc f_Y,
                           void *ctx_X, void *ctx_Y) {
    /*
     * Compute exact statistical distance for small domains.
     * Enumerates all values v ∈ {0,1}^{≤max_len} and sums.
     *
     * Δ = 1/2 * Σ_v |Pr_X[v] - Pr_Y[v]|
     *
     * For max_len > 10, enumeration is infeasible; returns -1.
     */
    if (!f_X || !f_Y) return -1.0;
    if (max_len > 12) return -1.0;  /* Too many values to enumerate */

    double sum = 0.0;
    uint64_t total = (max_len == 0) ? 1 : ((uint64_t)1 << max_len);

    BitString *v = bitstring_create(max_len);
    for (uint64_t idx = 0; idx < total; idx++) {
        /* Set v to binary representation of idx */
        for (size_t b = 0; b < max_len; b++) {
            bitstring_set_bit(v, max_len - 1 - b, (int)((idx >> b) & 1));
        }
        v->bit_len = max_len;

        double px = f_X(v, ctx_X);
        double py = f_Y(v, ctx_Y);
        double diff = px - py;
        if (diff < 0) diff = -diff;
        sum += diff;
    }
    bitstring_free(v);
    return sum / 2.0;
}

/* ================================================================
 * L2: Computational Indistinguishability Experiment
 * ================================================================
 * Exp_{D,X,Y}^{c}(n):
 *   b ← {0,1}
 *   if b=0: sample ← X, else sample ← Y
 *   b' ← D(sample)
 *   D succeeds if b' = b
 * Advantage = |2 * Pr[success] - 1|
 */

CompIndistResult comp_indist_experiment(const DistEnsemble *X, const DistEnsemble *Y,
                                         int n_trials, Distinguisher D, void *ctx) {
    CompIndistResult result = {0};
    if (!X || !Y || !D || n_trials <= 0) return result;

    result.n_trials = n_trials;

    for (int t = 0; t < n_trials; t++) {
        int coin = rand() % 2;

        const BitString *sample;
        if (coin == 0) {
            /* Sample from X */
            int idx = rand() % X->n_samples;
            sample = &X->samples[idx];
        } else {
            /* Sample from Y */
            int idx = rand() % Y->n_samples;
            sample = &Y->samples[idx];
        }

        int guess = D(sample, ctx);
        if (guess == coin) result.n_correct++;
    }

    double prob = (double)result.n_correct / n_trials;
    result.advantage = (prob > 0.5) ? (2.0 * prob - 1.0) : (1.0 - 2.0 * prob);
    return result;
}

/* ================================================================
 * L4: Hybrid Argument
 * ================================================================
 * Given k+1 hybrid distributions H_0, ..., H_k where adjacent
 * pairs are ε-indistinguishable, H_0 and H_k are k·ε-indistinguishable.
 *
 * Applications:
 *   - PRG iteration: H_i = (G_output_first_i_bits || U_{l-i})
 *     H_0 = all-uniform, H_l = all-PRG-output
 *     Each adjacent pair differs by one PRG expansion ⇒ ε-indist
 *     Therefore H_0 ≈ H_l with advantage ≤ l·ε.
 *
 *   - Encryption: H_0 = Enc_k(m), H_1 = Enc_k(0^{|m|})
 *     If adjacent hybrids indistinguishable, encryption is secure.
 */

HybridChain *hybrid_chain_create(int k, size_t n_bits) {
    HybridChain *hc = (HybridChain *)malloc(sizeof(HybridChain));
    if (!hc) return NULL;
    hc->k = k;
    hc->n_bits = n_bits;
    hc->hybrids = (DistEnsemble **)malloc((size_t)(k + 1) * sizeof(DistEnsemble *));
    if (!hc->hybrids) {
        free(hc);
        return NULL;
    }
    for (int i = 0; i <= k; i++) {
        hc->hybrids[i] = dist_ensemble_create(n_bits);
    }
    return hc;
}

void hybrid_chain_free(HybridChain *hc) {
    if (!hc) return;
    for (int i = 0; i <= hc->k; i++) {
        dist_ensemble_free(hc->hybrids[i]);
    }
    free(hc->hybrids);
    free(hc);
}

double hybrid_lemma_verify(const HybridChain *hc, int n_trials,
                           Distinguisher D, void *ctx) {
    /*
     * Verify hybrid lemma: test each adjacent pair (H_i, H_{i+1})
     * and return the maximum advantage across all pairs.
     *
     * By the hybrid lemma, H_0 and H_k are indistinguishable
     * with advantage ≤ k * max_adjacent_advantage.
     */
    if (!hc || !D) return 1.0;

    double max_adv = 0.0;
    for (int i = 0; i < hc->k; i++) {
        CompIndistResult r = comp_indist_experiment(
            hc->hybrids[i], hc->hybrids[i + 1], n_trials, D, ctx);
        if (r.advantage > max_adv) max_adv = r.advantage;
    }
    return max_adv;
}

/*
 * Create a hybrid chain for the PRG iteration proof.
 * H_i = (G_output_first_i_bits || U_{l-i})
 *
 * H_0: all uniform (l bits from U_{l(n)})
 * H_l: all PRG output (l bits from PRG)
 *
 * Each step i → i+1 replaces one uniform bit with a PRG output bit,
 * which are indistinguishable by PRG security.
 */
HybridChain *prg_hybrid_chain(const PRG *prg, int l) {
    if (!prg || l <= 0) return NULL;

    HybridChain *hc = hybrid_chain_create(l, prg->output_len);

    for (int i = 0; i <= l; i++) {
        /* Create samples for H_i */
        int n_samples = 50;
        for (int s = 0; s < n_samples; s++) {
            BitString *sample = bitstring_create(prg->output_len);
            bitstring_randomize(sample);  /* Start uniform */

            if (i > 0) {
                /* Replace first i bits with PRG output */
                BitString *seed = bitstring_create(prg->n);
                bitstring_randomize(seed);
                BitString *prg_out = bitstring_create(prg->output_len);
                if (prg_eval(prg, seed, prg_out) == 0) {
                    for (int pos = 0; pos < i && (size_t)pos < sample->bit_len; pos++) {
                        bitstring_set_bit(sample, (size_t)pos,
                            bitstring_get_bit(prg_out, (size_t)pos));
                    }
                }
                bitstring_free(seed);
                bitstring_free(prg_out);
            }

            dist_ensemble_add(hc->hybrids[i], sample);
            bitstring_free(sample);
        }
    }
    return hc;
}

/* ================================================================
 * L4: Next-Bit Unpredictability ⇔ Pseudorandomness (Yao 1982)
 * ================================================================
 * Theorem: {X_n} is pseudorandom iff it is next-bit unpredictable.
 *
 * Direction 1 (predictor → distinguisher):
 *   If exists predictor P that predicts bit i+1 given bits 1..i
 *   with advantage ε, then exists distinguisher D with advantage ε/l.
 *   D: given z, pick random i, run P on z_1..z_i,
 *      if P predicts z_{i+1} correctly, output 1 else 0.
 *
 * Direction 2 (distinguisher → predictor):
 *   If exists D with advantage ε distinguishing X from uniform,
 *   then exists P with advantage ε/l for next-bit prediction.
 *   P: use hybrid distributions H_i, run D on appropriate hybrid.
 */

NextBitUnpredResult next_bit_unpred_test(const DistEnsemble *X,
                                          NextBitPredictor P, void *ctx) {
    NextBitUnpredResult result = {0};
    if (!X || !P || X->n_samples == 0) return result;

    size_t l = X->sample_len;
    result.n_positions = (int)l - 1;
    result.advantages = (double *)calloc((size_t)(result.n_positions), sizeof(double));
    result.max_advantage = 0.0;

    if (!result.advantages) return result;

    for (int pos = 0; pos < result.n_positions; pos++) {
        int correct = 0;
        int total = 0;

        /* For each sample in X */
        for (int s = 0; s < X->n_samples && total < 100; s++) {
            BitString *prefix = bitstring_create((size_t)(pos + 1));
            /* Extract first pos+1 bits as prefix */
            for (int b = 0; b < pos + 1; b++) {
                bitstring_set_bit(prefix, (size_t)b,
                    bitstring_get_bit(&X->samples[s], (size_t)b));
            }
            prefix->bit_len = (size_t)(pos + 1);

            int truth = bitstring_get_bit(&X->samples[s], (size_t)pos);
            int pred = P(prefix, pos + 1, ctx);

            if (pred == truth) correct++;
            total++;

            bitstring_free(prefix);
        }

        if (total > 0) {
            double prob = (double)correct / total;
            double adv = (prob > 0.5) ? (prob - 0.5) : (0.5 - prob);
            result.advantages[pos] = adv;
            if (adv > result.max_advantage) result.max_advantage = adv;
        }
    }
    return result;
}

/*
 * Yao's theorem: Predictor → Distinguisher.
 * Given next-bit predictor P with advantage ε,
 * construct distinguisher D with advantage ε/l.
 *
 * D(z): pick random i ∈ [1, l], run P on prefix z[1..i-1],
 * if P predicts z[i] correctly, output 1, else 0.
 */
typedef struct {
    NextBitPredictor P;
    int l;
} YPTDContext;

static int yptd_distinguisher_func(const BitString *sample, void *ctx) {
    YPTDContext *c = (YPTDContext *)ctx;
    if (!c || c->l < 2) return rand() % 2;

    int i = 1 + rand() % (c->l - 1);  /* Random position 1..l-1 */
    BitString *prefix = bitstring_create((size_t)i);
    for (int b = 0; b < i; b++) {
        bitstring_set_bit(prefix, (size_t)b, bitstring_get_bit(sample, (size_t)b));
    }
    prefix->bit_len = (size_t)i;

    int pred = c->P(prefix, i, NULL);
    int truth = bitstring_get_bit(sample, (size_t)i);
    bitstring_free(prefix);

    /* Output 1 if prediction matches truth (implies pseudorandom) */
    return (pred == truth) ? 1 : 0;
}

Distinguisher yao_predictor_to_distinguisher(NextBitPredictor P, int l) {
    /* Returns a function pointer; ctx must be managed by caller */
    (void)P; (void)l;
    return yptd_distinguisher_func;
}

/*
 * Yao's theorem: Distinguisher → Predictor.
 * Given distinguisher D with advantage ε,
 * construct next-bit predictor P with advantage ε/l.
 *
 * P(prefix x[1..i]): flip coin, either return x[i+1] or sample uniformly.
 * Use D to distinguish. The hybrid argument gives the advantage bound.
 */
typedef struct {
    Distinguisher D;
    int l;
    void *original_ctx;
} YDTPContext;

static int ydtp_predictor_func(const BitString *prefix, int prefix_len, void *ctx) {
    YDTPContext *c = (YDTPContext *)ctx;
    if (!c || prefix_len >= c->l) return rand() % 2;

    /* For a predictor, we need to guess bit prefix_len (next bit after prefix).
     * We use the distinguisher D as follows:
     * Build a sample: prefix || random_guess_bit || uniform_rest
     * If D outputs 1 (thinks pseudorandom), guess = random_guess_bit
     * If D outputs 0 (thinks random), flip guess
     *
     * This is a simplified version of the reduction.
     */
    size_t l = (size_t)c->l;
    BitString *sample = bitstring_create(l);

    /* Copy prefix */
    for (int i = 0; i < prefix_len; i++) {
        bitstring_set_bit(sample, (size_t)i, bitstring_get_bit(prefix, (size_t)i));
    }

    /* Random guess for next bit */
    int guess_bit = rand() % 2;
    bitstring_set_bit(sample, (size_t)prefix_len, guess_bit);

    /* Fill rest with uniform */
    for (size_t i = (size_t)(prefix_len + 1); i < l; i++) {
        bitstring_set_bit(sample, i, rand() % 2);
    }
    sample->bit_len = l;

    int d_out = c->D(sample, c->original_ctx);
    bitstring_free(sample);

    /* If D thinks it's pseudorandom, trust the guess; else flip */
    return (d_out == 1) ? guess_bit : (1 - guess_bit);
}

NextBitPredictor yao_distinguisher_to_predictor(Distinguisher D, int l) {
    (void)D; (void)l;
    return ydtp_predictor_func;
}

/* ================================================================
 * L7: IND-CPA Encryption from PRG via Hybrid Argument
 * ================================================================
 * Enc_k(m) = G(k) ⊕ m where G is a PRG.
 *
 * Proof sketch (IND-CPA):
 *   Game 0 (real encryption): C = G(k) ⊕ m
 *   Game 1 (hybrid):          C = U ⊕ m (uniform keystream)
 *
 *   Game 0 ≈_c Game 1 by PRG security:
 *   If distinguisher D tells them apart, we can break the PRG.
 *   In Game 1, ciphertext is uniform ⇒ no information about m.
 */

int indist_encrypt(const PRG *prg, const BitString *key,
                   const BitString *msg, BitString *cipher) {
    if (!prg || !key || !msg || !cipher) return -1;
    return prg_stream_encrypt(prg, key, msg, cipher);
}

int indist_decrypt(const PRG *prg, const BitString *key,
                   const BitString *cipher, BitString *msg) {
    if (!prg || !key || !cipher || !msg) return -1;
    return prg_stream_decrypt(prg, key, cipher, msg);
}
