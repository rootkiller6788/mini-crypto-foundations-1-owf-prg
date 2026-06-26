/*
 * reduction.c — OWF ⇔ PRG Reduction (HILL Construction)
 *
 * Implements:
 *   - Stage 1+2: Goldreich-Levin augmented OWF with hardcore bit (L4)
 *   - Stage 3: 1-bit stretch PRG from OWF+hardcore (L4)
 *   - Stage 4: Arbitrary stretch via iteration (L4)
 *   - Full HILL reduction: OWF → PRG (L4)
 *   - PRG → OWF trivial direction (L4)
 *   - Entropy and pseudoentropy estimation (L5)
 *   - Leftover Hash Lemma (L5)
 *   - Reduction tightness analysis (L5)
 *   - Advanced: Pseudoentropy generator from OWF (L8)
 *
 * L4 Theorem (HILL 1999): OWF exist ⇒ PRG exist
 * L4 Theorem (trivial):     PRG exist ⇒ OWF exist
 * ⇒ OWF exist ⇔ PRG exist
 *
 * Reference:
 *   HILL (1999) — A Pseudorandom Generator from any One-way Function
 *   Goldreich (2001) — Foundations of Cryptography, Vol 1, Sec 3.4-3.5
 *   Vadhan (2012) — Pseudorandomness, Sec 6
 *   Holenstein (2006) — Pseudorandom Generators from One-Way Functions
 *   Haitner, Reingold, Vadhan (2010) — Efficiency Improvements
 *
 * Courses: MIT 6.875, Stanford CS255, Berkeley CS276
 */

#include "reduction.h"
#include "crypto_utils.h"
#include "hardcore_bit.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <math.h>

/* ================================================================
 * L4: Stage 1+2 — OWF with Hardcore Bit (Goldreich-Levin)
 * ================================================================
 * Given OWF f: {0,1}^n → {0,1}^n, construct:
 *   g(x, r) = (f(x), r)     where |x| = |r| = n
 *   hc(x, r) = <x, r>       hardcore predicate for g
 *
 * Goldreich-Levin Theorem (1989):
 * If f is a OWF, then g is a OWF and hc is hardcore for g.
 *
 * Proof sketch: Suppose adversary A predicts hc(x,r) from g(x,r) = (f(x), r)
 * with advantage ε. Build inverter B: given y = f(x), use A and list
 * decoding to recover x in time poly(n, 1/ε).
 */

OWFWithHardcoreBit *owf_add_hardcore_bit(OWF *f) {
    if (!f) return NULL;

    OWFWithHardcoreBit *owf_hc = (OWFWithHardcoreBit *)malloc(sizeof(OWFWithHardcoreBit));
    if (!owf_hc) return NULL;

    int n = f->n;
    owf_hc->f = f;
    owf_hc->input_len = 2 * n;

    /*
     * Create augmented OWF g(x, r) = (f(x), r).
     * g takes input (x||r) of 2n bits and outputs n + n bits.
     */
    owf_hc->g = owf_create(2 * n, gl_owf_eval, gl_params_create(f), "GL-augmented OWF");
    if (!owf_hc->g) {
        free(owf_hc);
        return NULL;
    }

    /*
     * Hardcore predicate hc(x, r) = <x, r>.
     */
    owf_hc->hc.owf = owf_hc->g;
    owf_hc->hc.pred = NULL;  /* Use gl_inner_product directly */
    owf_hc->hc.input_len = 2 * n;
    strncpy(owf_hc->hc.name, "GL-inner-product", 63);
    owf_hc->hc.name[63] = '\0';

    return owf_hc;
}

/* ================================================================
 * L4: Stage 3 — 1-Bit Stretch PRG from OWF with Hardcore
 * ================================================================
 * Given OWF g with hardcore predicate hc:
 *   G_1(s) = (g(s), hc(s))
 *   Input: n bits, Output: n+1 bits (stretch = 1)
 *
 * Security: If g is OWF and hc is hardcore for g,
 * then G_1 is a secure PRG.
 *
 * Proof: G_1(s) = (g(s), hc(s))
 *   ≈ (g(s), U_1)     by hardcore bit property
 *   ≈ (U_n, U_1)      by OWF property (g(s) comp. indist from uniform)
 *   = U_{n+1}
 */

/* 1-bit stretch PRG using augmented OWF and GL inner product */
typedef struct {
    OWFWithHardcoreBit *owf_hc;
} OneBitStretchParams;

static int one_bit_stretch_eval(const PRG *prg, const BitString *seed, BitString *output) {
    if (!prg || !seed || !output) return -1;
    OneBitStretchParams *p = (OneBitStretchParams *)prg->params;
    if (!p || !p->owf_hc) return -1;

    /* Compute g(seed) */
    BitString *g_out = bitstring_create(p->owf_hc->g->n);
    if (owf_eval(p->owf_hc->g, seed, g_out) != 0) {
        bitstring_free(g_out);
        return -1;
    }

    /* Compute hardcore bit: <x, r> from seed = (x||r) */
    size_t half = seed->bit_len / 2;
    BitString *x_part = bitstring_create(half);
    BitString *r_part = bitstring_create(half);
    for (size_t i = 0; i < half; i++) {
        bitstring_set_bit(x_part, i, bitstring_get_bit(seed, i));
        bitstring_set_bit(r_part, i, bitstring_get_bit(seed, half + i));
    }
    x_part->bit_len = half;
    r_part->bit_len = half;
    int hc_bit = gl_inner_product(x_part, r_part);
    bitstring_free(x_part);
    bitstring_free(r_part);

    /* Output = (g(seed) || hc_bit) — n+1 bits */
    /* Build output: copy g_out then append hardcore bit */
    output->bit_len = 0;
    for (size_t i = 0; i < g_out->bit_len; i++) {
        bitstring_set_bit(output, i, bitstring_get_bit(g_out, i));
    }
    output->bit_len = g_out->bit_len;
    bitstring_set_bit(output, output->bit_len, hc_bit);
    output->bit_len++;

    bitstring_free(g_out);
    return 0;
}

PRG *prg_one_bit_stretch(const OWFWithHardcoreBit *owf_hc) {
    if (!owf_hc) return NULL;

    OneBitStretchParams *params = (OneBitStretchParams *)malloc(
        sizeof(OneBitStretchParams));
    if (!params) return NULL;
    params->owf_hc = (OWFWithHardcoreBit *)owf_hc;  /* Non-const internally */

    /*
     * G_1: {0,1}^{2n} → {0,1}^{2n+1}
     * Input: 2n-bit seed (x||r)
     * Output: g(x,r) || hc(x,r) = (f(x)||r) || <x,r>
     */
    size_t input_len = (size_t)(owf_hc->input_len);
    size_t output_len = input_len + 1;

    return prg_create((SecurityParam)input_len, output_len,
                      one_bit_stretch_eval, params, "1bit-stretch PRG");
}

/* ================================================================
 * L4: Stage 4 — Arbitrary Polynomial Stretch via Iteration
 * ================================================================
 * Given PRG G with 1-bit stretch, iterate to get any desired stretch.
 *
 * G_l(s_0): for i = 0..l-1:
 *   (s_{i+1}, out_i) = decompose(G(s_i))
 *   Output: out_0 || out_1 || ... || out_{l-1}
 *
 * Security: Hybrid argument. Each step replaces one G expansion
 * with uniform, losing at most ε advantage per step.
 * Total loss: l·ε.
 */

PRG *prg_arbitrary_stretch(PRG *prg_one_bit, size_t total_output_len) {
    if (!prg_one_bit) return NULL;

    void *iter_params = prg_iterate_params_create(prg_one_bit, total_output_len);
    if (!iter_params) return NULL;

    return prg_create(prg_one_bit->n, total_output_len,
                      prg_iterate_eval, iter_params, "Arbitrary-stretch PRG");
}

/* ================================================================
 * L4: Full HILL Reduction — OWF ⇒ PRG with Arbitrary Stretch
 * ================================================================
 * Stage 1:      f (OWF) → g(x,r)=(f(x),r) + hc(x,r)=<x,r> (GL theorem)
 * Stage 2+3:    g + hc → G_1 (1-bit stretch PRG)
 * Stage 4:      G_1 → G_l (arbitrary stretch via iteration)
 *
 * Alternatively, simplified direct construction:
 *   Given OWF f, define G(s) using Blum-Micali iteration
 *   where each step outputs the GL hardcore bit.
 */

PRG *hill_owf_to_prg(OWF *owf, size_t output_len) {
    if (!owf || output_len == 0) return NULL;

    /*
     * Full HILL pipeline:
     * 1. Augment OWF with hardcore bit
     * 2. Build 1-bit stretch PRG
     * 3. Stretch to desired output length
     */
    OWFWithHardcoreBit *owf_hc = owf_add_hardcore_bit(owf);
    if (!owf_hc) return NULL;

    PRG *prg_1bit = prg_one_bit_stretch(owf_hc);
    if (!prg_1bit) {
        free(owf_hc);
        return NULL;
    }

    PRG *prg_final = prg_arbitrary_stretch(prg_1bit, output_len);
    if (!prg_final) {
        prg_free(prg_1bit);
        free(owf_hc);
        return NULL;
    }

    return prg_final;
}

/* ================================================================
 * L4: PRG ⇒ OWF (Trivial Direction)
 * ================================================================
 * Theorem: If PRG G: {0,1}^n → {0,1}^{2n} exists, then G is a OWF.
 *
 * Proof: Suppose inverter A exists that given y = G(x) finds x'
 * such that G(x') = y with probability ≥ 1/p(n) (non-negligible).
 *
 * Construct PRG distinguisher D:
 *   D(z):  x' = A(z)
 *          if G(x') = z output 1 (pseudorandom: inversion succeeded)
 *          else output 0 (random: random z unlikely in Im(G))
 *
 * Advantage of D:
 *   Pr[D(G(U_n)) = 1] ≥ 1/p(n)  (inverter succeeds on PRG output)
 *   Pr[D(U_{2n}) = 1] ≤ 2^n/2^{2n} = 2^{-n}  (random in image)
 *   Advantage ≥ 1/p(n) - 2^{-n} which is non-negligible.
 *
 * This contradicts PRG security, so no such A exists.
 * Therefore G is a one-way function.
 */

/* G itself as OWF: g(x) = G(x) */
static int prg_as_owf_eval(const OWF *owf, const BitString *x, BitString *y) {
    PRG *prg = (PRG *)owf->params;
    if (!prg) return -1;

    /* G(x): use PRG evaluation, truncate/pad to OWF output size */
    BitString *prg_out = bitstring_create(prg->output_len);
    if (prg_eval(prg, x, prg_out) != 0) {
        bitstring_free(prg_out);
        return -1;
    }

    /* Copy output (truncate if needed) */
    size_t copy_len = (prg_out->bit_len < y->bit_len) ? prg_out->bit_len : y->bit_len;
    y->bit_len = copy_len;
    for (size_t i = 0; i < copy_len; i++) {
        bitstring_set_bit(y, i, bitstring_get_bit(prg_out, i));
    }

    bitstring_free(prg_out);
    return 0;
}

OWF *prg_to_owf(PRG *prg) {
    if (!prg) return NULL;

    /*
     * Use the PRG as a OWF: f(x) = G(x) truncated to n bits.
     * For a PRG with stretch factor 2, this is length-preserving.
     */
    OWF *owf = owf_create(prg->n, prg_as_owf_eval, prg, "PRG-as-OWF");
    if (!owf) return NULL;

    /* Note: prg is now owned by owf->params; caller must not free prg separately */
    return owf;
}

/* ================================================================
 * L5: Entropy and Pseudoentropy
 * ================================================================
 * Min-entropy: H_∞(X) = -log₂(max_x Pr[X=x])
 *   Measures the worst-case unpredictability.
 *
 * Pseudoentropy (HILL): A distribution X has pseudo-min-entropy ≥ k
 * if there exists Y with H_∞(Y) ≥ k such that X ≈_c Y.
 *
 * The HILL construction shows:
 *   If f is a OWF, then (f(x), x) has pseudoentropy > n
 *   (it has n bits of real entropy in x hidden behind f(x)).
 */

EntropyProfile entropy_from_samples(const DistEnsemble *X) {
    EntropyProfile ep = {0};
    if (!X || X->n_samples == 0) return ep;

    /*
     * Estimate entropy from sample frequencies.
     * For each observed value v: freq(v) ≈ Pr[X=v].
     *
     * Min-entropy: -log₂(max_v freq(v))
     * Shannon entropy: -Σ_v freq(v)·log₂(freq(v))
     * Collision entropy: -log₂(Σ_v freq(v)²)
     */
    double max_freq = 0.0;
    double shannon = 0.0;
    double collision_sum = 0.0;

    for (int i = 0; i < X->n_samples; i++) {
        /* Count frequency of this sample */
        int count = 0;
        for (int j = 0; j < X->n_samples; j++) {
            if (bitstring_equal(&X->samples[i], &X->samples[j])) count++;
        }
        double freq = (double)count / X->n_samples;
        if (freq > max_freq) max_freq = freq;
        /* Only count each unique value once */
        int already_counted = 0;
        for (int j = 0; j < i; j++) {
            if (bitstring_equal(&X->samples[i], &X->samples[j])) {
                already_counted = 1;
                break;
            }
        }
        if (!already_counted) {
            if (freq > 0) shannon -= freq * log(freq) / log(2.0);
            collision_sum += freq * freq;
        }
    }

    ep.min_entropy = (max_freq > 0) ? -log(max_freq) / log(2.0) : 0.0;
    ep.shannon_entropy = shannon;
    ep.collision_entropy = (collision_sum > 0) ? -log(collision_sum) / log(2.0) : 0.0;
    /* Pseudo min-entropy lower bound: real entropy (cannot be less) */
    ep.pseudo_min_entropy = ep.min_entropy;

    return ep;
}

/* ================================================================
 * L5: Leftover Hash Lemma (Impagliazzo, Levin, Luby 1989)
 * ================================================================
 * If H is a universal hash family from {0,1}^n to {0,1}^m, and
 * X has min-entropy ≥ m + 2·log(1/ε), then:
 *   Δ( (H, H(X)), (H, U_m) ) ≤ ε/2
 *
 * I.e., applying a random universal hash to a high-entropy source
 * yields bits that are statistically close to uniform.
 *
 * Used in HILL: extract pseudorandom bits from (f(x), x).
 */

double leftover_hash_lemma(const DistEnsemble *X, int m,
                           const GF2HashFunc *hash, int n_samples) {
    /*
     * Empirically verify the leftover hash lemma.
     * Compute statistical distance between (hash, hash(X_sample))
     * and (hash, U_m).
     *
     * Returns estimated distance.
     */
    if (!X || !hash || n_samples <= 0) return 1.0;

    /* Create reference uniform distribution on m bits */
    DistEnsemble *uniform = dist_ensemble_create((size_t)m);
    dist_ensemble_randomize(uniform, n_samples);

    /* Create hashed distribution */
    DistEnsemble *hashed = dist_ensemble_create((size_t)m);
    BitString *h_out = bitstring_create((size_t)m);

    for (int i = 0; i < n_samples && i < X->n_samples; i++) {
        gf2_hash_eval(hash, &X->samples[i], h_out);
        dist_ensemble_add(hashed, h_out);
    }

    double dist = stat_distance_from_samples(hashed, uniform);

    bitstring_free(h_out);
    dist_ensemble_free(hashed);
    dist_ensemble_free(uniform);

    return dist;
}

/* ================================================================
 * L5: Reduction Tightness Analysis
 * ================================================================
 * Measure how much security is lost in the OWF ⇒ PRG reduction.
 *
 * Given: adversary A that breaks PRG with advantage ε_prg.
 *   Construct: inverter B that breaks OWF.
 *   Measure: ε_owf as function of ε_prg.
 *
 * Tightness ratio = ε_prg / ε_owf
 *   HILL (1999):          O(ε^3 / n)  — cubic loss
 *   Holenstein (2006):    O(ε^2 / n)  — quadratic loss
 *   HRV (2010):           O(ε / log n) — near-linear
 *
 * This function simulates the reduction and measures the
 * empirical tightness.
 */

ReductionTightness measure_reduction_tightness(OWF *owf, PRG *prg,
                                                int n_trials,
                                                PRGDistinguisherFunc D,
                                                OWFAdversaryFunc A) {
    ReductionTightness result = {0};
    if (!owf || !prg || !D || !A || n_trials <= 0) return result;

    /*
     * Measure PRG adversary advantage: ε_prg
     */
    PRGDistinguishingResult prg_res = prg_distinguishing_experiment(prg, n_trials, D);
    result.adv_prg = prg_res.advantage;

    /*
     * Measure OWF inverter advantage: ε_owf
     * Run inversion experiment using A as adversary.
     */
    OWFInversionResult owf_res = owf_inversion_experiment(owf, n_trials, A);
    result.adv_owf = owf_res.success_probability;

    /*
     * Compute tightness ratio.
     */
    if (result.adv_owf > 0.0) {
        result.tightness_ratio = result.adv_prg / result.adv_owf;
    } else {
        result.tightness_ratio = -1.0;  /* Undefined */
    }

    result.n_queries = n_trials;
    strncpy(result.construction, "HILL (1999) basic", 63);
    result.construction[63] = '\0';

    return result;
}

/* ================================================================
 * L8: Pseudoentropy Generator from OWF
 * ================================================================
 * Output (f(x), h_1(x), ..., h_k(x)) where h_i are from a
 * pairwise-independent hash family.
 *
 * By the leftover hash lemma, this output has pseudoentropy
 * at least H_∞(x | f(x)) - O(log n).
 *
 * This is the key insight in the HILL construction:
 * we can "extract" the hidden entropy of x given f(x)
 * using universal hashing.
 */

PseudoentropyGen *pseudoentropy_gen_create(OWF *owf, int n_hashes,
                                            int bits_per_hash) {
    if (!owf || n_hashes <= 0 || bits_per_hash <= 0) return NULL;

    PseudoentropyGen *peg = (PseudoentropyGen *)malloc(sizeof(PseudoentropyGen));
    if (!peg) return NULL;

    peg->owf = owf;
    peg->n_hashes = n_hashes;
    peg->bits_per_hash = bits_per_hash;
    peg->hashes = (GF2HashFunc *)malloc((size_t)n_hashes * sizeof(GF2HashFunc));
    if (!peg->hashes) {
        free(peg);
        return NULL;
    }

    /* Initialize each hash function */
    for (int i = 0; i < n_hashes; i++) {
        /* Create GF(2) hash from n to bits_per_hash */
        GF2HashFunc *h = gf2_hash_create(owf->n, bits_per_hash);
        if (!h) {
            for (int j = 0; j < i; j++) gf2_hash_free(&peg->hashes[j]);
            free(peg->hashes);
            free(peg);
            return NULL;
        }
        gf2_hash_set_random(h);
        peg->hashes[i] = *h;
        free(h); /* gf2_hash_create allocates, we copy the struct */
    }

    return peg;
}

void pseudoentropy_gen_free(PseudoentropyGen *peg) {
    if (!peg) return;
    for (int i = 0; i < peg->n_hashes; i++) {
        /* Free internal buffers of each hash */
        free(peg->hashes[i].matrix);
        free(peg->hashes[i].offset);
    }
    free(peg->hashes);
    free(peg);
}
