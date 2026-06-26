/*
 * prg.c — Pseudorandom Generator Implementations
 *
 * Implements:
 *   - PRG core framework (L1)
 *   - PRG distinguishing experiment (L1)
 *   - Blum-Micali construction from OWF+hardcore (L2)
 *   - HILL construction from any OWF (L2)
 *   - PRG iteration for arbitrary stretch (L5)
 *   - PRG as stream cipher (L7)
 *   - PRG for BPP derandomization (L7)
 *
 * Equivalence OWF ⇔ PRG is the central theorem of this module.
 *   OWF ⇒ PRG: HILL (1999) — highly non-trivial
 *   PRG ⇒ OWF: trivial — G itself is a OWF
 *
 * Reference:
 *   Blum & Micali (1984) — How to Generate Cryptographically Strong Sequences
 *   Yao (1982) — Theory and Applications of Trapdoor Functions
 *   HILL (1999) — A Pseudorandom Generator from any One-way Function
 *   Goldreich (2001) — Foundations of Cryptography, Vol 1, Ch 3
 *
 * Courses: MIT 6.875, Stanford CS255, Berkeley CS276, Princeton COS 522
 */

#include "prg.h"
#include "crypto_utils.h"
#include "hardcore_bit.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

/* ================================================================
 * L1: PRG Core Framework
 * ================================================================
 * G: {0,1}^n → {0,1}^{l(n)} with l(n) > n (stretch)
 * Computational indistinguishability: no PPT distinguisher can
 * tell G(U_n) from U_{l(n)} with non-negligible advantage.
 */

PRG *prg_create(SecurityParam n, size_t output_len, PRGEvalFunc eval,
                void *params, const char *name) {
    PRG *prg = (PRG *)malloc(sizeof(PRG));
    if (!prg) return NULL;
    prg->n = n;
    prg->output_len = output_len;
    prg->eval = eval;
    prg->params = params;
    if (name) {
        strncpy(prg->name, name, 63);
        prg->name[63] = '\0';
    } else {
        prg->name[0] = '\0';
    }
    return prg;
}

void prg_free(PRG *prg) {
    if (prg) {
        free(prg->params);
        free(prg);
    }
}

int prg_eval(const PRG *prg, const BitString *seed, BitString *output) {
    if (!prg || !prg->eval || !seed || !output) return -1;
    return prg->eval(prg, seed, output);
}

/* ================================================================
 * L1: PRG Distinguishing Experiment
 * ================================================================
 * Exp_{D,G}^{prg}(n):
 *   b ← {0,1}
 *   if b=0: z ← U_{l(n)} (uniform)
 *   if b=1: s ← U_n, z ← G(s) (pseudorandom)
 *   b' ← D(z)
 *   Success if b' = b
 * Advantage = |2 * Pr[success] - 1|
 */

PRGDistinguishingResult prg_distinguishing_experiment(const PRG *prg, int n_trials,
                                                       PRGDistinguisherFunc D) {
    PRGDistinguishingResult result = {0};
    if (!prg || !D || n_trials <= 0) return result;

    result.n_trials = n_trials;
    BitString *challenge = bitstring_create(prg->output_len);
    BitString *seed = bitstring_create(prg->n);

    for (int t = 0; t < n_trials; t++) {
        int real_coin = rand() % 2;  /* 0=random, 1=pseudorandom */

        if (real_coin == 0) {
            /* Generate truly random challenge */
            bitstring_randomize(challenge);
        } else {
            /* Generate pseudorandom challenge */
            bitstring_randomize(seed);
            prg_eval(prg, seed, challenge);
        }

        int guess = D(challenge, prg->n);
        if (guess == real_coin) result.n_correct++;
    }

    bitstring_free(challenge);
    bitstring_free(seed);

    double prob = (double)result.n_correct / n_trials;
    result.advantage = (prob > 0.5) ? (2.0 * prob - 1.0) : (1.0 - 2.0 * prob);
    return result;
}

/* ================================================================
 * L2: Blum-Micali PRG Construction (from hardcore bit)
 * ================================================================
 * Given: OWF f (permutation), hardcore predicate b
 * Define: G(s) = (f(s), b(s))  — stretches by 1 bit
 *
 * For l-bit stretch (iterated):
 *   s_0 = seed
 *   for i = 0..l-1: s_{i+1} = f(s_i), output b(s_i)
 *   Output: b(s_0) || b(s_1) || ... || b(s_{l-1})   (l output bits)
 */

int blum_micali_prg_eval(const PRG *prg, const BitString *seed, BitString *output) {
    if (!prg || !seed || !output) return -1;
    BlumMicaliParams *p = (BlumMicaliParams *)prg->params;
    if (!p || !p->f || !p->hardcore) return -1;

    size_t l = p->stretch;
    size_t n = p->f->n;
    output->bit_len = 0;

    /* Iterate f, extract hardcore bit each step */
    BitString *current = bitstring_create(n);
    /* Copy seed into current */
    for (size_t i = 0; i < n && i < seed->bit_len; i++) {
        bitstring_set_bit(current, i, bitstring_get_bit(seed, i));
    }
    current->bit_len = n;

    BitString *next_state = bitstring_create(n);

    for (size_t i = 0; i < l && output->bit_len < prg->output_len; i++) {
        /* Extract hardcore bit: b(current) */
        int bit = p->hardcore(current);
        bitstring_set_bit(output, output->bit_len, bit);
        output->bit_len++;

        /* Compute next state: s_{i+1} = f(s_i) */
        if (i < l - 1 || p->is_blum_micali) {
            if (owf_eval(p->f, current, next_state) != 0) {
                bitstring_free(current);
                bitstring_free(next_state);
                return -1;
            }
            /* Swap */
            BitString *temp = current;
            current = next_state;
            next_state = temp;
        }
    }

    bitstring_free(current);
    bitstring_free(next_state);
    return 0;
}

void *blum_micali_params_create(OWF *f, int (*hc)(const BitString *x),
                                 size_t stretch) {
    BlumMicaliParams *p = (BlumMicaliParams *)malloc(sizeof(BlumMicaliParams));
    if (!p) return NULL;
    p->f = f;
    p->hardcore = hc;
    p->stretch = stretch;
    p->is_blum_micali = 1;
    return p;
}

/* ================================================================
 * L2: PRG from OWF via HILL (high-level black-box assembly)
 * ================================================================
 * HILL Construction (1999):
 *   Stage 1: OWF f → augmented OWF g(x,r) = (f(x), r)
 *   Stage 2: Extract hardcore bit h(x,r) = <x,r> (Goldreich-Levin)
 *   Stage 3: 1-bit stretch PRG: G_1(s) = (g(s), h(s))
 *   Stage 4: Iterate for arbitrary stretch
 *
 * This implementation provides the high-level assembly;
 * the detailed stages are in reduction.c.
 */

int hill_prg_eval(const PRG *prg, const BitString *seed, BitString *output) {
    if (!prg || !seed || !output) return -1;
    HILLParams *p = (HILLParams *)prg->params;
    if (!p || !p->owf) return -1;

    /*
     * HILL evaluation: given seed s = (x, r) where |x| = |r| = n,
     * output the GL hardcore bits in a structured way.
     *
     * Simplified: G(s) = g(s) || h(s)  (1-bit stretch)
     * where g(s) = (f(x), r) and h(s) = <x, r>.
     *
     * For arbitrary stretch, we iterate using the core part
     * of g(s) as the next seed and output h(s).
     */
    size_t n = p->owf->n;
    output->bit_len = 0;

    BitString *current_s = bitstring_create(seed->bit_len);
    /* Copy seed */
    for (size_t i = 0; i < seed->bit_len; i++) {
        bitstring_set_bit(current_s, i, bitstring_get_bit(seed, i));
    }
    current_s->bit_len = seed->bit_len;

    size_t half = current_s->bit_len / 2;
    BitString *x_part = bitstring_create(half);
    BitString *r_part = bitstring_create(half);
    BitString *fx_out = bitstring_create(n);
    BitString *next_seed = bitstring_create(current_s->bit_len);

    while (output->bit_len < prg->output_len) {
        /* Split current_s into x and r parts */
        for (size_t i = 0; i < half; i++) {
            bitstring_set_bit(x_part, i, bitstring_get_bit(current_s, i));
            bitstring_set_bit(r_part, i, bitstring_get_bit(current_s, half + i));
        }
        x_part->bit_len = half;
        r_part->bit_len = half;

        /* Compute f(x) */
        if (owf_eval(p->owf, x_part, fx_out) != 0) {
            bitstring_free(current_s); bitstring_free(x_part);
            bitstring_free(r_part); bitstring_free(fx_out);
            bitstring_free(next_seed);
            return -1;
        }

        /* Output GL hardcore bit: <x, r> */
        int hc_bit = gf2_dot_product(x_part, r_part);
        bitstring_set_bit(output, output->bit_len, hc_bit);
        output->bit_len++;

        /* Next seed = f(x) || r' (next r derived from current state) */
        for (size_t i = 0; i < fx_out->bit_len; i++) {
            bitstring_set_bit(next_seed, i, bitstring_get_bit(fx_out, i));
        }
        /*
         * Deterministic update of r: r_{i+1} derived from prior state.
         * The full HILL construction uses pairwise-independent hashing
         * for provable entropy preservation; this simplified variant
         * demonstrates the structural iteration pattern.
         */
        for (size_t i = fx_out->bit_len; i < next_seed->bit_len && i < current_s->bit_len; i++) {
            int b = bitstring_get_bit(r_part, i - fx_out->bit_len) ^
                    bitstring_get_bit(fx_out, (i - fx_out->bit_len) % fx_out->bit_len);
            bitstring_set_bit(next_seed, i, b);
        }
        next_seed->bit_len = current_s->bit_len;

        /* Advance state */
        BitString *tmp = current_s;
        current_s = next_seed;
        next_seed = tmp;
    }

    bitstring_free(current_s); bitstring_free(x_part);
    bitstring_free(r_part); bitstring_free(fx_out);
    bitstring_free(next_seed);
    return 0;
}

void *hill_params_create(OWF *owf, size_t output_len) {
    HILLParams *p = (HILLParams *)malloc(sizeof(HILLParams));
    if (!p) return NULL;
    p->owf = owf;
    p->output_len = output_len;
    p->n_hashes = 2;
    p->current_state = NULL;
    p->bits_extracted = 0;
    p->bits_remaining = (int)output_len;
    return p;
}

/* ================================================================
 * L5: PRG Iteration (Arbitrary Polynomial Stretch)
 * ================================================================
 * Given a PRG G with 1-bit stretch: G: {0,1}^n → {0,1}^{n+1}
 * Construct G_l: {0,1}^n → {0,1}^{n+l} via iterative expansion:
 *
 * Let G(s) = (G_core(s), G_bit(s))
 *   G_core(s): first n bits (next seed)
 *   G_bit(s):  last 1 bit  (output bit)
 *
 * s_0 = seed
 * s_{i+1} = G_core(s_i)
 * out_i = G_bit(s_i)
 * Output: out_0 || out_1 || ... || out_{l-1}
 */

int prg_iterate_eval(const PRG *prg, const BitString *seed, BitString *output) {
    if (!prg || !seed || !output) return -1;
    PRGIteration *p = (PRGIteration *)prg->params;
    if (!p || !p->base_prg) return -1;

    size_t total_output = p->output_bits;
    output->bit_len = 0;

    BitString *s = bitstring_create(seed->bit_len);
    /* Copy seed */
    for (size_t i = 0; i < seed->bit_len; i++) {
        bitstring_set_bit(s, i, bitstring_get_bit(seed, i));
    }
    s->bit_len = seed->bit_len;

    BitString *g_out = bitstring_create(p->base_prg->output_len);
    BitString *core = bitstring_create(p->base_prg->n);
    BitString *bit_out = bitstring_create(1);

    while (output->bit_len < total_output) {
        if (prg_eval(p->base_prg, s, g_out) != 0) {
            bitstring_free(s); bitstring_free(g_out);
            bitstring_free(core); bitstring_free(bit_out);
            return -1;
        }

        /* Extract core (first n bits) for next seed */
        for (size_t i = 0; i < (size_t)p->base_prg->n; i++) {
            bitstring_set_bit(core, i, bitstring_get_bit(g_out, i));
        }
        core->bit_len = p->base_prg->n;

        /* Extract output bits (remaining bits after core) */
        for (size_t i = p->base_prg->n; i < g_out->bit_len && output->bit_len < total_output; i++) {
            bitstring_set_bit(output, output->bit_len, bitstring_get_bit(g_out, i));
            output->bit_len++;
        }

        /* Advance seed = core */
        BitString *tmp = s;
        s = core;
        core = tmp;
    }

    bitstring_free(s); bitstring_free(g_out);
    bitstring_free(core); bitstring_free(bit_out);
    return 0;
}

void *prg_iterate_params_create(PRG *base_prg, size_t output_bits) {
    PRGIteration *p = (PRGIteration *)malloc(sizeof(PRGIteration));
    if (!p) return NULL;
    p->base_prg = base_prg;
    p->output_bits = output_bits;
    return p;
}

/* ================================================================
 * L7: PRG as Stream Cipher
 * ================================================================
 * Standard symmetric encryption from PRG:
 *   Key = seed s ∈ {0,1}^n
 *   Keystream = G(s)
 *   Encrypt(m) = m ⊕ G(s)   (bitwise XOR)
 *   Decrypt(c) = c ⊕ G(s)   (same keystream)
 *
 * Security: IND-CPA secure if G is a secure PRG.
 * The proof uses a hybrid argument (implemented in indistinguish.c).
 */

int prg_stream_encrypt(const PRG *prg, const BitString *key,
                       const BitString *plaintext, BitString *ciphertext) {
    if (!prg || !key || !plaintext || !ciphertext) return -1;
    if (plaintext->bit_len > prg->output_len) return -1; /* Not enough keystream */

    /* Generate keystream from key (PRG seed) */
    BitString *keystream = bitstring_create(prg->output_len);
    if (prg_eval(prg, key, keystream) != 0) {
        bitstring_free(keystream);
        return -1;
    }

    /* ciphertext = plaintext ⊕ keystream */
    ciphertext->bit_len = plaintext->bit_len;
    size_t byte_len = (plaintext->bit_len + 7) / 8;
    for (size_t i = 0; i < byte_len; i++) {
        ciphertext->data[i] = plaintext->data[i] ^ keystream->data[i];
    }
    /* Zero out excess bits */
    size_t extra = byte_len * 8 - plaintext->bit_len;
    if (extra > 0) {
        ciphertext->data[byte_len - 1] &= (uint8_t)(0xFF >> extra);
    }

    bitstring_free(keystream);
    return 0;
}

int prg_stream_decrypt(const PRG *prg, const BitString *key,
                       const BitString *ciphertext, BitString *plaintext) {
    /*
     * Decryption is identical to encryption in stream cipher:
     * plaintext = ciphertext ⊕ G(key)
     * because (m ⊕ G(k)) ⊕ G(k) = m.
     */
    return prg_stream_encrypt(prg, key, ciphertext, plaintext);
}

/* ================================================================
 * L7: PRG for BPP Derandomization (Nisan-Wigderson framework)
 * ================================================================
 * If a PRG exists, then BPP ⊆ P/poly.
 *
 * Idea: A BPP algorithm uses r(n) random bits and errs with prob ≤ 1/3.
 * Run it on all n-bit seeds (2^n executions), use PRG to expand each
 * into r(n) pseudorandom bits, and take majority vote.
 *
 * If a PRG fooling the algorithm exists, the majority is correct
 * on all but finitely many inputs.
 */

int prg_derandomize_bpp(const PRG *prg, int (*bpp_algo)(const BitString *input,
                        const BitString *random), const BitString *input, int *result) {
    if (!prg || !bpp_algo || !input || !result) return -1;

    int yes_votes = 0;
    int no_votes = 0;
    int total_trials = 0;

    /*
     * Enumerate all possible n-bit seeds (2^n).
     * For small n (n ≤ 12, 2^12 = 4096), we can enumerate.
     * For larger n, sample seeds randomly (partial derandomization).
     */
    int max_seeds;
    if (prg->n <= 12) {
        max_seeds = 1 << prg->n;  /* Full enumeration */
    } else {
        max_seeds = 4096;  /* Sample */
    }

    BitString *seed = bitstring_create(prg->n);
    BitString *pseudorand = bitstring_create(prg->output_len);

    for (int i = 0; i < max_seeds; i++) {
        /* Generate i-th seed */
        if (prg->n <= 12) {
            /* Deterministic seed from counter */
            for (int j = 0; j < prg->n; j++) {
                bitstring_set_bit(seed, (size_t)j, (i >> j) & 1);
            }
        } else {
            bitstring_randomize(seed);
        }
        seed->bit_len = prg->n;

        /* Expand seed into pseudorandom bits */
        if (prg_eval(prg, seed, pseudorand) != 0) {
            continue;
        }

        /* Run BPP algorithm with pseudorandom bits */
        int vote = bpp_algo(input, pseudorand);
        if (vote) yes_votes++;
        else no_votes++;
        total_trials++;
    }

    bitstring_free(seed);
    bitstring_free(pseudorand);

    if (total_trials == 0) return -1;

    /* Majority vote */
    *result = (yes_votes > no_votes) ? 1 : 0;
    return 0;
}
