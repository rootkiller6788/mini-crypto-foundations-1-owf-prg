/*
 * owf.c ? One-Way Function Implementations
 *
 * Implements:
 *   - BitString operations (L1, L3)
 *   - OWF creation/evaluation framework (L1)
 *   - OWF inversion experiment (L1)
 *   - RSA candidate OWF (L2, L6)
 *   - Discrete log candidate OWF (L2, L6)
 *   - Rabin candidate OWF (L2, L6)
 *   - Subset sum candidate OWF (L2, L6)
 *   - OWF iteration and composition (L2)
 *   - Weak?Strong OWF via Yao amplification (L2, L8)
 *
 * Each candidate OWF embodies a distinct mathematical assumption
 * believed to be hard on average. These are the foundational
 * primitives for all of modern cryptography.
 */

#include "owf.h"
#include "crypto_utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>

/* Forward declaration */
static void bitstring_clone_to(const BitString *src, BitString *dst);

/* ================================================================
 * L1/L3: BitString Implementation
 * ================================================================ */

BitString *bitstring_create(size_t bit_len) {
    BitString *bs = (BitString *)malloc(sizeof(BitString));
    if (!bs) return NULL;
    size_t byte_len = (bit_len + 7) / 8;
    bs->data = (uint8_t *)calloc(byte_len, 1);
    if (!bs->data) { free(bs); return NULL; }
    bs->bit_len = bit_len;
    return bs;
}

void bitstring_free(BitString *bs) {
    if (bs) {
        free(bs->data);
        free(bs);
    }
}

BitString *bitstring_clone(const BitString *bs) {
    if (!bs) return NULL;
    BitString *clone = bitstring_create(bs->bit_len);
    if (!clone) return NULL;
    size_t byte_len = (bs->bit_len + 7) / 8;
    memcpy(clone->data, bs->data, byte_len);
    return clone;
}

void bitstring_randomize(BitString *bs) {
    if (!bs) return;
    size_t byte_len = (bs->bit_len + 7) / 8;
    for (size_t i = 0; i < byte_len; i++) {
        bs->data[i] = (uint8_t)(rand() & 0xFF);
    }
    /* Zero out excess bits in the last byte */
    size_t extra = byte_len * 8 - bs->bit_len;
    if (extra > 0) {
        bs->data[byte_len - 1] &= (uint8_t)(0xFF >> extra);
    }
}

int bitstring_equal(const BitString *a, const BitString *b) {
    if (!a || !b) return 0;
    if (a->bit_len != b->bit_len) return 0;
    size_t byte_len = (a->bit_len + 7) / 8;
    return memcmp(a->data, b->data, byte_len) == 0;
}

void bitstring_print(const BitString *bs, const char *label) {
    if (!bs) return;
    if (label) printf("%s [%zu bits]: ", label, bs->bit_len);
    for (size_t i = 0; i < bs->bit_len; i++) {
        printf("%d", bitstring_get_bit(bs, i));
    }
    printf("\n");
}

int bitstring_to_uint64(const BitString *bs, uint64_t *out) {
    if (!bs || !out) return 0;
    if (bs->bit_len > 64) return 0;
    *out = 0;
    for (size_t i = 0; i < bs->bit_len; i++) {
        *out = (*out << 1) | (uint64_t)bitstring_get_bit(bs, i);
    }
    return 1;
}

int uint64_to_bitstring(uint64_t val, size_t bit_len, BitString *out) {
    if (!out || bit_len > 64) return 0;
    out->bit_len = bit_len;
    size_t byte_len = (bit_len + 7) / 8;
    memset(out->data, 0, byte_len);
    for (int i = (int)bit_len - 1; i >= 0; i--) {
        bitstring_set_bit(out, i, (int)(val & 1));
        val >>= 1;
    }
    return 1;
}

void bitstring_set_bit(BitString *bs, size_t pos, int value) {
    if (!bs || pos >= bs->bit_len) return;
    size_t byte_idx = pos / 8;
    int bit_idx = 7 - (int)(pos % 8);  /* MSB first within byte */
    if (value)
        bs->data[byte_idx] |= (1u << bit_idx);
    else
        bs->data[byte_idx] &= ~(1u << bit_idx);
}

int bitstring_get_bit(const BitString *bs, size_t pos) {
    if (!bs || pos >= bs->bit_len) return 0;
    size_t byte_idx = pos / 8;
    int bit_idx = 7 - (int)(pos % 8);
    return (bs->data[byte_idx] >> bit_idx) & 1;
}

/* ================================================================
 * L1: OWF Core Framework
 * ================================================================ */

OWF *owf_create(SecurityParam n, OWFEvalFunc eval, void *params, const char *name) {
    OWF *owf = (OWF *)malloc(sizeof(OWF));
    if (!owf) return NULL;
    owf->n = n;
    owf->eval = eval;
    owf->params = params;
    if (name) {
        strncpy(owf->name, name, 63);
        owf->name[63] = '\0';
    } else {
        owf->name[0] = '\0';
    }
    return owf;
}

void owf_free(OWF *owf) {
    if (owf) {
        free(owf->params);
        free(owf);
    }
}

int owf_eval(const OWF *owf, const BitString *x, BitString *y) {
    if (!owf || !owf->eval || !x || !y) return -1;
    return owf->eval(owf, x, y);
}

/* ================================================================
 * L1: OWF Inversion Experiment
 * ================================================================ */

OWFInversionResult owf_inversion_experiment(const OWF *owf, int n_trials,
                                            OWFAdversaryFunc adversary) {
    OWFInversionResult result = {0};
    if (!owf || !adversary || n_trials <= 0) return result;

    result.n_trials = n_trials;
    BitString *x = bitstring_create(owf->n);
    BitString *y = bitstring_create(owf->n);
    BitString *x_guess = bitstring_create(owf->n);

    for (int t = 0; t < n_trials; t++) {
        bitstring_randomize(x);
        owf_eval(owf, x, y);

        int found = adversary(owf, y, x_guess);
        if (found > 0 && owf_check_collision(owf, x, x_guess)) {
            result.n_successes++;
        }
    }

    result.success_probability = (double)result.n_successes / n_trials;
    bitstring_free(x);
    bitstring_free(y);
    bitstring_free(x_guess);
    return result;
}

/* ================================================================
 * L2: RSA Candidate OWF
 * ================================================================ */

/*
 * f_{N,e}(x) = x^e mod N
 * This is a OWF under the RSA assumption: computing e-th roots
 * modulo N is hard without knowing the factorization of N.
 */

void *rsa_params_create(uint64_t p, uint64_t q, uint64_t e) {
    RSAParams *params = (RSAParams *)malloc(sizeof(RSAParams));
    if (!params) return NULL;
    params->N = p * q;
    params->e = e;
    params->phi = (p - 1) * (q - 1);
    /* Secret key d = e^{-1} mod phi(N) */
    params->d = mod_inverse(e, params->phi);
    return params;
}

int rsa_owf_eval(const OWF *owf, const BitString *x, BitString *y) {
    if (!owf || !x || !y) return -1;
    RSAParams *p = (RSAParams *)owf->params;
    if (!p) return -1;

    uint64_t x_val;
    if (!bitstring_to_uint64(x, &x_val)) return -1;
    if (x_val >= p->N) x_val = x_val % p->N;  /* Wrap to domain */

    uint64_t y_val = mod_pow(x_val, p->e, p->N);
    return uint64_to_bitstring(y_val, owf->n, y) ? 0 : -1;
}

/* ================================================================
 * L2: Discrete Log Candidate OWF
 * ================================================================ */

/*
 * f_{p,g}(x) = g^x mod p
 * This is a OWF under the discrete logarithm assumption:
 * given g^x mod p, it is hard to find x.
 */

void *dlog_params_create(uint64_t p, uint64_t g) {
    DiscreteLogParams *params = (DiscreteLogParams *)malloc(sizeof(DiscreteLogParams));
    if (!params) return NULL;
    params->p = p;
    params->g = g;
    params->order = p - 1;
    return params;
}

int dlog_owf_eval(const OWF *owf, const BitString *x, BitString *y) {
    if (!owf || !x || !y) return -1;
    DiscreteLogParams *p = (DiscreteLogParams *)owf->params;
    if (!p) return -1;

    uint64_t x_val;
    if (!bitstring_to_uint64(x, &x_val)) return -1;
    x_val = x_val % p->order;  /* Exponent in [0, p-2] */

    uint64_t y_val = mod_pow(p->g, x_val, p->p);
    return uint64_to_bitstring(y_val, owf->n, y) ? 0 : -1;
}

/* ================================================================
 * L2: Rabin Squaring Candidate OWF
 * ================================================================ */

/*
 * f_N(x) = x^2 mod N where N = p?q, p,q ? 3 (mod 4)
 * Inverting is provably as hard as factoring N.
 * This is a stronger result than RSA: we have a reduction
 * from factoring to Rabin inversion (not known for RSA).
 */

void *rabin_params_create(uint64_t p, uint64_t q) {
    RabinParams *params = (RabinParams *)malloc(sizeof(RabinParams));
    if (!params) return NULL;
    params->N = p * q;
    params->p = p;
    params->q = q;
    return params;
}

int rabin_owf_eval(const OWF *owf, const BitString *x, BitString *y) {
    if (!owf || !x || !y) return -1;
    RabinParams *p = (RabinParams *)owf->params;
    if (!p) return -1;

    uint64_t x_val;
    if (!bitstring_to_uint64(x, &x_val)) return -1;
    if (x_val >= p->N) x_val = x_val % p->N;

    uint64_t y_val = mod_pow(x_val, 2, p->N);
    return uint64_to_bitstring(y_val, owf->n, y) ? 0 : -1;
}

/* ================================================================
 * L2: Subset Sum Candidate OWF
 * ================================================================ */

/*
 * f_{a_1,...,a_n}(x_1,...,x_n) = (sum_{i=1}^n x_i * a_i, x)
 * where a_i are random weights.
 *
 * The second part (x) is included to make the function length-preserving
 * for the standard OWF definition, while the first part provides
 * the one-wayness based on the hardness of random subset sum.
 *
 * Note: Impagliazzo-Naor (1996) showed subset sum is a OWF
 * under the assumption that random subset sum is hard.
 */

void *subsetsum_params_create(int n, const uint64_t *weights, uint64_t modulus) {
    SubsetSumParams *params = (SubsetSumParams *)malloc(sizeof(SubsetSumParams));
    if (!params) return NULL;
    params->n = n;
    params->modulus = modulus;
    params->a = (uint64_t *)malloc((size_t)n * sizeof(uint64_t));
    if (!params->a) { free(params); return NULL; }
    if (weights) {
        memcpy(params->a, weights, (size_t)n * sizeof(uint64_t));
    } else {
        /* Generate random weights for testing */
        for (int i = 0; i < n; i++) {
            params->a[i] = ((uint64_t)rand() << 32) | (uint64_t)rand();
            params->a[i] %= modulus;
        }
    }
    return params;
}

int subset_sum_owf_eval(const OWF *owf, const BitString *x, BitString *y) {
    if (!owf || !x || !y) return -1;
    SubsetSumParams *p = (SubsetSumParams *)owf->params;
    if (!p) return -1;

    uint64_t sum = 0;
    for (int i = 0; i < p->n; i++) {
        if (bitstring_get_bit(x, (size_t)i)) {
            sum = (sum + p->a[i]) % p->modulus;
        }
    }

    return uint64_to_bitstring(sum, owf->n, y) ? 0 : -1;
}

/* ================================================================
 * L2: OWF Properties ? Collision, Iteration, Composition
 * ================================================================ */

int owf_check_collision(const OWF *owf, const BitString *x1, const BitString *x2) {
    if (!owf || !x1 || !x2) return 0;

    BitString *y1 = bitstring_create(owf->n);
    BitString *y2 = bitstring_create(owf->n);

    if (owf_eval(owf, x1, y1) != 0 || owf_eval(owf, x2, y2) != 0) {
        bitstring_free(y1);
        bitstring_free(y2);
        return 0;
    }

    int eq = bitstring_equal(y1, y2);
    bitstring_free(y1);
    bitstring_free(y2);
    return eq;
}

int owf_iterate(const OWF *owf, const BitString *x, int k, BitString *y) {
    if (!owf || !x || !y || k < 0) return -1;

    BitString *temp = bitstring_create(owf->n);
    bitstring_clone_to(x, temp);

    for (int i = 0; i < k; i++) {
        if (owf_eval(owf, temp, y) != 0) {
            bitstring_free(temp);
            return -1;
        }
        bitstring_clone_to(y, temp);
    }

    bitstring_free(temp);
    return 0;
}

int owf_compose(const OWF *f, const OWF *g, const BitString *x, BitString *y) {
    if (!f || !g || !x || !y) return -1;

    BitString *gx = bitstring_create(g->n);
    if (owf_eval(g, x, gx) != 0) {
        bitstring_free(gx);
        return -1;
    }

    int ret = owf_eval(f, gx, y);
    bitstring_free(gx);
    return ret;
}

/* Helper: copy bitstring content — declared before use */
static void bitstring_clone_to(const BitString *src, BitString *dst) {
    if (!src || !dst) return;
    dst->bit_len = src->bit_len;
    size_t byte_len = (src->bit_len + 7) / 8;
    memcpy(dst->data, src->data, byte_len);
}

/* ================================================================
 * L2/L8: Weak ? Strong OWF (Yao's Amplification)
 * ================================================================ */

/*
 * Yao's Theorem (1982): If weak OWF exists, then strong OWF exists.
 *
 * Weak definition: exists poly p(n) s.t. every inverter fails
 * with prob >= 1/p(n). (non-negligible hardness)
 *
 * Strong definition: every inverter fails with negl(n) prob.
 *
 * Construction: f'(x1,...,x_q) = (f(x1), ..., f(x_q))
 * where q = n * p(n). Parallel repetition amplifies hardness
 * exponentially: success prob goes from 1-1/p to (1-1/p)^q ? e^{-n}.
 */

void *yao_amplify_params_create(OWF *base_owf, int n_copies) {
    YaoAmplification *amp = (YaoAmplification *)malloc(sizeof(YaoAmplification));
    if (!amp) return NULL;
    amp->base_owf = base_owf;
    amp->n_copies = n_copies;
    return amp;
}

int yao_amplify_owf_eval(const OWF *owf, const BitString *x, BitString *y) {
    if (!owf || !x || !y) return -1;
    YaoAmplification *amp = (YaoAmplification *)owf->params;
    if (!amp) return -1;

    int block_len = amp->base_owf->n;
    int total_len = block_len * amp->n_copies;
    if ((int)x->bit_len < total_len) return -1;

    y->bit_len = 0;
    BitString *xi = bitstring_create(block_len);
    BitString *yi = bitstring_create(block_len);

    for (int i = 0; i < amp->n_copies; i++) {
        /* Extract i-th block */
        for (int j = 0; j < block_len; j++) {
            bitstring_set_bit(xi, (size_t)j,
                bitstring_get_bit(x, (size_t)(i * block_len + j)));
        }
        xi->bit_len = block_len;

        owf_eval(amp->base_owf, xi, yi);
        yi->bit_len = block_len;

        /* Append yi to y */
        for (int j = 0; j < block_len; j++) {
            bitstring_set_bit(y, y->bit_len, bitstring_get_bit(yi, (size_t)j));
            y->bit_len++;
        }
    }

    bitstring_free(xi);
    bitstring_free(yi);
    return 0;
}
