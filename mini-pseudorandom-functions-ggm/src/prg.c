/*
 * prg.c - Pseudorandom Generator Implementations
 *
 * Implements:
 *   L1: PRG definition as struct with evaluate function
 *   L3: BitString operations (GF(2) strings)
 *   L5: Toy PRG (hash-based), AES-CTR PRG
 *   Statistical tests: monobit, runs, serial, poker, NIST-lite battery
 *
 * Reference: Blum-Micali (1984), Yao (1982), NIST SP 800-22
 */

#include "prg.h"
#include "crypto_utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <assert.h>

/* ================================================================
 * BitString Implementation
 * ================================================================ */

/*
 * BitString: bits stored packed, 8 per byte, MSB-first within byte.
 * For n bits, we need ceil(n/8) bytes.
 */
static int bytes_for_bits(int n_bits) {
    return (n_bits + 7) / 8;
}

BitString* bs_create(int length) {
    BitString* bs = (BitString*)malloc(sizeof(BitString));
    if (!bs) return NULL;
    bs->length = length;
    bs->capacity = bytes_for_bits(length);
    bs->bits = (uint8_t*)calloc((size_t)bs->capacity, 1);
    if (!bs->bits) { free(bs); return NULL; }
    return bs;
}

BitString* bs_create_random(int length, uint64_t seed) {
    BitString* bs = bs_create(length);
    if (!bs) return NULL;
    CryptoRNG* rng = crypto_rng_create(seed);
    if (!rng) { bs_free(bs); return NULL; }
    crypto_rng_fill(rng, bs->bits, (size_t)bs->capacity);
    /* Mask unused bits in last byte */
    int extra = bs->capacity * 8 - length;
    if (extra > 0) {
        bs->bits[bs->capacity - 1] &= (uint8_t)(0xFF >> extra);
    }
    crypto_rng_free(rng);
    return bs;
}

BitString* bs_create_zeros(int length) {
    return bs_create(length);
}

BitString* bs_clone(const BitString* src) {
    if (!src) return NULL;
    BitString* dst = bs_create(src->length);
    if (!dst) return NULL;
    memcpy(dst->bits, src->bits, (size_t)dst->capacity);
    return dst;
}

void bs_free(BitString* bs) {
    if (bs) {
        free(bs->bits);
        free(bs);
    }
}

int bs_get_bit(const BitString* bs, int pos) {
    if (!bs || pos < 0 || pos >= bs->length) return -1;
    int byte_idx = pos / 8;
    int bit_idx  = 7 - (pos % 8);  /* MSB-first */
    return (bs->bits[byte_idx] >> bit_idx) & 1;
}

void bs_set_bit(BitString* bs, int pos, int value) {
    if (!bs || pos < 0 || pos >= bs->length) return;
    int byte_idx = pos / 8;
    int bit_idx  = 7 - (pos % 8);
    if (value) {
        bs->bits[byte_idx] |= (uint8_t)(1 << bit_idx);
    } else {
        bs->bits[byte_idx] &= (uint8_t)(~(1 << bit_idx));
    }
}

int bs_equal(const BitString* a, const BitString* b) {
    if (!a || !b) return (a == b) ? 1 : 0;
    if (a->length != b->length) return 0;
    /* Compare full bytes then masked last byte */
    int full_bytes = a->length / 8;
    if (full_bytes > 0) {
        if (memcmp(a->bits, b->bits, (size_t)full_bytes) != 0)
            return 0;
    }
    int rem = a->length % 8;
    if (rem > 0) {
        uint8_t mask = (uint8_t)(0xFF << (8 - rem));
        if ((a->bits[full_bytes] & mask) != (b->bits[full_bytes] & mask))
            return 0;
    }
    return 1;
}

int bs_compare(const BitString* a, const BitString* b) {
    if (!a || !b) return 0;
    int cmp_len = (a->length < b->length) ? a->length : b->length;
    for (int i = 0; i < cmp_len; i++) {
        int ba = bs_get_bit(a, i);
        int bb = bs_get_bit(b, i);
        if (ba != bb) return ba - bb;
    }
    return a->length - b->length;
}

void bs_print(const BitString* bs) {
    if (!bs) { printf("(null)\n"); return; }
    printf("BitString(len=%d): ", bs->length);
    for (int i = 0; i < bs->length && i < 128; i++) {
        printf("%d", bs_get_bit(bs, i));
    }
    if (bs->length > 128) printf("...");
    printf("\n");
}

void bs_print_bits(const BitString* bs) {
    if (!bs) return;
    crypto_print_hex(NULL, bs->bits, bs->capacity);
}

void bs_copy_bits_to(const BitString* src, BitString* dst, int offset) {
    if (!src || !dst) return;
    for (int i = 0; i < src->length && (offset + i) < dst->length; i++) {
        bs_set_bit(dst, offset + i, bs_get_bit(src, i));
    }
}

BitString* bs_concat(const BitString* a, const BitString* b) {
    if (!a && !b) return NULL;
    if (!a) return bs_clone(b);
    if (!b) return bs_clone(a);
    int total = a->length + b->length;
    BitString* result = bs_create(total);
    if (!result) return NULL;
    bs_copy_bits_to(a, result, 0);
    bs_copy_bits_to(b, result, a->length);
    return result;
}

BitString* bs_prefix(const BitString* src, int n_bits) {
    if (!src || n_bits < 0) return NULL;
    if (n_bits > src->length) n_bits = src->length;
    BitString* pref = bs_create(n_bits);
    if (!pref) return NULL;
    for (int i = 0; i < n_bits; i++) {
        bs_set_bit(pref, i, bs_get_bit(src, i));
    }
    return pref;
}

BitString* bs_suffix(const BitString* src, int n_bits) {
    if (!src || n_bits < 0) return NULL;
    if (n_bits > src->length) n_bits = src->length;
    int start = src->length - n_bits;
    BitString* suff = bs_create(n_bits);
    if (!suff) return NULL;
    for (int i = 0; i < n_bits; i++) {
        bs_set_bit(suff, i, bs_get_bit(src, start + i));
    }
    return suff;
}

void bs_split(const BitString* src, BitString** left, BitString** right) {
    if (!src || !left || !right) return;
    int half = src->length / 2;
    *left  = bs_prefix(src, half);
    *right = bs_suffix(src, src->length - half);
}

/* ================================================================
 * PRG Lifecycle
 * ================================================================ */

PRG* prg_create_length_doubling(int seed_len) {
    PRG* prg = (PRG*)calloc(1, sizeof(PRG));
    if (!prg) return NULL;
    prg->seed_len   = seed_len;
    prg->output_len = 2 * seed_len;
    prg->stretch    = seed_len;
    prg->is_length_doubling = 1;
    return prg;
}

PRG* prg_create_general(int seed_len, int output_len) {
    if (output_len <= seed_len) return NULL;
    PRG* prg = (PRG*)calloc(1, sizeof(PRG));
    if (!prg) return NULL;
    prg->seed_len = seed_len;
    prg->output_len = output_len;
    prg->stretch = output_len - seed_len;
    prg->is_length_doubling = (output_len == 2 * seed_len);
    return prg;
}

void prg_free(PRG* prg) {
    if (prg) {
        if (prg->state) free(prg->state);
        free(prg);
    }
}

BitString* prg_evaluate(const PRG* prg, const BitString* seed) {
    if (!prg || !seed) return NULL;
    if (seed->length != prg->seed_len) return NULL;
    if (!prg->evaluate) return NULL;
    return prg->evaluate(prg, seed);
}

int prg_is_expanding(const PRG* prg) {
    return (prg && prg->output_len > prg->seed_len) ? 1 : 0;
}

/* ================================================================
 * Length-doubling PRG Helpers for GGM
 * ================================================================ */

BitString* prg_evaluate_left(const PRG* prg, const BitString* seed) {
    BitString* full = prg_evaluate(prg, seed);
    if (!full) return NULL;
    int half = full->length / 2;
    BitString* left = bs_prefix(full, half);
    bs_free(full);
    return left;
}

BitString* prg_evaluate_right(const PRG* prg, const BitString* seed) {
    BitString* full = prg_evaluate(prg, seed);
    if (!full) return NULL;
    int half = full->length / 2;
    BitString* right = bs_suffix(full, full->length - half);
    bs_free(full);
    return right;
}

BitString* prg_sequential_eval(const PRG* prg,
                                const BitString* seed,
                                const BitString* input_bits) {
    if (!prg || !seed || !input_bits) return NULL;
    if (seed->length != prg->seed_len) return NULL;
    if (!prg->is_length_doubling) return NULL;

    /* Traverse tree path */
    BitString* current = bs_clone(seed);
    if (!current) return NULL;

    for (int i = 0; i < input_bits->length; i++) {
        int bit = bs_get_bit(input_bits, i);
        BitString* child;
        if (bit == 0) {
            child = prg_evaluate_left(prg, current);
        } else {
            child = prg_evaluate_right(prg, current);
        }
        bs_free(current);
        if (!child) return NULL;
        current = child;
    }

    return current;
}

/* ================================================================
 * Toy PRG Implementation (Hash-based)
 * ================================================================ */

/*
 * Toy PRG using iterated hash:
 *   G(s) = H(s || 0x00) || H(s || 0x01) || ... || H(s || 0x0k)
 *
 * For length-doubling with n-bit seed, pad to byte boundary.
 *
 * Security: NOT cryptographically secure. This is a DEMONSTRATION.
 * The construction is the standard "PRG from PRF/OWF" pattern.
 */

typedef struct {
    int seed_len;
    int seed_bytes;
    int out_blocks;  /* number of hash output blocks needed */
} ToyPRGState;

static BitString* toy_prg_evaluate(const PRG* prg, const BitString* seed) {
    ToyPRGState* state = (ToyPRGState*)prg->state;
    (void)state;

    int seed_bytes = bytes_for_bits(seed->length);
    uint8_t* seed_buf = (uint8_t*)calloc((size_t)seed_bytes, 1);
    if (!seed_buf) return NULL;
    memcpy(seed_buf, seed->bits, (size_t)seed_bytes);

    /* Count hash output blocks needed */
    int hash_bytes = CRYPTO_HASH_OUTPUT_SIZE;
    int blocks_needed = (prg->output_len + hash_bytes * 8 - 1) / (hash_bytes * 8);

    BitString* output = bs_create_zeros(prg->output_len);
    if (!output) { free(seed_buf); return NULL; }

    for (int block = 0; block < blocks_needed; block++) {
        /* Build input: seed || counter */
        int input_len = seed_bytes + 4;
        uint8_t* input = (uint8_t*)calloc((size_t)input_len, 1);
        if (!input) { bs_free(output); free(seed_buf); return NULL; }
        memcpy(input, seed_buf, (size_t)seed_bytes);
        input[seed_bytes]     = (uint8_t)((block >> 24) & 0xFF);
        input[seed_bytes + 1] = (uint8_t)((block >> 16) & 0xFF);
        input[seed_bytes + 2] = (uint8_t)((block >> 8) & 0xFF);
        input[seed_bytes + 3] = (uint8_t)(block & 0xFF);

        uint8_t digest[CRYPTO_HASH_OUTPUT_SIZE];
        crypto_hash_oneshot(input, (size_t)input_len, digest);

        /* Copy digest bits into output */
        int bit_offset = block * hash_bytes * 8;
        for (int b = 0; b < hash_bytes * 8; b++) {
            int out_pos = bit_offset + b;
            if (out_pos >= output->length) break;
            int byte_idx = b / 8;
            int bit_idx  = 7 - (b % 8);
            int bit_val = (digest[byte_idx] >> bit_idx) & 1;
            bs_set_bit(output, out_pos, bit_val);
        }
        free(input);
    }

    free(seed_buf);
    return output;
}

PRG* prg_create_toy_length_doubling(int seed_len) {
    PRG* prg = prg_create_length_doubling(seed_len);
    if (!prg) return NULL;

    ToyPRGState* state = (ToyPRGState*)malloc(sizeof(ToyPRGState));
    if (!state) { prg_free(prg); return NULL; }
    state->seed_len = seed_len;
    state->seed_bytes = bytes_for_bits(seed_len);
    state->out_blocks = (prg->output_len + CRYPTO_HASH_OUTPUT_SIZE * 8 - 1)
                        / (CRYPTO_HASH_OUTPUT_SIZE * 8);

    prg->state = state;
    prg->evaluate = toy_prg_evaluate;
    return prg;
}

/* ================================================================
 * AES-CTR-based PRG (Toy Implementation)
 * ================================================================ */

/*
 * G(k) = AES_k(0) || AES_k(1) for length-doubling.
 * For simplicity, pad/truncate seed to 128 bits for the toy cipher.
 */

typedef struct {
    int key_bytes;
} AESCTRPRGState;

static BitString* aes_ctr_prg_evaluate(const PRG* prg, const BitString* seed) {
    AESCTRPRGState* state = (AESCTRPRGState*)prg->state;

    /* Pad or truncate seed to key size */
    uint8_t key[CRYPTO_CIPHER_KEY_BYTES] = {0};
    int seed_bytes = bytes_for_bits(seed->length);
    int copy_bytes = (seed_bytes < CRYPTO_CIPHER_KEY_BYTES)
                     ? seed_bytes : CRYPTO_CIPHER_KEY_BYTES;
    memcpy(key, seed->bits, (size_t)copy_bytes);
    (void)state;

    ToyCipher* tc = toy_cipher_create(key, CRYPTO_CIPHER_KEY_BYTES);
    if (!tc) return NULL;

    /* Generate keystream: encrypt counter blocks */
    int out_bytes = bytes_for_bits(prg->output_len);
    uint8_t* out_buf = (uint8_t*)calloc((size_t)out_bytes, 1);
    if (!out_buf) { toy_cipher_free(tc); return NULL; }

    int blocks_needed = (out_bytes + CRYPTO_CIPHER_BLOCK_BYTES - 1)
                         / CRYPTO_CIPHER_BLOCK_BYTES;
    for (int i = 0; i < blocks_needed; i++) {
        uint8_t counter[CRYPTO_CIPHER_BLOCK_BYTES] = {0};
        counter[CRYPTO_CIPHER_BLOCK_BYTES - 4] = (uint8_t)((i >> 24) & 0xFF);
        counter[CRYPTO_CIPHER_BLOCK_BYTES - 3] = (uint8_t)((i >> 16) & 0xFF);
        counter[CRYPTO_CIPHER_BLOCK_BYTES - 2] = (uint8_t)((i >> 8) & 0xFF);
        counter[CRYPTO_CIPHER_BLOCK_BYTES - 1] = (uint8_t)(i & 0xFF);

        uint8_t enc_block[CRYPTO_CIPHER_BLOCK_BYTES];
        toy_cipher_encrypt_block(tc, counter, enc_block);

        int copy = CRYPTO_CIPHER_BLOCK_BYTES;
        if (i * CRYPTO_CIPHER_BLOCK_BYTES + copy > out_bytes)
            copy = out_bytes - i * CRYPTO_CIPHER_BLOCK_BYTES;
        memcpy(out_buf + i * CRYPTO_CIPHER_BLOCK_BYTES, enc_block, (size_t)copy);
    }

    /* Convert byte buffer to BitString */
    BitString* output = bs_create(prg->output_len);
    if (!output) { free(out_buf); toy_cipher_free(tc); return NULL; }
    for (int i = 0; i < out_bytes && i < output->capacity; i++) {
        output->bits[i] = out_buf[i];
    }
    /* Mask last byte */
    int extra = output->capacity * 8 - output->length;
    if (extra > 0) {
        output->bits[output->capacity - 1] &= (uint8_t)(0xFF >> extra);
    }

    free(out_buf);
    toy_cipher_free(tc);
    return output;
}

PRG* prg_create_aes_ctr_prg(int seed_len) {
    PRG* prg = prg_create_length_doubling(seed_len);
    if (!prg) return NULL;

    AESCTRPRGState* state = (AESCTRPRGState*)malloc(sizeof(AESCTRPRGState));
    if (!state) { prg_free(prg); return NULL; }
    state->key_bytes = bytes_for_bits(seed_len);

    prg->state = state;
    prg->evaluate = aes_ctr_prg_evaluate;
    return prg;
}

/* ================================================================
 * PRG Advantage Measurement
 * ================================================================ */

PRGAdvantage prg_measure_advantage(const PRG* prg,
                                   int (*distinguisher)(const BitString*),
                                   int num_trials) {
    PRGAdvantage result = {0.0, 0, 0};
    if (!prg || !distinguisher || num_trials <= 0) return result;

    result.seed_length = prg->seed_len;
    result.num_trials  = num_trials;
    int real_correct = 0;
    int rand_correct = 0;

    CryptoRNG* rng = crypto_rng_create(42); /* fixed seed for reproducibility */
    if (!rng) return result;

    for (int t = 0; t < num_trials; t++) {
        /* Real: generate PRG output */
        BitString* seed = bs_create_random(prg->seed_len, crypto_rng_next(rng));
        if (!seed) continue;
        BitString* prg_out = prg_evaluate(prg, seed);
        bs_free(seed);
        if (!prg_out) continue;

        int coin = (int)(crypto_rng_next(rng) & 1);
        BitString* sample;

        if (coin == 0) {
            /* Give PRG output */
            sample = prg_out;
            if (distinguisher(sample) == 1) real_correct++;
            bs_free(sample);
        } else {
            /* Give truly random string */
            BitString* random_str = bs_create_random(prg->output_len,
                                                      crypto_rng_next(rng));
            if (!random_str) { bs_free(prg_out); continue; }
            sample = random_str;
            if (distinguisher(sample) == 0) rand_correct++;
            bs_free(sample);
        }
    }

    crypto_rng_free(rng);

    int total_real = num_trials / 2 + num_trials % 2;
    int total_rand = num_trials / 2;
    double prob_real = (total_real > 0) ? (double)real_correct / total_real : 0.0;
    double prob_rand = (total_rand > 0) ? (double)rand_correct / total_rand : 0.0;
    result.advantage = fabs(prob_real - prob_rand);

    return result;
}

/* ================================================================
 * Statistical Tests (NIST SP 800-22 style)
 * ================================================================ */

/*
 * Monobit Test (Frequency Test):
 *   H0: proportion of 1's = 0.5
 *   Test statistic: S = sum(2*b_i - 1) / sqrt(n)
 *   p-value: erfc(|S|/sqrt(2))
 *
 * This tests the most basic property of randomness.
 */
double prg_statistical_monobit(const BitString* output) {
    if (!output || output->length == 0) return 0.0;
    int n = output->length;
    double sum = 0.0;
    for (int i = 0; i < n; i++) {
        sum += 2.0 * bs_get_bit(output, i) - 1.0;
    }
    double s = sum / sqrt((double)n);
    double p_value = erfc(fabs(s) / sqrt(2.0));
    return p_value;
}

/*
 * Runs Test:
 *   A run is a maximal sequence of consecutive identical bits.
 *   H0: number of runs follows expected distribution.
 *   p-value: erfc(|V_n(obs) - V_n(exp)| / (2*sigma*sqrt(n)))
 *   where V_n(obs) = #runs, V_n(exp) = 2n*pi*(1-pi) + 1
 */
double prg_statistical_runs(const BitString* output) {
    if (!output || output->length < 2) return 0.0;
    int n = output->length;

    /* Count ones for pi */
    int ones = 0;
    for (int i = 0; i < n; i++) {
        if (bs_get_bit(output, i)) ones++;
    }
    double pi = (double)ones / n;

    /* Check pre-requisite: |pi - 0.5| < 2/sqrt(n) */
    if (fabs(pi - 0.5) >= 2.0 / sqrt((double)n)) {
        return 0.0; /* test not applicable */
    }

    /* Count runs */
    int v_obs = 1;
    for (int i = 1; i < n; i++) {
        if (bs_get_bit(output, i) != bs_get_bit(output, i - 1))
            v_obs++;
    }

    /* Expected runs: V_n(exp) = 2*n*pi*(1-pi) + 1 */
    /* But for the standard runs test with pi = proportion of 1s:
     * Compute test statistic differently to match NIST formula */
    double num = fabs((double)v_obs - 2.0 * n * pi * (1.0 - pi));
    double den = 2.0 * sqrt(2.0 * n) * pi * (1.0 - pi);
    double p_value = (den > 0) ? erfc(num / den) : 0.0;
    return p_value;
}

/*
 * Serial Test (Two-bit):
 *   Tests the frequency of 00, 01, 10, 11 transitions.
 *   Uses chi-squared statistic with 3 degrees of freedom.
 */
double prg_statistical_serial(const BitString* output) {
    if (!output || output->length < 4) return 1.0;
    int n = output->length;

    /* Count pairs */
    int cnt[4] = {0, 0, 0, 0};
    for (int i = 0; i < n - 1; i++) {
        int pair = (bs_get_bit(output, i) << 1) | bs_get_bit(output, i + 1);
        cnt[pair]++;
    }

    double expected = (double)(n - 1) / 4.0;
    double chi2 = 0.0;
    for (int i = 0; i < 4; i++) {
        double diff = cnt[i] - expected;
        chi2 += diff * diff / expected;
    }

    /* Approximate p-value from chi-squared with 3 df */
    double p_value = 1.0;
    if (chi2 > 0) {
        /* Simple approximation: p = exp(-chi2/2) for large df */
        p_value = exp(-chi2 / 6.0); /* rough */
    }
    return p_value;
}

/*
 * Poker Test (Block Frequency):
 *   Divide sequence into m-bit blocks, check if each block
 *   value appears with roughly equal frequency.
 */
double prg_statistical_poker(const BitString* output, int block_size) {
    if (!output || block_size <= 0 || block_size > 8) return 0.0;
    int n = output->length;
    int m = block_size;
    int N = n / m; /* number of blocks */
    if (N < 5 * (1 << m)) return 0.0; /* need sufficient blocks */

    int num_patterns = 1 << m;
    int* counts = (int*)calloc((size_t)num_patterns, sizeof(int));
    if (!counts) return 0.0;

    for (int i = 0; i < N; i++) {
        int pattern = 0;
        for (int j = 0; j < m; j++) {
            pattern = (pattern << 1) | bs_get_bit(output, i * m + j);
        }
        counts[pattern]++;
    }

    /* Chi-squared: X = (2^m / N) * sum(n_i^2) - N */
    double sum_sq = 0.0;
    for (int i = 0; i < num_patterns; i++) {
        sum_sq += (double)counts[i] * counts[i];
    }
    double chi2 = (num_patterns / (double)N) * sum_sq - N;
    int df = num_patterns - 1;

    /* Approximate p-value */
    double p_value = (chi2 > 0 && df > 0) ? exp(-chi2 / (2.0 * df)) : 1.0;
    free(counts);
    return p_value;
}

/*
 * Full battery: Run all tests, return 1 if all pass.
 * Pass means p-value > alpha.
 */
int prg_statistical_battery(const BitString* output, double alpha) {
    if (!output) return 0;
    int passed = 1;
    double p;

    p = prg_statistical_monobit(output);
    if (p < alpha) { passed = 0; }

    p = prg_statistical_runs(output);
    if (p < alpha) { passed = 0; }

    p = prg_statistical_serial(output);
    if (p < alpha) { passed = 0; }

    p = prg_statistical_poker(output, 3);
    if (p < alpha) { passed = 0; }

    p = prg_statistical_poker(output, 4);
    if (p < alpha) { passed = 0; }

    return passed;
}
