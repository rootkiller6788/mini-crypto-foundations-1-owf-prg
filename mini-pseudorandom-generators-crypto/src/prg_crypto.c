/*
 * prg_crypto.c -- Cryptographic Pseudorandom Generator Implementations
 *
 * L1-L2: Implements PRG definitions, computational indistinguishability,
 *        statistical distance, security game, and next-bit unpredictability.
 *
 * Reference: Goldreich (2008), Arora-Barak (2009), Katz-Lindell (2015)
 * Courses: MIT 6.875, Stanford CS255, Berkeley CS276, Princeton COS 551
 */

#include "prg_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

/* ================================================================
 * PRG Base Implementation
 * ================================================================ */

PRG* prg_create(size_t seed_bits, size_t output_bits) {
    if (seed_bits == 0 || seed_bits > PRG_MAX_SEED_BITS) return NULL;
    if (output_bits == 0 || output_bits > PRG_MAX_OUTPUT_BITS) return NULL;
    if (output_bits <= seed_bits) return NULL; /* no expansion = not a PRG */

    PRG* prg = (PRG*)calloc(1, sizeof(PRG));
    if (!prg) return NULL;

    prg->params.seed_bits = seed_bits;
    prg->params.output_bits = output_bits;
    prg->params.stretch_bits = output_bits - seed_bits;
    prg->state_len = 0;
    prg->bits_produced = 0;
    prg->init = NULL;
    prg->next = NULL;
    prg->free_ctx = NULL;
    prg->priv = NULL;

    return prg;
}

int prg_init(PRG* prg, const uint8_t* seed, size_t seed_bytes) {
    if (!prg || !seed) return -1;
    if (seed_bytes < PRG_BYTES(prg->params.seed_bits)) return -1;

    if (prg->init) {
        return prg->init(prg, seed, seed_bytes);
    }

    /* Default: copy seed into state */
    size_t bytes_needed = PRG_BYTES(prg->params.seed_bits);
    memset(prg->state, 0, sizeof(prg->state));
    memcpy(prg->state, seed, bytes_needed);
    prg->state_len = bytes_needed;
    prg->bits_produced = 0;
    return 0;
}

int prg_generate(PRG* prg, uint8_t* output, size_t output_bytes) {
    if (!prg || !output) return -1;
    if (prg->bits_produced >= prg->params.output_bits) return -1;

    if (prg->next) {
        return prg->next(prg, output, output_bytes);
    }

    /* Default: copy state directly (generic fallback for PRG interface) */
    size_t copy_bytes = output_bytes;
    if (copy_bytes > prg->state_len) copy_bytes = prg->state_len;
    memcpy(output, prg->state, copy_bytes);
    prg->bits_produced += copy_bytes * 8;
    return (int)copy_bytes;
}

int prg_fill(PRG* prg, uint8_t* buffer, size_t buffer_bytes) {
    if (!prg || !buffer) return -1;

    size_t remaining = buffer_bytes;
    size_t offset = 0;

    while (remaining > 0) {
        size_t chunk = remaining;
        if (chunk > 256) chunk = 256; /* generate in chunks */
        int generated = prg_generate(prg, buffer + offset, chunk);
        if (generated < 0) return -1;
        if (generated == 0) break;
        offset += (size_t)generated;
        remaining -= (size_t)generated;
    }

    return (int)offset;
}

void prg_free(PRG* prg) {
    if (!prg) return;
    if (prg->free_ctx) {
        prg->free_ctx(prg);
    }
    if (prg->priv) {
        free(prg->priv);
    }
    memset(prg, 0, sizeof(PRG));
    free(prg);
}

/* ================================================================
 * Statistical Distance
 * ================================================================ */

double stat_distance(const DistributionPair* dp) {
    if (!dp || !dp->probs_a || !dp->probs_b || dp->domain_size == 0) {
        return 0.0;
    }

    double sum = 0.0;
    for (size_t i = 0; i < dp->domain_size; i++) {
        sum += fabs(dp->probs_a[i] - dp->probs_b[i]);
    }
    return 0.5 * sum;
}

double max_advantage_from_distance(double stat_dist) {
    /* For any event E: |P(E) - Q(E)| ? ?(P,Q) */
    return stat_dist;
}

/* ================================================================
 * Distinguisher Implementation
 * ================================================================ */

void distinguisher_init(Distinguisher* d, size_t input_bits) {
    if (!d) return;
    d->input_bits = input_bits;
    d->queries = 0;
    d->advantage_log = (double*)calloc(1024, sizeof(double));
    d->cumulative_advantage = 0.0;
}

void distinguisher_record_guess(Distinguisher* d, int guess, int actual) {
    if (!d) return;
    d->queries++;
    double outcome = (guess == actual) ? 1.0 : 0.0;

    /* Update cumulative advantage using exponential moving average */
    double alpha = 0.01; /* smoothing factor */
    d->cumulative_advantage = alpha * outcome + (1.0 - alpha) * d->cumulative_advantage;

    if (d->advantage_log && d->queries < 1024) {
        d->advantage_log[d->queries - 1] = 2.0 * d->cumulative_advantage - 1.0;
    }
}

double distinguisher_advantage(const Distinguisher* d) {
    if (!d || d->queries == 0) return 0.0;
    /* Advantage = 2 * accuracy - 1 (for balanced game) */
    return 2.0 * d->cumulative_advantage - 1.0;
}

void distinguisher_reset(Distinguisher* d) {
    if (!d) return;
    d->queries = 0;
    d->cumulative_advantage = 0.0;
    if (d->advantage_log) {
        memset(d->advantage_log, 0, 1024 * sizeof(double));
    }
}

/* ================================================================
 * PRG Security Game
 * ================================================================ */

void prg_security_game_init(PRGSecurityGame* game, size_t n, size_t l) {
    if (!game) return;
    game->n = n;
    game->l = l;
    game->trials = 0;
    game->successes_given_prg = 0;
    game->total_prg_trials = 0;
    game->successes_given_random = 0;
    game->total_random_trials = 0;
    game->estimated_advantage = 0.0;
}

int prg_security_game_trial(PRGSecurityGame* game, const uint8_t* sample,
                            int distinguisher_guess, int is_prg_output) {
    if (!game || !sample) return 0;

    game->trials++;

    if (is_prg_output) {
        game->total_prg_trials++;
        if (distinguisher_guess == 1) {
            game->successes_given_prg++;
        }
    } else {
        game->total_random_trials++;
        if (distinguisher_guess == 1) {
            game->successes_given_random++;
        }
    }

    /* Update estimated advantage */
    if (game->total_prg_trials > 0 && game->total_random_trials > 0) {
        double prg_rate = (double)game->successes_given_prg / (double)game->total_prg_trials;
        double random_rate = (double)game->successes_given_random / (double)game->total_random_trials;
        game->estimated_advantage = fabs(prg_rate - random_rate);
    }

    return 1;
}

double prg_security_game_advantage(const PRGSecurityGame* game) {
    if (!game) return 0.0;
    return game->estimated_advantage;
}

int prg_advantage_is_negligible(double advantage, size_t n, double poly_degree) {
    /* Check if advantage < 1/n^poly_degree (negligibility test) */
    if (advantage <= 0.0) return 1;
    if (n == 0) return 0;

    double threshold = 1.0 / pow((double)n, poly_degree);
    return advantage < threshold ? 1 : 0;
}

/* ================================================================
 * Next-bit Unpredictability
 * ================================================================ */

void nbp_init(NextBitPredictor* nbp, size_t n, size_t l, size_t position) {
    if (!nbp) return;
    nbp->seed_bits = n;
    nbp->output_bits = l;
    nbp->position = position;
    nbp->base_rate = 0.5;
    nbp->correct_guesses = 0;
    nbp->total_guesses = 0;
    nbp->observed_advantage = 0.0;
}

void nbp_record(NextBitPredictor* nbp, int prediction, int actual_bit) {
    if (!nbp) return;
    nbp->total_guesses++;
    if (prediction == actual_bit) {
        nbp->correct_guesses++;
    }
    double success_rate = (double)nbp->correct_guesses / (double)nbp->total_guesses;
    nbp->observed_advantage = success_rate - nbp->base_rate;
}

double nbp_advantage(const NextBitPredictor* nbp) {
    if (!nbp || nbp->total_guesses == 0) return 0.0;
    return nbp->observed_advantage;
}

/* ================================================================
 * Bit/Byte Utilities
 * ================================================================ */

void bytes_to_bits(const uint8_t* bytes, size_t byte_len,
                   int* bits, size_t bit_len) {
    if (!bytes || !bits) return;
    for (size_t i = 0; i < bit_len; i++) {
        size_t byte_idx = i / 8;
        size_t bit_idx = i % 8;
        if (byte_idx < byte_len) {
            bits[i] = (bytes[byte_idx] >> (7 - bit_idx)) & 1;
        } else {
            bits[i] = 0;
        }
    }
}

void bits_to_bytes(const int* bits, size_t bit_len,
                   uint8_t* bytes, size_t byte_capacity) {
    if (!bits || !bytes) return;
    size_t min_bytes = (bit_len + 7) / 8;
    if (byte_capacity < min_bytes) return;

    memset(bytes, 0, byte_capacity);
    for (size_t i = 0; i < bit_len; i++) {
        size_t byte_idx = i / 8;
        size_t bit_idx = i % 8;
        if (bits[i]) {
            bytes[byte_idx] |= (uint8_t)(1U << (7 - bit_idx));
        }
    }
}

void xor_bytes(uint8_t* dst, const uint8_t* a, const uint8_t* b, size_t len) {
    if (!dst || !a || !b) return;
    for (size_t i = 0; i < len; i++) {
        dst[i] = a[i] ^ b[i];
    }
}

int ct_memcmp(const uint8_t* a, const uint8_t* b, size_t len) {
    /* Constant-time memory comparison: resistant to timing attacks */
    if (!a || !b) return (a == b) ? 0 : 1;
    int result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= (int)(a[i] ^ b[i]);
    }
    return result; /* 0 if equal, nonzero otherwise */
}

/* ================================================================
 * Randomness Utilities (for simulation/testing)
 * ================================================================ */

/* Simple PRNG for generating test seeds (NOT cryptographically secure) */
static uint64_t simple_prng_state = 0;

void prg_test_srand(uint64_t seed) {
    simple_prng_state = seed;
}

uint64_t prg_test_rand(void) {
    /* Xorshift64* generator ? fast, good statistics, not crypto-secure */
    simple_prng_state ^= simple_prng_state >> 12;
    simple_prng_state ^= simple_prng_state << 25;
    simple_prng_state ^= simple_prng_state >> 27;
    return simple_prng_state * 0x2545F4914F6CDD1DULL;
}

void prg_fill_random(uint8_t* buffer, size_t n_bytes) {
    if (!buffer) return;
    for (size_t i = 0; i < n_bytes; i++) {
        if (i % 8 == 0) {
            uint64_t r = prg_test_rand();
            for (int j = 0; j < 8 && (i + j) < n_bytes; j++) {
                buffer[i + j] = (uint8_t)(r >> (j * 8));
            }
        }
    }
}

int prg_random_bit(void) {
    return (int)(prg_test_rand() & 1);
}
