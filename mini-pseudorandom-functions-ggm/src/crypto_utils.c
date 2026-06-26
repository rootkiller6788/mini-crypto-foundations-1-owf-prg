/*
 * crypto_utils.c - Cryptographic Utility Implementations
 *
 * Implements:
 *   L2: One-way function templates, hard-core predicate
 *   L3: Deterministic PRNG (LCG), GF(2) vector operations
 *   L5: Simplified Davies-Meyer hash, Toy Feistel cipher, CTR mode
 *   L5: Goldreich-Levin hard-core bit construction (OWF => PRG)
 *   L7: Hash-based PRG, AES-CTR-style PRG building blocks
 *
 * Reference:
 *   Goldreich Vol 1, section 2.4 (hard-core predicates)
 *   Katz-Lindell section 8.3 (hash functions)
 *   Galbraith "Mathematics of Public Key Cryptography" (2012)
 *   Menezes-vanOorschot-Vanstone Handbook of Applied Crypto (1996)
 */

#include "crypto_utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <assert.h>

/* ================================================================
 * Deterministic CryptoRNG (Linear Congruential Generator)
 *
 * For reproducibility only. NOT cryptographically secure.
 * Uses: X_{n+1} = (a * X_n + c) mod m
 * Parameters from Knuth (TAOCP Vol 2): a=6364136223846793005,
 *   c=1442695040888963407, m=2^64
 * ================================================================ */

CryptoRNG* crypto_rng_create(uint64_t seed) {
    CryptoRNG* rng = (CryptoRNG*)malloc(sizeof(CryptoRNG));
    if (!rng) return NULL;
    rng->state = seed;
    /* Knuth LCG parameters with good spectral properties */
    rng->a = 6364136223846793005ULL;
    rng->c = 1442695040888963407ULL;
    rng->m = 0; /* implicit 2^64 for uint64_t overflow */
    return rng;
}

void crypto_rng_free(CryptoRNG* rng) {
    free(rng);
}

uint64_t crypto_rng_next(CryptoRNG* rng) {
    if (!rng) return 0;
    rng->state = rng->a * rng->state + rng->c;
    return rng->state;
}

void crypto_rng_fill(CryptoRNG* rng, uint8_t* buf, size_t len) {
    if (!rng || !buf) return;
    for (size_t i = 0; i < len; i++) {
        uint64_t val = crypto_rng_next(rng);
        buf[i] = (uint8_t)(val & 0xFF);
    }
}

/* ================================================================
 * Simplified Davies-Meyer Hash Function
 *
 * Construction: H_i = E_{m_i}(H_{i-1}) XOR H_{i-1}
 * where E is a simple Feistel network block cipher.
 * This is the Davies-Meyer compression function from the
 * Merkle-Damgard construction (L3: Mathematical Structure).
 *
 * For pedagogy, we use XOR with counter as a toy round function.
 * Real Davies-Meyer uses a proper block cipher (e.g., AES).
 *
 * Reference: Winternitz (1984), Davies-Meyer (1985)
 *            Preneel-Govaerts-Vandewalle (1993)
 * ================================================================ */

/*
 * Toy round function for Davies-Meyer:
 *   f(state, message_block) = RotateLeft(state XOR message_block, 7) XOR state
 * This is NOT secure but demonstrates the structure.
 */
static void hash_compress_round(uint8_t* state, const uint8_t* block,
                                 int len, int round) {
    uint8_t tmp[CRYPTO_HASH_STATE_SIZE];
    memset(tmp, 0, CRYPTO_HASH_STATE_SIZE);

    for (int i = 0; i < len && i < CRYPTO_HASH_STATE_SIZE; i++) {
        /* XOR state, block, and round constant */
        uint8_t mix = state[i] ^ block[i] ^ (uint8_t)(round * 7 + i * 13);
        /* Rotate left by 3 bits within byte (toy nonlinearity) */
        uint8_t rotated = (uint8_t)((mix << 3) | (mix >> 5));
        /* Non-linear feedback: XOR with rotated version of state */
        tmp[i] = rotated ^ state[(i + 3) % CRYPTO_HASH_STATE_SIZE]
                        ^ (uint8_t)(state[(i + 7) % CRYPTO_HASH_STATE_SIZE] >> 1);
    }

    /* Davies-Meyer: H_i = compress(state, block_i) XOR H_{i-1} */
    for (int i = 0; i < CRYPTO_HASH_STATE_SIZE; i++) {
        state[i] ^= tmp[i];
    }
}

CryptoHash* crypto_hash_create(void) {
    CryptoHash* h = (CryptoHash*)calloc(1, sizeof(CryptoHash));
    if (!h) return NULL;

    /* Initialization Vector: simplified SHA-256 style constants.
     * First 16 bytes derived from fractional sqrt(2). */
    static const uint8_t iv[CRYPTO_HASH_STATE_SIZE] = {
        0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
        0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a
    };
    memcpy(h->state, iv, CRYPTO_HASH_STATE_SIZE);
    h->buf_used = 0;
    h->total_bits = 0;
    h->finalized = 0;
    return h;
}

void crypto_hash_update(CryptoHash* h, const uint8_t* data, size_t len) {
    if (!h || !data || h->finalized) return;

    h->total_bits += len * 8;

    for (size_t i = 0; i < len; i++) {
        h->buffer[h->buf_used] = data[i];
        h->buf_used++;

        if (h->buf_used >= CRYPTO_HASH_BLOCK_SIZE) {
            hash_compress_round(h->state, h->buffer,
                                CRYPTO_HASH_BLOCK_SIZE, 0);
            /* Additional rounds for better diffusion (toy) */
            for (int r = 1; r < 4; r++) {
                hash_compress_round(h->state, h->buffer,
                                    CRYPTO_HASH_BLOCK_SIZE, r);
            }
            h->buf_used = 0;
        }
    }
}

void crypto_hash_finalize(CryptoHash* h) {
    if (!h || h->finalized) return;

    /* Merkle-Damgard padding: append 0x80, then zeros, then length.
     * Standard MD-strengthening from Damgard (1989). */
    int pad_len = CRYPTO_HASH_BLOCK_SIZE - h->buf_used;
    uint8_t padding[CRYPTO_HASH_BLOCK_SIZE];
    memset(padding, 0, CRYPTO_HASH_BLOCK_SIZE);
    padding[0] = 0x80;

    if (pad_len < 8) {
        /* Need an extra block for length encoding */
        crypto_hash_update(h, padding, (size_t)pad_len);
        memset(padding, 0, CRYPTO_HASH_BLOCK_SIZE);
        pad_len = CRYPTO_HASH_BLOCK_SIZE;
    }

    /* Encode total bit length in last 8 bytes (big-endian) */
    pad_len -= 8;
    padding[pad_len + 0] = (uint8_t)((h->total_bits >> 56) & 0xFF);
    padding[pad_len + 1] = (uint8_t)((h->total_bits >> 48) & 0xFF);
    padding[pad_len + 2] = (uint8_t)((h->total_bits >> 40) & 0xFF);
    padding[pad_len + 3] = (uint8_t)((h->total_bits >> 32) & 0xFF);
    padding[pad_len + 4] = (uint8_t)((h->total_bits >> 24) & 0xFF);
    padding[pad_len + 5] = (uint8_t)((h->total_bits >> 16) & 0xFF);
    padding[pad_len + 6] = (uint8_t)((h->total_bits >> 8) & 0xFF);
    padding[pad_len + 7] = (uint8_t)(h->total_bits & 0xFF);

    crypto_hash_update(h, padding, (size_t)(pad_len + 8));

    /* Output digest = final state */
    memcpy(h->digest, h->state, CRYPTO_HASH_OUTPUT_SIZE);
    h->finalized = 1;
}

void crypto_hash_free(CryptoHash* h) {
    if (h) {
        crypto_secure_zero(h, sizeof(CryptoHash));
        free(h);
    }
}

const uint8_t* crypto_hash_digest(const CryptoHash* h) {
    if (!h || !h->finalized) return NULL;
    return h->digest;
}

int crypto_hash_output_bytes(const CryptoHash* h) {
    (void)h;
    return CRYPTO_HASH_OUTPUT_SIZE;
}

void crypto_hash_oneshot(const uint8_t* data, size_t len,
                          uint8_t* digest_out) {
    if (!data || !digest_out) return;
    CryptoHash* h = crypto_hash_create();
    if (!h) return;
    crypto_hash_update(h, data, len);
    crypto_hash_finalize(h);
    memcpy(digest_out, h->digest, CRYPTO_HASH_OUTPUT_SIZE);
    crypto_hash_free(h);
}

/* ================================================================
 * Toy Feistel Network Block Cipher
 *
 * Construction: A simplified Feistel network operating
 * on 128-bit blocks with a 128-bit key. The round function uses
 * byte-wise XOR and S-box-like substitution.
 *
 * This demonstrates the Feistel structure (L3):
 *   L_{i+1} = R_i
 *   R_{i+1} = L_i XOR F(R_i, K_i)
 *
 * The round function F is a toy; the overall cipher is NOT secure.
 *
 * Reference: Feistel (1973), DES (NBS 1977), Luby-Rackoff (1988)
 *   "How to Construct Pseudorandom Permutations from PRFs"
 * ================================================================ */

/* Toy S-box: 4-bit substitution (nibble-based), bijective */
static const uint8_t toy_sbox[16] = {
    0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
    0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7
};

static uint8_t sbox_substitute(uint8_t byte) {
    /* Apply 4-bit S-box to each nibble independently */
    uint8_t hi = toy_sbox[(byte >> 4) & 0xF];
    uint8_t lo = toy_sbox[byte & 0xF];
    return (uint8_t)((hi << 4) | lo);
}

static void feistel_round_function(const uint8_t* half_block,
                                    const uint8_t* round_key,
                                    uint8_t* output, int half_bytes) {
    for (int i = 0; i < half_bytes; i++) {
        /* XOR with round key byte, then S-box, then XOR with index */
        uint8_t x = half_block[i] ^ round_key[i];
        x = sbox_substitute(x);
        x ^= (uint8_t)(i * 17 + 31);
        /* Mix in another round key byte with wrap-around */
        x ^= round_key[(i + 3) % half_bytes];
        output[i] = x;
    }
}

static void feistel_round(uint8_t* left, uint8_t* right,
                           const uint8_t* round_key, int half_bytes) {
    uint8_t f_out[CRYPTO_CIPHER_BLOCK_BYTES / 2];
    feistel_round_function(right, round_key, f_out, half_bytes);

    /* new_left = R_i, new_right = L_i XOR F(R_i, K_i) */
    uint8_t new_left[CRYPTO_CIPHER_BLOCK_BYTES / 2];
    memcpy(new_left, right, (size_t)half_bytes);

    for (int i = 0; i < half_bytes; i++) {
        right[i] = left[i] ^ f_out[i];
    }

    memcpy(left, new_left, (size_t)half_bytes);
}

/* Key schedule: derive round keys by rotating and S-box mixing */
static void derive_round_keys(const uint8_t* key, int key_bytes,
                               uint8_t round_keys[][CRYPTO_CIPHER_BLOCK_BYTES],
                               int num_rounds) {
    uint8_t working[CRYPTO_CIPHER_BLOCK_BYTES];
    memset(working, 0, CRYPTO_CIPHER_BLOCK_BYTES);

    /* Expand key to fill block: XOR with rotation pattern */
    for (int i = 0; i < CRYPTO_CIPHER_BLOCK_BYTES; i++) {
        working[i] = key[i % key_bytes] ^ (uint8_t)(i * 71);
    }

    for (int r = 0; r <= num_rounds; r++) {
        memcpy(round_keys[r], working, CRYPTO_CIPHER_BLOCK_BYTES);

        /* Key schedule: rotate left by 5 bytes, XOR with round
         * constant, apply S-box substitution */
        for (int i = 0; i < CRYPTO_CIPHER_BLOCK_BYTES; i++) {
            uint8_t next = working[(i + 5) % CRYPTO_CIPHER_BLOCK_BYTES];
            working[i] = sbox_substitute((uint8_t)(next ^ (r * 43 + i)));
        }
    }
}

ToyCipher* toy_cipher_create(const uint8_t* key, int key_bytes) {
    if (!key || key_bytes <= 0) return NULL;

    ToyCipher* tc = (ToyCipher*)malloc(sizeof(ToyCipher));
    if (!tc) return NULL;

    tc->rounds = CRYPTO_CIPHER_ROUNDS;
    derive_round_keys(key, key_bytes, tc->round_keys, tc->rounds);
    return tc;
}

void toy_cipher_free(ToyCipher* tc) {
    if (tc) {
        crypto_secure_zero(tc, sizeof(ToyCipher));
        free(tc);
    }
}

void toy_cipher_encrypt_block(const ToyCipher* tc,
                               const uint8_t* plaintext,
                               uint8_t* ciphertext) {
    if (!tc || !plaintext || !ciphertext) return;

    int half = CRYPTO_CIPHER_BLOCK_BYTES / 2;
    uint8_t left[CRYPTO_CIPHER_BLOCK_BYTES / 2];
    uint8_t right[CRYPTO_CIPHER_BLOCK_BYTES / 2];

    /* Initial whitening with round key 0 */
    for (int i = 0; i < half; i++) {
        left[i]  = plaintext[i] ^ tc->round_keys[0][i];
        right[i] = plaintext[i + half] ^ tc->round_keys[0][i + half];
    }

    /* Feistel rounds */
    for (int r = 1; r <= tc->rounds; r++) {
        feistel_round(left, right, tc->round_keys[r], half);
    }

    /* Final whitening and concatenate */
    for (int i = 0; i < half; i++) {
        ciphertext[i]      = left[i] ^ tc->round_keys[tc->rounds][i];
        ciphertext[i + half] = right[i] ^ tc->round_keys[tc->rounds][i + half];
    }
}

void toy_cipher_decrypt_block(const ToyCipher* tc,
                               const uint8_t* ciphertext,
                               uint8_t* plaintext) {
    if (!tc || !ciphertext || !plaintext) return;

    int half = CRYPTO_CIPHER_BLOCK_BYTES / 2;
    uint8_t left[CRYPTO_CIPHER_BLOCK_BYTES / 2];
    uint8_t right[CRYPTO_CIPHER_BLOCK_BYTES / 2];

    /* Un-whiten with final round key */
    for (int i = 0; i < half; i++) {
        left[i]  = ciphertext[i] ^ tc->round_keys[tc->rounds][i];
        right[i] = ciphertext[i + half] ^ tc->round_keys[tc->rounds][i + half];
    }

    /* Inverse Feistel rounds (reverse order).
     * Feistel is self-inverse: same structure with reversed keys. */
    for (int r = tc->rounds; r >= 1; r--) {
        uint8_t f_out[CRYPTO_CIPHER_BLOCK_BYTES / 2];
        feistel_round_function(left, tc->round_keys[r], f_out, half);

        uint8_t prev_right[CRYPTO_CIPHER_BLOCK_BYTES / 2];
        memcpy(prev_right, left, (size_t)half);

        for (int i = 0; i < half; i++) {
            left[i] = right[i] ^ f_out[i];
        }
        memcpy(right, prev_right, (size_t)half);
    }

    /* Un-whiten with initial round key */
    for (int i = 0; i < half; i++) {
        plaintext[i]      = left[i] ^ tc->round_keys[0][i];
        plaintext[i + half] = right[i] ^ tc->round_keys[0][i + half];
    }
}

/* ================================================================
 * CTR Mode Stream Cipher (from Toy Cipher)
 *
 * CTR mode: encrypt successive counter values with block cipher
 * and XOR the resulting keystream with plaintext.
 * Key insight for PRG: CTR mode is a length-doubling PRG!
 *   G(k) = E_k(0) || E_k(1) || ... || E_k(t)
 *
 * Reference: Diffie-Hellman (1979), NIST SP 800-38A
 * ================================================================ */

ToyCTR* toy_ctr_create(const uint8_t* key, int key_bytes,
                        const uint8_t* nonce, int nonce_bytes) {
    if (!key || key_bytes <= 0) return NULL;

    ToyCTR* ctr = (ToyCTR*)malloc(sizeof(ToyCTR));
    if (!ctr) return NULL;

    ctr->cipher = toy_cipher_create(key, key_bytes);
    if (!ctr->cipher) { free(ctr); return NULL; }

    /* Initialize counter from nonce */
    memset(ctr->counter, 0, CRYPTO_CIPHER_BLOCK_BYTES);
    if (nonce && nonce_bytes > 0) {
        int copy = (nonce_bytes < CRYPTO_CIPHER_BLOCK_BYTES)
                   ? nonce_bytes : CRYPTO_CIPHER_BLOCK_BYTES;
        memcpy(ctr->counter, nonce, (size_t)copy);
    }

    /* Pre-generate first keystream block */
    toy_cipher_encrypt_block(ctr->cipher, ctr->counter, ctr->keystream);
    ctr->keystream_pos = 0;
    return ctr;
}

void toy_ctr_free(ToyCTR* ctr) {
    if (ctr) {
        toy_cipher_free(ctr->cipher);
        crypto_secure_zero(ctr, sizeof(ToyCTR));
        free(ctr);
    }
}

uint8_t toy_ctr_next_byte(ToyCTR* ctr) {
    if (!ctr) return 0;

    /* If keystream exhausted, increment counter and re-encrypt */
    if (ctr->keystream_pos >= CRYPTO_CIPHER_BLOCK_BYTES) {
        /* Increment counter (big-endian, with carry) */
        for (int i = CRYPTO_CIPHER_BLOCK_BYTES - 1; i >= 0; i--) {
            ctr->counter[i]++;
            if (ctr->counter[i] != 0) break;
        }
        toy_cipher_encrypt_block(ctr->cipher, ctr->counter, ctr->keystream);
        ctr->keystream_pos = 0;
    }

    return ctr->keystream[ctr->keystream_pos++];
}

void toy_ctr_generate(ToyCTR* ctr, uint8_t* output, size_t len) {
    if (!ctr || !output) return;
    for (size_t i = 0; i < len; i++) {
        output[i] = toy_ctr_next_byte(ctr);
    }
}

/* ================================================================
 * Toy One-Way Function (OWF)
 *
 * f(x) = (p * q) where p,q are primes derived from x.
 *
 * This models the hardness of factoring (RSA assumption):
 *   Given N = p*q, finding p and q is believed hard.
 *
 * In this toy, we derive p and q from input bits via deterministic
 * processing (toy prime generation), then output their product.
 *
 * L2: OWF is easy to compute but hard to invert.
 * Reference: Rivest-Shamir-Adleman (1978), Goldreich Vol 1
 * ================================================================ */

/* Check primality by trial division (demonstration only) */
static int toy_is_prime(uint32_t n) {
    if (n < 2) return 0;
    if (n % 2 == 0) return n == 2;
    for (uint32_t d = 3; d * d <= n; d += 2) {
        if (n % d == 0) return 0;
    }
    return 1;
}

/* Find the smallest prime >= start_value */
static uint32_t toy_next_prime(uint32_t start) {
    uint32_t n = start;
    if (n < 2) n = 2;
    if (n % 2 == 0) n++;
    while (!toy_is_prime(n)) {
        n += 2;
        if (n < 2) return 2; /* overflow guard */
    }
    return n;
}

/* Derive two primes from input bytes */
static void toy_owf_derive_primes(const uint8_t* input, int input_bytes,
                                   uint32_t* p, uint32_t* q) {
    /* Use first 4 bytes as p seed, next 4 bytes as q seed */
    uint32_t seed_p = 0, seed_q = 0;
    for (int i = 0; i < 4 && i < input_bytes; i++) {
        seed_p = (seed_p << 8) | input[i];
        seed_q = (seed_q << 8) | input[i + 4];
    }
    /* Ensure seeds are in reasonable range for 32-bit primes */
    seed_p = (seed_p % 1000000) + 1000000;
    seed_q = (seed_q % 1000000) + 2000000;
    *p = toy_next_prime(seed_p);
    *q = toy_next_prime(seed_q);
}

typedef struct {
    int bit_length;
} ToyOWFState;

static int toy_owf_evaluate_fn(const OWF* owf, const uint8_t* input,
                                uint8_t* output) {
    if (!owf || !input || !output) return 0;
    ToyOWFState* st = (ToyOWFState*)owf->params;
    int in_bytes = st->bit_length / 8;

    uint32_t p, q;
    toy_owf_derive_primes(input, in_bytes, &p, &q);
    uint64_t product = (uint64_t)p * (uint64_t)q;

    /* Write product as 8-byte big-endian */
    uint64_t tmp = product;
    for (int i = 7; i >= 0; i--) {
        output[i] = (uint8_t)(tmp & 0xFF);
        tmp >>= 8;
    }
    /* Fill remaining output bytes with zeros */
    for (int i = 8; i < in_bytes; i++) {
        output[i] = 0;
    }
    return 1;
}

static int toy_owf_verify_fn(const OWF* owf, const uint8_t* input,
                              const uint8_t* output) {
    if (!owf || !input || !output) return 0;
    ToyOWFState* st = (ToyOWFState*)owf->params;
    int in_bytes = st->bit_length / 8;
    uint8_t computed[16] = {0};
    if (!toy_owf_evaluate_fn(owf, input, computed)) return 0;
    return (memcmp(computed, output, (size_t)in_bytes) == 0) ? 1 : 0;
}

OWF* owf_create_toy_multiply(int bit_length) {
    OWF* owf = (OWF*)malloc(sizeof(OWF));
    if (!owf) return NULL;

    ToyOWFState* st = (ToyOWFState*)malloc(sizeof(ToyOWFState));
    if (!st) { free(owf); return NULL; }
    st->bit_length = bit_length;

    owf->input_len  = bit_length;
    owf->output_len = bit_length;
    owf->params     = st;
    owf->evaluate   = toy_owf_evaluate_fn;
    owf->verify     = toy_owf_verify_fn;
    return owf;
}

void owf_free(OWF* owf) {
    if (owf) {
        free(owf->params);
        free(owf);
    }
}

int owf_evaluate(const OWF* owf, const uint8_t* input, uint8_t* output) {
    if (!owf || !owf->evaluate) return 0;
    return owf->evaluate(owf, input, output);
}

/* ================================================================
 * Goldreich-Levin Hard-Core Bit
 *
 * Theorem (Goldreich-Levin, 1989):
 *   If g is a one-way function, then the inner product
 *   <x, r> mod 2 is a hard-core predicate for
 *     h(x, r) = (g(x), r).
 *
 * This means: given g(x) and r, predicting <x,r> mod 2
 * is as hard as inverting g.
 *
 * L4: Goldreich-Levin Theorem.
 * L5: GL PRG = iterate GL hard-core bit to stretch.
 *
 * Reference: Goldreich-Levin (STOC 1989)
 *   "A Hard-Core Predicate for All One-Way Functions"
 * ================================================================ */

int crypto_hardcore_bit_gl(const uint8_t* x, int x_bits,
                            const uint8_t* r, int r_bits) {
    if (!x || !r || x_bits <= 0 || r_bits <= 0) return 0;

    /* Compute inner product <x, r> mod 2 over GF(2) */
    int min_bits = (x_bits < r_bits) ? x_bits : r_bits;
    return gf2_inner_product(x, r, min_bits);
}

/* ================================================================
 * GF(2) Vector Operations
 *
 * GF(2) = {0, 1} with XOR as addition and AND as multiplication.
 * These operations are fundamental to all cryptographic primitives
 * (L3: Mathematical Structures).
 *
 * Inner product: <a, b> = sum_i (a_i * b_i) mod 2
 * Vector addition: (a XOR b)_i = a_i XOR b_i
 * Hamming weight: wt(x) = number of 1-bits in x
 * Hamming distance: dist(x, y) = wt(x XOR y)
 * ================================================================ */

int gf2_inner_product(const uint8_t* x, const uint8_t* y, int n_bits) {
    if (!x || !y || n_bits <= 0) return 0;

    int dot = 0;
    for (int i = 0; i < n_bits; i++) {
        int byte_idx = i / 8;
        int bit_idx  = 7 - (i % 8);
        int x_bit = (x[byte_idx] >> bit_idx) & 1;
        int y_bit = (y[byte_idx] >> bit_idx) & 1;
        dot ^= (x_bit & y_bit);  /* XOR = sum mod 2 */
    }
    return dot;
}

void gf2_vector_add(const uint8_t* a, const uint8_t* b,
                     uint8_t* result, int n_bits) {
    if (!a || !b || !result) return;
    int n_bytes = (n_bits + 7) / 8;
    for (int i = 0; i < n_bytes; i++) {
        result[i] = a[i] ^ b[i];
    }
    /* Mask unused bits in last byte */
    int extra = n_bytes * 8 - n_bits;
    if (extra > 0) {
        result[n_bytes - 1] &= (uint8_t)(0xFF >> extra);
    }
}

int gf2_hamming_weight(const uint8_t* x, int n_bits) {
    if (!x) return 0;
    int wt = 0;
    for (int i = 0; i < n_bits; i++) {
        int byte_idx = i / 8;
        int bit_idx  = 7 - (i % 8);
        if ((x[byte_idx] >> bit_idx) & 1) wt++;
    }
    return wt;
}

int gf2_hamming_distance(const uint8_t* x, const uint8_t* y, int n_bits) {
    if (!x || !y) return 0;
    int n_bytes = (n_bits + 7) / 8;
    uint8_t* diff = (uint8_t*)calloc((size_t)n_bytes, 1);
    if (!diff) return -1;
    gf2_vector_add(x, y, diff, n_bits);
    int dist = gf2_hamming_weight(diff, n_bits);
    free(diff);
    return dist;
}

/* ================================================================
 * Secure Utility Functions
 * ================================================================ */

/*
 * Constant-time comparison: iterate over all bytes regardless of
 * whether a difference has been found. This prevents timing attacks
 * that could reveal partial information about secret values.
 *
 * Used for MAC/tag verification where the secret determines correctness.
 *
 * L7 (Applications): Timing side-channel resistant crypto construction
 */
int crypto_constant_time_compare(const uint8_t* a, const uint8_t* b,
                                  int len) {
    if (!a || !b || len <= 0) return 0;
    uint8_t diff = 0;
    for (int i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    /* Return 1 if equal (diff == 0), 0 otherwise */
    return (diff == 0) ? 1 : 0;
}

void crypto_bin_to_hex(const uint8_t* bin, int bin_len, char* hex_out) {
    if (!bin || !hex_out || bin_len <= 0) return;
    static const char hex_digits[] = "0123456789abcdef";
    for (int i = 0; i < bin_len; i++) {
        hex_out[i * 2]     = hex_digits[(bin[i] >> 4) & 0xF];
        hex_out[i * 2 + 1] = hex_digits[bin[i] & 0xF];
    }
    hex_out[bin_len * 2] = '\0';
}

int crypto_hex_to_bin(const char* hex, uint8_t* bin_out, int max_len) {
    if (!hex || !bin_out || max_len <= 0) return 0;
    int hex_len = (int)strlen(hex);
    if (hex_len % 2 != 0) return 0;  /* hex must be even length */

    int bin_len = hex_len / 2;
    if (bin_len > max_len) bin_len = max_len;

    for (int i = 0; i < bin_len; i++) {
        char c_hi = hex[i * 2];
        char c_lo = hex[i * 2 + 1];
        uint8_t val = 0;

        if (c_hi >= '0' && c_hi <= '9')
            val = (uint8_t)((c_hi - '0') << 4);
        else if (c_hi >= 'a' && c_hi <= 'f')
            val = (uint8_t)((c_hi - 'a' + 10) << 4);
        else if (c_hi >= 'A' && c_hi <= 'F')
            val = (uint8_t)((c_hi - 'A' + 10) << 4);
        else return 0;

        if (c_lo >= '0' && c_lo <= '9')
            val |= (uint8_t)(c_lo - '0');
        else if (c_lo >= 'a' && c_lo <= 'f')
            val |= (uint8_t)(c_lo - 'a' + 10);
        else if (c_lo >= 'A' && c_lo <= 'F')
            val |= (uint8_t)(c_lo - 'A' + 10);
        else return 0;

        bin_out[i] = val;
    }
    return bin_len;
}

void crypto_bytes_to_bits(const uint8_t* bytes, int n_bytes,
                           uint8_t* bits, int n_bits) {
    if (!bytes || !bits) return;
    int max_bits = n_bytes * 8;
    if (n_bits > max_bits) n_bits = max_bits;
    for (int i = 0; i < n_bits; i++) {
        int byte_idx = i / 8;
        int bit_idx  = 7 - (i % 8);
        bits[i] = (uint8_t)((bytes[byte_idx] >> bit_idx) & 1);
    }
}

void crypto_bits_to_bytes(const uint8_t* bits, int n_bits,
                           uint8_t* bytes, int n_bytes) {
    if (!bits || !bytes) return;
    memset(bytes, 0, (size_t)n_bytes);
    int max_bits = n_bytes * 8;
    if (n_bits > max_bits) n_bits = max_bits;
    for (int i = 0; i < n_bits; i++) {
        int byte_idx = i / 8;
        int bit_idx  = 7 - (i % 8);
        if (bits[i]) {
            bytes[byte_idx] |= (uint8_t)(1 << bit_idx);
        }
    }
}

void crypto_print_hex(const char* label, const uint8_t* data, int len) {
    if (label) printf("%s: ", label);
    for (int i = 0; i < len && i < 64; i++) {
        printf("%02x", data[i]);
    }
    if (len > 64) printf("...");
    printf("\n");
}

/*
 * Secure zero: overwrite memory to prevent sensitive data
 * from being recovered from freed memory or core dumps.
 * The volatile pointer prevents compiler optimization from
 * eliminating the memset call.
 */
void crypto_secure_zero(void* ptr, size_t len) {
    if (ptr && len > 0) {
        volatile uint8_t* p = (volatile uint8_t*)ptr;
        while (len--) {
            *p++ = 0;
        }
    }
}