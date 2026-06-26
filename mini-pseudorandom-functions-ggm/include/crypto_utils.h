/*
 * crypto_utils.h - Cryptographic Utilities for mini-crypto-foundations
 *
 * Provides common cryptographic operations shared across modules:
 *   - Hash functions (for toy/demo PRG)
 *   - Random number generation (deterministic, seed-based)
 *   - AES-like block cipher (simplified for demonstration)
 *   - One-way function templates
 *   - Hard-core bit extraction
 *
 * L2 Core Concepts: one-way function, hard-core predicate
 * L3 Mathematical Structures: GF(2) arithmetic, Merkle-Damgard
 * L7 Applications: hash-based constructions
 *
 * Reference:
 *   Goldreich Vol 1, section 2.4 (hard-core predicates)
 *   Katz-Lindell section 8.3 (hash functions)
 */

#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stdint.h>
#include <stddef.h>

/* ================================================================
 * Deterministic Pseudo-Random Number Generator (for reproducibility)
 * ================================================================ */

/*
 * Simple LCG-based PRNG seeded deterministically.
 * Used ONLY for generating test vectors and reproducible experiments.
 * NOT cryptographically secure.
 */
typedef struct {
    uint64_t state;
    uint64_t a;
    uint64_t c;
    uint64_t m;
} CryptoRNG;

CryptoRNG* crypto_rng_create(uint64_t seed);
void       crypto_rng_free(CryptoRNG* rng);
uint64_t   crypto_rng_next(CryptoRNG* rng);
void       crypto_rng_fill(CryptoRNG* rng, uint8_t* buf, size_t len);

/* ================================================================
 * Simplified Hash Function (Davies-Meyer construction)
 * ================================================================ */

/*
 * A simplified block-cipher-based hash using a toy cipher.
 * For length-doubling PRG construction:
 *   G(s) = Hash(s || counter_1) || Hash(s || counter_2) || ...
 *
 * NOT cryptographically secure ¡ª pedagogical only.
 */
#define CRYPTO_HASH_BLOCK_SIZE  16
#define CRYPTO_HASH_OUTPUT_SIZE 16
#define CRYPTO_HASH_STATE_SIZE  16

typedef struct {
    uint8_t state[CRYPTO_HASH_STATE_SIZE];
    uint8_t buffer[CRYPTO_HASH_BLOCK_SIZE];
    int     buf_used;
    uint64_t total_bits;
    uint8_t digest[CRYPTO_HASH_OUTPUT_SIZE];
    int     finalized;
} CryptoHash;

CryptoHash* crypto_hash_create(void);
void        crypto_hash_update(CryptoHash* h, const uint8_t* data, size_t len);
void        crypto_hash_finalize(CryptoHash* h);
void        crypto_hash_free(CryptoHash* h);
const uint8_t* crypto_hash_digest(const CryptoHash* h);
int         crypto_hash_output_bytes(const CryptoHash* h);

/* One-shot hash */
void crypto_hash_oneshot(const uint8_t* data, size_t len,
                          uint8_t* digest_out);

/* ================================================================
 * Simplified Block Cipher (Toy AES-like)
 * ================================================================ */

/*
 * A Feistel-network based toy cipher for AES-CTR PRG.
 * Block size = 128 bits (16 bytes), Key size = 128 bits.
 *
 * Used ONLY for demonstration of CTR-mode PRG.
 * NOT cryptographically secure ¡ª use real AES in production.
 */
#define CRYPTO_CIPHER_BLOCK_BYTES  16
#define CRYPTO_CIPHER_KEY_BYTES    16
#define CRYPTO_CIPHER_ROUNDS       8

typedef struct {
    uint8_t round_keys[CRYPTO_CIPHER_ROUNDS + 1][CRYPTO_CIPHER_BLOCK_BYTES];
    int     rounds;
} ToyCipher;

ToyCipher* toy_cipher_create(const uint8_t* key, int key_bytes);
void       toy_cipher_free(ToyCipher* tc);
void       toy_cipher_encrypt_block(const ToyCipher* tc,
                                     const uint8_t* plaintext,
                                     uint8_t* ciphertext);
void       toy_cipher_decrypt_block(const ToyCipher* tc,
                                     const uint8_t* ciphertext,
                                     uint8_t* plaintext);

/* CTR mode stream cipher */
typedef struct {
    ToyCipher* cipher;
    uint8_t    counter[CRYPTO_CIPHER_BLOCK_BYTES];
    uint8_t    keystream[CRYPTO_CIPHER_BLOCK_BYTES];
    int        keystream_pos;
} ToyCTR;

ToyCTR* toy_ctr_create(const uint8_t* key, int key_bytes,
                        const uint8_t* nonce, int nonce_bytes);
void    toy_ctr_free(ToyCTR* ctr);
uint8_t toy_ctr_next_byte(ToyCTR* ctr);
void    toy_ctr_generate(ToyCTR* ctr, uint8_t* output, size_t len);

/* ================================================================
 * One-Way Function (OWF) Template
 * ================================================================ */

/*
 * A one-way function f: {0,1}^n -> {0,1}^n satisfies:
 *   1. Easy to compute: f(x) is polynomial-time
 *   2. Hard to invert: for all PPT A, Pr[A(f(x)) in f^{-1}(f(x))] <= negl(n)
 *
 * Candidate OWF (toy): f(x) = x^2 mod N where N = pq (RSA-style).
 * We use a simplified factoring-based OWF for pedagogy.
 */
typedef struct OWF_impl OWF;

struct OWF_impl {
    int  input_len;
    int  output_len;
    void* params;       /* OWF-specific parameters */

    int  (*evaluate)(const OWF* owf, const uint8_t* input,
                     uint8_t* output);
    int  (*verify)(const OWF* owf, const uint8_t* input,
                   const uint8_t* output);
};

/* Toy OWF: multiply two n-bit primes */
OWF* owf_create_toy_multiply(int bit_length);
void owf_free(OWF* owf);
int  owf_evaluate(const OWF* owf, const uint8_t* input, uint8_t* output);

/* ================================================================
 * Hard-Core Bit (GL ¡ª Goldreich-Levin)
 * ================================================================ */

/*
 * Goldreich-Levin Theorem: If f is a OWF, then
 *   g(x, r) = (f(x), r, <x, r> mod 2)
 * is a PRG with expansion n+1 bits.
 *
 * <x, r> = inner product mod 2 is a hard-core predicate.
 */

/* Compute hard-core bit using GL: hcb = <x, r> mod 2 (inner product) */
int  crypto_hardcore_bit_gl(const uint8_t* x, int x_bits,
                            const uint8_t* r, int r_bits);

/* GL-based length-doubling PRG from OWF:
 * G_GL(x, r) = (f(x), r, <x,r>) using hard-core bit + iterate */
typedef struct {
    OWF*  owf;
    int   n;          /* security parameter */
    int   iter;       /* iterations for length-doubling */
} GLPRG;

/* ================================================================
 * GF(2) Vector Operations
 * ================================================================ */

/* Inner product mod 2: sum(x_i * y_i mod 2) */
int gf2_inner_product(const uint8_t* x, const uint8_t* y, int n_bits);

/* Vector addition mod 2 (XOR) */
void gf2_vector_add(const uint8_t* a, const uint8_t* b,
                     uint8_t* result, int n_bits);

/* Hamming weight (number of 1 bits) */
int gf2_hamming_weight(const uint8_t* x, int n_bits);

/* Hamming distance between two vectors */
int gf2_hamming_distance(const uint8_t* x, const uint8_t* y, int n_bits);

/* ================================================================
 * Utility Functions
 * ================================================================ */

/* Secure comparison (constant-time, for MAC verification) */
int crypto_constant_time_compare(const uint8_t* a, const uint8_t* b,
                                  int len);

/* Hex encoding/decoding */
void crypto_bin_to_hex(const uint8_t* bin, int bin_len, char* hex_out);
int  crypto_hex_to_bin(const char* hex, uint8_t* bin_out, int max_len);

/* Byte-to-bit conversion utilities */
void crypto_bytes_to_bits(const uint8_t* bytes, int n_bytes,
                           uint8_t* bits, int n_bits);
void crypto_bits_to_bytes(const uint8_t* bits, int n_bits,
                           uint8_t* bytes, int n_bytes);

/* Print bytes as hex */
void crypto_print_hex(const char* label, const uint8_t* data, int len);

/* Timing-safe memory comparison and clearing */
void crypto_secure_zero(void* ptr, size_t len);

#endif /* CRYPTO_UTILS_H */
