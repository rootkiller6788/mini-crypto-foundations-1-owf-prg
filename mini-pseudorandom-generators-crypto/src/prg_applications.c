/*
 * prg_applications.c -- Cryptographic Applications of PRGs
 *
 * L7 Applications: Demonstrates real-world cryptographic uses of
 * pseudorandom generators beyond the basic generator interface.
 *
 * Applications implemented:
 *   1. Stream Cipher: PRG output XORed with plaintext (like RC4/ChaCha)
 *   2. Key Derivation: Stretch a short key into multiple subkeys
 *   3. Cryptographic Nonce Generation: Unpredictable random values
 *   4. Challenge-Response: Random challenge generation for authentication
 *
 * Reference: Katz & Lindell (2015) "Introduction to Modern Cryptography"
 *            Ferguson, Schneier, Kohno (2010) "Cryptography Engineering"
 * Courses: MIT 6.875, Stanford CS255, Princeton COS 551
 */
#include "prg_crypto.h"
#include "prg_construction.h"
#include <string.h>
#include <stdlib.h>

/* ================================================================
 * Stream Cipher from PRG (L7)
 * ================================================================ */

/*
 * L7: Simple stream cipher using PRG output as keystream.
 *
 * Construction:
 *   Keystream = G(seed || nonce)  [PRG with seed+nonce]
 *   Ciphertext = Plaintext XOR Keystream
 *
 * This is the fundamental construction underlying:
 *   - RC4 (using RC4 PRGA as G)
 *   - Salsa20/ChaCha20 (block function as G)
 *   - AES-CTR (AES in counter mode as G)
 *
 * Security: If G is a secure PRG, then this is IND-CPA secure
 * (indistinguishable from one-time pad to PPT adversary).
 *
 * Parameters:
 *   - prg: initialized PRG instance
 *   - plaintext: input data
 *   - len: data length in bytes
 *   - ciphertext: output (may equal plaintext for in-place)
 */
int prg_stream_encrypt(PRG* prg, uint8_t* plaintext, size_t len,
                       uint8_t* ciphertext) {
    if (!prg || !plaintext || !ciphertext || len == 0) return -1;

    /* Generate keystream of required length */
    uint8_t* keystream = (uint8_t*)calloc(1, len);
    if (!keystream) return -1;

    int filled = prg_fill(prg, keystream, len);
    if (filled < 0 || (size_t)filled < len) {
        free(keystream);
        return -1;
    }

    /* XOR plaintext with keystream */
    for (size_t i = 0; i < len; i++) {
        ciphertext[i] = plaintext[i] ^ keystream[i];
    }

    /* Zero keystream from memory (defense-in-depth) */
    memset(keystream, 0, len);
    free(keystream);
    return (int)len;
}

/*
 * L7: Stream cipher decryption (identical to encryption: XOR is its own inverse).
 *   Plaintext = Ciphertext XOR Keystream
 */
int prg_stream_decrypt(PRG* prg, uint8_t* ciphertext, size_t len,
                       uint8_t* plaintext) {
    /* Stream cipher decryption = encryption (XOR symmetry) */
    return prg_stream_encrypt(prg, ciphertext, len, plaintext);
}

/* ================================================================
 * Key Derivation from PRG (L7)
 * ================================================================ */

/*
 * L7: Key derivation function (KDF) using PRG.
 *
 * Problem: Given a master key K of length n bits, derive multiple
 * subkeys K1, K2, ..., Km of total length L bits.
 *
 * Construction (simplified HKDF-like):
 *   output = G(K)  (stretch from n to L bits)
 *   K1 = output[0..l1-1]
 *   K2 = output[l1..l1+l2-1]
 *   ...
 *
 * This demonstrates the stretch property of PRGs applied to key material.
 * In practice, HKDF (RFC 5869) uses HMAC-based extract-then-expand,
 * but the core idea is identical: use PRG to expand key entropy.
 *
 * Parameters:
 *   - prg: initialized PRG (seed = master key)
 *   - subkeys: output buffer for all subkeys
 *   - total_bytes: total bytes of subkey material needed
 */
int prg_derive_keys(PRG* prg, uint8_t* subkeys, size_t total_bytes) {
    if (!prg || !subkeys || total_bytes == 0) return -1;
    return prg_fill(prg, subkeys, total_bytes);
}

/* ================================================================
 * Cryptographic Nonce Generation (L7)
 * ================================================================ */

/*
 * L7: Generate a cryptographic nonce (number used once).
 *
 * Nonces must be:
 *   1. Unpredictable (to prevent chosen-nonce attacks)
 *   2. Unique with overwhelming probability
 *   3. Generated from high-entropy seed material
 *
 * A secure PRG satisfies all three properties:
 *   - Unpredictable: follows from PRG security
 *   - Unique: collision probability ~ 1/2^{bitlen}
 *   - High entropy: follows from random-looking output
 *
 * Typical nonce sizes: 96 bits (TLS), 128 bits (IPsec).
 */
int prg_generate_nonce(PRG* prg, uint8_t* nonce, size_t nonce_bytes) {
    if (!prg || !nonce || nonce_bytes == 0) return -1;
    return prg_fill(prg, nonce, nonce_bytes);
}

/* ================================================================
 * Challenge-Response Authentication (L7)
 * ================================================================ */

/*
 * L7: Generate a random challenge for challenge-response authentication.
 *
 * Protocol:
 *   Verifier generates random challenge C, sends to Prover.
 *   Prover computes response R = MAC(key, C), sends R.
 *   Verifier verifies R matches expected value.
 *
 * The security relies on C being unpredictable (otherwise replay attacks).
 * A secure PRG guarantees unpredictability.
 *
 * Parameters:
 *   - prg: initialized PRG instance
 *   - challenge: output buffer
 *   - challenge_bytes: challenge length (typically 16-32 bytes)
 */
int prg_generate_challenge(PRG* prg, uint8_t* challenge, size_t challenge_bytes) {
    if (!prg || !challenge || challenge_bytes == 0) return -1;
    return prg_fill(prg, challenge, challenge_bytes);
}

/* ================================================================
 * GGM Pseudorandom Function from PRG (L8 Advanced)
 * ================================================================ */

/*
 * L8: Goldreich-Goldwasser-Micali (GGM) PRF construction from PRG.
 *
 * Theorem (GGM 1986): If a PRG G: {0,1}^n -> {0,1}^{2n} exists,
 * then a pseudorandom function F: {0,1}^n x {0,1}^n -> {0,1}^n exists.
 *
 * Construction (binary tree):
 *   Let G(x) = G_0(x) || G_1(x) where |G_0(x)| = |G_1(x)| = n.
 *   Define F_k(x) by walking down a binary tree:
 *     k_eps = k
 *     For i = 1 to n:
 *       k_{prefix} = G_{x_i}(k_{parent})
 *     Output k_x
 *
 * This is a foundational result: PRG => PRF.
 * Combined with GGM PRF => PRP (Luby-Rackoff 1988), we get:
 *   OWF exists => PRG exists (HILL 1999)
 *   PRG exists => PRF exists (GGM 1986)
 *   PRF exists => PRP exists (Luby-Rackoff 1988)
 *
 * We implement a simplified version for educational purposes.
 * The GGM tree has 2^n leaves but we only compute the path
 * for a given input, taking O(n) PRG evaluations.
 */

/*
 * GGM PRF tree node structure.
 * We use a single bit to navigate left (0) or right (1).
 */
typedef struct {
    size_t n;              /* security parameter (key length = input length) */
    uint8_t* key;          /* current node value (n bits) */
    size_t depth;          /* current depth in the tree */
} GGMNode;

/*
 * L8: Evaluate the GGM PRF: F(k, x) where k is n bits, x is n bits.
 *
 * Algorithm:
 *   node = k
 *   for i = 0 to n-1:
 *     (left, right) = G(node)   // G expands n bits to 2n bits
 *     if x[i] == 0: node = left
 *     else:         node = right
 *   return node
 *
 * For demo purposes, we simulate G using our PRG infrastructure.
 * n_bits is the security parameter (both key and input length).
 *
 * Parameters:
 *   - seed: the PRF key k (n_bits)
 *   - input: the input x (n_bits)
 *   - n_bytes: bytes for n_bits
 *   - output: F(k,x) result (n_bits)
 *
 * Returns 0 on success, -1 on error.
 */
int ggm_prf_evaluate(const uint8_t* seed, const uint8_t* input,
                     size_t n_bytes, uint8_t* output) {
    if (!seed || !input || !output || n_bytes == 0) return -1;

    /* For the demonstration, we use the iterated PRG structure
     * to simulate the tree walk. Each step of G takes the current
     * node and produces two child values.
     *
     * Since we don't have a full G:{0,1}^n -> {0,1}^{2n} readily
     * available, we simulate: G_0(x) = first half of PRG(x),
     * G_1(x) = second half. */

    /* Start with k as current node */
    uint8_t node[64] = {0};
    size_t actual_bytes = (n_bytes < 64) ? n_bytes : 64;
    memcpy(node, seed, actual_bytes);

    /* Walk the tree bit by bit */
    size_t n_bits = n_bytes * 8;
    for (size_t i = 0; i < n_bits; i++) {
        /* Get input bit x_i */
        size_t byte_idx = i / 8;
        size_t bit_idx = i % 8;
        int x_i = (input[byte_idx] >> (7 - bit_idx)) & 1;

        /* Simulate G(node) = left || right using XOR-based expansion.
         * In a full implementation, this would be a real PRG call.
         * Here we use a deterministic transformation that simulates
         * the tree structure. */
        uint8_t expanded[128] = {0};
        size_t exp_bytes = actual_bytes * 2;
        if (exp_bytes > 128) exp_bytes = 128;

        /* Deterministic expansion: expanded = PRG_simulate(node) */
        /* Simple simulation for educational demo */
        for (size_t j = 0; j < exp_bytes && j < 128; j++) {
            expanded[j] = node[j % actual_bytes] ^ (uint8_t)(j * 0x9D);
        }
        /* Apply nonlinear round: mix with rotated copies */
        for (size_t j = actual_bytes; j < exp_bytes && j < 128; j++) {
            expanded[j] ^= expanded[j - actual_bytes] ^ (uint8_t)(j);
        }

        /* Pick left or right half based on x_i */
        size_t half = actual_bytes;
        if (x_i == 0) {
            memcpy(node, expanded, half);
        } else {
            memcpy(node, expanded + half, half);
        }
    }

    /* Output the final node value */
    memcpy(output, node, actual_bytes);
    return 0;
}
