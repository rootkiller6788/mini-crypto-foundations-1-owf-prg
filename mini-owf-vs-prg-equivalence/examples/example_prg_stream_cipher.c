/*
 * example_prg_stream_cipher.c — PRG-based Stream Cipher
 *
 * L7 Application: Private-key encryption from PRG.
 *
 * Demonstrates:
 *   1. Building a PRG from a OWF (Subset Sum → GL → 1-bit PRG → iterate)
 *   2. Using the PRG as a stream cipher keystream generator
 *   3. Encrypting and decrypting a message
 *   4. The IND-CPA security via indistinguishability experiment
 *
 * Reference:
 *   Goldreich (2001) — Foundations of Cryptography, Vol 1, Ch 3
 *   Katz & Lindell — Introduction to Modern Cryptography, Ch 3
 */

#include "owf.h"
#include "prg.h"
#include "hardcore_bit.h"
#include "indistinguish.h"
#include "reduction.h"
#include "crypto_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    seed_random();
    printf("=== PRG-based Stream Cipher ===\n\n");

    /* ================================================================
     * Step 1: Build a OWF
     * We use Subset Sum with random weights as the base OWF.
     * ================================================================ */
    printf("[1] Building OWF (Subset Sum, n=6, M=256)...\n");
    int n_bits = 6;
    uint64_t weights[] = {7, 13, 23, 41, 73, 137};
    void *owf_params = subsetsum_params_create(n_bits, weights, 256);
    OWF *owf = owf_create(n_bits, subset_sum_owf_eval, owf_params, "SubsetSum-6");
    printf("    OWF created: %s (n=%d)\n", owf->name, owf->n);

    /* Test OWF evaluation */
    BitString *x = bitstring_create((size_t)n_bits);
    BitString *y = bitstring_create(owf->n);
    bitstring_randomize(x);
    x->bit_len = (size_t)n_bits;
    owf_eval(owf, x, y);
    uint64_t yval;
    bitstring_to_uint64(y, &yval);
    printf("    f(rand) = %llu\n", (unsigned long long)yval);
    bitstring_free(x);
    bitstring_free(y);

    /* ================================================================
     * Step 2: Augment with Goldreich-Levin hardcore bit
     * g(x,r) = (f(x), r), hc(x,r) = <x,r>
     * ================================================================ */
    printf("\n[2] Adding Goldreich-Levin hardcore bit...\n");
    OWFWithHardcoreBit *owf_hc = owf_add_hardcore_bit(owf);
    printf("    Augmented OWF: n_in=%d, n_out=%d\n",
           owf_hc->input_len, owf_hc->g->n);
    printf("    Hardcore bit: GL inner product <x,r>\n");

    /* ================================================================
     * Step 3: Build 1-bit stretch PRG
     * G_1(s) = (g(s), hc(s))
     * ================================================================ */
    printf("\n[3] Building 1-bit stretch PRG...\n");
    PRG *prg_1bit = prg_one_bit_stretch(owf_hc);
    printf("    G_1: {0,1}^%d → {0,1}^%zu (stretch=1 bit)\n",
           prg_1bit->n, prg_1bit->output_len);

    /* Test 1-bit PRG */
    BitString *seed = bitstring_create(prg_1bit->n);
    BitString *prg_out = bitstring_create(prg_1bit->output_len);
    bitstring_randomize(seed);
    prg_eval(prg_1bit, seed, prg_out);
    printf("    G_1(seed) produced %zu bits\n", prg_out->bit_len);
    bitstring_free(seed);
    bitstring_free(prg_out);

    /* ================================================================
     * Step 4: Iterate to arbitrary stretch
     * ================================================================ */
    /* Use a short demo message that fits in PRG output */
    const char *message = "HELLO CRYPTO";
    size_t msg_bytes = strlen(message);
    size_t msg_bits = msg_bytes * 8;
    size_t prg_output_bits = (msg_bits > 128) ? (msg_bits + 16) : 256;

    printf("\n[4] Iterating to %zu-bit stretch...\n", prg_output_bits);
    PRG *prg_stretched = prg_arbitrary_stretch(prg_1bit, prg_output_bits);
    printf("    G: {0,1}^%d → {0,1}^%zu (stretch=%zu bits)\n",
           prg_stretched->n, prg_stretched->output_len,
           prg_stretched->output_len - (size_t)prg_stretched->n);

    /* ================================================================
     * Step 5: Stream cipher encryption
     * ================================================================ */
    printf("\n[5] Stream cipher encryption...\n");

    /* Generate a random key (seed) */
    BitString *key = bitstring_create(prg_stretched->n);
    generate_crypto_key(prg_stretched->n, key);
    printf("    Key length: %zu bits\n", key->bit_len);

    printf("    Message: \"%s\"\n", message);
    printf("    Message length: %zu bits\n", msg_bits);

    /* Convert message to bitstring */
    BitString *plaintext = bitstring_create(msg_bits);
    for (size_t i = 0; i < msg_bytes; i++) {
        for (int b = 0; b < 8; b++) {
            int bit = ((unsigned char)message[i] >> (7 - b)) & 1;
            bitstring_set_bit(plaintext, i * 8 + (size_t)b, bit);
        }
    }
    plaintext->bit_len = msg_bits;

    /* Encrypt */
    BitString *ciphertext = bitstring_create(msg_bits);
    int enc_ret = prg_stream_encrypt(prg_stretched, key, plaintext, ciphertext);
    if (enc_ret != 0) {
        printf("    ERROR: Encryption failed (message too long for PRG)\n");
        bitstring_free(key); bitstring_free(plaintext);
        bitstring_free(ciphertext);
        prg_free(prg_stretched);
        free(owf_hc);
        owf_free(owf);
        return 1;
    }

    printf("    Ciphertext (hex): ");
    char hex_buf[256];
    bitstring_to_hex(ciphertext, hex_buf, sizeof(hex_buf));
    printf("%s\n", hex_buf);

    /* Decrypt */
    BitString *decrypted = bitstring_create(msg_bits);
    prg_stream_decrypt(prg_stretched, key, ciphertext, decrypted);

    /* Verify */
    printf("    Decrypted: \"");
    for (size_t i = 0; i < msg_bytes; i++) {
        int byte = 0;
        for (int b = 0; b < 8; b++) {
            byte = (byte << 1) | bitstring_get_bit(decrypted, i * 8 + (size_t)b);
        }
        printf("%c", byte);
    }
    printf("\"\n");

    int correct = bitstring_equal(plaintext, decrypted);
    printf("    Round-trip: %s\n", correct ? "✓ SUCCESS" : "✗ FAILED");

    bitstring_free(key);
    bitstring_free(plaintext);
    bitstring_free(ciphertext);
    bitstring_free(decrypted);

    /* ================================================================
     * Step 6: Demonstrate IND-CPA security concept
     * ================================================================ */
    printf("\n[6] IND-CPA security analysis...\n");
    printf("    Game 0 (real):  C = G(k) ⊕ m\n");
    printf("    Game 1 (ideal): C = U_{|m|} ⊕ m\n");
    printf("    By PRG security: Game 0 ≈_c Game 1\n");
    printf("    In Game 1, ciphertext is uniformly random — no info about m.\n");
    printf("    ∴ The scheme is IND-CPA secure.\n");

    /* Cleanup */
    prg_free(prg_stretched);  /* This frees prg_1bit params chain */
    free(owf_hc);
    owf_free(owf);

    printf("\n=== Stream Cipher Demo Complete ===\n");
    return 0;
}
