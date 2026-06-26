/*
 * example_kdf.c - GGM-based Key Derivation Function (L7 Application)
 *
 * Demonstrates using GGM-PRF as a secure Key Derivation Function (KDF):
 *   DerivedKey = F_{master_key}(salt || context)
 *
 * This is analogous to HKDF (RFC 5869) and NIST SP 800-108,
 * which use PRFs as building blocks for key derivation.
 *
 * L7: Cryptographic application - secure key derivation
 *
 * Reference:
 *   Krawczyk (CRYPTO 2010), "Cryptographic Extraction and Key Derivation: The HKDF Scheme"
 *   NIST SP 800-108, "Recommendation for Key Derivation Using Pseudorandom Functions"
 */

#include "ggm.h"
#include "prf.h"
#include "prg.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    printf("=== GGM-based Key Derivation Function (KDF) ===\n\n");

    /* Setup: Create GGM PRF family */
    PRG* prg = prg_create_toy_length_doubling(64);
    PRF_Family* ggm_family = ggm_create_prf_family(prg, 32);
    printf("PRF family: n=%d, m=%d\n",
           ggm_family->key_len, ggm_family->input_len);

    /* Master key: the secret symmetric key */
    BitString* master_key = bs_create_random(64, 0xABCD);
    printf("\nMaster Key: ");
    bs_print_bits(master_key);

    /* Application 1: Derive encryption key from master key */
    printf("\n--- Application 1: Encryption Key Derivation ---\n");
    BitString* salt1 = bs_create(16);
    for (int i = 0; i < 16; i++) bs_set_bit(salt1, i, i % 3 == 0);
    BitString* context1 = bs_create(16);
    for (int i = 0; i < 16; i++) bs_set_bit(context1, i, (i/4) % 2);

    /* KDF_derive(salt, context) = F_{master}(salt || context) */
    BitString* enc_key = ggm_kdf_derive(ggm_family, master_key, salt1, context1);
    printf("  Salt:     ");
    bs_print_bits(salt1);
    printf("  Context:  ");
    bs_print_bits(context1);
    printf("  Enc Key:  ");
    bs_print_bits(enc_key);

    /* Application 2: Derive MAC key with different context */
    printf("\n--- Application 2: MAC Key Derivation ---\n");
    BitString* salt2 = bs_create(16);
    for (int i = 0; i < 16; i++) bs_set_bit(salt2, i, (i * 7 + 3) % 2);
    BitString* context2 = bs_create(16);
    for (int i = 0; i < 16; i++) bs_set_bit(context2, i, 1);

    BitString* mac_key = ggm_kdf_derive(ggm_family, master_key, salt2, context2);
    printf("  Salt:     ");
    bs_print_bits(salt2);
    printf("  Context:  ");
    bs_print_bits(context2);
    printf("  MAC Key:  ");
    bs_print_bits(mac_key);

    /* Verify: different contexts produce different keys */
    printf("\n--- Verification: Key Separation ---\n");
    int equal = bs_equal(enc_key, mac_key);
    printf("  enc_key == mac_key: %s (should be 0)\n",
           equal ? "YES" : "NO");

    /* Application 3: Derive key for specific counter */
    printf("\n--- Application 3: Counter-based KDF ---\n");
    BitString* counter_inputs[3];
    BitString* counter_keys[3];
    for (int c = 0; c < 3; c++) {
        /* encode counter in input bits */
        char label[17];
        sprintf(label, "key-counter-%d", c);
        BitString* context = bs_create(32);
        for (int i = 0; i < (int)strlen(label) && i < 32; i++) {
            bs_set_bit(context, i, (label[i] >> 0) & 1);
        }
        counter_inputs[c] = context;
        counter_keys[c] = ggm_kdf_derive(ggm_family, master_key, salt1, context);
        printf("  Key %d: ", c);
        bs_print_bits(counter_keys[c]);
    }

    /* All derived keys should be distinct */
    int collisions = 0;
    for (int i = 0; i < 3; i++) {
        for (int j = i + 1; j < 3; j++) {
            if (bs_equal(counter_keys[i], counter_keys[j])) collisions++;
        }
    }
    printf("  Collisions among 3 derived keys: %d\n", collisions);

    /* Cleanup */
    bs_free(master_key);
    bs_free(salt1); bs_free(context1); bs_free(enc_key);
    bs_free(salt2); bs_free(context2); bs_free(mac_key);
    for (int c = 0; c < 3; c++) {
        bs_free(counter_inputs[c]);
        bs_free(counter_keys[c]);
    }
    free(ggm_family);
    prg_free(prg);

    printf("\n=== KDF Demo Complete ===\n");
    return 0;
}
