/**
 * example_rsa_full.c -- Full RSA Demo with PKE
 *
 * Demonstrates the complete RSA life cycle:
 *   1. Key generation with known small primes (deterministic)
 *   2. Public-key encryption (RSA-OAEP style)
 *   3. Decryption with CRT optimization
 *   4. RSA homomorphism demonstration
 *   5. Random self-reducibility
 *   6. Comparative timing (naive vs CRT)
 *   7. Textbook vs OAEP security comparison
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "tdp_core.h"
#include "modular_math.h"
#include "rsa.h"
#include "rsa_keygen.h"
#include "tdp_pke.h"

int main(void) {
    printf("========================================\n");
    printf("  Full RSA Cryptosystem Demo\n");
    printf("========================================\n\n");

    /* Step 1: Key generation with known small primes */
    printf("[1] Generating RSA key pair (p=11, q=17, e=3)...\n");
    rsa_keypair_t key;
    bigint_t p = bigint_from_uint64(11);
    bigint_t q = bigint_from_uint64(17);
    bigint_t e = bigint_from_uint64(3);
    tdp_status_t status = rsa_keypair_from_primes(&key, &p, &q, &e);
    if (status != TDP_SUCCESS) {
        printf("Key generation FAILED!\n");
        return 1;
    }
    printf("    n = 11 * 17 = 187\n");
    printf("    phi(n) = 10 * 16 = 160\n");
    printf("    e = 3, d = 107 (3*107 = 321 = 2*160 + 1)\n\n");

    bigint_print_hex("    p      = ", &key.params.p);
    bigint_print_hex("    q      = ", &key.params.q);
    bigint_print_hex("    n      = ", &key.params.n);
    bigint_print_hex("    e      = ", &key.params.e);
    bigint_print_hex("    d      = ", &key.params.d);
    printf("\n");

    /* Step 2: Encryption */
    printf("[2] RSA Encryption...\n");
    bigint_t message = bigint_from_uint64(42);
    printf("    Original message: ");
    bigint_print_dec("", &message);

    tdp_eval_result_t ciphertext = rsa_encrypt(&key.params, &message);
    if (!ciphertext.valid) {
        printf("Encryption FAILED!\n");
        return 1;
    }
    printf("    Ciphertext (42^3 mod 187): ");
    bigint_print_dec("", &ciphertext.value);
    printf("\n");

    /* Step 3: Decryption with CRT */
    printf("[3] RSA Decryption (CRT-accelerated)...\n");
    tdp_domain_elem_t decrypted = rsa_decrypt_crt(&key, &ciphertext.value);
    if (!decrypted.in_domain) {
        printf("Decryption FAILED!\n");
        return 1;
    }
    printf("    Decrypted message: ");
    bigint_print_dec("", &decrypted.value);
    printf("    Roundtrip success: %s\n",
           bigint_compare(&decrypted.value, &message) == 0 ? "YES" : "NO");
    printf("\n");

    /* Step 4: Compare CRT vs Naive */
    printf("[4] Decryption comparison (CRT vs Naive)...\n");
    tdp_domain_elem_t dec_naive = rsa_decrypt_naive(&key.params, &ciphertext.value);
    printf("    CRT result: ");
    bigint_print_dec("", &decrypted.value);
    printf("    Naive result: ");
    bigint_print_dec("", &dec_naive.value);
    printf("    Identical: %s\n\n",
           bigint_compare(&decrypted.value, &dec_naive.value) == 0 ? "YES" : "NO");

    /* Step 5: Homomorphism */
    printf("[5] RSA Multiplicative Homomorphism...\n");
    bigint_t x1 = bigint_from_uint64(5);
    bigint_t x2 = bigint_from_uint64(7);
    printf("    x1 = 5, x2 = 7\n");
    printf("    Enc(x1) * Enc(x2) mod n == Enc(x1 * x2 mod n)?\n");
    bool homo = rsa_verify_homomorphism(&key.params, &x1, &x2);
    printf("    Result: %s\n", homo ? "YES (homomorphism holds)" : "NO");
    if (homo) {
        printf("    This means RSA is malleable -- OAEP padding is essential!\n");
    }
    printf("\n");

    /* Step 6: Random self-reducibility */
    printf("[6] Random Self-Reducibility of RSA...\n");
    bigint_t blinded_y, r, r_inv;
    rsa_random_self_reduce(&key.params, &ciphertext.value,
                            &blinded_y, &r, &r_inv);
    printf("    Original y  : ");
    bigint_print_dec("", &ciphertext.value);
    printf("    Blinded y   : ");
    bigint_print_dec("", &blinded_y);
    printf("    Random r    : ");
    bigint_print_dec("", &r);
    printf("    r^{-1} mod n: ");
    bigint_print_dec("", &r_inv);
    printf("\n");

    /* Step 7: PKE -- OAEP */
    printf("[7] RSA-OAEP Encryption/Decryption...\n");
    const char *test_msg = "Hello, Crypto!";
    uint8_t seed[32];
    memset(seed, 0xAB, 32);
    printf("    Message: \"%s\"\n", test_msg);

    pke_ciphertext_t ct = pke_rsa_oaep_encrypt(&key,
                                                (const uint8_t *)test_msg,
                                                strlen(test_msg),
                                                (const uint8_t *)"", 0, seed);
    printf("    OAEP ciphertext produced.\n");

    uint8_t recovered[256];
    size_t recovered_len = 0;
    bool ok = pke_rsa_oaep_decrypt(&key, &ct, recovered, &recovered_len,
                                    (const uint8_t *)"", 0);
    printf("    Decryption: %s\n", ok ? "SUCCESS" : "FAILURE");
    if (ok) {
        recovered[recovered_len] = '\0';
        printf("    Recovered: \"%s\"\n", recovered);
        printf("    Match: %s\n",
               memcmp(recovered, test_msg, recovered_len) == 0 ? "YES" : "NO");
    }
    printf("\n");

    /* Step 8: Security level comparison */
    printf("[8] Security Level Comparison...\n");
    printf("    Textbook RSA:  No security (deterministic, homomorphic)\n");
    printf("    RSA + GL bit:  IND-CPA secure\n");
    printf("    RSA-OAEP:      IND-CCA2 secure (in ROM)\n\n");

    printf("    Security progression:\n");
    printf("    %s < %s < %s (strength increases)\n",
           pke_security_level_name(PKE_SEC_IND_CPA),
           pke_security_level_name(PKE_SEC_IND_CCA1),
           pke_security_level_name(PKE_SEC_IND_CCA2));

    printf("\n========================================\n");
    printf("  Full RSA Demo Complete\n");
    printf("========================================\n");
    return 0;
}
