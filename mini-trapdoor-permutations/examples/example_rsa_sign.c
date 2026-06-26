/**
 * example_rsa_sign.c -- RSA Digital Signatures Demo
 *
 * Demonstrates digital signatures from RSA trapdoor permutation:
 *   1. Textbook RSA sign/verify
 *   2. Full Domain Hash (FDH) signature
 *   3. Probabilistic Signature Scheme (PSS)
 *   4. Existential forgery attack on textbook RSA
 *   5. Multiplicative forgery attack on textbook RSA
 *   6. Security comparison of the three schemes
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "tdp_core.h"
#include "modular_math.h"
#include "rsa.h"
#include "rsa_keygen.h"
#include "tdp_signatures.h"

int main(void) {
    printf("========================================\n");
    printf("  RSA Digital Signatures Demo\n");
    printf("========================================\n\n");

    /* Step 1: Generate key with small known primes */
    printf("[1] Key generation (p=11, q=17, e=3)...\n");
    rsa_keypair_t key;
    bigint_t p = bigint_from_uint64(11);
    bigint_t q = bigint_from_uint64(17);
    bigint_t e = bigint_from_uint64(3);
    if (rsa_keypair_from_primes(&key, &p, &q, &e) != TDP_SUCCESS) {
        printf("Key generation FAILED!\n");
        return 1;
    }
    printf("    n = 187, e = 3, d = 107\n\n");

    /* Step 2: Textbook RSA signatures */
    printf("[2] Textbook RSA Signatures (INSECURE -- demo only)...\n");
    bigint_t msg1 = bigint_from_uint64(42);
    printf("    Message: ");
    bigint_print_dec("", &msg1);

    signature_t sig1 = rsa_textbook_sign(&key, &msg1);
    printf("    Signature: ");
    bigint_print_dec("", &sig1.sigma);

    bool valid1 = rsa_textbook_verify(&key.params, &msg1, &sig1);
    printf("    Verification: %s\n\n", valid1 ? "VALID" : "INVALID");

    /* Step 3: FDH signatures */
    printf("[3] Full Domain Hash (FDH) Signatures -- EUF-CMA in ROM...\n");
    const char *message_fdh = "Alice pays Bob $100";
    printf("    Message: \"%s\"\n", message_fdh);

    signature_t sig_fdh = rsa_fdh_sign(&key,
                                        (const uint8_t *)message_fdh,
                                        strlen(message_fdh));
    printf("    FDH Signature produced.\n");

    bool valid_fdh = rsa_fdh_verify(&key.params,
                                     (const uint8_t *)message_fdh,
                                     strlen(message_fdh), &sig_fdh);
    printf("    Verification: %s\n", valid_fdh ? "VALID" : "INVALID");

    /* Tamper test */
    bool tampered = rsa_fdh_verify(&key.params,
                                    (const uint8_t *)"Alice pays Bob $101",
                                    strlen("Alice pays Bob $101"), &sig_fdh);
    printf("    Tampered msg verification: %s (should be INVALID)\n\n",
           tampered ? "VALID (BAD!)" : "INVALID");

    /* Step 4: PSS signatures */
    printf("[4] RSA-PSS Signatures -- tight security reduction...\n");
    const char *message_pss = "Transfer $500 to Charlie";
    uint8_t salt[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
    printf("    Message: \"%s\"\n", message_pss);

    signature_t sig_pss = rsa_pss_sign(&key,
                                        (const uint8_t *)message_pss,
                                        strlen(message_pss), salt, 8);
    printf("    PSS Signature produced.\n");

    bool valid_pss = rsa_pss_verify(&key.params,
                                     (const uint8_t *)message_pss,
                                     strlen(message_pss), &sig_pss);
    printf("    Verification: %s\n\n", valid_pss ? "VALID" : "INVALID");

    /* Step 5: Forgery demonstrations */
    printf("[5] Forgery Attacks on Textbook RSA...\n");

    printf("    --- Existential Forgery ---\n");
    printf("    Attack: choose random sigma, compute m = sigma^e mod n.\n");
    printf("    (m, sigma) is a valid message-signature pair!\n");
    bigint_t forged_msg;
    signature_t forged_sig;
    rsa_demonstrate_existential_forgery(&key.params, &forged_msg, &forged_sig);
    printf("    Forged message: ");
    bigint_print_dec("", &forged_msg);
    bool forged_valid = rsa_textbook_verify(&key.params, &forged_msg, &forged_sig);
    printf("    Forged signature verified: %s\n", forged_valid ? "YES (attack works!)" : "NO");

    printf("\n    --- Multiplicative Forgery ---\n");
    printf("    Given valid (m1, sig1) and (m2, sig2):\n");
    printf("    sig_forge = sig1 * sig2 mod n is valid on m_forge = m1 * m2 mod n.\n");
    bigint_t m1 = bigint_from_uint64(5);
    bigint_t m2 = bigint_from_uint64(7);
    signature_t sig_m1 = rsa_textbook_sign(&key, &m1);
    signature_t sig_m2 = rsa_textbook_sign(&key, &m2);
    bigint_t forged_msg2;
    signature_t forged_sig2;
    rsa_demonstrate_multiplicative_forgery(&key.params,
                                            &m1, &sig_m1, &m2, &sig_m2,
                                            &forged_msg2, &forged_sig2);
    printf("    Forged message (5*7 mod 187): ");
    bigint_print_dec("", &forged_msg2);
    bool forged_valid2 = rsa_textbook_verify(&key.params, &forged_msg2, &forged_sig2);
    printf("    Forged signature verified: %s\n", forged_valid2 ? "YES (attack works!)" : "NO");
    printf("\n");

    /* Step 6: Security comparison */
    printf("[6] Signature Scheme Security Comparison...\n");
    printf("    +------------------+---------------+-------------+\n");
    printf("    | Scheme           | Security      | Reduction   |\n");
    printf("    +------------------+---------------+-------------+\n");
    printf("    | Textbook RSA     | NONE          | N/A         |\n");
    printf("    | RSA-FDH          | EUF-CMA (ROM) | Loose (q*h) |\n");
    printf("    | RSA-PSS          | EUF-CMA (ROM) | Tight       |\n");
    printf("    +------------------+---------------+-------------+\n");
    printf("\n");

    printf("    Concrete FDH security bound:\n");
    printf("    If RSA advantage = 2^{-80}, signing queries = 2^{20}, hash queries = 2^{30}:\n");
    double bound = sig_fdh_security_bound(pow(2.0, -80), 1<<20, 1<<30);
    printf("    FDH advantage <= 2^{-80} * 2^{20} * 2^{30} = 2^{-30} ~= %.2e\n", bound);
    printf("    This is non-negligible! FDH needs larger RSA keys.\n");
    printf("    PSS has tight reduction (no factor), so advantage <= 2^{-80}.\n");

    printf("\n========================================\n");
    printf("  RSA Signatures Demo Complete\n");
    printf("========================================\n");
    return 0;
}
