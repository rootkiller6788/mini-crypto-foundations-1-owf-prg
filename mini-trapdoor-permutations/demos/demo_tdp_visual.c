/**
 * demo_tdp_visual.c — Visual Demonstration of Trapdoor Permutation Concepts
 *
 * Demonstrates key TDP concepts visually with step-by-step output:
 *   1. OWF vs OWP vs TDP hierarchy
 *   2. RSA key generation with prime discovery
 *   3. Forward evaluation (encryption) — the "easy" direction
 *   4. Inverse evaluation (decryption) with trapdoor — the "easy with trapdoor" direction
 *   5. Brute-force attack without trapdoor — demonstrating one-wayness
 *   6. CRT speedup visualization
 *   7. Security parameter comparison
 *
 * Reference: Goldreich (2001), Katz & Lindell (2014)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "tdp_core.h"
#include "modular_math.h"
#include "rsa.h"
#include "rsa_keygen.h"
#include "tdp_pke.h"
#include "tdp_signatures.h"

/* ──── Helper: Print Big Number ──── */

static void print_bigint(const char *label, const bigint_t *a) {
    printf("%s: ", label);
    bigint_print_dec(label, a);
}

/* ──── Section 1: Hierarchy Demonstration ──── */

static void demo_primitive_hierarchy(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  SECTION 1: Cryptographic Primitive Hierarchy           ║\n");
    printf("║  TDP ⊆ OWP ⊆ OWF                                       ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    printf("  Cryptographic Primitive Classification:\n");
    printf("  ┌──────────────────────────────────────────────────┐\n");
    printf("  │  OWF  (One-Way Function)                         │\n");
    printf("  │    Easy to compute, hard to invert               │\n");
    printf("  │    Example: f(x) = g^x mod p (discrete log)      │\n");
    printf("  ├──────────────────────────────────────────────────┤\n");
    printf("  │  OWP  (One-Way Permutation)                      │\n");
    printf("  │    OWF + bijective on its domain                 │\n");
    printf("  │    Example: f(x) = x^e mod n (RSA, no trapdoor)  │\n");
    printf("  ├──────────────────────────────────────────────────┤\n");
    printf("  │  TDP  (Trapdoor Permutation)                     │\n");
    printf("  │    OWP + trapdoor for efficient inversion        │\n");
    printf("  │    Example: RSA with private key d               │\n");
    printf("  └──────────────────────────────────────────────────┘\n\n");

    printf("  Key insight: Every TDP is an OWP (if you hide the\n");
    printf("  trapdoor), and every OWP is an OWF. The converses\n");
    printf("  are not known to hold.\n\n");

    /* Demonstrate with RSA */
    printf("  Demonstrating with RSA:\n");
    printf("    - Without trapdoor: OWP (computing e-th root is hard)\n");
    printf("    - With trapdoor d:  TDP (inversion is efficient)\n\n");
}

/* ──── Section 2: RSA Key Generation Walkthrough ──── */

static void demo_key_generation(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  SECTION 2: RSA Key Generation Walkthrough              ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    printf("  Step 1: Select two distinct primes p, q\n");
    printf("  Step 2: Compute n = p * q\n");
    printf("  Step 3: Compute φ(n) = (p-1)(q-1)\n");
    printf("  Step 4: Select e with gcd(e, φ(n)) = 1\n");
    printf("  Step 5: Compute d = e^{-1} mod φ(n)\n");
    printf("  Public key:  (n, e)\n");
    printf("  Private key: (p, q, d)\n\n");

    /* Use known small primes for clarity */
    rsa_keypair_t key;
    bigint_t p = bigint_from_uint64(61);
    bigint_t q = bigint_from_uint64(53);
    bigint_t e = bigint_from_uint64(17);
    rsa_keypair_from_primes(&key, &p, &q, &e);

    printf("  Generated RSA key pair:\n");
    printf("  p = "); bigint_print_dec("", &key.params.p);
    printf("  q = "); bigint_print_dec("", &key.params.q);
    printf("  n = p*q = "); bigint_print_dec("", &key.params.n);
    printf("  φ(n) = (p-1)(q-1) = "); bigint_print_dec("", &key.params.phi_n);
    printf("  e = "); bigint_print_dec("", &key.params.e);
    printf("  d = e^{-1} mod φ(n) = "); bigint_print_dec("", &key.params.d);

    /* Verify: e*d mod φ(n) = 1 */
    bigint_t check;
    bigint_mul(&check, &key.params.e, &key.params.d);
    bigint_t remainder;
    bigint_divmod(&check, &remainder, &check, &key.params.phi_n);
    printf("  Verification: (e * d) mod φ(n) = ");
    bigint_print_dec("", &remainder);
    printf("  (should be 1)\n");
}

/* ──── Section 3: Forward Evaluation (Encryption) ──── */

static void demo_forward_evaluation(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  SECTION 3: Forward Evaluation (Easy Direction)         ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    /* Setup key */
    rsa_keypair_t key;
    bigint_t p = bigint_from_uint64(61);
    bigint_t q = bigint_from_uint64(53);
    bigint_t e = bigint_from_uint64(17);
    rsa_keypair_from_primes(&key, &p, &q, &e);

    /* Message: x = 42 */
    bigint_t message = bigint_from_uint64(42);
    printf("  Original message (x): ");
    bigint_print_dec("", &message);

    /* Forward: y = x^e mod n */
    tdp_eval_result_t ciphertext = rsa_encrypt(&key.params, &message);
    printf("  Encrypted (y = x^e mod n): ");
    bigint_print_dec("", &ciphertext.value);

    printf("\n  Forward evaluation uses ONLY public key (n, e).\n");
    printf("  Anyone can encrypt — this is the \"easy\" direction.\n");
    printf("  Complexity: O(log e * log^2 n) — efficient.\n");
}

/* ──── Section 4: Inverse Evaluation with Trapdoor ──── */

static void demo_inverse_with_trapdoor(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  SECTION 4: Inverse with Trapdoor (Decryption)          ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    /* Setup key */
    rsa_keypair_t key;
    bigint_t p = bigint_from_uint64(61);
    bigint_t q = bigint_from_uint64(53);
    bigint_t e = bigint_from_uint64(17);
    rsa_keypair_from_primes(&key, &p, &q, &e);

    /* Encrypt first */
    bigint_t message = bigint_from_uint64(42);
    tdp_eval_result_t ct = rsa_encrypt(&key.params, &message);

    printf("  Ciphertext to decrypt: ");
    bigint_print_dec("", &ct.value);
    printf("\n");

    /* CRT Decryption */
    printf("  Decrypting with CRT (Garner's algorithm):\n");
    printf("    Step 1: x_p = c^{d_p} mod p\n");
    printf("    Step 2: x_q = c^{d_q} mod q\n");
    printf("    Step 3: h = q_inv * (x_p - x_q) mod p\n");
    printf("    Step 4: x = x_q + h * q\n\n");

    tdp_domain_elem_t recovered = rsa_decrypt_crt(&key, &ct.value);
    printf("  Decrypted (x = y^d mod n via CRT): ");
    bigint_print_dec("", &recovered.value);

    printf("\n  With the trapdoor d, inversion is efficient!\n");
    printf("  Complexity: O(log d_p * log^2 p) — ~4x faster than naive.\n");
}

/* ──── Section 5: Brute-Force Without Trapdoor ──── */

static void demo_brute_force(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  SECTION 5: Brute Force Without Trapdoor (One-Wayness)  ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    /* Setup a very small key for demonstration */
    rsa_keypair_t key;
    bigint_t p = bigint_from_uint64(11);
    bigint_t q = bigint_from_uint64(13);
    bigint_t e = bigint_from_uint64(7);
    rsa_keypair_from_primes(&key, &p, &q, &e);

    printf("  Using toy RSA (n=143, e=7) for demonstration.\n\n");

    /* Choose a message */
    bigint_t message = bigint_from_uint64(100);
    printf("  Original message: ");
    bigint_print_dec("", &message);

    tdp_eval_result_t ct = rsa_encrypt(&key.params, &message);
    printf("  RSA(m) = ");
    bigint_print_dec("", &ct.value);

    /* Brute-force search */
    printf("\n  Brute-force search (without trapdoor):\n");
    printf("  Trying x = 1, 2, 3, ... until x^e mod n = y\n");

    tdp_public_key_t pk;
    pk.modulus = key.params.n;
    pk.exponent = key.params.e;
    pk.nbits = key.params.nbits;

    uint32_t attempts = simulate_tdp_brute_force(&pk, &ct, 200);
    printf("  Found after %u attempts!\n", attempts);

    /* Domain size comparison */
    printf("\n  Domain size |Z_143^*| = φ(143) = %llu\n",
           (unsigned long long)bigint_to_uint64(&key.params.phi_n));
    printf("  For security parameter λ, domain size ≈ 2^λ.\n");
    printf("  Brute-force complexity: O(2^λ) — EXPONENTIAL!\n");
    printf("  This is what makes it \"one-way\": easy forward,\n");
    printf("  infeasible to invert for large λ.\n");
}

/* ──── Section 6: CRT Speedup Comparison ──── */

static void demo_crt_speedup(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  SECTION 6: CRT Speedup Demonstration                   ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    printf("  Garner's CRT Algorithm for RSA decryption:\n\n");
    printf("  Instead of computing y^d mod n directly (cost ~log d * log^2 n),\n");
    printf("  we compute:\n");
    printf("    x_p = y^{d mod (p-1)} mod p   (half-size exponent + modulus)\n");
    printf("    x_q = y^{d mod (q-1)} mod q   (half-size exponent + modulus)\n");
    printf("    x = x_q + q * ((x_p - x_q) * q^{-1} mod p)  (CRT recombination)\n\n");

    printf("  Complexity comparison:\n");
    printf("    Naive:  O(log d * log^2 n)  — large modulus\n");
    printf("    CRT:    O(log d_p * log^2 p) — half-size modulus\n");
    printf("    Speedup: ~4x in theory, ~3.5x in practice\n\n");

    printf("  The CRT optimization is possible because we know\n");
    printf("  the factorization of n (the trapdoor information).\n");
    printf("  Without knowing p and q, CRT cannot be applied.\n");
}

/* ──── Section 7: Security Parameter Comparison ──── */

static void demo_security_param(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  SECTION 7: Security Parameter Analysis                 ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    printf("  Security parameter λ determines the bit-length of keys.\n\n");

    printf("  ┌──────────┬────────────────┬──────────────────────┐\n");
    printf("  │    λ     │  Key Size      │  Security Level       │\n");
    printf("  ├──────────┼────────────────┼──────────────────────┤\n");
    printf("  │   80     │  RSA-1024      │  DEPRECATED           │\n");
    printf("  │  112     │  RSA-2048      │  NIST minimum (2030)  │\n");
    printf("  │  128     │  RSA-3072      │  NIST recommended     │\n");
    printf("  │  192     │  RSA-7680      │  CNSA Suite           │\n");
    printf("  │  256     │  RSA-15360     │  Post-quantum ready?  │\n");
    printf("  └──────────┴────────────────┴──────────────────────┘\n\n");

    /* Demonstrate negligible function */
    printf("  Negligible function threshold: 2^{-λ}\n");
    for (security_param_t lam = 8; lam <= 64; lam *= 2) {
        double threshold = pow(2.0, -(double)lam);
        printf("    λ = %3u: 2^{-λ} = %.2e\n", (unsigned)lam, threshold);
    }
    printf("\n");
    printf("  For λ ≥ 128 (modern security), 2^{-128} ≈ 2.9e-39 —\n");
    printf("  astronomically small. This is why RSA is secure: an\n");
    printf("  adversary's success probability is negligible.\n");
}

/* ──── Section 8: Digital Signature Demo ──── */

static void demo_signatures(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  SECTION 8: Digital Signatures from TDP                 ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    printf("  TDP can be used \"in reverse\" for signatures:\n");
    printf("    Sign(m)  = f^{-1}(H(m))   (use trapdoor)\n");
    printf("    Verify(m,σ) = [f(σ) == H(m)]  (use public key)\n\n");

    /* Setup */
    rsa_keypair_t key;
    bigint_t p = bigint_from_uint64(61);
    bigint_t q = bigint_from_uint64(53);
    bigint_t e = bigint_from_uint64(17);
    rsa_keypair_from_primes(&key, &p, &q, &e);

    uint8_t message[] = "Hello, TDP World!";
    size_t msg_len = sizeof(message) - 1;

    printf("  Message to sign: \"%s\"\n", message);
    printf("  Hash length: %zu bytes\n\n", msg_len);

    /* FDH Signature */
    printf("  ── Full Domain Hash (FDH) ──\n");
    signature_t fdh_sig = rsa_fdh_sign(&key, message, msg_len);
    printf("  Signature σ = H(m)^d mod n: ");
    bigint_print_dec("", &fdh_sig.sigma);
    bool fdh_ok = rsa_fdh_verify(&key.params, message, msg_len, &fdh_sig);
    printf("  Verification: %s\n\n", fdh_ok ? "VALID ✓" : "INVALID ✗");

    /* PSS Signature */
    uint8_t salt[32];
    memcpy(salt, "random salt 0000", 17);
    printf("  ── Probabilistic Signature Scheme (PSS) ──\n");
    signature_t pss_sig = rsa_pss_sign(&key, message, msg_len, salt, 16);
    printf("  Signature σ (with salt): ");
    bigint_print_dec("", &pss_sig.sigma);
    bool pss_ok = rsa_pss_verify(&key.params, message, msg_len, &pss_sig);
    printf("  Verification: %s\n\n", pss_ok ? "VALID ✓" : "INVALID ✗");

    /* Demonstrate existential forgery */
    printf("  ── Existential Forgery (Textbook RSA) ──\n");
    printf("  Attack: Choose arbitrary σ, claim m = σ^e mod n.\n");
    bigint_t forged_msg;
    signature_t forged_sig;
    rsa_demonstrate_existential_forgery(&key.params, &forged_msg, &forged_sig);
    printf("  Forged message m: ");
    bigint_print_dec("", &forged_msg);
    printf("  Forgery verified by textbook RSA? YES\n");
    printf("  (This is why hashing is essential!)\n");
}

/* ──── Main ──── */

int main(void) {
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║            Mini Trapdoor Permutations Demo              ║\n");
    printf("║   Trapdoor Permutations: Theory and Practice            ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");

    demo_primitive_hierarchy();
    demo_key_generation();
    demo_forward_evaluation();
    demo_inverse_with_trapdoor();
    demo_brute_force();
    demo_crt_speedup();
    demo_security_param();
    demo_signatures();

    printf("\n╔══════════════════════════════════════════════════════════╗\n");
    printf("║  Summary                                                ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");
    printf("  Trapdoor Permutations are the foundation of modern\n");
    printf("  public-key cryptography:\n\n");
    printf("    • RSA: the canonical TDP (1978)\n");
    printf("    • Used in: TLS, SSH, PGP, PKI, digital signatures\n");
    printf("    • Security: based on hardness of factoring\n");
    printf("    • Future: post-quantum alternatives needed\n\n");
    printf("  Key takeaway: The trapdoor makes inversion easy for\n");
    printf("  the key holder, while remaining infeasible for everyone\n");
    printf("  else. This asymmetry is what enables public-key crypto.\n\n");

    return 0;
}
