/**
 * tdp_pke.h — Public-Key Encryption from Trapdoor Permutations
 *
 * A trapdoor permutation can be used to construct a public-key encryption
 * scheme. The basic (textbook) construction is:
 *
 *   Enc_{pk}(m) = f_{pk}(m)           (apply TDP to message)
 *   Dec_{sk}(c)  = f^{-1}_{sk}(c)     (invert using trapdoor)
 *
 * However, this textbook scheme is NOT IND-CPA secure (it's deterministic
 * and homomorphic). To achieve security, we need:
 *   1. Hard-core bits (Goldreich-Levin): Encrypt m XOR hc-bits.
 *   2. OAEP (Optimal Asymmetric Encryption Padding): CCA-secure scheme.
 *   3. Randomized padding + hashing (RSA-OAEP in PKCS#1 v2+).
 *
 * Reference: Bellare & Rogaway, "Optimal Asymmetric Encryption" (EUROCRYPT 1994)
 *            Fujisaki, Okamoto, Pointcheval, Stern, "RSA-OAEP is Secure" (CRYPTO 2001)
 *            Katz & Lindell (2014), Ch. 10
 *
 * Course mapping:
 *   MIT 6.875 — Public-key encryption constructions
 *   Stanford CS255 — IND-CPA, IND-CCA definitions
 *   Berkeley CS276 — TDP → PKE reduction
 *   CMU 15-856 — Advanced cryptography
 */

#ifndef TDP_PKE_H
#define TDP_PKE_H

#include <stddef.h>
#include "tdp_core.h"
#include "rsa.h"

/* ──── PKE Security Definitions ──── */

/**
 * IND-CPA (Indistinguishability under Chosen-Plaintext Attack):
 * A PKE scheme (Gen, Enc, Dec) is IND-CPA secure if for all PPT A:
 *   |Pr[A(pk, Enc_{pk}(m_0)) = 1] - Pr[A(pk, Enc_{pk}(m_1)) = 1]| ≤ negl(λ)
 * where (pk, sk) ← Gen(1^λ), (m_0, m_1) ← A(pk), and |m_0| = |m_1|.
 *
 * Reference: Goldwasser & Micali (1984); Goldreich (2004), §5.2.
 */

typedef enum {
    PKE_SEC_IND_CPA = 0,   /* Indistinguishability under CPA */
    PKE_SEC_IND_CCA1 = 1,  /* Non-adaptive CCA */
    PKE_SEC_IND_CCA2 = 2,  /* Adaptive CCA (strongest) */
} pke_security_level_t;

/**
 * PKE ciphertext structure.
 */
typedef struct {
    bigint_t c0;       /* Main ciphertext component (TDP output) */
    uint8_t c1[64];    /* Padding/hard-core bits (up to 512 bits) */
    size_t c1_len;     /* Actual length of padding component */
} pke_ciphertext_t;

/**
 * PKE key pair wrapping a TDP key pair.
 */
typedef struct {
    tdp_keypair_t tdp_key;
    pke_security_level_t sec_level;
} pke_keypair_t;

/* ──── Textbook PKE (INSECURE — for education only) ──── */

/**
 * Textbook RSA encryption: c = m^e mod n.
 * WARNING: This is deterministic and homomorphic; not IND-CPA secure.
 * Included for educational purposes to demonstrate why padding is needed.
 *
 * Complexity: O(log e * log^2 n).
 */
pke_ciphertext_t pke_textbook_encrypt(const rsa_params_t *params, const bigint_t *message);

/**
 * Textbook RSA decryption: m = c^d mod n.
 * Complexity: O(log d * log^2 n).
 */
bool pke_textbook_decrypt(const rsa_keypair_t *key, const pke_ciphertext_t *ciphertext,
                          bigint_t *message_out);

/* ──── Hard-Core Bit Based PKE (IND-CPA Secure) ──── */

/**
 * Goldreich-Levin hard-core bit construction adapted for TDP.
 *
 * Given a TDP f, define hc(x, r) = ⊕_{i} x_i ∧ r_i (the GL bit).
 * The encryption:
 *   1. Sample random x, r.
 *   2. Compute c0 = f(x).
 *   3. Compute c1 = m ⊕ hc(x, r).
 *   4. Output (c0, r, c1).
 *
 * Decryption (with trapdoor):
 *   1. Recover x = f^{-1}(c0).
 *   2. Compute m = c1 ⊕ hc(x, r).
 *
 * This achieves IND-CPA security assuming f is a TDP.
 *
 * Complexity: O(log^3 n) per encryption.
 *
 * Reference: Goldreich & Levin, "A Hard-Core Predicate for All One-Way
 *            Functions" (STOC 1989).
 */
pke_ciphertext_t pke_gl_encrypt(const tdp_public_key_t *pk, uint8_t message_bit,
                                 const bigint_t *r, const bigint_t *x);

/**
 * Decrypt a GL-encrypted bit using the trapdoor.
 * Complexity: O(log^3 n).
 */
uint8_t pke_gl_decrypt(const tdp_public_key_t *pk, const tdp_trapdoor_t *td,
                       const pke_ciphertext_t *ciphertext);

/* ──── OAEP (Optimal Asymmetric Encryption Padding) ──── */

/**
 * OAEP: a padding scheme for TDP that achieves IND-CCA2 security in the
 * random oracle model.
 *
 * OAEP(m, r) = s || t where:
 *   s = (m || 0^{k0}) ⊕ G(r)
 *   t = r ⊕ H(s)
 * Output: E(s || t) where E is the TDP forward evaluation.
 *
 * Parameters:
 *   k0: security parameter for zero-padding (typically 128 or 256).
 *   k1: random seed length.
 *   G, H: hash functions modeled as random oracles.
 *
 * Complexity: O(|m| + k0 + k1).
 *
 * Reference: Bellare & Rogaway (EUROCRYPT 1994).
 *            PKCS#1 v2.2 (RFC 8017).
 */
bool pke_oaep_pad(uint8_t *padded, size_t *padded_len,
                   const uint8_t *message, size_t msg_len,
                   const uint8_t *r, size_t r_len,
                   size_t k0);

/**
 * OAEP unpadding: recover message from OAEP-padded data.
 * Returns false if the zero-padding check fails.
 * Complexity: O(|padded|).
 */
bool pke_oaep_unpad(uint8_t *message, size_t *msg_len,
                     const uint8_t *padded, size_t padded_len,
                     size_t k0);

/* ──── Full OAEP-RSA Encryption ──── */

/**
 * RSA-OAEP encryption (as specified in PKCS#1 v2.2 / RFC 8017).
 * This is the industry-standard IND-CCA2 secure scheme.
 *
 * Complexity: O(log^3 n) for RSA + O(k0+k1) for OAEP.
 */
pke_ciphertext_t pke_rsa_oaep_encrypt(const rsa_keypair_t *key,
                                        const uint8_t *message, size_t msg_len,
                                        const uint8_t *label, size_t label_len,
                                        const uint8_t *seed);

/**
 * RSA-OAEP decryption.
 * Returns false if padding check fails (invalid ciphertext).
 *
 * Complexity: O(log^3 n).
 */
bool pke_rsa_oaep_decrypt(const rsa_keypair_t *key,
                            const pke_ciphertext_t *ciphertext,
                            uint8_t *message, size_t *msg_len,
                            const uint8_t *label, size_t label_len);

/* ──── Security Notions Comparison ──── */

/**
 * Compare different PKE security notions.
 * IND-CPA < IND-CCA1 < IND-CCA2 in terms of strength.
 *
 * Textbook RSA: None (deterministic, homomorphic).
 * RSA + GL bit: IND-CPA.
 * RSA-OAEP: IND-CCA2 (in ROM).
 */
const char *pke_security_level_name(pke_security_level_t level);

/**
 * Check if a PKE scheme built from a TDP satisfies a target security level.
 * Complexity: O(1) — informational.
 */
bool pke_check_security_level(pke_security_level_t achieved,
                               pke_security_level_t target);

/* ──── Brute-force / Attack Simulation ──── */

/**
 * Simulate a naive brute-force inversion attempt on a TDP.
 * This demonstrates concretely why the trapdoor is essential:
 * without it, the best generic attack is exhaustive search over the domain.
 *
 * Complexity: O(|domain|) which is exponential in λ.
 */
uint32_t simulate_tdp_brute_force(const tdp_public_key_t *pk,
                                   const tdp_eval_result_t *y,
                                   uint32_t max_attempts);

#endif /* TDP_PKE_H */
