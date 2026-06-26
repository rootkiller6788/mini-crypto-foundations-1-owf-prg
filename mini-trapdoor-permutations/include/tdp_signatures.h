/**
 * tdp_signatures.h — Digital Signatures from Trapdoor Permutations
 *
 * A trapdoor permutation can be used "in reverse" to construct digital
 * signature schemes:
 *
 *   Sign_{sk}(m)  = f^{-1}_{sk}(H(m))    (apply inverse TDP to hash)
 *   Verify_{pk}(m,σ) = [f_{pk}(σ) == H(m)] (apply forward TDP to signature)
 *
 * The basic construction is "textbook RSA signatures" (not secure on their own).
 * Secure constructions include:
 *   - Full Domain Hash (FDH): Sign(m) = f^{-1}(H(m)) where H is modeled as RO.
 *   - Probabilistic Signature Scheme (PSS): adds randomness + hashing.
 *
 * Reference: Bellare & Rogaway, "Exact Security of Digital Signatures" (1996)
 *            (Full Domain Hash in the random oracle model)
 *            PKCS#1 v2.2 (RFC 8017) — RSA-PSS
 *            Goldwasser, Micali, Rivest, "A Digital Signature Scheme
 *            Secure Against Adaptive Chosen-Message Attacks" (1988)
 *
 * Course mapping:
 *   MIT 6.875 — Digital signatures from TDP
 *   Stanford CS255 — Signature schemes and security
 *   Berkeley CS276 — EUF-CMA security
 *   Princeton COS 551 — RSA-based signatures
 *   ETH 263-4660 — PKCS#1 implementations
 */

#ifndef TDP_SIGNATURES_H
#define TDP_SIGNATURES_H

#include <stddef.h>
#include "tdp_core.h"
#include "rsa.h"

/* ──── Signature Security Definitions ──── */

/**
 * EUF-CMA (Existential Unforgeability under Chosen-Message Attack):
 * A signature scheme (Gen, Sign, Verify) is EUF-CMA secure if for all PPT A:
 *   Pr[Verify_{pk}(m*, σ*) = 1 ∧ m* ∉ Q] ≤ negl(λ)
 * where (pk, sk) ← Gen(1^λ), (m*, σ*) ← A^{Sign_{sk}(·)}(pk),
 * and Q is the set of messages queried to the signing oracle.
 *
 * Reference: Goldwasser, Micali, Rivest (1988).
 */

typedef enum {
    SIG_SEC_EUF_CMA = 0,     /* Standard EUF-CMA */
    SIG_SEC_SUF_CMA = 1,     /* Strong unforgeability */
    SIG_SEC_EUF_NA_CMA = 2,  /* Non-adaptive CMA */
} sig_security_level_t;

/**
 * Signature structure.
 */
typedef struct {
    bigint_t sigma;          /* Main signature component */
    uint8_t salt[64];        /* Optional random salt (for PSS) */
    size_t salt_len;
    uint8_t hash_output[64]; /* Hash value that was signed */
    size_t hash_len;
} signature_t;

/**
 * Signature key pair (wraps TDP key with inverse role).
 * Note: In signatures, sk is used for signing (TDP inverse) and
 * pk is used for verification (TDP forward), thus reversing the
 * encryption roles.
 */
typedef struct {
    tdp_keypair_t tdp_key;
    sig_security_level_t sec_level;
} sig_keypair_t;

/* ──── Hash Function Abstraction ──── */

/**
 * Simple hash function used for signature hashing.
 * In practice, this would be SHA-256/SHA-512, but for educational
 * purposes we use a simple Merkle-Damgård-like construction.
 *
 * Complexity: O(len(input)).
 */
void sig_hash(uint8_t *output, size_t *output_len,
              const uint8_t *input, size_t input_len,
              size_t target_bits);

/* ──── Textbook RSA Signatures (INSECURE — education only) ──── */

/**
 * Textbook RSA signature: σ = m^d mod n.
 * WARNING: Insecure due to:
 *   1. No hashing → existential forgery (sign random σ, claim m = σ^e).
 *   2. Multiplicative homomorphism → forgery (σ1*σ2 is valid for m1*m2).
 *   3. Chosen-message attacks.
 *
 * Included for educational purposes to demonstrate why padding/hashing is required.
 *
 * Complexity: O(log d * log^2 n).
 */
signature_t rsa_textbook_sign(const rsa_keypair_t *key, const bigint_t *message);

/**
 * Textbook RSA verification: check σ^e mod n == m.
 * Complexity: O(log e * log^2 n).
 */
bool rsa_textbook_verify(const rsa_params_t *params, const bigint_t *message,
                          const signature_t *signature);

/* ──── Full Domain Hash (FDH) — EUF-CMA in ROM ──── */

/**
 * FDH signature: σ = H(m)^d mod n.
 * Where H: {0,1}* → Z_n^* is a hash function modeled as a random oracle.
 *
 * Security: EUF-CMA secure in the random oracle model, assuming the RSA
 * assumption holds.
 *
 * Intuition: The random oracle model forces H(m) to be a truly random
 * element in Z_n^*. An adversary that can forge FDH signatures can be
 * used to compute RSA inverses on random elements, breaking the RSA
 * assumption.
 *
 * Complexity: O(log d * log^2 n).
 *
 * Reference: Bellare & Rogaway, "The Exact Security of Digital Signatures
 *            — How to Sign with RSA and Rabin" (EUROCRYPT 1996).
 */
signature_t rsa_fdh_sign(const rsa_keypair_t *key,
                           const uint8_t *message, size_t msg_len);

/**
 * FDH verification: σ^e mod n == H(m).
 * Complexity: O(log e * log^2 n).
 */
bool rsa_fdh_verify(const rsa_params_t *params,
                      const uint8_t *message, size_t msg_len,
                      const signature_t *signature);

/* ──── Probabilistic Signature Scheme (PSS) — EUF-CMA ──── */

/**
 * RSA-PSS signature as specified in PKCS#1 v2.2 / RFC 8017.
 *
 * PSS encoding:
 *   - M' = (0x00...00 || Hash(m) || salt) padded.
 *   - DB = M' || 0x00...00 || 0x01.
 *   - maskedDB = DB ⊕ MGF(seed).
 *   - EM = maskedDB || seed || 0xBC.
 *   - σ = EM^d mod n.
 *
 * PSS achieves tight security reduction to the RSA assumption.
 *
 * Complexity: O(log d * log^2 n) for RSA + O(|m| + salt_len) for PSS.
 *
 * Reference: Bellare & Rogaway, "PSS: Provably Secure Encoding Method
 *            for Digital Signatures" (submission to IEEE P1363, 1998).
 *            RFC 8017, §8.1.
 */
signature_t rsa_pss_sign(const rsa_keypair_t *key,
                            const uint8_t *message, size_t msg_len,
                            const uint8_t *salt, size_t salt_len);

/**
 * RSA-PSS verification.
 * Returns false if the PSS encoding check fails.
 *
 * Complexity: O(log e * log^2 n).
 */
bool rsa_pss_verify(const rsa_params_t *params,
                      const uint8_t *message, size_t msg_len,
                      const signature_t *signature);

/* ──── Common Forgery Attacks (Educational) ──── */

/**
 * Demonstrate existential forgery on textbook RSA signatures:
 * Given only pk = (n, e), an attacker can:
 *   1. Choose arbitrary σ ∈ Z_n^*.
 *   2. Compute m = σ^e mod n.
 *   3. Claim (m, σ) as a valid message-signature pair.
 *
 * This shows why hashing is essential: without it, any σ is a valid
 * signature on some message.
 *
 * Complexity: O(log e * log^2 n).
 */
void rsa_demonstrate_existential_forgery(const rsa_params_t *params,
                                           bigint_t *forged_message,
                                           signature_t *forged_signature);

/**
 * Demonstrate multiplicative forgery on textbook RSA:
 * Given valid signatures σ1 on m1, σ2 on m2:
 *   σ = σ1 * σ2 mod n is a valid signature on m = m1 * m2 mod n.
 *
 * Complexity: O(log^2 n).
 */
void rsa_demonstrate_multiplicative_forgery(const rsa_params_t *params,
                                              const bigint_t *m1, const signature_t *sig1,
                                              const bigint_t *m2, const signature_t *sig2,
                                              bigint_t *forged_message,
                                              signature_t *forged_signature);

/* ──── Signature Security Analysis ──── */

/**
 * Check if a signature scheme meets a target security level.
 * Complexity: O(1) — informational.
 */
const char *sig_security_level_name(sig_security_level_t level);

/**
 * Compute the concrete security bound for FDH-RSA.
 * In the random oracle model, if the RSA problem is (t, ε)-hard, then
 * FDH-RSA is (t', ε')-secure where:
 *   ε' ≤ q_s * q_h * ε
 * where q_s = signing queries, q_h = hash queries.
 *
 * Reference: Bellare & Rogaway (1996), Theorem 6.1.
 */
double sig_fdh_security_bound(double rsa_advantage,
                                uint32_t signing_queries,
                                uint32_t hash_queries);

#endif /* TDP_SIGNATURES_H */
