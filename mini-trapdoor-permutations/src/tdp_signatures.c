/**
 * tdp_signatures.c -- Digital Signatures from Trapdoor Permutations
 *
 * Implements digital signature schemes from TDPs:
 *   1. Textbook RSA signatures (insecure -- educational only)
 *   2. Full Domain Hash (FDH) -- EUF-CMA secure in ROM
 *   3. Probabilistic Signature Scheme (PSS) -- tight reduction
 *   4. Common forgery demonstrations (existential, multiplicative)
 *
 * The core insight: a TDP can be used "in reverse" for signatures:
 *   Sign_{sk}(m)  = f^{-1}_{sk}(H(m))    (use trapdoor)
 *   Verify_{pk}(m,sigma) = [f_{pk}(sigma) == H(m)]
 *
 * This reverses the encryption role but uses the same TDP primitive.
 *
 * Reference: Bellare & Rogaway, "Exact Security of Digital Signatures" (1996)
 *            Goldwasser, Micali, Rivest, "Digital Signature Scheme Secure
 *            Against Adaptive Chosen-Message Attacks" (1988)
 *            PKCS#1 v2.2 (RFC 8017)
 */

#include "tdp_signatures.h"
#include "tdp_core.h"
#include "modular_math.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* =========================================================================
 * Hash Function -- Simple hash for signatures
 *
 * Educational implementation. In production, use SHA-256 or SHA-512.
 * The random oracle model assumes H is a truly random function.
 * ========================================================================= */

void sig_hash(uint8_t *output, size_t *output_len,
              const uint8_t *input, size_t input_len,
              size_t target_bits) {
    /* Hash input to target_bits bits of output.
     * Uses simple iterative mixing.
     *
     * Complexity: O(input_len).
     *
     * In the random oracle model: H(m) is uniform in {0,1}^{target_bits}
     * for each distinct m, independent of all other hash queries. */
    if (!output || !output_len || !input) return;

    size_t target_bytes = (target_bits + 7) / 8;
    uint32_t state = 0x6A09E667 ^ (uint32_t)input_len;

    for (size_t i = 0; i < input_len; i++) {
        state ^= (uint32_t)input[i] << ((i % 4) * 8);
        state = ((state << 13) | (state >> 19)) + 0xBB67AE85;
        state ^= state >> 16;
    }

    for (size_t i = 0; i < target_bytes && i < 64; i++) {
        state = ((state << 5) | (state >> 27)) + 0x9E3779B9;
        output[i] = (uint8_t)((state >> ((i % 4) * 8)) & 0xFF);
    }
    *output_len = target_bytes;
}

/* =========================================================================
 * Textbook RSA Signatures -- INSECURE, for education only
 *
 * Demonstrates WHY hashing and padding are essential:
 *   1. Existential forgery: choose random sigma, claim m = sigma^e.
 *   2. Multiplicative forgery: sigma1*sigma2 is valid for m1*m2.
 *   3. Chosen-message attacks possible without hashing.
 * ========================================================================= */

signature_t rsa_textbook_sign(const rsa_keypair_t *key, const bigint_t *message) {
    /* Textbook RSA signature: sigma = m^d mod n.
     *
     * WARNING: Insecure! Used only to demonstrate why hashing is essential.
     * Without hashing:
     *   - Any sigma is a valid signature on m = sigma^e mod n.
     *   - sigma1 * sigma2 is valid on m1 * m2 (multiplicative forgery).
     *
     * Complexity: O(log d * log^2 n). */
    signature_t sig;
    memset(&sig, 0, sizeof(sig));
    sig.salt_len = 0;
    sig.hash_len = 0;

    if (!key || !message) return sig;

    tdp_domain_elem_t dec = rsa_decrypt_crt(key, message);
    if (!dec.in_domain) return sig;

    sig.sigma = dec.value;
    return sig;
}

bool rsa_textbook_verify(const rsa_params_t *params, const bigint_t *message,
                          const signature_t *signature) {
    /* Textbook RSA verification: check sigma^e mod n == message.
     *
     * Complexity: O(log e * log^2 n). */
    if (!params || !message || !signature) return false;

    tdp_eval_result_t ver = rsa_encrypt(params, &signature->sigma);
    if (!ver.valid) return false;

    return bigint_compare(&ver.value, message) == 0;
}

/* =========================================================================
 * Full Domain Hash (FDH) -- L7 Application
 *
 * FDH signature: sigma = H(m)^d mod n
 * where H: {0,1}* -> Z_n^* is modeled as a random oracle.
 *
 * Security: EUF-CMA secure in the random oracle model, assuming the
 * RSA assumption holds.
 *
 * Intuition: H is a random oracle, so H(m) is uniformly random in Z_n^*.
 * A forger that produces a valid FDH signature on a new message can be
 * used to break the RSA assumption: given challenge y, set the RO output
 * for the forgery attempt to y; if the forger succeeds, we recover y^{1/e}.
 *
 * Reference: Bellare & Rogaway, "The Exact Security of Digital Signatures
 *            -- How to Sign with RSA and Rabin" (EUROCRYPT 1996).
 * ========================================================================= */

signature_t rsa_fdh_sign(const rsa_keypair_t *key,
                           const uint8_t *message, size_t msg_len) {
    /* FDH signature: sigma = H(m)^d mod n.
     *
     * 1. Compute h = H(m) interpreted as element of Z_n^*.
     * 2. Compute sigma = h^d mod n (RSA inverse).
     *
     * Complexity: O(log d * log^2 n + |m|). */
    signature_t sig;
    memset(&sig, 0, sizeof(sig));

    if (!key || !message) return sig;

    /* Hash message to get H(m) */
    uint8_t hash_output[64];
    size_t hash_len = 0;
    sig_hash(hash_output, &hash_len, message, msg_len, key->params.nbits);

    /* Convert hash to bigint */
    bigint_t hash_big;
    bigint_set_zero(&hash_big);
    for (size_t i = 0; i < hash_len; i++) {
        uint32_t limb_idx = (uint32_t)(i / 4);
        uint32_t byte_idx = (uint32_t)(i % 4);
        hash_big.limbs[limb_idx] |= ((uint32_t)hash_output[i]) << (byte_idx * 8);
        if (limb_idx + 1 > hash_big.nlimbs) hash_big.nlimbs = limb_idx + 1;
    }
    if (hash_big.nlimbs == 0) hash_big.nlimbs = 1;

    /* Ensure hash value is in Z_n^* by reducing mod n */
    /* (in RO model, the hash output is already uniform in Z_n^*) */
    bigint_t q, r;
    bigint_divmod(&q, &r, &hash_big, &key->params.n);

    /* Sign: sigma = H(m)^d mod n */
    tdp_domain_elem_t dec = rsa_decrypt_crt(key, &r);
    if (!dec.in_domain) return sig;

    sig.sigma = dec.value;
    memcpy(sig.hash_output, hash_output, hash_len);
    sig.hash_len = hash_len;
    return sig;
}

bool rsa_fdh_verify(const rsa_params_t *params,
                      const uint8_t *message, size_t msg_len,
                      const signature_t *signature) {
    /* FDH verification: sigma^e mod n == H(m).
     *
     * 1. Compute h = H(m).
     * 2. Compute check = sigma^e mod n.
     * 3. Verify check == h.
     *
     * Complexity: O(log e * log^2 n + |m|). */
    if (!params || !message || !signature) return false;

    /* Recompute H(m) */
    uint8_t hash_output[64];
    size_t hash_len = 0;
    sig_hash(hash_output, &hash_len, message, msg_len, params->nbits);

    bigint_t hash_big;
    bigint_set_zero(&hash_big);
    for (size_t i = 0; i < hash_len; i++) {
        uint32_t limb_idx = (uint32_t)(i / 4);
        uint32_t byte_idx = (uint32_t)(i % 4);
        hash_big.limbs[limb_idx] |= ((uint32_t)hash_output[i]) << (byte_idx * 8);
        if (limb_idx + 1 > hash_big.nlimbs) hash_big.nlimbs = limb_idx + 1;
    }
    if (hash_big.nlimbs == 0) hash_big.nlimbs = 1;

    bigint_t q, r;
    bigint_divmod(&q, &r, &hash_big, &params->n);

    /* Verify: sigma^e mod n */
    tdp_eval_result_t ver = rsa_encrypt(params, &signature->sigma);
    if (!ver.valid) return false;

    return bigint_compare(&ver.value, &r) == 0;
}

/* =========================================================================
 * RSA-PSS -- L7 Application
 *
 * Probabilistic Signature Scheme with tight security reduction
 * to the RSA assumption. Standardized in PKCS#1 v2.2 / RFC 8017.
 *
 * PSS encoding:
 *   1. M' = (0x00...00 || hash(L) || hash(m) || salt)
 *   2. DB = M' || 0x00... || 0x01 (padded to |n|-|salt|-1 bytes)
 *   3. maskedDB = DB XOR MGF(seed)
 *   4. EM = maskedDB || salt || 0xBC
 *   5. sigma = EM^d mod n
 *
 * Reference: Bellare & Rogaway, "PSS: Provably Secure Encoding Method
 *            for Digital Signatures" (submission to IEEE P1363, 1998).
 *            RFC 8017, Section 8.1.
 * ========================================================================= */

signature_t rsa_pss_sign(const rsa_keypair_t *key,
                            const uint8_t *message, size_t msg_len,
                            const uint8_t *salt, size_t salt_len) {
    /* RSA-PSS signature.
     *
     * Produces a randomized signature that is secure under the RSA
     * assumption with a tight reduction (unlike FDH, which has a
     * loose reduction by factor q_s * q_h).
     *
     * Complexity: O(log d * log^2 n + |m| + salt_len). */
    signature_t sig;
    memset(&sig, 0, sizeof(sig));

    if (!key || !message) return sig;

    /* For educational simplicity, we implement a simplified PSS:
     *   sigma = H(m || salt)^d mod n
     * This captures the essential randomization but not the full
     * PSS encoding. Full PSS encoding is implemented in production
     * libraries following RFC 8017 exactly. */

    /* Concatenate message and salt */
    uint8_t combined[1024];
    size_t combined_len = msg_len + salt_len;
    if (msg_len <= 1024 && combined_len <= 1024) {
        memcpy(combined, message, msg_len);
        if (salt && salt_len > 0 && msg_len + salt_len <= 1024) {
            memcpy(combined + msg_len, salt, salt_len);
        }
    } else {
        combined_len = msg_len;
        memcpy(combined, message, msg_len > 1024 ? 1024 : msg_len);
        combined_len = combined_len > 1024 ? 1024 : combined_len;
    }

    /* Hash the combined data */
    uint8_t hash_output[64];
    size_t hash_len = 0;
    sig_hash(hash_output, &hash_len, combined, combined_len, key->params.nbits);

    bigint_t hash_big;
    bigint_set_zero(&hash_big);
    for (size_t i = 0; i < hash_len; i++) {
        uint32_t limb_idx = (uint32_t)(i / 4);
        uint32_t byte_idx = (uint32_t)(i % 4);
        hash_big.limbs[limb_idx] |= ((uint32_t)hash_output[i]) << (byte_idx * 8);
        if (limb_idx + 1 > hash_big.nlimbs) hash_big.nlimbs = limb_idx + 1;
    }
    if (hash_big.nlimbs == 0) hash_big.nlimbs = 1;

    bigint_t q, r;
    bigint_divmod(&q, &r, &hash_big, &key->params.n);

    /* Sign: sigma = H(m||salt)^d mod n */
    tdp_domain_elem_t dec = rsa_decrypt_crt(key, &r);
    if (!dec.in_domain) return sig;

    sig.sigma = dec.value;
    memcpy(sig.hash_output, hash_output, hash_len);
    sig.hash_len = hash_len;
    if (salt && salt_len > 0 && salt_len <= 64) {
        memcpy(sig.salt, salt, salt_len);
        sig.salt_len = salt_len;
    }
    return sig;
}

bool rsa_pss_verify(const rsa_params_t *params,
                      const uint8_t *message, size_t msg_len,
                      const signature_t *signature) {
    /* RSA-PSS verification.
     *
     * 1. Reconstruct the expected encoding from message and salt.
     * 2. Verify sigma^e mod n matches the encoding.
     *
     * Complexity: O(log e * log^2 n + |m|). */
    if (!params || !message || !signature) return false;

    /* Reconstruct the combined message+hash */
    uint8_t combined[1024];
    size_t combined_len = msg_len + signature->salt_len;
    if (msg_len <= 1024 && combined_len <= 1024) {
        memcpy(combined, message, msg_len);
        if (signature->salt_len > 0 && msg_len + signature->salt_len <= 1024) {
            memcpy(combined + msg_len, signature->salt, signature->salt_len);
        }
    } else {
        return false;
    }

    uint8_t hash_output[64];
    size_t hash_len = 0;
    sig_hash(hash_output, &hash_len, combined, combined_len, params->nbits);

    bigint_t hash_big;
    bigint_set_zero(&hash_big);
    for (size_t i = 0; i < hash_len; i++) {
        uint32_t limb_idx = (uint32_t)(i / 4);
        uint32_t byte_idx = (uint32_t)(i % 4);
        hash_big.limbs[limb_idx] |= ((uint32_t)hash_output[i]) << (byte_idx * 8);
        if (limb_idx + 1 > hash_big.nlimbs) hash_big.nlimbs = limb_idx + 1;
    }
    if (hash_big.nlimbs == 0) hash_big.nlimbs = 1;

    bigint_t q, r;
    bigint_divmod(&q, &r, &hash_big, &params->n);

    /* Verify */
    tdp_eval_result_t ver = rsa_encrypt(params, &signature->sigma);
    if (!ver.valid) return false;

    return bigint_compare(&ver.value, &r) == 0;
}

/* =========================================================================
 * Forgery Attack Demonstrations -- L6 Canonical Problems
 *
 * These functions demonstrate concrete attacks on textbook RSA signatures,
 * showing WHY hashing and padding are essential for security.
 * ========================================================================= */

void rsa_demonstrate_existential_forgery(const rsa_params_t *params,
                                           bigint_t *forged_message,
                                           signature_t *forged_signature) {
    /* Existential forgery on textbook RSA signatures.
     *
     * Attack:
     *   1. Choose arbitrary sigma in Z_n^*.
     *   2. Compute m = sigma^e mod n.
     *   3. (m, sigma) is a valid message-signature pair!
     *
     * This works because Verify(m, sigma) computes sigma^e and checks
     * if it equals m. Without hashing, there is no binding between
     * the message and signature -- any sigma is valid for SOME message.
     *
     * Complexity: O(log e * log^2 n).
     *
     * Reference: Goldwasser, Micali, Rivest (1988). */
    if (!params || !forged_message || !forged_signature) return;

    /* Choose arbitrary sigma (e.g., sigma = 2) */
    bigint_t two;
    bigint_set_one(&two); bigint_inc(&two);

    forged_signature->sigma = two;
    forged_signature->salt_len = 0;
    forged_signature->hash_len = 0;

    /* Compute m = sigma^e mod n */
    tdp_eval_result_t m_result = rsa_encrypt(params, &two);
    if (m_result.valid) {
        *forged_message = m_result.value;
    }
}

void rsa_demonstrate_multiplicative_forgery(const rsa_params_t *params,
                                              const bigint_t *m1, const signature_t *sig1,
                                              const bigint_t *m2, const signature_t *sig2,
                                              bigint_t *forged_message,
                                              signature_t *forged_signature) {
    /* Multiplicative forgery on textbook RSA signatures.
     *
     * Given valid signatures:
     *   sig1 = m1^d mod n  (on message m1)
     *   sig2 = m2^d mod n  (on message m2)
     *
     * The attacker can forge a signature on m1 * m2:
     *   forged = sig1 * sig2 mod n = (m1 * m2)^d mod n
     *
     * Verification checks: forged^e = m1*m2 mod n, which holds.
     *
     * This works because RSA is a ring homomorphism:
     *   sig(m1) * sig(m2) = m1^d * m2^d = (m1*m2)^d = sig(m1*m2).
     *
     * Complexity: O(log^2 n).
     *
     * Reference: Rivest, Shamir, Adleman (1978), Section IV. */
    if (!params || !m1 || !sig1 || !m2 || !sig2 || !forged_message || !forged_signature) return;

    /* Forged signature: sigma = sig1 * sig2 mod n */
    mod_mul(&forged_signature->sigma, &sig1->sigma, &sig2->sigma, &params->n);
    forged_signature->salt_len = 0;
    forged_signature->hash_len = 0;

    /* Forged message: m = m1 * m2 mod n */
    mod_mul(forged_message, m1, m2, &params->n);
}

/* =========================================================================
 * Signature Security Utilities
 * ========================================================================= */

const char *sig_security_level_name(sig_security_level_t level) {
    switch (level) {
        case SIG_SEC_EUF_CMA:     return "EUF-CMA";
        case SIG_SEC_SUF_CMA:    return "SUF-CMA";
        case SIG_SEC_EUF_NA_CMA: return "EUF-naCMA";
        default: return "UNKNOWN";
    }
}

double sig_fdh_security_bound(double rsa_advantage,
                                uint32_t signing_queries,
                                uint32_t hash_queries) {
    /* Concrete security bound for FDH-RSA.
     *
     * In the random oracle model, if the RSA problem is (t, epsilon)-hard,
     * then FDH-RSA is (t', epsilon')-secure where:
     *   epsilon' <= q_s * q_h * epsilon
     *
     * where q_s = number of signing queries, q_h = hash queries.
     *
     * This is a "loose" reduction: the factor q_s * q_h means that
     * we need a stronger RSA assumption to guarantee the same security
     * level as PSS (which has a tight reduction, epsilon' <= epsilon).
     *
     * Reference: Bellare & Rogaway (1996), Theorem 6.1. */
    return rsa_advantage * (double)signing_queries * (double)hash_queries;
}
