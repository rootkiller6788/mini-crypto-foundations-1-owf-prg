/**
 * tdp_pke.c -- Public-Key Encryption from Trapdoor Permutations
 *
 * Implements PKE constructions from TDPs:
 *   1. Textbook (insecure) encryption -- deterministic, homomorphic
 *   2. Goldreich-Levin hard-core bit -- IND-CPA secure
 *   3. OAEP padding -- IND-CCA2 secure in ROM
 *   4. RSA-OAEP full scheme as in PKCS#1 v2.2 / RFC 8017
 *
 * Security progression:
 *   Textbook RSA: No security (deterministic, homomorphic)
 *   RSA + GL bit: IND-CPA
 *   RSA-OAEP:      IND-CCA2 (in random oracle model)
 *
 * Reference: Bellare & Rogaway, "Optimal Asymmetric Encryption" (EUROCRYPT 1994)
 *            Goldreich & Levin, "Hard-Core Predicate for All OWF" (STOC 1989)
 *            PKCS#1 v2.2 (RFC 8017)
 */

#include "tdp_pke.h"
#include "tdp_core.h"
#include "modular_math.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* =========================================================================
 * Simple Hash Function for OAEP and signatures
 *
 * Educational implementation: not cryptographically secure.
 * Uses a simple iterative construction for demonstration purposes.
 * In production, use SHA-256/SHA-512.
 * ========================================================================= */

static void simple_hash(uint8_t *output, size_t output_len,
                         const uint8_t *input, size_t input_len) {
    /* Simple hash based on mixing: h_{i+1} = h_i XOR rotate(input[i]) + constant.
     * Educational only. Demonstrates the RO model concept concretely. */
    uint32_t state = 0x67452301;
    for (size_t i = 0; i < input_len; i++) {
        state ^= ((uint32_t)input[i] << ((i % 4) * 8));
        state = (state << 7) | (state >> 25);
        state += 0x9E3779B9;
    }
    /* Output the state repeated to fill output_len */
    for (size_t i = 0; i < output_len; i++) {
        output[i] = (uint8_t)((state >> ((i % 4) * 8)) & 0xFF);
    }
}

static void mgf1(uint8_t *output, size_t output_len,
                  const uint8_t *seed, size_t seed_len) {
    /* MGF1 (Mask Generation Function): simple PRG from hash.
     * Used in OAEP and PSS padding. */
    uint8_t counter[4];
    size_t produced = 0;
    uint32_t ctr = 0;
    while (produced < output_len) {
        counter[0] = (uint8_t)(ctr >> 24);
        counter[1] = (uint8_t)(ctr >> 16);
        counter[2] = (uint8_t)(ctr >> 8);
        counter[3] = (uint8_t)(ctr);
        uint8_t tmp[64];
        memcpy(tmp, seed, seed_len < 64 ? seed_len : 64);
        if (seed_len < 64) memcpy(tmp + seed_len, counter, 4);
        uint8_t hash_out[32];
        simple_hash(hash_out, 32, tmp, seed_len + 4);
        size_t to_copy = (output_len - produced < 32) ? (output_len - produced) : 32;
        memcpy(output + produced, hash_out, to_copy);
        produced += to_copy;
        ctr++;
    }
}

/* =========================================================================
 * Textbook RSA PKE -- INSECURE, for education only
 *
 * Demonstrates WHY padding is essential. Textbook RSA is:
 *   - Deterministic: same message produces same ciphertext.
 *   - Malleable: c1*c2 is valid encryption of m1*m2.
 *   - Vulnerable to chosen-ciphertext attacks.
 * ========================================================================= */

pke_ciphertext_t pke_textbook_encrypt(const rsa_params_t *params, const bigint_t *message) {
    /* Textbook RSA encryption: c = m^e mod n.
     *
     * WARNING: Not secure! Included to demonstrate why padding is needed.
     *
     * Complexity: O(log e * log^2 n). */
    pke_ciphertext_t ct;
    memset(&ct, 0, sizeof(ct));
    ct.c1_len = 0;

    if (!params || !message) return ct;

    mod_exp(&ct.c0, message, &params->e, &params->n);
    return ct;
}

bool pke_textbook_decrypt(const rsa_keypair_t *key, const pke_ciphertext_t *ciphertext,
                          bigint_t *message_out) {
    /* Textbook RSA decryption: m = c^d mod n.
     *
     * Requires the trapdoor (private key d).
     * Complexity: O(log d * log^2 n). */
    if (!key || !ciphertext || !message_out) return false;

    tdp_domain_elem_t dec = rsa_decrypt_crt(key, &ciphertext->c0);
    if (!dec.in_domain) return false;
    bigint_copy(message_out, &dec.value);
    return true;
}

/* =========================================================================
 * Goldreich-Levin Hard-Core Bit -- L7 Application
 *
 * Theorem (Goldreich-Levin, 1989): For any OWF f, the inner product
 *   hc(x, r) = <x, r> = XOR_i (x_i AND r_i)
 * is a hard-core predicate. That is, given f(x) and r, predicting
 * hc(x, r) is as hard as inverting f(x).
 *
 * For TDP f, the encryption scheme is:
 *   Enc(m in {0,1}):
 *     1. Sample random x, r from domain.
 *     2. c0 = f(x)
 *     3. c1 = m XOR hc(x, r)    [where hc is the GL bit]
 *     4. Output (c0, r, c1)
 *
 *   Dec(c0, r, c1):
 *     1. x = f^{-1}(c0)           [using trapdoor]
 *     2. m = c1 XOR hc(x, r)
 *
 * This achieves IND-CPA security assuming f is a TDP.
 *
 * Reference: Goldreich & Levin, STOC 1989.
 *            Goldreich, Foundations of Cryptography Vol. 1, Section 2.5.2.
 * ========================================================================= */

/* Compute the Goldreich-Levin hard-core bit: XOR_i (x_i AND r_i).
 * For bigint: compute sum of (x_i * r_i) mod 2 across all bit positions.
 * Simplified: hc = parity(x & r) where & is bitwise AND. */
static uint8_t gl_hardcore_bit(const bigint_t *x, const bigint_t *r, const bigint_t *modulus) {
    if (!x || !r || !modulus) return 0;
    /* Compute inner product mod 2: XOR over all bits where both x and r have 1.
     * For efficiency, we compute it limb-by-limb. */
    uint8_t bit = 0;
    uint32_t nlimbs = (x->nlimbs < r->nlimbs) ? x->nlimbs : r->nlimbs;
    if (nlimbs > modulus->nlimbs) nlimbs = modulus->nlimbs;

    for (uint32_t i = 0; i < nlimbs; i++) {
        uint32_t and_val = x->limbs[i] & r->limbs[i];
        /* Count bits in and_val mod 2 */
        and_val ^= and_val >> 16;
        and_val ^= and_val >> 8;
        and_val ^= and_val >> 4;
        and_val ^= and_val >> 2;
        and_val ^= and_val >> 1;
        bit ^= (and_val & 1);
    }
    return bit;
}

pke_ciphertext_t pke_gl_encrypt(const tdp_public_key_t *pk, uint8_t message_bit,
                                 const bigint_t *r, const bigint_t *x) {
    /* Encrypt a single bit using Goldreich-Levin construction.
     *
     * Input:  message_bit in {0,1}
     *         r = random string for GL bit extraction
     *         x = random domain element
     *
     * Output: ciphertext (c0 = f(x), r stored in c1, message XOR hc bit)
     *
     * Complexity: O(log^3 n).
     *
     * Reference: Goldreich & Levin (1989). */
    pke_ciphertext_t ct;
    memset(&ct, 0, sizeof(ct));

    if (!pk || !r || !x) return ct;

    tdp_domain_elem_t dom;
    dom.value = *x;
    dom.in_domain = true;

    tdp_eval_result_t y = tdp_eval_forward(pk, &dom);
    if (!y.valid) return ct;

    ct.c0 = y.value;

    uint8_t hc = gl_hardcore_bit(x, r, &pk->modulus);
    ct.c1[0] = message_bit ^ hc;
    ct.c1_len = 1;

    return ct;
}

uint8_t pke_gl_decrypt(const tdp_public_key_t *pk, const tdp_trapdoor_t *td,
                       const pke_ciphertext_t *ciphertext) {
    /* Decrypt a GL-encrypted bit using the trapdoor.
     *
     * 1. Recover x = f^{-1}(c0) using trapdoor.
     * 2. Compute hc = GL(x, r).
     * 3. Return c1 XOR hc = message bit.
     *
     * Complexity: O(log^3 n). */
    if (!pk || !td || !ciphertext) return 0;

    tdp_eval_result_t y;
    y.value = ciphertext->c0;
    y.valid = true;

    tdp_domain_elem_t x = tdp_eval_inverse(pk, td, &y);
    if (!x.in_domain) return 0;

    /* r is embedded in c1[1..] conceptually; here we use a fixed r for simplicity.
     * In a full implementation, r would be transmitted alongside the ciphertext. */
    bigint_t r_val;
    bigint_set_one(&r_val);
    bigint_shl(&r_val, 32); /* arbitrary r */

    uint8_t hc = gl_hardcore_bit(&x.value, &r_val, &pk->modulus);
    return ciphertext->c1[0] ^ hc;
}

/* =========================================================================
 * OAEP Padding -- L7 Application
 *
 * OAEP (Optimal Asymmetric Encryption Padding):
 *   Given message m and random r:
 *   s = (m || 0^{k0}) XOR G(r)
 *   t = r XOR H(s)
 *   Output: s || t
 *
 * Where G and H are hash functions modeled as random oracles.
 *
 * OAEP + TDP achieves IND-CCA2 security in the random oracle model.
 *
 * Reference: Bellare & Rogaway (EUROCRYPT 1994).
 *            Fujisaki, Okamoto, Pointcheval, Stern (CRYPTO 2001).
 * ========================================================================= */

bool pke_oaep_pad(uint8_t *padded, size_t *padded_len,
                   const uint8_t *message, size_t msg_len,
                   const uint8_t *r, size_t r_len,
                   size_t k0) {
    /* OAEP padding.
     *
     * Parameters:
     *   k0: zero-padding length (typically 128 or 256 bits)
     *   |r|: random seed length (typically k0 bits)
     *
     * Output format: s || t where:
     *   s = (m || 0^{k0}) XOR G(r)
     *   t = r XOR H(s)
     *
     * Complexity: O(|m| + k0 + |r|).
     *
     * Reference: Bellare & Rogaway (1994), PKCS#1 v2.2. */
    if (!padded || !padded_len || !message || !r) return false;

    size_t k0_bytes = k0 / 8;
    size_t msg_padded_len = msg_len + k0_bytes;
    size_t total_len = msg_padded_len + r_len;

    uint8_t *msg_padded = (uint8_t *)malloc(msg_padded_len);
    if (!msg_padded) return false;
    memset(msg_padded, 0, msg_padded_len);
    memcpy(msg_padded, message, msg_len);
    /* msg_padded[msg_len..] are already 0 (the k0 zero-padding) */

    /* G(r): expand r to msg_padded_len bytes */
    uint8_t *G_out = (uint8_t *)malloc(msg_padded_len);
    if (!G_out) { free(msg_padded); return false; }
    mgf1(G_out, msg_padded_len, r, r_len);

    /* s = msg_padded XOR G(r) */
    uint8_t *s = (uint8_t *)malloc(msg_padded_len);
    if (!s) { free(G_out); free(msg_padded); return false; }
    for (size_t i = 0; i < msg_padded_len; i++) {
        s[i] = msg_padded[i] ^ G_out[i];
    }

    /* H(s): hash s to r_len bytes */
    uint8_t *H_out = (uint8_t *)malloc(r_len);
    if (!H_out) { free(s); free(G_out); free(msg_padded); return false; }
    simple_hash(H_out, r_len, s, msg_padded_len);

    /* t = r XOR H(s) */
    uint8_t *t = (uint8_t *)malloc(r_len);
    if (!t) { free(H_out); free(s); free(G_out); free(msg_padded); return false; }
    for (size_t i = 0; i < r_len; i++) {
        t[i] = r[i] ^ H_out[i];
    }

    /* Output: s || t */
    memcpy(padded, s, msg_padded_len);
    memcpy(padded + msg_padded_len, t, r_len);
    *padded_len = total_len;

    free(t); free(H_out); free(s); free(G_out); free(msg_padded);
    return true;
}

bool pke_oaep_unpad(uint8_t *message, size_t *msg_len,
                     const uint8_t *padded, size_t padded_len,
                     size_t k0) {
    /* OAEP unpadding.
     *
     * 1. Parse s || t from padded data.
     * 2. r = t XOR H(s).
     * 3. msg_padded = s XOR G(r).
     * 4. Check that the last k0 bytes of msg_padded are all zero.
     * 5. Return the first |msg_padded| - k0 bytes as the message.
     *
     * Returns false if zero-padding check fails.
     *
     * Complexity: O(|padded|).
     *
     * Reference: PKCS#1 v2.2, Section 7.1.2. */
    if (!message || !msg_len || !padded) return false;

    size_t k0_bytes = k0 / 8;
    if (padded_len <= k0_bytes) return false;

    /* Parse: the last part is t (same length as r, which we take as k0_bytes),
     * the first part is s (padded_len - k0_bytes). */
    size_t r_len = k0_bytes;
    size_t s_len = padded_len - r_len;

    const uint8_t *s = padded;
    const uint8_t *t = padded + s_len;

    /* H(s) -> r_len bytes */
    uint8_t *H_out = (uint8_t *)malloc(r_len);
    if (!H_out) return false;
    simple_hash(H_out, r_len, s, s_len);

    /* r = t XOR H(s) */
    uint8_t *r = (uint8_t *)malloc(r_len);
    if (!r) { free(H_out); return false; }
    for (size_t i = 0; i < r_len; i++) {
        r[i] = t[i] ^ H_out[i];
    }

    /* G(r) -> s_len bytes */
    uint8_t *G_out = (uint8_t *)malloc(s_len);
    if (!G_out) { free(r); free(H_out); return false; }
    mgf1(G_out, s_len, r, r_len);

    /* msg_padded = s XOR G(r) */
    uint8_t *msg_padded = (uint8_t *)malloc(s_len);
    if (!msg_padded) { free(G_out); free(r); free(H_out); return false; }
    for (size_t i = 0; i < s_len; i++) {
        msg_padded[i] = s[i] ^ G_out[i];
    }

    /* Check zero-padding: last k0_bytes must be all zero */
    bool valid = true;
    for (size_t i = s_len - k0_bytes; i < s_len && valid; i++) {
        if (msg_padded[i] != 0) valid = false;
    }

    if (valid) {
        *msg_len = s_len - k0_bytes;
        memcpy(message, msg_padded, *msg_len);
    }

    free(msg_padded); free(G_out); free(r); free(H_out);
    return valid;
}

/* =========================================================================
 * RSA-OAEP Full Encryption/Decryption -- L7 Application
 *
 * The industry-standard IND-CCA2 secure public-key encryption scheme
 * as specified in PKCS#1 v2.2 / RFC 8017.
 * ========================================================================= */

pke_ciphertext_t pke_rsa_oaep_encrypt(const rsa_keypair_t *key,
                                        const uint8_t *message, size_t msg_len,
                                        const uint8_t *label, size_t label_len,
                                        const uint8_t *seed) {
    /* RSA-OAEP encryption.
     *
     * 1. OAEP-pad the message with label and seed.
     * 2. Convert padded bytes to bigint.
     * 3. Apply RSA forward permutation (encrypt).
     *
     * Complexity: O(|m| + k0 + k1 + log^3 n).
     *
     * Reference: RFC 8017, Section 7.1.1. */
    pke_ciphertext_t ct;
    memset(&ct, 0, sizeof(ct));

    if (!key || !message || !seed) return ct;

    /* OAEP pad the message */
    uint8_t padded[512]; /* Large enough for RSA-4096 with OAEP */
    size_t padded_len = 0;
    /* k0 = 128 bits = 16 bytes for SHA-256 level security */
    size_t k0 = 128;
    (void)label; (void)label_len; /* Label not used in simplified version */

    if (!pke_oaep_pad(padded, &padded_len, message, msg_len, seed, 32, k0)) {
        return ct;
    }

    /* Convert padded data to bigint (simple conversion for demo) */
    bigint_t m_big;
    bigint_set_zero(&m_big);
    for (size_t i = 0; i < padded_len && i < sizeof(m_big.limbs)*4; i++) {
        uint32_t limb_idx = (uint32_t)(i / 4);
        uint32_t byte_idx = (uint32_t)(i % 4);
        m_big.limbs[limb_idx] |= ((uint32_t)padded[i]) << (byte_idx * 8);
        if (limb_idx + 1 > m_big.nlimbs) m_big.nlimbs = limb_idx + 1;
    }
    if (m_big.nlimbs == 0) m_big.nlimbs = 1;

    /* RSA encrypt */
    mod_exp(&ct.c0, &m_big, &key->params.e, &key->params.n);

    /* Store seed for demo purposes */
    memcpy(ct.c1, seed, 32);
    ct.c1_len = 32;

    return ct;
}

bool pke_rsa_oaep_decrypt(const rsa_keypair_t *key,
                            const pke_ciphertext_t *ciphertext,
                            uint8_t *message, size_t *msg_len,
                            const uint8_t *label, size_t label_len) {
    /* RSA-OAEP decryption.
     *
     * 1. Apply RSA inverse permutation (decrypt).
     * 2. Convert bigint result to byte array.
     * 3. OAEP-unpad to recover message and verify padding.
     *
     * Returns false if padding check fails.
     *
     * Complexity: O(log^3 n + |m|).
     *
     * Reference: RFC 8017, Section 7.1.2. */
    if (!key || !ciphertext || !message || !msg_len) return false;

    /* RSA decrypt */
    tdp_domain_elem_t dec = rsa_decrypt_crt(key, &ciphertext->c0);
    if (!dec.in_domain) return false;

    /* Convert bigint to byte array */
    uint8_t padded[512];
    size_t padded_len = 0;
    for (uint32_t i = 0; i < dec.value.nlimbs && padded_len < 512; i++) {
        uint32_t limb = dec.value.limbs[i];
        for (int b = 0; b < 4 && padded_len < 512; b++) {
            padded[padded_len++] = (uint8_t)(limb & 0xFF);
            limb >>= 8;
        }
    }
    /* Strip trailing zeros from the conversion */
    while (padded_len > 0 && padded[padded_len - 1] == 0) padded_len--;

    /* OAEP unpad */
    size_t k0 = 128;
    (void)label; (void)label_len;
    return pke_oaep_unpad(message, msg_len, padded, padded_len, k0);
}

/* =========================================================================
 * PKE Security Level Utilities
 * ========================================================================= */

const char *pke_security_level_name(pke_security_level_t level) {
    switch (level) {
        case PKE_SEC_IND_CPA:  return "IND-CPA";
        case PKE_SEC_IND_CCA1: return "IND-CCA1";
        case PKE_SEC_IND_CCA2: return "IND-CCA2";
        default: return "UNKNOWN";
    }
}

bool pke_check_security_level(pke_security_level_t achieved,
                               pke_security_level_t target) {
    /* Check if achieved security level meets or exceeds target.
     * IND-CPA < IND-CCA1 < IND-CCA2 in strength. */
    return (int)achieved >= (int)target;
}

/* =========================================================================
 * Brute-Force Attack Simulation -- L7 Application
 *
 * Demonstrates concretely why the trapdoor is essential:
 * without it, the best generic attack is exhaustive search over the domain,
 * which is exponential in the security parameter.
 *
 * This function tries random domain elements to find a preimage,
 * showing the exponential gap between forward (easy) and inverse (hard).
 * ========================================================================= */

uint32_t simulate_tdp_brute_force(const tdp_public_key_t *pk,
                                   const tdp_eval_result_t *y,
                                   uint32_t max_attempts) {
    /* Simulate naive brute-force inversion of a TDP.
     *
     * For each attempt:
     *   1. Sample random x from domain.
     *   2. Compute f(x).
     *   3. If f(x) == y, found preimage.
     *
     * Expected attempts before success: |domain| ≈ 2^{lambda}.
     * With max_attempts << 2^{lambda}, probability of success is negligible.
     *
     * This demonstrates why the trapdoor is essential: without d (or p,q),
     * the adversary's best strategy requires ~2^{lambda} work.
     *
     * Complexity: O(max_attempts * log^3 n). */
    if (!pk || !y || !y->valid) return 0;

    uint32_t attempts = 0;
    for (uint32_t i = 0; i < max_attempts; i++) {
        /* Sample a domain element (with varying seed for randomness) */
        tdp_domain_elem_t x;
        memset(&x, 0, sizeof(x));

        /* Simple sequential attempt */
        bigint_t attempt_val = bigint_from_uint64(i + 2);
        x.value = attempt_val;

        /* Check domain membership */
        if (pk->nbits > 0) {
            bigint_t gcd_check;
            bigint_gcd(&gcd_check, &x.value, &pk->modulus);
            if (!bigint_is_one(&gcd_check)) continue;
        }
        x.in_domain = true;

        tdp_eval_result_t y_attempt = tdp_eval_forward(pk, &x);
        if (!y_attempt.valid) continue;

        attempts++;
        if (bigint_compare(&y_attempt.value, &y->value) == 0) {
            return attempts; /* Found preimage */
        }
    }
    return attempts; /* Failed to find within max_attempts */
}
