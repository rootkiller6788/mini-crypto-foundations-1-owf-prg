/*
 * crypto_primitives.c — Supporting Cryptographic Primitives
 *
 * Implementations of additional cryptographic building blocks
 * that use the OWF and hardcore bit foundations:
 * - Hash functions via Merkle-Damgård from OWF
 * - Commitment schemes from OWF
 * - Digital signatures from OWF (Lamport one-time signatures)
 * - Key derivation from hardcore bits
 *
 * Knowledge Points Covered:
 *   L2: Cryptographic hash functions from OWFs
 *   L5: Merkle-Damgård construction, Lamport signatures
 *   L7: Commitment schemes and their applications
 *   L7: Digital signatures from one-way functions
 *   L8: Relationship between cryptographic primitives
 *
 * Reference: Goldreich Vol.1-2; Arora-Barak §9
 * Courses: MIT 6.875, Stanford CS255, Princeton COS 551
 */

#include "owf.h"
#include "hardcore_bit.h"
#include "security_params.h"
#include "bit_operations.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ───────────────────────────────────────────────────────────────
 * Hash Function via Merkle-Damgård from OWF
 *
 * Construction (Damgård 1989, Merkle 1989):
 * Given a compression function h: {0,1}^{2n} → {0,1}^n built
 * from an OWF, we construct a hash function H: {0,1}^* → {0,1}^n.
 *
 * The compression function can be instantiated as:
 *   h(key, block) = f(key || block)  [truncated to n bits]
 *
 * Security: If f is a OWF and collision-resistant, then the
 * Merkle-Damgård construction yields a collision-resistant hash.
 * ───────────────────────────────────────────────────────────── */

typedef struct {
    OWF*       owf;
    size_t     output_bits;
    size_t     block_bits;
    BitString* iv;           /* Initialization Vector */
} HashFromOWF;

HashFromOWF* hash_from_owf_create(OWF* owf, size_t output_bits, size_t block_bits) {
    if (!owf || output_bits == 0 || block_bits == 0) return NULL;
    HashFromOWF* h = (HashFromOWF*)malloc(sizeof(HashFromOWF));
    if (!h) return NULL;
    h->owf         = owf;
    h->output_bits = output_bits;
    h->block_bits  = block_bits;
    h->iv          = bs_create_random(output_bits);
    if (!h->iv) { free(h); return NULL; }
    return h;
}

void hash_from_owf_free(HashFromOWF* h) {
    if (h) {
        bs_free(h->iv);
        free(h);
    }
}

int hash_from_owf_update(HashFromOWF* h, BitString* state,
                          const BitString* block) {
    if (!h || !state || !block) return 0;
    /* Compression: state' = f(state || block) truncated to output_bits */
    /* Simplified: XOR state with block and compute OWF */
    BitString* combined = bs_create(state->n_bits);
    if (!combined) return 0;
    bs_xor(combined, state, block);
    /* Apply OWF as compression */
    BitString* output = bs_create(h->output_bits);
    if (!output) { bs_free(combined); return 0; }
    owf_eval(h->owf, combined, output);
    /* Update state */
    size_t copy_words = state->n_words;
    if (output->n_words < copy_words) copy_words = output->n_words;
    memcpy(state->data, output->data, copy_words * sizeof(uint64_t));
    bs_free(combined);
    bs_free(output);
    return 1;
}

int hash_from_owf_digest(HashFromOWF* h, const uint8_t* data, size_t len,
                          uint8_t* digest, size_t digest_len) {
    if (!h || !data || !digest) return 0;
    /* Initialize state with IV */
    BitString* state = bs_clone(h->iv);
    if (!state) return 0;
    /* Process blocks */
    size_t block_bytes = h->block_bits / 8;
    size_t pos = 0;
    while (pos < len) {
        size_t chunk = len - pos;
        if (chunk > block_bytes) chunk = block_bytes;
        BitString* block = bs_create_from_bytes(data + pos, chunk);
        if (!block) { bs_free(state); return 0; }
        hash_from_owf_update(h, state, block);
        bs_free(block);
        pos += chunk;
    }
    /* Output digest */
    u64_to_bytes(digest, state->data, digest_len);
    bs_free(state);
    return 1;
}

/* ───────────────────────────────────────────────────────────────
 * Commitment Scheme from OWF
 *
 * A commitment scheme allows a sender to commit to a value v
 * without revealing it (hiding), while being bound to v (binding).
 *
 * Construction (Naor 1991):
 *   Commit(v): Choose random r; output C = f(v || r)
 *   Reveal:    Send (v, r); verifier checks f(v || r) = C
 *
 * Hiding: Given C, PPT adversary cannot learn v (OWF security).
 * Binding: Sender cannot find (v',r') ≠ (v,r) with f(v'||r')=C
 *          (requires collision resistance of f).
 * ───────────────────────────────────────────────────────────── */

typedef struct {
    BitString* value;
    BitString* randomness;
    BitString* commitment;
} Commitment;

Commitment* commitment_create(OWF* owf, const BitString* value) {
    if (!owf || !value) return NULL;
    Commitment* com = (Commitment*)malloc(sizeof(Commitment));
    if (!com) return NULL;
    com->value      = bs_clone(value);
    com->randomness = bs_create_random(owf->input_bits / 2);
    com->commitment = bs_create(owf->output_bits);
    if (!com->value || !com->randomness || !com->commitment) {
        bs_free(com->value); bs_free(com->randomness);
        bs_free(com->commitment); free(com);
        return NULL;
    }
    /* C = f(value || randomness) */
    BitString* combined = bs_create(value->n_bits + com->randomness->n_bits);
    if (!combined) {
        bs_free(com->value); bs_free(com->randomness);
        bs_free(com->commitment); free(com);
        return NULL;
    }
    /* Simple concatenation via XOR for demonstration */
    bs_xor(combined, value, com->randomness);
    owf_eval(owf, combined, com->commitment);
    bs_free(combined);
    return com;
}

void commitment_free(Commitment* com) {
    if (com) {
        bs_free(com->value);
        bs_free(com->randomness);
        bs_free(com->commitment);
        free(com);
    }
}

int commitment_verify(OWF* owf, const BitString* commitment,
                       const BitString* value, const BitString* randomness) {
    if (!owf || !commitment || !value || !randomness) return 0;
    BitString* combined = bs_create(value->n_bits + randomness->n_bits);
    BitString* computed = bs_create(owf->output_bits);
    if (!combined || !computed) { bs_free(combined); bs_free(computed); return 0; }
    bs_xor(combined, value, randomness);
    owf_eval(owf, combined, computed);
    int result = bs_equal(computed, commitment);
    bs_free(combined);
    bs_free(computed);
    return result;
}

/* ───────────────────────────────────────────────────────────────
 * Lamport One-Time Signature from OWF
 *
 * Lamport (1979) showed how to construct digital signatures from
 * any one-way function. This is a fundamental result establishing
 * that OWFs suffice for digital signatures.
 *
 * Construction:
 *   KeyGen: For i=1..k and b∈{0,1}, pick random x_{i,b}.
 *           Public key: y_{i,b} = f(x_{i,b}).
 *           Secret key: x_{i,b}.
 *   Sign(m): For each bit m_i of hash(m), reveal x_{i, m_i}.
 *   Verify:  Check f(revealed) = y_{i, m_i} for all i.
 *
 * This is one-time: signing two different messages reveals both
 * preimages for some i, breaking security.
 * ───────────────────────────────────────────────────────────── */

typedef struct {
    size_t      k;               /* number of bits in message hash */
    BitString** sk_0;            /* secret keys for bit 0 */
    BitString** sk_1;            /* secret keys for bit 1 */
    BitString** pk_0;            /* public keys for bit 0 */
    BitString** pk_1;            /* public keys for bit 1 */
    OWF*        owf;
} LamportOTS;

LamportOTS* lamport_keygen(OWF* owf, size_t k) {
    if (!owf || k == 0) return NULL;
    LamportOTS* lkey = (LamportOTS*)malloc(sizeof(LamportOTS));
    if (!lkey) return NULL;
    lkey->k   = k;
    lkey->owf = owf;
    lkey->sk_0 = (BitString**)malloc(k * sizeof(BitString*));
    lkey->sk_1 = (BitString**)malloc(k * sizeof(BitString*));
    lkey->pk_0 = (BitString**)malloc(k * sizeof(BitString*));
    lkey->pk_1 = (BitString**)malloc(k * sizeof(BitString*));
    if (!lkey->sk_0 || !lkey->sk_1 || !lkey->pk_0 || !lkey->pk_1) {
        free(lkey->sk_0); free(lkey->sk_1);
        free(lkey->pk_0); free(lkey->pk_1);
        free(lkey);
        return NULL;
    }
    for (size_t i = 0; i < k; i++) {
        lkey->sk_0[i] = bs_create_random(owf->input_bits);
        lkey->sk_1[i] = bs_create_random(owf->input_bits);
        lkey->pk_0[i] = bs_create(owf->output_bits);
        lkey->pk_1[i] = bs_create(owf->output_bits);
        if (!lkey->sk_0[i] || !lkey->sk_1[i] || !lkey->pk_0[i] || !lkey->pk_1[i])
            continue;
        owf_eval(owf, lkey->sk_0[i], lkey->pk_0[i]);
        owf_eval(owf, lkey->sk_1[i], lkey->pk_1[i]);
    }
    return lkey;
}

void lamport_free(LamportOTS* lkey) {
    if (lkey) {
        for (size_t i = 0; i < lkey->k; i++) {
            bs_free(lkey->sk_0[i]); bs_free(lkey->sk_1[i]);
            bs_free(lkey->pk_0[i]); bs_free(lkey->pk_1[i]);
        }
        free(lkey->sk_0); free(lkey->sk_1);
        free(lkey->pk_0); free(lkey->pk_1);
        free(lkey);
    }
}

int lamport_sign(const LamportOTS* lkey, const int* message_hash,
                  BitString*** signature_out) {
    if (!lkey || !message_hash || !signature_out) return 0;
    *signature_out = (BitString**)malloc(lkey->k * sizeof(BitString*));
    if (!*signature_out) return 0;
    for (size_t i = 0; i < lkey->k; i++) {
        (*signature_out)[i] = bs_clone(
            message_hash[i] ? lkey->sk_1[i] : lkey->sk_0[i]);
    }
    return 1;
}

int lamport_verify(const LamportOTS* lkey, const int* message_hash,
                    BitString** signature) {
    if (!lkey || !message_hash || !signature) return 0;
    for (size_t i = 0; i < lkey->k; i++) {
        BitString* computed = bs_create(lkey->owf->output_bits);
        if (!computed) return 0;
        owf_eval(lkey->owf, signature[i], computed);
        int match = bs_equal(computed,
            message_hash[i] ? lkey->pk_1[i] : lkey->pk_0[i]);
        bs_free(computed);
        if (!match) return 0;
    }
    return 1;
}

/* ───────────────────────────────────────────────────────────────
 * Key Derivation from Hardcore Bits
 *
 * Given an OWF f and its Goldreich-Levin hardcore bit b(x,r)=⟨x,r⟩,
 * we can derive cryptographic key material:
 *
 *   KDF(x) = (b(x, r_1), b(x, r_2), ..., b(x, r_k))
 *
 * where r_1, ..., r_k are public random strings. The security of
 * the derived key follows from the hardcore bit property:
 * given only f(x), each derived bit is pseudorandom.
 *
 * This is a core technique underlying PRG construction from OWFs.
 * ───────────────────────────────────────────────────────────── */

int kdf_derive_bit(const BitString* x, const BitString* r) {
    return hc_inner_product(x, r, NULL);
}

void kdf_derive_bits(const BitString* x, const BitString** r_values,
                      size_t k, uint8_t* output) {
    if (!x || !r_values || !output) return;
    for (size_t i = 0; i < k; i++) {
        int bit = kdf_derive_bit(x, r_values[i]);
        if (bit) {
            output[i / 8] |= (1 << (i % 8));
        }
    }
}

/* ───────────────────────────────────────────────────────────────
 * Pseudorandom Generator via Hardcore Bit Expansion
 *
 * Given an OWF f and hardcore bit b, we can expand n random bits
 * into n + poly(n) pseudorandom bits:
 *
 *   G(s) = (b(s, r_1), b(s, r_2), ..., b(s, r_k), f(s), r)
 *
 * This is the Blum-Micali / Yao construction: each iteration
 * outputs one hardcore bit and updates the state via f.
 *
 * The Goldreich-Levin theorem guarantees that the output is
 * computationally indistinguishable from random.
 * ───────────────────────────────────────────────────────────── */

size_t prg_stretch_from_owf(OWF* owf, const BitString* seed,
                              BitString* output) {
    if (!owf || !seed || !output) return 0;
    /* Simple PRG: G(s) = (s, f(s))
     * Stretch factor: |s| + |f(s)| bits from |s| bits
     * With hardcore bit: stretch to |s| + t bits for any t = poly(|s|) */
    size_t out_pos = 0;
    /* Copy seed to output */
    for (size_t i = 0; i < seed->n_bits && out_pos < output->n_bits; i++) {
        bs_set_bit(output, out_pos++, bs_get_bit(seed, i));
    }
    /* Compute f(s) */
    BitString* fs = bs_create(owf->output_bits);
    if (!fs) return out_pos;
    owf_eval(owf, seed, fs);
    for (size_t i = 0; i < fs->n_bits && out_pos < output->n_bits; i++) {
        bs_set_bit(output, out_pos++, bs_get_bit(fs, i));
    }
    bs_free(fs);
    return out_pos;
}
