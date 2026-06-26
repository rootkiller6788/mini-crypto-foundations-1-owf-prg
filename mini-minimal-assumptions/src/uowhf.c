/*
 * uowhf.c — Universal One-Way Hash Function Implementation
 * Reference: Rompel (STOC 1990) — OWF → UOWHF
 */
#include "uowhf.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

UOWHFKey* uowhf_keygen(size_t input_bits, size_t output_bits) {
    if (input_bits <= output_bits || output_bits == 0 || output_bits > 512)
        return NULL;
    UOWHFKey* key = calloc(1, sizeof(UOWHFKey));
    if (!key) return NULL;
    key->input_bits = input_bits;
    key->output_bits = output_bits;
    key->key_bits = output_bits * 2;
    key->key = calloc(1, (key->key_bits + 7) / 8);
    if (!key->key) { free(key); return NULL; }
    uint64_t seed = 0xCAFEBABEDEADBEEFULL;
    size_t key_bytes = (key->key_bits + 7) / 8;
    for (size_t i = 0; i < key_bytes; i++) {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        key->key[i] = (uint8_t)(seed >> 56);
    }
    return key;
}

void uowhf_hash(const UOWHFKey* key, const uint8_t* msg, size_t msg_len,
                uint8_t* digest, size_t digest_len) {
    if (!key || !msg || !digest || digest_len == 0) return;
    size_t out_bytes = (key->output_bits + 7) / 8;
    size_t actual = (digest_len < out_bytes) ? digest_len : out_bytes;
    uint8_t state[64];
    memset(state, 0, sizeof(state));
    size_t key_bytes = (key->key_bits + 7) / 8;
    for (size_t i = 0; i < key_bytes && i < sizeof(state); i++)
        state[i] = key->key[i];
    size_t block_size = out_bytes;
    size_t n_blocks = (msg_len + block_size - 1) / block_size;
    if (n_blocks == 0) n_blocks = 1;
    for (size_t b = 0; b < n_blocks; b++) {
        for (size_t i = 0; i < block_size && i < msg_len - b * block_size; i++) {
            state[i] ^= msg[b * block_size + i];
            state[i] = (state[i] << 3) | (state[i] >> 5);
        }
        for (int round = 0; round < 4; round++) {
            for (size_t i = 0; i < sizeof(state); i++) {
                size_t next = (i + 1) % sizeof(state);
                state[i] ^= state[next] + (uint8_t)(round * 37);
                state[i] = (state[i] << 1) | (state[i] >> 7);
            }
        }
    }
    memcpy(digest, state, actual);
}

void uowhf_free_key(UOWHFKey* key) {
    if (!key) return;
    free(key->key); free(key);
}

UOWHFAttack uowhf_adversary_attempt(const UOWHFChallenge* challenge) {
    UOWHFAttack attack;
    memset(&attack, 0, sizeof(attack));
    if (!challenge || !challenge->current_key) return attack;
    size_t buf_len = challenge->target_len;
    attack.second_preimage = calloc(1, buf_len);
    if (!attack.second_preimage) return attack;
    for (size_t bit = 0; bit < challenge->target_len * 8 && bit < 256; bit++) {
        memcpy(attack.second_preimage, challenge->target_input, buf_len);
        size_t bi = bit / 8;
        int bj = bit % 8;
        attack.second_preimage[bi] ^= (uint8_t)(1 << bj);
        uint8_t test_hash[64];
        memset(test_hash, 0, sizeof(test_hash));
        uowhf_hash(challenge->current_key, attack.second_preimage, buf_len,
                   test_hash, sizeof(test_hash));
        if (memcmp(test_hash, challenge->target_hash, challenge->hash_len) == 0 &&
            memcmp(attack.second_preimage, challenge->target_input, buf_len) != 0) {
            attack.success = 1;
            attack.collision_key = NULL;
            attack.second_len = buf_len;
            return attack;
        }
    }
    free(attack.second_preimage);
    attack.second_preimage = NULL;
    return attack;
}

int uowhf_verify_attack(const UOWHFChallenge* challenge, const UOWHFAttack* attack) {
    if (!challenge || !attack || !attack->success || !attack->second_preimage)
        return 0;
    if (memcmp(attack->second_preimage, challenge->target_input,
               challenge->target_len) == 0) return 0;
    uint8_t hash[64];
    uowhf_hash(challenge->current_key, attack->second_preimage,
               attack->second_len, hash, challenge->hash_len);
    return (memcmp(hash, challenge->target_hash, challenge->hash_len) == 0) ? 1 : 0;
}

int uowhf_security_proof_rompel(size_t security_param) {
    printf("\n=== Rompel Security Proof (OWF -> UOWHF) ===\n");
    printf("Security parameter: %zu\n", security_param);
    printf("Reduction: UOWHF adversary A -> OWF inverter I\n");
    printf("1. I receives y = f(x) (OWF challenge)\n");
    printf("2. I constructs UOWHF key k from y\n");
    printf("3. I gets target x* from A\n");
    printf("4. I gives k to A, receives x' != x* collision\n");
    printf("5. I uses collision to recover x (OWF preimage)\n");
    printf("Security loss factor: poly(n)\n");
    printf("=== End Security Proof ===\n");
    return 0;
}

RompelConstruction uowhf_from_owf_rompel(size_t security_param,
                                          double owf_hardness) {
    RompelConstruction rc;
    memset(&rc, 0, sizeof(rc));
    rc.n_stages = 3;
    rc.stage_security = calloc(rc.n_stages, sizeof(double));
    rc.stage_key_bits = calloc(rc.n_stages, sizeof(size_t));
    rc.stage_key_bits[0] = security_param;
    rc.stage_security[0] = owf_hardness;
    rc.stage_key_bits[1] = security_param * 2;
    rc.stage_security[1] = owf_hardness * 0.5;
    rc.stage_key_bits[2] = security_param * 3;
    rc.stage_security[2] = owf_hardness * 0.25;
    rc.final_secure = (rc.stage_security[2] < 0.01) ? 1 : 0;
    return rc;
}

void rompel_construction_free(RompelConstruction* rc) {
    if (!rc) return;
    free(rc->stage_security); free(rc->stage_key_bits);
}

int uowhf_compose_hash_chain(const uint8_t** messages, size_t* msg_lens,
                              int n_msgs, uint8_t* final_digest, size_t dlen) {
    if (!messages || !msg_lens || n_msgs <= 0 || !final_digest) return -1;
    UOWHFKey* key = uowhf_keygen(256, 128);
    if (!key) return -1;
    uint8_t state[64];
    memset(state, 0, sizeof(state));
    size_t state_len = 32;
    uint8_t combined[256];
    for (int i = 0; i < n_msgs; i++) {
        if (state_len + msg_lens[i] > sizeof(combined)) {
            uowhf_free_key(key); return -1;
        }
        memcpy(combined, state, state_len);
        memcpy(combined + state_len, messages[i], msg_lens[i]);
        uowhf_hash(key, combined, state_len + msg_lens[i], state, state_len);
    }
    memcpy(final_digest, state, (dlen < state_len) ? dlen : state_len);
    uowhf_free_key(key);
    return 0;
}

int uowhf_compare_security(const UOWHFKey* k1, const UOWHFKey* k2) {
    if (!k1 || !k2) return 0;
    if (k1->key_bits > k2->key_bits) return 1;
    if (k1->key_bits < k2->key_bits) return -1;
    double r1 = (double)k1->input_bits / k1->output_bits;
    double r2 = (double)k2->input_bits / k2->output_bits;
    if (r1 > r2) return 1;
    if (r1 < r2) return -1;
    return 0;
}

void uowhf_print_params(const UOWHFKey* key) {
    if (!key) return;
    printf("\n=== UOWHF Parameters ===\n");
    printf("Input bits:  %zu\n", key->input_bits);
    printf("Output bits: %zu\n", key->output_bits);
    printf("Key bits:    %zu\n", key->key_bits);
    printf("Compression: %.2f:1\n",
           (double)key->input_bits / key->output_bits);
    printf("=== End UOWHF Params ===\n");
}
