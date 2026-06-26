#ifndef UOWHF_H
#define UOWHF_H
#include "minimal_assumptions.h"
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    size_t input_bits;
    size_t output_bits;
    size_t key_bits;
    uint8_t* key;
} UOWHFKey;

typedef struct {
    UOWHFKey* current_key;
    const uint8_t* target_input;
    size_t target_len;
    const uint8_t* target_hash;
    size_t hash_len;
} UOWHFChallenge;

UOWHFKey* uowhf_keygen(size_t input_bits, size_t output_bits);
void uowhf_hash(const UOWHFKey* key, const uint8_t* msg, size_t msg_len,
                uint8_t* digest, size_t digest_len);
void uowhf_free_key(UOWHFKey* key);

typedef struct {
    int success;
    UOWHFKey* collision_key;
    uint8_t* second_preimage;
    size_t second_len;
} UOWHFAttack;

UOWHFAttack uowhf_adversary_attempt(const UOWHFChallenge* challenge);
int uowhf_verify_attack(const UOWHFChallenge* challenge, const UOWHFAttack* attack);
int uowhf_security_proof_rompel(size_t security_param);

typedef struct {
    size_t n_stages;
    double* stage_security;
    size_t* stage_key_bits;
    int final_secure;
} RompelConstruction;

RompelConstruction uowhf_from_owf_rompel(size_t security_param,
                                          double owf_hardness);
void rompel_construction_free(RompelConstruction* rc);

int uowhf_compose_hash_chain(const uint8_t** messages, size_t* msg_lens,
                              int n_msgs, uint8_t* final_digest, size_t dlen);
int uowhf_compare_security(const UOWHFKey* k1, const UOWHFKey* k2);
void uowhf_print_params(const UOWHFKey* key);

#ifdef __cplusplus
}
#endif
#endif
