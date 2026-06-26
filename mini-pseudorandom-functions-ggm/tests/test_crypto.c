/* test_crypto.c - Tests for Cryptographic Utilities */
#include "crypto_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int tests_run = 0, tests_passed = 0;
#define TEST(n) do { tests_run++; printf("  TEST: %s ... ", #n); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)

static void test_crypto_rng(void) {
    TEST(crypto_rng);
    CryptoRNG* rng = crypto_rng_create(12345);
    assert(rng != NULL);
    uint64_t v1 = crypto_rng_next(rng);
    uint64_t v2 = crypto_rng_next(rng);
    assert(v1 != v2);
    uint8_t buf[32];
    crypto_rng_fill(rng, buf, sizeof(buf));
    crypto_rng_free(rng);
    PASS();
}

static void test_crypto_hash(void) {
    TEST(crypto_hash);
    CryptoHash* h = crypto_hash_create();
    assert(h != NULL);
    const char* msg = "Hello, World!";
    crypto_hash_update(h, (const uint8_t*)msg, strlen(msg));
    crypto_hash_finalize(h);
    assert(h->finalized);
    const uint8_t* d = crypto_hash_digest(h);
    assert(d != NULL);
    crypto_hash_free(h);
    PASS();
}

static void test_crypto_hash_oneshot(void) {
    TEST(crypto_hash_oneshot);
    uint8_t d1[16], d2[16];
    const char* m1 = "message1";
    const char* m2 = "message2";
    crypto_hash_oneshot((const uint8_t*)m1, strlen(m1), d1);
    crypto_hash_oneshot((const uint8_t*)m2, strlen(m2), d2);
    int diff = 0;
    for (int i = 0; i < 16; i++) diff |= (d1[i] ^ d2[i]);
    assert(diff != 0); /* Different messages should hash differently */
    PASS();
}

static void test_toy_cipher(void) {
    TEST(toy_cipher);
    uint8_t key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    ToyCipher* tc = toy_cipher_create(key, 16);
    assert(tc != NULL);

    uint8_t pt[16] = {0};
    uint8_t ct[16] = {0};
    uint8_t rec[16] = {0};
    toy_cipher_encrypt_block(tc, pt, ct);
    toy_cipher_decrypt_block(tc, ct, rec);
    assert(memcmp(pt, rec, 16) == 0);
    toy_cipher_free(tc);
    PASS();
}

static void test_toy_ctr(void) {
    TEST(toy_ctr);
    uint8_t key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    ToyCTR* ctr = toy_ctr_create(key, 16, NULL, 0);
    assert(ctr != NULL);
    uint8_t buf[32];
    toy_ctr_generate(ctr, buf, sizeof(buf));
    uint8_t buf2[32];
    ToyCTR* ctr2 = toy_ctr_create(key, 16, NULL, 0);
    toy_ctr_generate(ctr2, buf2, sizeof(buf2));
    assert(memcmp(buf, buf2, 32) == 0); /* deterministic */
    toy_ctr_free(ctr);
    toy_ctr_free(ctr2);
    PASS();
}

static void test_gf2_operations(void) {
    TEST(gf2_operations);
    uint8_t x[4] = {0xFF, 0x00, 0xAA, 0x55};
    uint8_t y[4] = {0x0F, 0xF0, 0x55, 0xAA};
    /* Inner product */
    int ip = gf2_inner_product(x, y, 32);
    assert(ip == 0 || ip == 1);

    /* Vector addition */
    uint8_t sum[4];
    gf2_vector_add(x, y, sum, 32);
    for (int i = 0; i < 4; i++) assert(sum[i] == (x[i] ^ y[i]));

    /* Hamming weight */
    int wt = gf2_hamming_weight(x, 32);
    assert(wt == 16); /* 0xFF(8) + 0x00(0) + 0xAA(4) + 0x55(4) = 16 */

    /* Hamming distance */
    int dist = gf2_hamming_distance(x, y, 32);
    assert(dist >= 0);
    PASS();
}

static void test_owf(void) {
    TEST(owf);
    OWF* owf = owf_create_toy_multiply(128);
    assert(owf != NULL);
    uint8_t input[16] = {0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,
                          0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
    uint8_t output[16] = {0};
    int ret = owf_evaluate(owf, input, output);
    assert(ret == 1);
    owf_free(owf);
    PASS();
}

static void test_hardcore_bit(void) {
    TEST(hardcore_bit);
    uint8_t x[8] = {0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55};
    uint8_t r[8] = {0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00};
    int hcb = crypto_hardcore_bit_gl(x, 64, r, 64);
    assert(hcb == 0 || hcb == 1);
    PASS();
}

static void test_constant_time_compare(void) {
    TEST(constant_time_compare);
    uint8_t a[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t b[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t c[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,17};
    assert(crypto_constant_time_compare(a, b, 16) == 1);
    assert(crypto_constant_time_compare(a, c, 16) == 0);
    assert(crypto_constant_time_compare(NULL, b, 16) == 0);
    PASS();
}

static void test_hex_conversion(void) {
    TEST(hex_conversion);
    uint8_t bin[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    char hex[9];
    crypto_bin_to_hex(bin, 4, hex);
    assert(strcmp(hex, "deadbeef") == 0);
    uint8_t back[4] = {0};
    int n = crypto_hex_to_bin(hex, back, 4);
    assert(n == 4);
    assert(memcmp(bin, back, 4) == 0);
    PASS();
}

int main(void) {
    printf("=== Crypto Utils Tests ===\n");
    test_crypto_rng();
    test_crypto_hash();
    test_crypto_hash_oneshot();
    test_toy_cipher();
    test_toy_ctr();
    test_gf2_operations();
    test_owf();
    test_hardcore_bit();
    test_constant_time_compare();
    test_hex_conversion();
    printf("\nResults: %d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
