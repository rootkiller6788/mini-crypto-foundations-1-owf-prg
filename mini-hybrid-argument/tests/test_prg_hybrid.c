/*
 * test_prg_hybrid.c - Tests for PRG hybrid argument
 */
#include "prg_hybrid.h"
#include "distinguisher.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static int tests_run = 0, tests_passed = 0;

#define TEST(n) do { tests_run++; printf("  TEST: %s ... ", n); } while(0)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(m) do { printf("FAIL: %s\n", m); } while(0)

static void test_prg_create_trivial(void) {
    TEST("prg_create_trivial");
    PRG* g = prg_create_trivial();
    assert(g != NULL);
    assert(g->name != NULL);
    prg_free(g);
    PASS();
}

static void test_prg_trivial_eval(void) {
    TEST("trivial PRG output size");
    PRG* g = prg_create_trivial();
    uint8_t seed[8] = {0};
    uint8_t out[32] = {0};
    size_t ob = 0;
    prg_evaluate(g, seed, 16, out, &ob);
    assert(ob == 32);
    prg_free(g);
    PASS();
}

static void test_prg_trivial_complement(void) {
    TEST("trivial PRG: complement check");
    PRG* g = prg_create_trivial();
    uint8_t seed[2] = {0x55, 0xAA};
    uint8_t out[32] = {0};
    size_t ob = 0;
    prg_evaluate(g, seed, 16, out, &ob);
    assert(ob == 32);
    assert(out[0] == 0x55);
    assert(out[2] == (uint8_t)(~0x55));
    prg_free(g);
    PASS();
}

static void test_prg_create_lcg(void) {
    TEST("prg_create_lcg");
    PRG* g = prg_create_lcg(6364136223846793005ULL, 1442695040888963407ULL, 0);
    assert(g != NULL);
    prg_free(g);
    PASS();
}

static void test_prg_create_xorshift(void) {
    TEST("prg_create_xorshift");
    PRG* g = prg_create_xorshift(12345ULL);
    assert(g != NULL);
    uint8_t seed[4] = {1,2,3,4};
    uint8_t out[128] = {0};
    size_t ob = 0;
    prg_evaluate(g, seed, 32, out, &ob);
    assert(ob >= 288);
    prg_free(g);
    PASS();
}

static void test_prg_create_hash_chain(void) {
    TEST("prg_create_hash_chain");
    PRG* g = prg_create_hash_chain(4);
    assert(g != NULL);
    uint8_t seed[8] = {0};
    uint8_t out[128] = {0};
    size_t ob = 0;
    prg_evaluate(g, seed, 64, out, &ob);
    assert(ob == 320);
    prg_free(g);
    PASS();
}

static void test_security_game(void) {
    TEST("prg_security_game with trivial dist");
    PRG* g = prg_create_trivial();
    Distinguisher* adv = dist_create_trivial(1);
    PRGSecurityGame game = prg_security_game_run(g, adv, 16, 50);
    assert(game.num_trials == 50);
    prg_free(g);
    dist_free_with_state(adv);
    PASS();
}

static void test_stream_xor(void) {
    TEST("prg_stream_xor encrypt/decrypt");
    PRG* g = prg_create_xorshift(42ULL);
    uint8_t key[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint8_t plain[] = "HELLO";
    uint8_t cipher[8] = {0};
    uint8_t decrypted[8] = {0};
    prg_stream_xor(g, key, 32, plain, 40, cipher);
    prg_stream_xor(g, key, 32, cipher, 40, decrypted);
    assert(memcmp(plain, decrypted, 5) == 0);
    prg_free(g);
    PASS();
}

static void test_kdf_derive(void) {
    TEST("prg_kdf_derive");
    PRG* g = prg_create_xorshift(99ULL);
    uint8_t mk[4] = {1,2,3,4};
    uint8_t salt[2] = {0xAA, 0xBB};
    uint8_t sub[8] = {0};
    int r = prg_kdf_derive(g, mk, 32, salt, 16, sub, 64);
    assert(r == 0);
    int non_zero = 0;
    for (int i = 0; i < 8; i++) if (sub[i] != 0) non_zero = 1;
    assert(non_zero);
    prg_free(g);
    PASS();
}

static void test_analyze_output(void) {
    TEST("prg_analyze_output");
    PRG* g = prg_create_xorshift(7ULL);
    uint8_t seed[8] = {0};
    PRGStatistics stats = prg_analyze_output(g, seed, 64);
    assert(stats.output_bits > 0);
    assert(stats.mean_bit_fraction > 0.0);
    assert(stats.num_runs > 0);
    prg_free(g);
    PASS();
}

int main(void) {
    printf("=== test_prg_hybrid ===\n");
    rand_seed(42);
    test_prg_create_trivial();
    test_prg_trivial_eval();
    test_prg_trivial_complement();
    test_prg_create_lcg();
    test_prg_create_xorshift();
    test_prg_create_hash_chain();
    test_security_game();
    test_stream_xor();
    test_kdf_derive();
    test_analyze_output();
    printf("\n=== RESULTS: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
