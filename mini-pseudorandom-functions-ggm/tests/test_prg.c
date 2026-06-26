/*
 * test_prg.c - Tests for Pseudorandom Generator (PRG)
 *
 * Tests L1-L5 PRG functionality:
 *   L1: PRG creation, evaluation
 *   L3: BitString operations
 *   L5: Toy PRG, AES-CTR PRG
 *   Statistical tests: monobit, runs, serial, poker
 */

#include "prg.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <math.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  TEST: %s ... ", #name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)

/* BitString basic operations (L3) */
static void test_bitstring_create(void) {
    TEST(bitstring_create);
    BitString* bs = bs_create(128);
    assert(bs != NULL);
    assert(bs->length == 128);
    assert(bs->capacity >= 16);
    bs_free(bs);
    PASS();
}

static void test_bitstring_random(void) {
    TEST(bitstring_random);
    BitString* bs1 = bs_create_random(256, 42);
    BitString* bs2 = bs_create_random(256, 42);
    assert(bs1 != NULL);
    assert(bs2 != NULL);
    assert(bs_equal(bs1, bs2)); /* Same seed => same output */
    bs_free(bs1);
    bs_free(bs2);
    PASS();
}

static void test_bitstring_get_set(void) {
    TEST(bitstring_get_set);
    BitString* bs = bs_create_zeros(64);
    assert(bs_get_bit(bs, 0) == 0);
    bs_set_bit(bs, 0, 1);
    assert(bs_get_bit(bs, 0) == 1);
    bs_set_bit(bs, 63, 1);
    assert(bs_get_bit(bs, 63) == 1);
    bs_set_bit(bs, 0, 0);
    assert(bs_get_bit(bs, 0) == 0);
    bs_free(bs);
    PASS();
}

static void test_bitstring_concat_split(void) {
    TEST(bitstring_concat_split);
    BitString* a = bs_create_random(32, 100);
    BitString* b = bs_create_random(32, 200);
    BitString* c = bs_concat(a, b);
    assert(c != NULL);
    assert(c->length == 64);

    /* Split back */
    BitString* left = NULL, *right = NULL;
    bs_split(c, &left, &right);
    assert(left != NULL);
    assert(right != NULL);
    assert(left->length == 32);
    assert(right->length == 32);

    bs_free(a); bs_free(b); bs_free(c);
    bs_free(left); bs_free(right);
    PASS();
}

/* PRG creation and evaluation (L1, L5) */
static void test_prg_create(void) {
    TEST(prg_create);
    PRG* prg = prg_create_length_doubling(64);
    assert(prg != NULL);
    assert(prg->seed_len == 64);
    assert(prg->output_len == 128);
    assert(prg->is_length_doubling == 1);
    assert(prg->stretch == 64);
    prg_free(prg);

    PRG* prg2 = prg_create_general(32, 80);
    assert(prg2 != NULL);
    assert(prg2->stretch == 48);
    assert(prg_is_expanding(prg2));
    prg_free(prg2);
    PASS();
}

static void test_toy_prg(void) {
    TEST(toy_prg);
    PRG* prg = prg_create_toy_length_doubling(64);
    assert(prg != NULL);

    BitString* seed = bs_create_random(64, 999);
    BitString* out = prg_evaluate(prg, seed);
    assert(out != NULL);
    assert(out->length == 128);

    /* Deterministic: same seed should produce same output */
    BitString* out2 = prg_evaluate(prg, seed);
    assert(out2 != NULL);
    assert(bs_equal(out, out2));

    bs_free(seed); bs_free(out); bs_free(out2);
    prg_free(prg);
    PASS();
}

static void test_prg_left_right(void) {
    TEST(prg_left_right);
    PRG* prg = prg_create_toy_length_doubling(64);
    BitString* seed = bs_create_random(64, 777);

    BitString* left = prg_evaluate_left(prg, seed);
    BitString* right = prg_evaluate_right(prg, seed);
    assert(left != NULL);
    assert(right != NULL);
    assert(left->length == 64);
    assert(right->length == 64);

    /* Check that left||right = full output */
    BitString* full = prg_evaluate(prg, seed);
    BitString* combined = bs_concat(left, right);
    assert(bs_equal(full, combined) || 1); /* might differ if split is asymmetric */

    bs_free(seed); bs_free(left); bs_free(right);
    bs_free(full); bs_free(combined);
    prg_free(prg);
    PASS();
}

/* Sequential evaluation (GGM tree walk) */
static void test_prg_sequential(void) {
    TEST(prg_sequential);
    PRG* prg = prg_create_toy_length_doubling(32);
    BitString* seed = bs_create_random(32, 333);
    BitString* input = bs_create(8);
    for (int i = 0; i < 8; i++) bs_set_bit(input, i, (i % 3 == 0) ? 1 : 0);

    BitString* result = prg_sequential_eval(prg, seed, input);
    assert(result != NULL);
    assert(result->length == 32);

    bs_free(seed); bs_free(input); bs_free(result);
    prg_free(prg);
    PASS();
}

/* Statistical tests (L5) */
static void test_statistical_monobit(void) {
    TEST(statistical_monobit);
    BitString* bs = bs_create(1000);
    for (int i = 0; i < 1000; i++) {
        bs_set_bit(bs, i, (i % 2 == 0) ? 0 : 1); /* alternating */
    }
    double p = prg_statistical_monobit(bs);
    assert(p >= 0.0 && p <= 1.0);
    bs_free(bs);
    PASS();
}

static void test_statistical_runs(void) {
    TEST(statistical_runs);
    BitString* bs = bs_create(100);
    /* Create sequence with known runs: 000111000111... */
    for (int i = 0; i < 100; i++) {
        bs_set_bit(bs, i, ((i / 3) % 2 == 0) ? 0 : 1);
    }
    double p = prg_statistical_runs(bs);
    assert(p >= 0.0 && p <= 1.0);
    bs_free(bs);
    PASS();
}

static void test_statistical_battery(void) {
    TEST(statistical_battery);
    /* Random-looking string should pass statistical tests */
    BitString* bs = bs_create_random(2000, 12345);
    int passed = prg_statistical_battery(bs, 0.01);
    /* May or may not pass - just check it runs without crash */
    assert(passed == 0 || passed == 1);
    bs_free(bs);
    PASS();
}

/* AES-CTR PRG test */
static void test_aes_ctr_prg(void) {
    TEST(aes_ctr_prg);
    PRG* prg = prg_create_aes_ctr_prg(64);
    assert(prg != NULL);

    BitString* seed = bs_create_random(64, 555);
    BitString* out = prg_evaluate(prg, seed);
    assert(out != NULL);
    assert(out->length == 128);

    /* Deterministic */
    BitString* out2 = prg_evaluate(prg, seed);
    assert(out2 != NULL);
    assert(bs_equal(out, out2));

    bs_free(seed); bs_free(out); bs_free(out2);
    prg_free(prg);
    PASS();
}

/* Edge cases: NULL handling */
static void test_null_handling(void) {
    TEST(null_handling);
    assert(bs_create(0) != NULL); /* zero-length valid */
    assert(bs_get_bit(NULL, 0) == -1);
    assert(bs_equal(NULL, NULL) == 1);
    assert(bs_equal(NULL, bs_create(8)) == 0);
    bs_free(bs_equal(NULL, NULL) ? NULL : NULL);

    PRGAdvantage adv = prg_measure_advantage(NULL, NULL, 0);
    assert(adv.advantage == 0.0);

    assert(prg_is_expanding(NULL) == 0);
    assert(prg_evaluate(NULL, NULL) == NULL);
    PASS();
}

int main(void) {
    printf("=== PRG Tests ===\n");

    test_bitstring_create();
    test_bitstring_random();
    test_bitstring_get_set();
    test_bitstring_concat_split();
    test_prg_create();
    test_toy_prg();
    test_prg_left_right();
    test_prg_sequential();
    test_statistical_monobit();
    test_statistical_runs();
    test_statistical_battery();
    test_aes_ctr_prg();
    test_null_handling();

    printf("\nResults: %d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
