/*
 * test_next_bit_unpredictable.c - Tests for next-bit unpredictability
 */
#include "next_bit_unpredictable.h"
#include <assert.h>
#include <stdio.h>
#include <math.h>

static int tests_run = 0, tests_passed = 0;

#define TEST(n) do { tests_run++; printf("  TEST: %s ... ", n); } while(0)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(m) do { printf("FAIL: %s\n", m); } while(0)

static void test_predictor_create_trivial(void) {
    TEST("predictor_create_constant");
    NextBitPredictor* P = predictor_create_constant(1);
    assert(P != NULL);
    int guess = predictor_predict(P, NULL, 0, 0, 0);
    assert(guess == 1);
    predictor_free(P);
    PASS();
}

static void test_predictor_create_constant_zero(void) {
    TEST("predictor_create_constant(0)");
    NextBitPredictor* P = predictor_create_constant(0);
    assert(P != NULL);
    int guess = predictor_predict(P, NULL, 0, 0, 0);
    assert(guess == 0);
    predictor_free(P);
    PASS();
}

static void test_majority_predictor(void) {
    TEST("majority prefix predictor");
    NextBitPredictor* P = predictor_create_majority_prefix(4);
    assert(P != NULL);
    /* All-ones prefix -> predict 1 */
    uint8_t buf[1] = {0xF0}; /* 1111 0000 */
    int guess = predictor_predict(P, buf, 4, 4, 8);
    assert(guess == 1);
    /* All-zeros -> predict 0 */
    buf[0] = 0x00;
    guess = predictor_predict(P, buf, 4, 4, 8);
    assert(guess == 0);
    predictor_free(P);
    PASS();
}

static void test_xor_predictor(void) {
    TEST("XOR prefix predictor");
    NextBitPredictor* P = predictor_create_xor_of_prefix(3);
    assert(P != NULL);
    /* Three 1's -> XOR = 1 */
    uint8_t buf[1] = {0xE0}; /* 1110 0000 */
    int guess = predictor_predict(P, buf, 3, 3, 8);
    assert(guess == 1);
    /* Two 1's -> XOR = 0 */
    buf[0] = 0xC0; /* 1100 0000 */
    guess = predictor_predict(P, buf, 3, 3, 8);
    assert(guess == 0);
    predictor_free(P);
    PASS();
}

static void test_complement_predictor(void) {
    TEST("complement predictor");
    NextBitPredictor* P = predictor_create_complement_of_last();
    assert(P != NULL);
    uint8_t buf[1] = {0x00};
    int guess = predictor_predict(P, buf, 1, 1, 8);
    assert(guess == 1);  /* complement of 0 = 1 */
    predictor_free(P);
    PASS();
}

static void test_periodic_predictor(void) {
    TEST("periodic predictor");
    NextBitPredictor* P = predictor_create_periodic(2);
    assert(P != NULL);
    /* Pattern: 1 0 1 0 -> bit at position 0 is 1 */
    uint8_t buf[1] = {0xA0}; /* 1010 0000 */
    int guess = predictor_predict(P, buf, 4, 4, 8);
    assert(guess == 1);  /* bit at pos 2 = bit at pos 0 = 1 */
    predictor_free(P);
    PASS();
}

static void test_next_bit_game(void) {
    TEST("next_bit_game with trivial PRG");
    PRG* g = prg_create_trivial();
    NextBitPredictor* P = predictor_create_constant(0);
    NextBitGameResult res = next_bit_game_run(g, P, 4, 16, 50);
    assert(res.num_trials == 50);
    assert(res.success_rate >= 0.0 && res.success_rate <= 1.0);
    prg_free(g);
    predictor_free(P);
    PASS();
}

static void test_yao_predictor_to_distinguisher(void) {
    TEST("Yao: predictor -> distinguisher");
    NextBitPredictor* P = predictor_create_constant(1);
    Distinguisher* D = yao_predictor_to_distinguisher(P, 8);
    assert(D != NULL);
    assert(D->name != NULL);
    dist_free_with_state(D);
    predictor_free(P);
    PASS();
}

static void test_yao_dist_to_pred(void) {
    TEST("Yao: distinguisher -> predictor");
    Distinguisher* D = dist_create_trivial(1);
    NextBitPredictor* P = yao_distinguisher_to_predictor(D, 256);
    assert(P != NULL);
    predictor_free(P);
    dist_free_with_state(D);
    PASS();
}

static void test_yao_equivalence(void) {
    TEST("Yao equivalence verification");
    PRG* g = prg_create_xorshift(42ULL);
    Distinguisher* D = dist_create_first_k_zero(4);
    YaoEquivalenceResult yr = yao_verify_equivalence(g, D, 16, 128, 50);
    assert(yr.equivalence_holds);
    prg_free(g);
    dist_free_with_state(D);
    PASS();
}

static void test_next_bit_test_full(void) {
    TEST("next_bit_test_full");
    PRG* g = prg_create_xorshift(7ULL);
    NextBitPredictor* P = predictor_create_majority_prefix(8);
    NextBitTestReport* rpt = next_bit_test_full(g, P, 16, 30, 32);
    assert(rpt != NULL);
    assert(rpt->num_positions > 0);
    next_bit_test_report_free(rpt);
    predictor_free(P);
    prg_free(g);
    PASS();
}

static void test_prg_assess_via_prediction(void) {
    TEST("prg_assess_via_prediction");
    PRG* g = prg_create_xorshift(99ULL);
    PRGPredictionSecurity ps = prg_assess_via_prediction(g, 16, 40, 0.15);
    assert(ps.positions_tested > 0);
    prg_free(g);
    PASS();
}

int main(void) {
    printf("=== test_next_bit_unpredictable ===\n");
    rand_seed(42);

    test_predictor_create_trivial();
    test_predictor_create_constant_zero();
    test_majority_predictor();
    test_xor_predictor();
    test_complement_predictor();
    test_periodic_predictor();
    test_next_bit_game();
    test_yao_predictor_to_distinguisher();
    test_yao_dist_to_pred();
    test_yao_equivalence();
    test_next_bit_test_full();
    test_prg_assess_via_prediction();

    printf("\n=== RESULTS: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
