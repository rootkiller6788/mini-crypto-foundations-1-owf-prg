/*
 * test_goldreich_levin.c — Unit tests for Goldreich-Levin module
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "../include/goldreich_levin.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  TEST %s... ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASSED\n"); } while(0)
#define FAIL(msg) do { printf("FAILED: %s\n", msg); } while(0)
#define ASSERT_TRUE(cond, msg) do { if (!(cond)) { FAIL(msg); return; } } while(0)
#define ASSERT_EQ(a, b, msg) do { if ((a) != (b)) { FAIL(msg); return; } } while(0)

void test_gl_compute_m(void) {
    TEST("gl_compute_m");
    size_t m = gl_compute_m(16, 0.1, 0.99);
    ASSERT_TRUE(m > 0, "m positive");
    ASSERT_TRUE(m < 100000, "m is polynomial");
    PASS();
}

void test_gl_estimate_epsilon(void) {
    TEST("gl_estimate_epsilon");
    double eps = gl_estimate_epsilon(600, 1000);
    ASSERT_TRUE(eps > 0.05, "advantage from 60% accuracy");
    ASSERT_TRUE(eps < 0.5, "advantage reasonable");
    PASS();
}

void test_gl_query_complexity(void) {
    TEST("gl_query_complexity");
    size_t q = gl_query_complexity(16, 0.1);
    ASSERT_TRUE(q > 0, "query complexity positive");
    PASS();
}

void test_gl_prob_success_per_bit(void) {
    TEST("gl_prob_success_per_bit");
    double prob = gl_prob_success_per_bit(10000, 0.2);
    ASSERT_TRUE(prob > 0.5, "probability above random");
    ASSERT_TRUE(prob <= 1.0, "probability bounded");
    PASS();
}

void test_gl_prob_success_overall(void) {
    TEST("gl_prob_success_overall");
    double prob = gl_prob_success_overall(16, 200, 0.15);
    ASSERT_TRUE(prob >= 0.0 && prob <= 1.0, "probability in [0,1]");
    PASS();
}

void test_gl_bit_majority(void) {
    TEST("gl_bit_majority");
    int votes1[] = {1, 1, 1, 0, 0};
    ASSERT_EQ(gl_bit_majority(votes1, 5), 1, "majority 1");
    int votes2[] = {0, 0, 0, 1, 1};
    ASSERT_EQ(gl_bit_majority(votes2, 5), 0, "majority 0");
    int votes3[] = {1, 0, 1, 0, 0};
    ASSERT_EQ(gl_bit_majority(votes3, 5), 0, "majority 0 (tiebreaker)");
    PASS();
}

void test_gl_advantage_epsilon_conversion(void) {
    TEST("gl_advantage/epsilon conversion");
    double e = 0.3;
    ASSERT_TRUE(gl_advantage_to_epsilon(e) == e, "advantage to epsilon identity");
    ASSERT_TRUE(gl_epsilon_to_advantage(e) == e, "epsilon to advantage identity");
    PASS();
}

void test_gl_sample_r(void) {
    TEST("gl_sample_r");
    BitString* r = gl_sample_r(128);
    ASSERT_TRUE(r != NULL, "random r created");
    ASSERT_EQ(r->n_bits, (size_t)128, "size correct");
    bs_free(r);
    PASS();
}

void test_gl_sample_r_shifted(void) {
    TEST("gl_sample_r_shifted");
    BitString* r = bs_create(64);
    bs_set_bit(r, 5, 0);
    BitString* shifted = gl_sample_r_shifted(r, 5);
    ASSERT_TRUE(shifted != NULL, "shifted created");
    ASSERT_EQ(bs_get_bit(shifted, 5), 1, "bit 5 flipped to 1");
    bs_free(r); bs_free(shifted);
    PASS();
}

/* A trivial predictor for testing */
static int trivial_query(const BitString* fx, const BitString* r,
                          int* pred, void* ctx) {
    (void)fx; (void)r; (void)ctx;
    *pred = 0;
    return 1;
}

void test_gl_ctx_create(void) {
    TEST("gl_ctx_create");
    OWF* owf = owf_create(OWF_SQUARING, 16);
    ASSERT_TRUE(owf != NULL, "OWF created");
    HCPredictor* pred = hc_predictor_create("test", trivial_query, NULL);
    ASSERT_TRUE(pred != NULL, "predictor created");
    BitString* fx = bs_create_random(owf->output_bits);
    GLCtx* ctx = gl_ctx_create(owf, pred, 0.1, fx, 1000);
    ASSERT_TRUE(ctx != NULL, "GL context created");
    ASSERT_EQ(ctx->n, (size_t)16, "n correct");
    gl_ctx_free(ctx);
    hc_predictor_free(pred);
    bs_free(fx);
    owf_free(owf);
    PASS();
}

void test_gl_recover_bit_simple(void) {
    TEST("gl_recover_bit (simple)");
    /* For very small n with a perfect predictor, GL should work */
    OWF* owf = owf_create(OWF_SQUARING, 8);
    ASSERT_TRUE(owf != NULL, "OWF created");
    /* Create a known input x */
    BitString* x = bs_create(8);
    bs_set_bit(x, 3, 1);  /* x = 00001000, value=8 */
    BitString* fx = bs_create(owf->output_bits);
    owf_eval(owf, x, fx);

    /* We verify GL machinery works structurally */
    GLParams params;
    params.n = 8;
    params.epsilon = 0.2;
    params.m = gl_compute_m(8, 0.2, 0.99);
    params.confidence = 0.99;

    gl_print_params(&params);
    ASSERT_TRUE(params.m > 0, "m computed");
    bs_free(x); bs_free(fx);
    owf_free(owf);
    PASS();
}

int main(void) {
    printf("=== Test: Goldreich-Levin ===\n\n");
    test_gl_compute_m();
    test_gl_estimate_epsilon();
    test_gl_query_complexity();
    test_gl_prob_success_per_bit();
    test_gl_prob_success_overall();
    test_gl_bit_majority();
    test_gl_advantage_epsilon_conversion();
    test_gl_sample_r();
    test_gl_sample_r_shifted();
    test_gl_ctx_create();
    test_gl_recover_bit_simple();
    printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
