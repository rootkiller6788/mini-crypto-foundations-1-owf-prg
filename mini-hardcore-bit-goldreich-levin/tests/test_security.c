/*
 * test_security.c — Unit tests for security parameters module
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <math.h>
#include "../include/security_params.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  TEST %s... ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASSED\n"); } while(0)
#define FAIL(msg) do { printf("FAILED: %s\n", msg); } while(0)
#define ASSERT_TRUE(cond, msg) do { if (!(cond)) { FAIL(msg); return; } } while(0)
#define ASSERT_EQ(a, b, msg) do { if ((a) != (b)) { FAIL(msg); return; } } while(0)

void test_negl_exponential(void) {
    TEST("negl_exponential");
    double v = negl_exponential(10);
    ASSERT_TRUE(v < 0.001, "2^{-10} ~ 0.00098");
    ASSERT_TRUE(v > 0.0, "positive");
    PASS();
}

void test_negl_superpoly(void) {
    TEST("negl_superpoly");
    double v = negl_superpoly(10);
    ASSERT_TRUE(v < 1.0, "superpoly < 1");
    ASSERT_TRUE(v > 0.0, "positive");
    PASS();
}

void test_is_negligible(void) {
    TEST("is_negligible");
    /* negl_exponential(20) = 2^{-20}, compare at n=19 (threshold = 2^{-19}) */
    ASSERT_TRUE(is_negligible(negl_exponential(20), 19), "2^{-20} < 2^{-19}");
    ASSERT_TRUE(!is_negligible(0.5, 5), "0.5 is not negligible");
    PASS();
}

void test_chernoff_upper(void) {
    TEST("chernoff_upper");
    double bound = chernoff_upper(100.0, 0.5);
    ASSERT_TRUE(bound > 0.0 && bound < 1.0, "bound in (0,1)");
    ASSERT_TRUE(chernoff_upper(100.0, 0.0) == 1.0, "delta=0 → bound=1");
    PASS();
}

void test_chernoff_lower(void) {
    TEST("chernoff_lower");
    double bound = chernoff_lower(100.0, 0.5);
    ASSERT_TRUE(bound > 0.0 && bound < 1.0, "bound in (0,1)");
    PASS();
}

void test_hoeffding_bound(void) {
    TEST("hoeffding_bound");
    double bound = hoeffding_bound(100, 0.1);
    ASSERT_TRUE(bound < 1.0, "hoeffding < 1");
    ASSERT_TRUE(bound > 0.0, "hoeffding > 0");
    PASS();
}

void test_sample_size(void) {
    TEST("chernoff_sample_size");
    size_t m = chernoff_sample_size(0.1, 0.01);
    ASSERT_TRUE(m > 0, "sample size positive");
    m = hoeffding_sample_size(0.1, 0.01);
    ASSERT_TRUE(m > 0, "hoeffding sample size positive");
    PASS();
}

void test_gl_sample_complexity(void) {
    TEST("gl_sample_complexity");
    size_t m = gl_sample_complexity(32, 0.05, 0.01);
    ASSERT_TRUE(m > 0, "GL sample complexity positive");
    PASS();
}

void test_advantage_accuracy(void) {
    TEST("advantage/accuracy conversion");
    ASSERT_TRUE(fabs(advantage_to_accuracy(0.1) - 0.6) < 1e-9, "0.1 adv → 0.6 acc");
    ASSERT_TRUE(fabs(accuracy_to_advantage(0.6) - 0.1) < 1e-9, "0.6 acc → 0.1 adv");
    ASSERT_TRUE(fabs(accuracy_to_advantage(0.4) - 0.0) < 1e-9, "0.4 acc → 0 adv");
    PASS();
}

void test_is_nonnegl_advantage(void) {
    TEST("is_nonnegl_advantage");
    ASSERT_TRUE(is_nonnegl_advantage(0.1, 10), "0.1 > 1/100");
    /* 0.001 = 1/1000, poly bound at n=10 is 1/100. 0.001 < 0.01, so negligible */
    ASSERT_TRUE(!is_nonnegl_advantage(0.001, 10), "0.001 < 1/100 at n=10");
    PASS();
}

void test_majority_vote(void) {
    TEST("majority_vote");
    int v1[] = {1, 1, 0};
    ASSERT_EQ(majority_vote(v1, 3), 1, "2/3 = 1");
    int v2[] = {0, 0, 1, 0, 0};
    ASSERT_EQ(majority_vote(v2, 5), 0, "4/5 = 0");
    PASS();
}

void test_weighted_majority(void) {
    TEST("weighted_majority");
    int v[] = {1, 0, 0};
    double w[] = {10.0, 1.0, 1.0};
    ASSERT_EQ(weighted_majority_vote(v, w, 3), 1, "weighted → 1");
    double w2[] = {0.1, 1.0, 1.0};
    ASSERT_EQ(weighted_majority_vote(v, w2, 3), 0, "weighted → 0");
    PASS();
}

void test_majority_correct_prob(void) {
    TEST("majority_correct_prob");
    /* Chernoff bound: with 500 samples at p=0.6, prob > 0.9 */
    double prob = majority_correct_prob(500, 0.6);
    ASSERT_TRUE(prob > 0.9, "high confidence with 500 samples at p=0.6");
    /* For m=0 or p<=0.5, returns p */
    double prob_low = majority_correct_prob(0, 0.4);
    ASSERT_TRUE(prob_low < 0.5, "p <= 0.5 returns p");
    PASS();
}

void test_security_levels(void) {
    TEST("security_level_to_n");
    ASSERT_EQ(security_level_to_n(SEC_LEVEL_STANDARD), (size_t)256, "standard = 256");
    ASSERT_EQ(security_level_to_n(SEC_LEVEL_PARANOID), (size_t)512, "paranoid = 512");
    PASS();
}

void test_estimate_security_level(void) {
    TEST("estimate_security_level");
    SecurityLevel sl = estimate_security_level(256, 0.0);
    ASSERT_TRUE(sl >= SEC_LEVEL_STANDARD, "256-bit key → at least standard");
    PASS();
}

void test_keylen_recommendation(void) {
    TEST("keylen_recommendation");
    KeyLenRecommendation* rec = keylen_for_level(SEC_LEVEL_STANDARD);
    ASSERT_TRUE(rec != NULL, "recommendation created");
    ASSERT_TRUE(rec->symmetric_key_bits == 128, "AES-128");
    keylen_recommendation_free(rec);
    PASS();
}

void test_rand_double(void) {
    TEST("rand_double");
    for (int i = 0; i < 100; i++) {
        double r = rand_double();
        ASSERT_TRUE(r >= 0.0 && r < 1.0, "rand in [0,1)");
    }
    PASS();
}

void test_statistical_distance(void) {
    TEST("statistical_distance");
    double p[] = {1.0, 0.0};
    double q[] = {0.0, 1.0};
    double d = statistical_distance(p, q, 2);
    ASSERT_TRUE(d >= 0.99 && d <= 1.01, "distance = 1 for disjoint dist.");
    double r[] = {0.5, 0.5};
    d = statistical_distance(p, r, 2);
    ASSERT_TRUE(d >= 0.49 && d <= 0.51, "distance = 0.5");
    PASS();
}

void test_estimate_entropy(void) {
    TEST("estimate_entropy");
    uint8_t data[256];
    for (int i = 0; i < 256; i++) data[i] = (uint8_t)i;
    double ent = estimate_entropy(data, 256);
    ASSERT_TRUE(ent >= 7.9 && ent <= 8.1,
               "uniform distribution entropy ≈ 8 bits/byte");
    PASS();
}

int main(void) {
    printf("=== Test: Security Parameters ===\n\n");
    test_negl_exponential();
    test_negl_superpoly();
    test_is_negligible();
    test_chernoff_upper();
    test_chernoff_lower();
    test_hoeffding_bound();
    test_sample_size();
    test_gl_sample_complexity();
    test_advantage_accuracy();
    test_is_nonnegl_advantage();
    test_majority_vote();
    test_weighted_majority();
    test_majority_correct_prob();
    test_security_levels();
    test_estimate_security_level();
    test_keylen_recommendation();
    test_rand_double();
    test_statistical_distance();
    test_estimate_entropy();
    printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
