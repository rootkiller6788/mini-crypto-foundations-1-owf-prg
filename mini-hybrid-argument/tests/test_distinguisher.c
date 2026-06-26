/*
 * test_distinguisher.c - Tests for distinguisher constructions
 */
#include "distinguisher.h"
#include <assert.h>
#include <stdio.h>
#include <math.h>

static int tests_run = 0, tests_passed = 0;

#define TEST(n) do { tests_run++; printf("  TEST: %s ... ", n); } while(0)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(m) do { printf("FAIL: %s\n", m); } while(0)

static void test_trivial_dist(void) {
    TEST("trivial distinguisher");
    Distinguisher* D = dist_create_trivial(1);
    assert(D != NULL);
    DistributionSample* s = dsample_create(16);
    int r = dist_evaluate(D, s);
    assert(r == 1);
    dsample_free(s);
    dist_free_with_state(D);
    PASS();
}

static void test_first_k_zero(void) {
    TEST("first_k_zero test");
    Distinguisher* D = dist_create_first_k_zero(4);
    assert(D != NULL);
    DistributionSample* s = dsample_create(16);
    memset(s->data, 0, s->byte_length);
    int r = dist_evaluate(D, s);
    assert(r == 1);
    s->data[0] = 0x80; /* first bit = 1 */
    r = dist_evaluate(D, s);
    assert(r == 0); /* first bit is 1, so not all first 4 are 0 */
    dsample_free(s);
    dist_free_with_state(D);
    PASS();
}

static void test_bit_count(void) {
    TEST("bit_count threshold");
    Distinguisher* D = dist_create_bit_count_threshold(16, 0.3);
    assert(D != NULL);
    DistributionSample* s = dsample_create(16);
    memset(s->data, 0xFF, s->byte_length); /* all 1-bits: 16 ones */
    int r = dist_evaluate(D, s);
    assert(r == 1); /* |16-16|/16 = 0 <= 0.3 */
    dsample_free(s);
    dist_free_with_state(D);
    PASS();
}

static void test_bit_pattern(void) {
    TEST("bit_pattern test");
    Distinguisher* D = dist_create_bit_pattern(0, 1);
    assert(D != NULL);
    DistributionSample* s = dsample_create(16);
    s->data[0] = 0x80;
    assert(dist_evaluate(D, s) == 1);
    s->data[0] = 0x00;
    assert(dist_evaluate(D, s) == 0);
    dsample_free(s);
    dist_free_with_state(D);
    PASS();
}

static void test_linear(void) {
    TEST("linear test");
    uint8_t mask[1] = {0xFF};
    Distinguisher* D = dist_create_linear_test(mask, 8);
    assert(D != NULL);
    DistributionSample* s = dsample_create(16);
    s->data[0] = 0x03;
    int r = dist_evaluate(D, s);
    assert(r == 0);
    dsample_free(s);
    dist_free_with_state(D);
    PASS();
}

static void test_repeat_pattern(void) {
    TEST("repeat pattern");
    Distinguisher* D = dist_create_repeat_pattern(8);
    assert(D != NULL);
    DistributionSample* s = dsample_create(16);
    s->data[0] = 0xAA; s->data[1] = 0xAA;
    int r = dist_evaluate(D, s);
    assert(r == 1);
    dsample_free(s);
    dist_free_with_state(D);
    PASS();
}

static void test_runs(void) {
    TEST("runs test");
    Distinguisher* D = dist_create_runs_test(8.5, 0.5);
    assert(D != NULL);
    DistributionSample* s = dsample_create(16);
    memset(s->data, 0xAA, s->byte_length);
    dist_evaluate(D, s);
    dsample_free(s);
    dist_free_with_state(D);
    PASS();
}

static void test_conjunction(void) {
    TEST("conjunction dist");
    Distinguisher* d1 = dist_create_trivial(1);
    Distinguisher* d2 = dist_create_trivial(1);
    Distinguisher* dists[2] = {d1, d2};
    Distinguisher* D = dist_create_conjunction(dists, 2);
    assert(D != NULL);
    DistributionSample* s = dsample_create(16);
    assert(dist_evaluate(D, s) == 1);
    dsample_free(s);
    dist_free_with_state(D);
    dist_free_with_state(d1);
    dist_free_with_state(d2);
    PASS();
}

int main(void) {
    printf("=== test_distinguisher ===\n");
    rand_seed(42);
    test_trivial_dist();
    test_first_k_zero();
    test_bit_count();
    test_bit_pattern();
    test_linear();
    test_repeat_pattern();
    test_runs();
    test_conjunction();
    printf("\n=== RESULTS: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
