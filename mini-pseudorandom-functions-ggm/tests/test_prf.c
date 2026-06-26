/* test_prf.c - Tests for Pseudorandom Functions */
#include "prf.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <math.h>

static int tests_run = 0, tests_passed = 0;
#define TEST(n) do { tests_run++; printf("  TEST: %s ... ", #n); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)

static void test_oracle_create_real(void) {
    TEST(oracle_create_real);
    PRF_Family* fam = prf_create_trivial_1bit(16, 32);
    PRFOracle* ora = prf_oracle_create_real(fam);
    assert(ora != NULL);
    assert(ora->type == PRF_ORACLE_REAL);
    prf_oracle_free(ora);
    free(fam->state); free(fam);
    PASS();
}

static void test_oracle_create_random(void) {
    TEST(oracle_create_random);
    PRFOracle* ora = prf_oracle_create_random(32, 16);
    assert(ora != NULL);
    assert(ora->type == PRF_ORACLE_RANDOM);
    prf_oracle_free(ora);
    PASS();
}

static void test_oracle_query_real(void) {
    TEST(oracle_query_real);
    PRF_Family* fam = prf_create_trivial_1bit(16, 32);
    PRFOracle* ora = prf_oracle_create_real(fam);
    BitString* inp = bs_create(32);
    BitString* out = prf_oracle_query(ora, inp);
    assert(out != NULL);
    assert(out->length == 1);
    bs_free(inp); bs_free(out);
    prf_oracle_free(ora);
    free(fam->state); free(fam);
    PASS();
}

static void test_oracle_query_random(void) {
    TEST(oracle_query_random);
    PRFOracle* ora = prf_oracle_create_random(8, 4);
    BitString* inp = bs_create_zeros(8);
    BitString* out1 = prf_oracle_query(ora, inp);
    BitString* out2 = prf_oracle_query(ora, inp);
    assert(out1 != NULL && out2 != NULL);
    assert(bs_equal(out1, out2)); /* same input => same output */
    bs_free(inp); bs_free(out1); bs_free(out2);
    prf_oracle_free(ora);
    PASS();
}

static void test_random_func(void) {
    TEST(random_func);
    RandomFunc* rf = rf_create(8, 8);
    assert(rf != NULL);
    BitString* inp = bs_create_random(8, 1);
    BitString* out1 = rf_evaluate(rf, inp);
    BitString* out2 = rf_evaluate(rf, inp);
    assert(out1 != NULL && out2 != NULL);
    assert(bs_equal(out1, out2)); /* deterministic per input */
    assert(rf_unique_queries(rf) == 1);
    bs_free(inp); bs_free(out1); bs_free(out2);
    rf_reset(rf);
    assert(rf_unique_queries(rf) == 0);
    rf_free(rf);
    PASS();
}

static void test_trivial_prf(void) {
    TEST(trivial_prf);
    PRF_Family* fam = prf_create_trivial_1bit(16, 32);
    BitString* key = fam->keygen(fam);
    BitString* inp = bs_create(32);
    BitString* out = fam->eval(fam, key, inp);
    assert(out != NULL && out->length == 1);
    BitString* inp2 = bs_create(32);
    for (int i = 0; i < 32; i++) bs_set_bit(inp2, i, 1);
    BitString* out2 = fam->eval(fam, key, inp2);
    assert(bs_equal(out, out2)); /* input ignored */
    bs_free(key); bs_free(inp); bs_free(inp2); bs_free(out); bs_free(out2);
    free(fam->state); free(fam);
    PASS();
}

static void test_linear_prf(void) {
    TEST(linear_prf);
    PRF_Family* fam = prf_create_linear_inner_product(16);
    BitString* key = fam->keygen(fam);
    BitString* x = bs_create_random(16, 42);
    BitString* y = bs_create_random(16, 99);
    BitString* z = bs_create(16);
    for (int i = 0; i < 16; i++) {
        int bx = bs_get_bit(x, i);
        int by = bs_get_bit(y, i);
        bs_set_bit(z, i, bx ^ by);
    }
    /* linearity property test: f_k(x) + f_k(y) = f_k(x^y) for 1-bit output */
    BitString* fx = fam->eval(fam, key, x);
    BitString* fy = fam->eval(fam, key, y);
    BitString* fz = fam->eval(fam, key, z);
    int vx = bs_get_bit(fx, 0), vy = bs_get_bit(fy, 0), vz = bs_get_bit(fz, 0);
    assert((vx ^ vy) == vz);
    bs_free(key); bs_free(x); bs_free(y); bs_free(z);
    bs_free(fx); bs_free(fy); bs_free(fz);
    free(fam->state); free(fam);
    PASS();
}

static void test_advantage(void) {
    TEST(advantage);
    PRFAdvantage adv = {0.0, 0.0, 0.0, 0, 0, 0};
    adv.advantage = 1.0 / 65536.0;
    double bits = prf_security_bits(&adv);
    assert(bits > 15.0 && bits < 17.0);
    assert(prf_is_negligible_advantage(&adv, 128));
    PASS();
}

static void test_metrics(void) {
    TEST(metrics);
    PRFMetrics* m = prf_metrics_create();
    assert(m != NULL);
    m->eval_count = 100;
    prf_metrics_reset(m);
    assert(m->eval_count == 0);
    prf_metrics_free(m);
    PASS();
}

int main(void) {
    printf("=== PRF Tests ===\n");
    test_oracle_create_real();
    test_oracle_create_random();
    test_oracle_query_real();
    test_oracle_query_random();
    test_random_func();
    test_trivial_prf();
    test_linear_prf();
    test_advantage();
    test_metrics();
    printf("\nResults: %d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
