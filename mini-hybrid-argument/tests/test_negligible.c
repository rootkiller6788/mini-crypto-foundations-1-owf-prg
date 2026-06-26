/*
 * test_negligible.c - Tests for negligible function analysis
 */
#include "negligible.h"
#include <assert.h>
#include <stdio.h>
#include <math.h>

static int tests_run = 0, tests_passed = 0;

#define TEST(n) do { tests_run++; printf("  TEST: %s ... ", n); } while(0)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(m) do { printf("FAIL: %s\n", m); } while(0)

static void test_closure_sum(void) {
    TEST("negl closure: sum negligible");
    NegligibleFunction f = negl_exp();
    NegligibleFunction g = negl_near_exp();
    NegligibleClosure nc = negl_closure_check(&f, &g, 20, 1.0, 2.0);
    assert(nc.is_sum_negligible);
    PASS();
}

static void test_closure_product(void) {
    TEST("negl closure: product negligible");
    NegligibleFunction f = negl_exp();
    NegligibleFunction g = negl_exp();
    NegligibleClosure nc = negl_closure_check(&f, &g, 10, 1.0, 2.0);
    assert(nc.is_product_negligible);
    PASS();
}

static void test_compare(void) {
    TEST("negl_compare");
    NegligibleFunction f = negl_exp();
    NegligibleFunction g = negl_exp_sqrt();
    NegligibleComparison nc = negl_compare(&f, &g, 20);
    assert(nc.f_smaller);
    assert(nc.ratio < 1.0);
    PASS();
}

static void test_noticeable(void) {
    TEST("negl_is_noticeable");
    NegligibleFunction f = negl_exp();
    assert(!negl_is_noticeable(&f, 10, 1e-3));
    assert(negl_is_noticeable(&f, 1, 1e-3));
    PASS();
}

static void test_overwhelming(void) {
    TEST("negl_is_overwhelming");
    assert(negl_is_overwhelming(0.9999, 10, 1e-4));
    assert(!negl_is_overwhelming(0.5, 10, 1e-4));
    PASS();
}

static void test_make_functions(void) {
    TEST("negl_make_* constructors");
    NegligibleFunction f1 = negl_make_exp(2.0, 3.0);
    double v1 = negl_eval(&f1, 10);
    assert(v1 > 0.0);
    NegligibleFunction f2 = negl_make_poly_over_exp(3, 1.0);
    double v2 = negl_eval(&f2, 10);
    assert(v2 > 0.0);
    PASS();
}

static void test_eval_series(void) {
    TEST("negl_eval_series");
    NegligibleFunction f = negl_exp();
    NegligibleEvalSeries* s = negl_eval_series(&f, 1, 10, 5);
    assert(s != NULL);
    assert(s->count == 5);
    assert(s->ns[0] == 1);
    assert(s->values[4] < s->values[0]);
    negl_eval_series_free(s);
    PASS();
}

static void test_security_parameter_for_target(void) {
    TEST("security_parameter_for_target");
    NegligibleFunction f = negl_exp();
    security_param_t n = negl_security_parameter_for_target(&f, 0.001, 100);
    assert(n > 0);
    assert(negl_eval(&f, n) < 0.001);
    PASS();
}

static void test_half_life(void) {
    TEST("negl_half_life");
    NegligibleFunction f = negl_exp();
    security_param_t n = negl_half_life(&f, 100);
    assert(n > 0 && n <= 10);
    PASS();
}

int main(void) {
    printf("=== test_negligible ===\n");
    rand_seed(42);
    test_closure_sum();
    test_closure_product();
    test_compare();
    test_noticeable();
    test_overwhelming();
    test_make_functions();
    test_eval_series();
    test_security_parameter_for_target();
    test_half_life();
    printf("\n=== RESULTS: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
