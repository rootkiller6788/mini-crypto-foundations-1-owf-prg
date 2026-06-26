/*
 * test_hybrid_argument.c - Tests for core hybrid argument framework
 */
#include "hybrid_argument.h"
#include <assert.h>
#include <stdio.h>
#include <math.h>

static int tests_run = 0, tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  TEST: %s ... ", name); } while(0)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)
#define ASSERT_EQ(a, b, msg) do { if ((a) != (b)) { FAIL(msg); return; } } while(0)
#define ASSERT_TRUE(cond, msg) do { if (!(cond)) { FAIL(msg); return; } } while(0)
#define ASSERT_DBL_NEAR(a, b, tol, msg) do { if (fabs((a)-(b)) > tol) { FAIL(msg); return; } } while(0)

/* ===== Negligible Functions ===== */

static void test_negl_exp(void) {
    TEST("negl_exp(10) < 0.001");
    NegligibleFunction f = negl_exp();
    double v = negl_eval(&f, 10);
    ASSERT_TRUE(v < 0.001, "2^{-10} should be ~0.000977");
    PASS();
}

static void test_negl_is_negligible(void) {
    TEST("negl_is_negligible at n=20");
    NegligibleFunction f = negl_exp();
    ASSERT_TRUE(negl_is_negligible(&f, 20, 1e-6), "2^{-20} < 1e-6");
    PASS();
}

static void test_negl_type_names(void) {
    TEST("negl_type_name");
    ASSERT_TRUE(strcmp(negl_type_name(NEGL_TYPE_EXP), "2^{-n}") == 0, "type name");
    ASSERT_TRUE(strcmp(negl_type_name(NEGL_TYPE_SUPERPOLY), "n^{-log n}") == 0, "type name");
    PASS();
}

static void test_negl_monotonicity(void) {
    TEST("negl monotonicity");
    NegligibleFunction f = negl_exp();
    double v10 = negl_eval(&f, 10);
    double v20 = negl_eval(&f, 20);
    ASSERT_TRUE(v20 < v10, "2^{-20} < 2^{-10}");
    PASS();
}

/* ===== DistributionSample ===== */

static void test_dsample_create(void) {
    TEST("dsample_create(256)");
    DistributionSample* s = dsample_create(256);
    ASSERT_TRUE(s != NULL, "allocation");
    ASSERT_EQ(s->length, (size_t)256, "length");
    ASSERT_EQ(s->byte_length, (size_t)32, "byte_length=32");
    dsample_free(s);
    PASS();
}

static void test_dsample_clone(void) {
    TEST("dsample_clone");
    DistributionSample* s = dsample_create(64);
    s->data[0] = 0xAA;
    DistributionSample* c = dsample_clone(s);
    ASSERT_TRUE(c != NULL, "clone allocation");
    ASSERT_EQ(dsample_cmp(s, c), 0, "comparison equal");
    ASSERT_EQ(c->data[0], (uint8_t)0xAA, "data preserved");
    dsample_free(s);
    dsample_free(c);
    PASS();
}

static void test_dsample_randomize(void) {
    TEST("dsample_randomize");
    DistributionSample* s = dsample_create(64);
    dsample_randomize(s);
    int non_zero = 0;
    for (size_t i = 0; i < s->byte_length; i++)
        if (s->data[i] != 0) non_zero = 1;
    ASSERT_TRUE(non_zero, "randomized data should not be all zero");
    dsample_free(s);
    PASS();
}

/* ===== DistributionEnsemble ===== */

static size_t test_out_len(security_param_t n) { return n; }

static void test_sampler(const DistributionEnsemble* ens,
                          security_param_t n, DistributionSample* out) {
    (void)ens; (void)n;
    if (out) dsample_randomize(out);
}

static void test_dens_create(void) {
    TEST("dens_create + dens_sample");
    DistributionEnsemble* ens = dens_create("Test", test_out_len, test_sampler, NULL);
    ASSERT_TRUE(ens != NULL, "creation");
    DistributionSample* s = dsample_create(64);
    dens_sample(ens, 64, s);
    ASSERT_TRUE(s != NULL, "sample after dens_sample");
    dsample_free(s);
    dens_free(ens);
    PASS();
}

/* ===== Distinguisher ===== */

static int always_one(const Distinguisher* D, const DistributionSample* x) {
    (void)D; (void)x;
    return 1;
}

static void test_dist_create(void) {
    TEST("dist_create + dist_evaluate");
    Distinguisher* D = dist_create("Always1", always_one, NULL, 1);
    ASSERT_TRUE(D != NULL, "creation");
    DistributionSample* s = dsample_create(8);
    int r = dist_evaluate(D, s);
    ASSERT_EQ(r, 1, "always returns 1");
    dsample_free(s);
    dist_free(D);
    PASS();
}

/* ===== HybridSequence ===== */

static void test_hseq_create(void) {
    TEST("hseq_create + hseq_add");
    HybridSequence* hs = hseq_create(5);
    ASSERT_TRUE(hs != NULL, "creation");
    ASSERT_EQ(hseq_length(hs), 0, "initial length 0");

    DistributionEnsemble* e1 = dens_create("E1", test_out_len, test_sampler, NULL);
    int idx = hseq_add(hs, e1);
    ASSERT_EQ(idx, 0, "first index 0");
    ASSERT_EQ(hseq_length(hs), 1, "length 1");
    ASSERT_EQ(hseq_get(hs, 0), e1, "get returns same");

    dens_free(e1);
    hseq_free(hs);
    PASS();
}

/* ===== Statistical Distance ===== */

static void test_stat_dist_uniform_vs_biased(void) {
    TEST("stat_dist_uniform_vs_biased");
    double d1 = stat_dist_uniform_vs_biased(0.5);
    ASSERT_DBL_NEAR(d1, 0.0, 1e-10, "uniform vs uniform = 0");
    double d2 = stat_dist_uniform_vs_biased(0.75);
    ASSERT_DBL_NEAR(d2, 0.25, 1e-10, "uniform vs 0.75-biased = 0.25");
    PASS();
}

static void test_stat_dist_triangle(void) {
    TEST("stat_dist_triangle_inequality");
    ASSERT_TRUE(stat_dist_triangle_inequality(0.2, 0.3, 0.4), "0.4 <= 0.2+0.3");
    ASSERT_TRUE(stat_dist_triangle_inequality(0.1, 0.1, 0.2), "0.2 <= 0.1+0.1");
    PASS();
}

/* ===== Entropy ===== */

static void test_shannon_entropy(void) {
    TEST("shannon_entropy non-negative");
    uint8_t buf1_data[1] = {0xAB};
    DistributionSample s1;
    s1.data = buf1_data; s1.length = 8; s1.byte_length = 1;
    const DistributionSample* samples[] = {&s1};
    double H = shannon_entropy_estimate(samples, 1);
    ASSERT_TRUE(H >= 0.0, "entropy >= 0");
    PASS();
}

/* ===== KS Test ===== */

static void test_ks_statistic_identical(void) {
    TEST("ks_statistic for identical samples");
    uint8_t buf[1] = {0x55};
    DistributionSample s1, s2;
    s1.data = buf; s1.length = 8; s1.byte_length = 1;
    s2.data = buf; s2.length = 8; s2.byte_length = 1;
    const DistributionSample* a[] = {&s1};
    const DistributionSample* b[] = {&s2};
    double ks = ks_statistic(a, 1, b, 1);
    ASSERT_DBL_NEAR(ks, 0.0, 0.01, "identical samples => KS ~ 0");
    PASS();
}

int main(void) {
    printf("=== test_hybrid_argument ===\n");
    rand_seed(42);

    test_negl_exp();
    test_negl_is_negligible();
    test_negl_type_names();
    test_negl_monotonicity();
    test_dsample_create();
    test_dsample_clone();
    test_dsample_randomize();
    test_dens_create();
    test_dist_create();
    test_hseq_create();
    test_stat_dist_uniform_vs_biased();
    test_stat_dist_triangle();
    test_shannon_entropy();
    test_ks_statistic_identical();

    printf("\n=== RESULTS: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
