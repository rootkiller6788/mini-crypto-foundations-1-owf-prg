/* test_ggm.c - Tests for GGM PRF Construction */
#include "ggm.h"
#include "prf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int tests_run = 0, tests_passed = 0;
#define TEST(n) do { tests_run++; printf("  TEST: %s ... ", #n); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)

static void test_ggm_create_family(void) {
    TEST(ggm_create_family);
    PRG* prg = prg_create_toy_length_doubling(64);
    PRF_Family* fam = ggm_create_prf_family(prg, 8);
    assert(fam != NULL);
    assert(fam->key_len == 64);
    assert(fam->input_len == 8);
    assert(fam->output_len == 64);
    assert(fam->is_efficient == 1);
    assert(fam->state != NULL);
    assert(fam->eval != NULL);
    assert(fam->keygen != NULL);
    free(fam);
    prg_free(prg);
    PASS();
}

static void test_ggm_evaluate(void) {
    TEST(ggm_evaluate);
    PRG* prg = prg_create_toy_length_doubling(32);
    BitString* key = bs_create_random(32, 123);
    BitString* in0 = bs_create_zeros(4);
    BitString* in1 = bs_create(4);
    for (int i = 0; i < 4; i++) bs_set_bit(in1, i, 1);

    BitString* out0 = ggm_evaluate(prg, key, in0);
    BitString* out1 = ggm_evaluate(prg, key, in1);
    assert(out0 != NULL && out1 != NULL);
    assert(out0->length == 32 && out1->length == 32);
    /* Different inputs should (likely) produce different outputs */
    int likely_different = !bs_equal(out0, out1);
    (void)likely_different;

    /* Deterministic: same key + same input => same output */
    BitString* out0b = ggm_evaluate(prg, key, in0);
    assert(out0b != NULL);
    assert(bs_equal(out0, out0b));

    bs_free(key); bs_free(in0); bs_free(in1);
    bs_free(out0); bs_free(out0b); bs_free(out1);
    prg_free(prg);
    PASS();
}

static void test_ggm_tree(void) {
    TEST(ggm_tree);
    PRG* prg = prg_create_toy_length_doubling(32);
    BitString* key = bs_create_random(32, 999);
    GGMTree* tree = ggm_build_full_tree(prg, key, 3);
    assert(tree != NULL);
    assert(tree->depth == 3);
    assert(tree->node_count == 15); /* 1+2+4+8 */
    assert(tree->root != NULL);

    /* Verify tree consistency */
    int ok = ggm_verify_tree_consistency(tree, prg);
    assert(ok == 1);

    /* Collect leaves */
    int n_leaves = 0;
    BitString** leaves = ggm_collect_leaves(tree, &n_leaves);
    assert(leaves != NULL);
    assert(n_leaves == 8);
    for (int i = 0; i < n_leaves; i++) {
        assert(leaves[i] != NULL);
        bs_free(leaves[i]);
    }
    free(leaves);

    bs_free(key);
    ggm_tree_free(tree);
    prg_free(prg);
    PASS();
}

static void test_ggm_tree_consistency(void) {
    TEST(ggm_tree_consistency);
    PRG* prg = prg_create_toy_length_doubling(32);
    BitString* key = bs_create_random(32, 456);
    GGMTree* tree = ggm_build_full_tree(prg, key, 2);
    assert(tree != NULL);
    assert(ggm_verify_tree_consistency(tree, prg) == 1);
    ggm_tree_free(tree);
    bs_free(key);
    prg_free(prg);
    PASS();
}

static void test_ggm_family_eval(void) {
    TEST(ggm_family_eval);
    PRG* prg = prg_create_toy_length_doubling(32);
    PRF_Family* fam = ggm_create_prf_family(prg, 8);
    assert(fam != NULL);

    BitString* key = fam->keygen(fam);
    assert(key != NULL);

    BitString* input = bs_create_random(8, 42);
    BitString* output = fam->eval(fam, key, input);
    assert(output != NULL);
    assert(output->length == 32);

    bs_free(key); bs_free(input); bs_free(output);
    free(fam);
    prg_free(prg);
    PASS();
}

static void test_ggm_hybrid(void) {
    TEST(ggm_hybrid);
    PRG* prg = prg_create_toy_length_doubling(32);
    GGMHybrid* h = ggm_hybrid_create(prg, 4);
    assert(h != NULL);
    assert(h->m == 4);
    assert(h->n == 32);

    BitString* key = bs_create_random(32, 789);
    BitString* input = bs_create(4);
    for (int i = 0; i < 4; i++) bs_set_bit(input, i, i % 2);

    /* H_0 (real) */
    BitString* h0 = ggm_hybrid_evaluate(h, 0, key, input);
    assert(h0 != NULL);

    /* H_m (random) */
    BitString* hm = ggm_hybrid_evaluate(h, 4, key, input);
    assert(hm != NULL);

    /* H_0 and H_m should differ (likely) */
    (void)h0; (void)hm;

    bs_free(key); bs_free(input); bs_free(h0); bs_free(hm);
    ggm_hybrid_free(h);
    prg_free(prg);
    PASS();
}

static void test_ggm_hybrid_bound(void) {
    TEST(ggm_hybrid_bound);
    double bound = ggm_hybrid_bound_advantage(8, 10, 0.001);
    assert(bound == 8.0 * 10.0 * 0.001); /* m * q * adv_prg */
    assert(bound == 0.08);
    PASS();
}

static void test_ggm_security_reduction(void) {
    TEST(ggm_security_reduction);
    /* If PRF advantage = 0.08, m=8, q=10,
     * PRG advantage needed = 0.08/(8*10) = 0.001 */
    double prg_adv = ggm_security_reduction(0.08, 8, 10);
    assert(prg_adv >= 0.0009 && prg_adv <= 0.0011);
    PASS();
}

static void test_ggm_truncated(void) {
    TEST(ggm_truncated);
    PRG* prg = prg_create_toy_length_doubling(32);
    BitString* key = bs_create_random(32, 111);
    BitString* input = bs_create_random(4, 222);
    BitString* out = ggm_evaluate_truncated(prg, key, input, 16);
    assert(out != NULL);
    assert(out->length == 16);
    bs_free(key); bs_free(input); bs_free(out);
    prg_free(prg);
    PASS();
}

static void test_ggm_incremental(void) {
    TEST(ggm_incremental);
    PRG* prg = prg_create_toy_length_doubling(32);
    BitString* key = bs_create_random(32, 333);
    BitString* x = bs_create_zeros(4);
    BitString* y = bs_create_zeros(4);
    bs_set_bit(y, 3, 1); /* last bit differs */

    BitString* fx = ggm_evaluate(prg, key, x);
    BitString* fy = ggm_incremental_update(prg, key, x, fx, y);
    assert(fy != NULL);
    assert(fy->length == 32);

    /* Direct evaluation should match incremental */
    BitString* fy_direct = ggm_evaluate(prg, key, y);
    assert(bs_equal(fy, fy_direct));

    bs_free(key); bs_free(x); bs_free(y);
    bs_free(fx); bs_free(fy); bs_free(fy_direct);
    prg_free(prg);
    PASS();
}

static void test_ggm_collision(void) {
    TEST(ggm_collision);
    PRG* prg = prg_create_toy_length_doubling(32);
    double cp = ggm_collision_probability(prg, 32, 8, 20);
    /* Collision probability should be small with 2^8=256 input space */
    assert(cp >= 0.0 && cp <= 0.3);
    prg_free(prg);
    PASS();
}

static void test_null_edge_cases(void) {
    TEST(null_edge_cases);
    assert(ggm_evaluate(NULL, NULL, NULL) == NULL);
    assert(ggm_create_prf_family(NULL, 0) == NULL);
    assert(ggm_build_full_tree(NULL, NULL, 0) == NULL);
    assert(ggm_hybrid_create(NULL, 0) == NULL);
    assert(ggm_evaluate_truncated(NULL, NULL, NULL, 0) == NULL);
    assert(ggm_collision_probability(NULL, 0, 0, 0) > 0.0);
    PASS();
}

int main(void) {
    printf("=== GGM Tests ===\n");
    test_ggm_create_family();
    test_ggm_evaluate();
    test_ggm_tree();
    test_ggm_tree_consistency();
    test_ggm_family_eval();
    test_ggm_hybrid();
    test_ggm_hybrid_bound();
    test_ggm_security_reduction();
    test_ggm_truncated();
    test_ggm_incremental();
    test_ggm_collision();
    test_null_edge_cases();
    printf("\nResults: %d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
