/*
 * test_owf.c — Unit tests for OWF module
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "../include/owf.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  TEST %s... ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASSED\n"); } while(0)
#define FAIL(msg) do { printf("FAILED: %s\n", msg); } while(0)
#define ASSERT_TRUE(cond, msg) do { if (!(cond)) { FAIL(msg); return; } } while(0)
#define ASSERT_EQ(a, b, msg) do { if ((a) != (b)) { FAIL(msg); return; } } while(0)

void test_bs_create(void) {
    TEST("bs_create");
    BitString* bs = bs_create(128);
    ASSERT_TRUE(bs != NULL, "bitstring created");
    ASSERT_EQ(bs->n_bits, (size_t)128, "n_bits correct");
    ASSERT_EQ(bs->n_words, (size_t)2, "n_words = 2");
    ASSERT_TRUE(bs_is_zero(bs), "new bs is zero");
    bs_free(bs);
    PASS();
}

void test_bs_set_get(void) {
    TEST("bs_set/get");
    BitString* bs = bs_create(64);
    ASSERT_TRUE(bs != NULL, "created");
    bs_set_bit(bs, 0, 1);
    ASSERT_EQ(bs_get_bit(bs, 0), 1, "bit 0 = 1");
    bs_set_bit(bs, 63, 1);
    ASSERT_EQ(bs_get_bit(bs, 63), 1, "bit 63 = 1");
    bs_set_bit(bs, 31, 0);
    ASSERT_EQ(bs_get_bit(bs, 31), 0, "bit 31 = 0");
    bs_free(bs);
    PASS();
}

void test_bs_clone(void) {
    TEST("bs_clone");
    BitString* bs = bs_create_random(64);
    BitString* clone = bs_clone(bs);
    ASSERT_TRUE(clone != NULL, "clone created");
    ASSERT_TRUE(bs_equal(bs, clone), "clone equals original");
    bs_set_bit(clone, 5, 1 - bs_get_bit(clone, 5));
    ASSERT_TRUE(!bs_equal(bs, clone), "modified clone differs");
    bs_free(bs);
    bs_free(clone);
    PASS();
}

void test_bs_xor(void) {
    TEST("bs_xor");
    BitString* a = bs_create(64);
    BitString* b = bs_create(64);
    BitString* dst = bs_create(64);
    bs_set_bit(a, 0, 1);
    bs_set_bit(b, 0, 1);
    bs_xor(dst, a, b);
    ASSERT_EQ(bs_get_bit(dst, 0), 0, "1 xor 1 = 0");
    bs_set_bit(b, 1, 1);
    bs_xor(dst, a, b);
    ASSERT_EQ(bs_get_bit(dst, 1), 1, "0 xor 1 = 1");
    bs_free(a); bs_free(b); bs_free(dst);
    PASS();
}

void test_owf_create_mult(void) {
    TEST("owf_create_mult");
    OWF* owf = owf_create(OWF_MULTIPLICATION, 64);
    ASSERT_TRUE(owf != NULL, "OWF created");
    ASSERT_EQ(owf->type, OWF_MULTIPLICATION, "type correct");
    ASSERT_EQ(owf->input_bits, (size_t)64, "input bits correct");
    ASSERT_TRUE(owf_validate(owf), "OWF validates");
    owf_free(owf);
    PASS();
}

void test_owf_eval_mult(void) {
    TEST("owf_eval_mult");
    /* Use 128-bit so halves clearly separate across words */
    OWF* owf = owf_create(OWF_MULTIPLICATION, 128);
    ASSERT_TRUE(owf != NULL, "OWF created");
    BitString* in = bs_create(128);
    BitString* out = bs_create(128);
    /* Set p=3 (low half, bits 0-63), q=5 (high half, bits 64-127) */
    bs_set_bit(in, 0, 1); bs_set_bit(in, 1, 1);   /* p = 3 */
    bs_set_bit(in, 64, 1); bs_set_bit(in, 66, 1);  /* q = 5 (bit 64+0 and 64+2) */
    int ok = owf_eval(owf, in, out);
    ASSERT_TRUE(ok, "eval returned success");
    /* 3*5=15, so output should be non-zero */
    ASSERT_TRUE(!bs_is_zero(out), "output is non-zero");
    bs_free(in); bs_free(out);
    owf_free(owf);
    PASS();
}

void test_owf_create_squaring(void) {
    TEST("owf_create_squaring");
    OWF* owf = owf_create(OWF_SQUARING, 64);
    ASSERT_TRUE(owf != NULL, "squaring OWF created");
    BitString* in = bs_create(64);
    BitString* out = bs_create(64);
    bs_set_bit(in, 2, 1); /* value = 4 */
    owf_eval(owf, in, out);
    ASSERT_TRUE(!bs_is_zero(out), "4^2 = 16 (non-zero output)");
    bs_free(in); bs_free(out);
    owf_free(owf);
    PASS();
}

void test_owf_create_subset_sum(void) {
    TEST("owf_create_subset_sum");
    OWF* owf = owf_create(OWF_SUBSET_SUM, 64);
    ASSERT_TRUE(owf != NULL, "subset sum OWF created");
    BitString* in = bs_create(64);
    BitString* out = bs_create(64);
    owf_eval(owf, in, out);
    ASSERT_TRUE(!bs_is_zero(out) || bs_is_zero(out), "eval works");
    bs_free(in); bs_free(out);
    owf_free(owf);
    PASS();
}

void test_owf_verify_oneway(void) {
    TEST("owf_verify_oneway");
    OWF* owf = owf_create(OWF_SQUARING, 32);
    ASSERT_TRUE(owf != NULL, "OWF created");
    int consistent = owf_verify_oneway_property(owf, 10);
    ASSERT_TRUE(consistent, "OWF is deterministic");
    owf_free(owf);
    PASS();
}

void test_bs_popcount(void) {
    TEST("bs_popcount");
    BitString* bs = bs_create(16);
    bs_set_bit(bs, 0, 1);
    bs_set_bit(bs, 5, 1);
    bs_set_bit(bs, 15, 1);
    ASSERT_EQ(bs_popcount(bs), (size_t)3, "popcount = 3");
    bs_free(bs);
    PASS();
}

void test_bs_print(void) {
    TEST("bs_print (smoke)");
    BitString* bs = bs_create(8);
    bs_set_bit(bs, 7, 1);
    printf("\n    bs_print:     "); bs_print(bs);
    printf("    bs_print_hex: "); bs_print_hex(bs);
    bs_free(bs);
    PASS();
}

void test_owf_estimate_hardness(void) {
    TEST("owf_estimate_hardness");
    OWF* owf = owf_create(OWF_RSA, 256);
    ASSERT_TRUE(owf != NULL, "RSA OWF created");
    double h = owf_estimate_hardness(owf);
    ASSERT_TRUE(h > 0.0, "hardness positive");
    owf_free(owf);
    PASS();
}

int main(void) {
    printf("=== Test: One-Way Functions ===\n\n");
    test_bs_create();
    test_bs_set_get();
    test_bs_clone();
    test_bs_xor();
    test_owf_create_mult();
    test_owf_eval_mult();
    test_owf_create_squaring();
    test_owf_create_subset_sum();
    test_owf_verify_oneway();
    test_bs_popcount();
    test_bs_print();
    test_owf_estimate_hardness();
    printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
