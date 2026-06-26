/*
 * test_hardcore_bit.c — Unit tests for hardcore bit module
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "../include/hardcore_bit.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  TEST %s... ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASSED\n"); } while(0)
#define FAIL(msg) do { printf("FAILED: %s\n", msg); } while(0)
#define ASSERT_TRUE(cond, msg) do { if (!(cond)) { FAIL(msg); return; } } while(0)
#define ASSERT_EQ(a, b, msg) do { if ((a) != (b)) { FAIL(msg); return; } } while(0)

void test_hc_inner_product(void) {
    TEST("hc_inner_product");
    BitString* x = bs_create(8);
    BitString* r = bs_create(8);
    bs_set_bit(x, 0, 1);
    bs_set_bit(r, 0, 1);
    int bit = hc_inner_product(x, r, NULL);
    ASSERT_EQ(bit, 1, "<x,r> with matching bits = 1");
    bs_set_bit(r, 0, 0);
    bit = hc_inner_product(x, r, NULL);
    ASSERT_EQ(bit, 0, "<x,r> with non-matching bits = 0");
    bs_free(x); bs_free(r);
    PASS();
}

void test_hc_msb(void) {
    TEST("hc_msb");
    BitString* x = bs_create(8);
    bs_set_bit(x, 7, 1);
    int bit = hc_msb(x, NULL, NULL);
    ASSERT_EQ(bit, 1, "MSB of 0x80 = 1");
    bs_set_bit(x, 7, 0);
    bit = hc_msb(x, NULL, NULL);
    ASSERT_EQ(bit, 0, "MSB of 0x00 = 0");
    bs_free(x);
    PASS();
}

void test_hc_lsb(void) {
    TEST("hc_lsb");
    BitString* x = bs_create(8);
    bs_set_bit(x, 0, 1);
    int bit = hc_lsb(x, NULL, NULL);
    ASSERT_EQ(bit, 1, "LSB of 0x01 = 1");
    bs_set_bit(x, 0, 0);
    bit = hc_lsb(x, NULL, NULL);
    ASSERT_EQ(bit, 0, "LSB of 0x00 = 0");
    bs_free(x);
    PASS();
}

void test_hc_gl_bit(void) {
    TEST("hc_gl_bit (same as inner product)");
    BitString* x = bs_create(4);
    BitString* r = bs_create(4);
    bs_set_bit(x, 0, 1); bs_set_bit(x, 1, 1);
    bs_set_bit(r, 0, 0); bs_set_bit(r, 1, 1);
    int bit = hc_gl_bit(x, r, NULL);
    ASSERT_EQ(bit, 1, "GL bit = <x,r>");
    bs_free(x); bs_free(r);
    PASS();
}

void test_hc_create_eval(void) {
    TEST("hc_create / hc_eval");
    HardcorePredicate* hc = hc_create("test", hc_lsb, NULL, 0);
    ASSERT_TRUE(hc != NULL, "predicate created");
    BitString* x = bs_create(8);
    BitString* r = bs_create(8);
    bs_set_bit(x, 0, 1);
    int bit = hc_eval(hc, x, r);
    ASSERT_EQ(bit, 1, "eval via predicate struct");
    hc_free(hc);
    bs_free(x); bs_free(r);
    PASS();
}

void test_gl_construct(void) {
    TEST("gl_construct");
    OWF* owf = owf_create(OWF_SQUARING, 32);
    ASSERT_TRUE(owf != NULL, "OWF created");
    GLConstruction* gl = gl_construct(owf);
    ASSERT_TRUE(gl != NULL, "GL construction created");
    BitString* x = bs_create_random(32);
    BitString* r = bs_create_random(32);
    BitString* g_out = bs_create(owf->output_bits);
    int hc_out;
    int ok = gl_compute_output(gl, x, r, g_out, &hc_out);
    ASSERT_TRUE(ok, "gl_compute_output works");
    gl_construct_free(gl);
    bs_free(x); bs_free(r); bs_free(g_out);
    owf_free(owf);
    PASS();
}

void test_hc_verify_hardcore(void) {
    TEST("hc_verify_hardcore");
    OWF* owf = owf_create(OWF_SQUARING, 16);
    ASSERT_TRUE(owf != NULL, "OWF created");
    HardcorePredicate* hc = hc_create("test", hc_lsb, NULL, 0);
    ASSERT_TRUE(hc != NULL, "predicate created");
    int result = hc_verify_hardcore(hc, owf, 50, 0.3);
    ASSERT_TRUE(result >= 0, "verification runs");
    hc_free(hc);
    owf_free(owf);
    PASS();
}

int main(void) {
    printf("=== Test: Hardcore Bits ===\n\n");
    test_hc_inner_product();
    test_hc_msb();
    test_hc_lsb();
    test_hc_gl_bit();
    test_hc_create_eval();
    test_gl_construct();
    test_hc_verify_hardcore();
    printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
