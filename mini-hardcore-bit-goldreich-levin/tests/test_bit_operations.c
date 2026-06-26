/*
 * test_bit_operations.c — Unit tests for bit operations module
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include "../include/bit_operations.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  TEST %s... ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASSED\n"); } while(0)
#define FAIL(msg) do { printf("FAILED: %s\n", msg); } while(0)
#define ASSERT_EQ(a, b, msg) do { if ((a) != (b)) { FAIL(msg); return; } } while(0)
#define ASSERT_TRUE(cond, msg) do { if (!(cond)) { FAIL(msg); return; } } while(0)

void test_popcount(void) {
    TEST("popcount_u64");
    ASSERT_EQ(bit_popcount_u64(0), 0, "popcount(0)");
    ASSERT_EQ(bit_popcount_u64(1), 1, "popcount(1)");
    ASSERT_EQ(bit_popcount_u64(0xFF), 8, "popcount(0xFF)");
    ASSERT_EQ(bit_popcount_u64(0xFFFFFFFFFFFFFFFFULL), 64, "popcount(-1)");
    PASS();
}

void test_popcount_buf(void) {
    TEST("popcount_buf");
    uint64_t buf[2] = {0x0F, 0xF0};
    ASSERT_EQ(bit_popcount_buf(buf, 2), 8, "popcount buffer");
    PASS();
}

void test_hamming_distance(void) {
    TEST("hamming_distance");
    uint64_t a[1] = {0x0F};
    uint64_t b[1] = {0xF0};
    ASSERT_EQ(bit_hamming_distance(a, b, 1), 8, "hamming distance");
    uint64_t c[1] = {0x0F};
    ASSERT_EQ(bit_hamming_distance(a, c, 1), 0, "hamming distance identical");
    PASS();
}

void test_parity(void) {
    TEST("parity");
    ASSERT_EQ(bit_parity_u64(0), 0, "parity(0)");
    ASSERT_EQ(bit_parity_u64(1), 1, "parity(1)");
    ASSERT_EQ(bit_parity_u64(3), 0, "parity(3)");
    ASSERT_EQ(bit_parity_u64(7), 1, "parity(7)");
    PASS();
}

void test_inner_product(void) {
    TEST("inner_product");
    uint64_t a[1] = {0x01}; /* 0001 */
    uint64_t b[1] = {0x01}; /* 0001 */
    ASSERT_EQ(bit_inner_product(a, b, 1), 1, "<0001,0001> = 1");
    uint64_t c[1] = {0x02}; /* 0010 */
    ASSERT_EQ(bit_inner_product(a, c, 1), 0, "<0001,0010> = 0");
    PASS();
}

void test_inner_product_bilinearity(void) {
    TEST("inner_product bilinearity");
    uint64_t a[1] = {0x03};
    uint64_t b[1] = {0x01};
    uint64_t c[1] = {0x02};
    uint64_t d[1];
    bit_xor_buf(d, b, c, 1); /* d = b ⊕ c */
    int left = bit_inner_product(a, d, 1);
    int right = bit_inner_product(a, b, 1) ^ bit_inner_product(a, c, 1);
    ASSERT_EQ(left, right, "<a, b⊕c> = <a,b> ⊕ <a,c>");
    PASS();
}

void test_bit_set_get(void) {
    TEST("bit_set / bit_get");
    uint64_t buf[2] = {0};
    bit_set(buf, 0, 1);
    ASSERT_EQ(bit_get(buf, 0), 1, "bit_set(0,1)");
    bit_set(buf, 63, 1);
    ASSERT_EQ(bit_get(buf, 63), 1, "bit_set(63,1)");
    bit_set(buf, 64, 1);
    ASSERT_EQ(bit_get(buf, 64), 1, "bit_set(64,1) cross-word");
    bit_set(buf, 0, 0);
    ASSERT_EQ(bit_get(buf, 0), 0, "bit_set(0,0)");
    PASS();
}

void test_bit_flip(void) {
    TEST("bit_flip");
    uint64_t buf[1] = {0};
    bit_flip(buf, 5);
    ASSERT_EQ(bit_get(buf, 5), 1, "flip 0→1");
    bit_flip(buf, 5);
    ASSERT_EQ(bit_get(buf, 5), 0, "flip 1→0");
    PASS();
}

void test_bit_xor_and_or_not(void) {
    TEST("bitwise ops");
    uint64_t a[1] = {0x0F}, b[1] = {0xF0}, dst[1];
    bit_xor_buf(dst, a, b, 1);
    ASSERT_EQ(dst[0], 0xFFULL, "XOR");
    bit_and_buf(dst, a, b, 1);
    ASSERT_EQ(dst[0], 0ULL, "AND");
    bit_or_buf(dst, a, b, 1);
    ASSERT_EQ(dst[0], 0xFFULL, "OR");
    bit_not_buf(dst, a, 1);
    ASSERT_EQ(dst[0], ~0x0FULL, "NOT");
    PASS();
}

void test_bit_shift(void) {
    TEST("shift operations");
    uint64_t src[2] = {0x01, 0x00};
    uint64_t dst[2] = {0};
    bit_shift_left(dst, src, 2, 1);
    ASSERT_EQ(dst[0], 2ULL, "shift left by 1");
    bit_shift_right(dst, src, 2, 1);
    ASSERT_EQ(dst[1], 0ULL, "shift right by 1");
    PASS();
}

void test_unit_vector(void) {
    TEST("unit_vector");
    uint64_t buf[2] = {0};
    bit_unit_vector(buf, 128, 65);
    ASSERT_EQ(bit_get(buf, 65), 1, "unit vector pos 65 = 1");
    ASSERT_EQ(bit_get(buf, 0), 0, "unit vector pos 0 = 0");
    PASS();
}

void test_random_weight(void) {
    TEST("random_weight");
    uint64_t buf[1] = {0};
    bit_random_weight(buf, 32, 8);
    size_t w = bit_popcount_buf(buf, 1);
    ASSERT_EQ(w, 8, "random weight = 8");
    PASS();
}

void test_bit_add(void) {
    TEST("bit_add");
    uint64_t a[1] = {5}, b[1] = {3}, dst[1];
    bit_add(dst, a, b, 1);
    ASSERT_EQ(dst[0], 8ULL, "5 + 3 = 8");
    PASS();
}

void test_bit_sub(void) {
    TEST("bit_sub");
    uint64_t a[1] = {5}, b[1] = {3}, dst[1];
    bit_sub(dst, a, b, 1);
    ASSERT_EQ(dst[0], 2ULL, "5 - 3 = 2");
    PASS();
}

void test_bit_mul(void) {
    TEST("bit_mul");
    /* 3 * 5 = 15, no overflow between words */
    uint64_t a[1] = {3};
    uint64_t b[1] = {5};
    uint64_t dst[2] = {0};
    bit_mul(dst, a, 1, b, 1);
    ASSERT_EQ(dst[0], 15ULL, "3 * 5 = 15");
    ASSERT_EQ(dst[1], 0ULL, "no carry");
    PASS();
}

void test_bit_cmp(void) {
    TEST("bit_cmp");
    uint64_t a[1] = {5}, b[1] = {3};
    ASSERT_TRUE(bit_cmp(a, b, 1) > 0, "5 > 3");
    ASSERT_TRUE(bit_cmp(b, a, 1) < 0, "3 < 5");
    ASSERT_TRUE(bit_cmp(a, a, 1) == 0, "5 = 5");
    PASS();
}

void test_bit_is_zero(void) {
    TEST("bit_is_zero");
    uint64_t z[1] = {0}, nz[1] = {1};
    ASSERT_TRUE(bit_is_zero(z, 1), "zero is zero");
    ASSERT_TRUE(!bit_is_zero(nz, 1), "non-zero is not zero");
    PASS();
}

void test_conversion(void) {
    TEST("byte/u64 conversion");
    uint8_t bytes[8] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    uint64_t words[1] = {0};
    bytes_to_u64(words, bytes, 8);
    uint8_t out[8] = {0};
    u64_to_bytes(out, words, 8);
    ASSERT_TRUE(memcmp(bytes, out, 8) == 0, "round-trip conversion");
    PASS();
}

void test_hadamard_truth_table(void) {
    TEST("hadamard_truth_table");
    uint64_t x[1] = {0x03}; /* 2-bit, x = (1,1) */
    int table[4] = {0};
    bit_hadamard_truth_table(table, x, 2);
    /* r=0: ⟨(1,1), (0,0)⟩ = 0 */
    ASSERT_EQ(table[0], 0, "⟨x,00⟩");
    /* r=1: ⟨(1,1), (1,0)⟩ = 1 */
    ASSERT_EQ(table[1], 1, "⟨x,01⟩");
    /* r=2: ⟨(1,1), (0,1)⟩ = 1 */
    ASSERT_EQ(table[2], 1, "⟨x,10⟩");
    /* r=3: ⟨(1,1), (1,1)⟩ = 0 */
    ASSERT_EQ(table[3], 0, "⟨x,11⟩");
    PASS();
}

void test_equal_buf(void) {
    TEST("equal/zero buffers");
    uint64_t a[1] = {0xDEADBEEF}, b[1] = {0xDEADBEEF};
    ASSERT_TRUE(bit_equal_buf(a, b, 1), "equal");
    b[0] = 0xCAFEBABE;
    ASSERT_TRUE(!bit_equal_buf(a, b, 1), "not equal");
    uint64_t z[1] = {0};
    ASSERT_TRUE(bit_is_zero_buf(z, 1), "zero buf");
    PASS();
}

int main(void) {
    printf("=== Test: Bit Operations ===\n\n");
    test_popcount();
    test_popcount_buf();
    test_hamming_distance();
    test_parity();
    test_inner_product();
    test_inner_product_bilinearity();
    test_bit_set_get();
    test_bit_flip();
    test_bit_xor_and_or_not();
    test_bit_shift();
    test_unit_vector();
    test_random_weight();
    test_bit_add();
    test_bit_sub();
    test_bit_mul();
    test_bit_cmp();
    test_bit_is_zero();
    test_conversion();
    test_hadamard_truth_table();
    test_equal_buf();
    printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
