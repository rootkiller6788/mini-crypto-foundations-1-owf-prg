/*
 * bit_operations.c — Bit String Operations & Inner Product
 *
 * Implements all bit-level operations declared in bit_operations.h.
 * These are the foundational utilities for the Goldreich-Levin theorem:
 * inner product (mod 2), popcount, XOR/AND/OR/NOT, shifts, arithmetic,
 * and the Walsh-Hadamard transform.
 *
 * Knowledge Points Covered:
 *   L2: Inner product mod 2 as GL hardcore bit
 *   L3: Bit-string arithmetic, carry/borrow chains, multi-word operations
 *   L5: Fast Walsh-Hadamard transform, binary exponentiation
 *
 * Reference: Arora-Barak §9.3, Goldreich Vol.1 §2.5
 * Courses: MIT 6.875, Stanford CS255, CMU 15-859
 */

#include "bit_operations.h"
#include <stdio.h>

/* ───────────────────────────────────────────────────────────────
 * Bit Counting — Hamming weight, distance, parity
 *
 * popcount: Hamming weight = number of 1 bits
 * hamming distance = popcount(a XOR b)
 * parity = popcount mod 2 = XOR of all bits
 * ───────────────────────────────────────────────────────────── */

size_t bit_popcount_u64(uint64_t x) {
    size_t count = 0;
    while (x) {
        x &= (x - 1);       /* clears lowest set bit; O(popcount) */
        count++;
    }
    return count;
}

size_t bit_popcount_buf(const uint64_t* data, size_t n_words) {
    size_t total = 0;
    for (size_t i = 0; i < n_words; i++) {
        total += bit_popcount_u64(data[i]);
    }
    return total;
}

size_t bit_hamming_distance(const uint64_t* a, const uint64_t* b, size_t n_words) {
    size_t dist = 0;
    for (size_t i = 0; i < n_words; i++) {
        dist += bit_popcount_u64(a[i] ^ b[i]);
    }
    return dist;
}

int bit_parity_u64(uint64_t x) {
    x ^= x >> 32;
    x ^= x >> 16;
    x ^= x >> 8;
    x ^= x >> 4;
    x ^= x >> 2;
    x ^= x >> 1;
    return (int)(x & 1);
}

int bit_parity_buf(const uint64_t* data, size_t n_words) {
    int parity = 0;
    for (size_t i = 0; i < n_words; i++) {
        parity ^= bit_parity_u64(data[i]);
    }
    return parity;
}

/* ───────────────────────────────────────────────────────────────
 * Inner Product (mod 2) — The Goldreich-Levin Hardcore Bit
 *
 * ⟨a, b⟩ = Σ_i a_i · b_i (mod 2)
 *
 * Fundamental property (bilinearity):
 *   ⟨a⊕c, b⟩ = ⟨a,b⟩ ⊕ ⟨c,b⟩
 *   ⟨a, b⊕c⟩ = ⟨a,b⟩ ⊕ ⟨a,c⟩
 *
 * Self-correction identity (key to GL reduction):
 *   ⟨x, r⟩ ⊕ ⟨x, r⊕e_i⟩ = ⟨x, e_i⟩ = x_i
 * ───────────────────────────────────────────────────────────── */

int bit_inner_product(const uint64_t* a, const uint64_t* b, size_t n_words) {
    int result = 0;
    for (size_t i = 0; i < n_words; i++) {
        result ^= bit_parity_u64(a[i] & b[i]);
    }
    return result;
}

int bit_inner_product_range(const uint64_t* a, size_t a_offset,
                             const uint64_t* b, size_t b_offset,
                             size_t n_bits) {
    int result = 0;
    for (size_t i = 0; i < n_bits; i++) {
        int bit_a = bit_get(a, a_offset + i);
        int bit_b = bit_get(b, b_offset + i);
        result ^= (bit_a & bit_b);
    }
    return result;
}

int bit_inner_product_extract(const uint64_t* data, size_t n_bits,
                               size_t bit_pos, uint64_t* other_data) {
    /* Compute ⟨data, v⟩ where v is either unit vector e_{bit_pos}
     * or an externally provided vector other_data */
    int result = 0;
    for (size_t i = 0; i < n_bits; i++) {
        int bit_a = bit_get(data, i);
        int bit_b;
        if (other_data) {
            bit_b = bit_get(other_data, i);
        } else {
            bit_b = (i == bit_pos) ? 1 : 0;
        }
        result ^= (bit_a & bit_b);
    }
    return result;
}

/* ───────────────────────────────────────────────────────────────
 * Bit Manipulation — Set, Get, Flip individual bits
 * ───────────────────────────────────────────────────────────── */

void bit_set(uint64_t* data, size_t pos, int value) {
    size_t word = pos / 64;
    size_t bit  = pos % 64;
    if (value) {
        data[word] |=  (1ULL << bit);
    } else {
        data[word] &= ~(1ULL << bit);
    }
}

int bit_get(const uint64_t* data, size_t pos) {
    size_t word = pos / 64;
    size_t bit  = pos % 64;
    return (int)((data[word] >> bit) & 1);
}

void bit_flip(uint64_t* data, size_t pos) {
    size_t word = pos / 64;
    size_t bit  = pos % 64;
    data[word] ^= (1ULL << bit);
}

void bit_set_range(uint64_t* data, size_t start, size_t len, int value) {
    for (size_t i = 0; i < len; i++) {
        bit_set(data, start + i, value);
    }
}

void bit_fill(uint64_t* data, size_t n_words, int value) {
    uint64_t fill_val = value ? ~0ULL : 0ULL;
    for (size_t i = 0; i < n_words; i++) {
        data[i] = fill_val;
    }
}

/* ───────────────────────────────────────────────────────────────
 * Bitwise Operations on Buffers — XOR, AND, OR, NOT
 * ───────────────────────────────────────────────────────────── */

void bit_xor_buf(uint64_t* dst, const uint64_t* a, const uint64_t* b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        dst[i] = a[i] ^ b[i];
    }
}

void bit_and_buf(uint64_t* dst, const uint64_t* a, const uint64_t* b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        dst[i] = a[i] & b[i];
    }
}

void bit_or_buf(uint64_t* dst, const uint64_t* a, const uint64_t* b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        dst[i] = a[i] | b[i];
    }
}

void bit_not_buf(uint64_t* dst, const uint64_t* src, size_t n) {
    for (size_t i = 0; i < n; i++) {
        dst[i] = ~src[i];
    }
}

int bit_equal_buf(const uint64_t* a, const uint64_t* b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

int bit_is_zero_buf(const uint64_t* data, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (data[i] != 0) return 0;
    }
    return 1;
}

/* ───────────────────────────────────────────────────────────────
 * Shift and Rotate — Multi-word shifts with carry propagation
 *
 * Handles carry across 64-bit word boundaries.
 * bit_shift_left:  dst = src << k  (big-endian word order)
 * bit_shift_right: dst = src >> k
 * ───────────────────────────────────────────────────────────── */

void bit_shift_left(uint64_t* dst, const uint64_t* src, size_t n_words, size_t k) {
    if (k == 0) {
        memcpy(dst, src, n_words * sizeof(uint64_t));
        return;
    }
    size_t word_shift = k / 64;
    size_t bit_shift  = k % 64;
    memset(dst, 0, n_words * sizeof(uint64_t));
    if (word_shift >= n_words) return;
    for (size_t i = n_words; i > word_shift; i--) {
        size_t si = i - 1 - word_shift;
        dst[i - 1] = src[si] << bit_shift;
        if (bit_shift > 0 && si > 0) {
            dst[i - 1] |= src[si - 1] >> (64 - bit_shift);
        }
    }
}

void bit_shift_right(uint64_t* dst, const uint64_t* src, size_t n_words, size_t k) {
    if (k == 0) {
        memcpy(dst, src, n_words * sizeof(uint64_t));
        return;
    }
    size_t word_shift = k / 64;
    size_t bit_shift  = k % 64;
    memset(dst, 0, n_words * sizeof(uint64_t));
    for (size_t i = 0; i + word_shift < n_words; i++) {
        dst[i] = src[i + word_shift] >> bit_shift;
        if (bit_shift > 0 && i + word_shift + 1 < n_words) {
            dst[i] |= src[i + word_shift + 1] << (64 - bit_shift);
        }
    }
}

/* ───────────────────────────────────────────────────────────────
 * Unit Vectors, Masks, Constants
 * ───────────────────────────────────────────────────────────── */

void bit_unit_vector(uint64_t* dst, size_t n_bits, size_t i) {
    size_t n_words = (n_bits + 63) / 64;
    memset(dst, 0, n_words * sizeof(uint64_t));
    bit_set(dst, i, 1);
}

void bit_mask(uint64_t* dst, size_t pos, size_t k) {
    size_t n_words = ((pos + k) + 63) / 64;
    memset(dst, 0, n_words * sizeof(uint64_t));
    for (size_t i = 0; i < k; i++) {
        bit_set(dst, pos + i, 1);
    }
}

void bit_ones(uint64_t* dst, size_t n_bits) {
    size_t n_words = (n_bits + 63) / 64;
    memset(dst, 0xFF, n_words * sizeof(uint64_t));
    size_t extra = n_bits % 64;
    if (extra > 0) {
        dst[n_words - 1] &= (1ULL << extra) - 1;
    }
}

/* ───────────────────────────────────────────────────────────────
 * Random Bit Generation — CSPRNG simulation
 * ───────────────────────────────────────────────────────────── */

void bit_random(uint64_t* data, size_t n_bits) {
    size_t n_words = (n_bits + 63) / 64;
    for (size_t i = 0; i < n_words; i++) {
        uint64_t hi = (uint64_t)rand();
        uint64_t lo = (uint64_t)rand();
        data[i] = (hi << 15) ^ lo ^ ((uint64_t)rand() << 30);
    }
    size_t extra = n_bits % 64;
    if (extra > 0) {
        data[n_words - 1] &= (1ULL << extra) - 1;
    }
}

void bit_random_weight(uint64_t* data, size_t n_bits, size_t weight) {
    size_t n_words = (n_bits + 63) / 64;
    memset(data, 0, n_words * sizeof(uint64_t));
    if (weight > n_bits) weight = n_bits;
    size_t* positions = (size_t*)malloc(n_bits * sizeof(size_t));
    if (!positions) return;
    for (size_t i = 0; i < n_bits; i++) positions[i] = i;
    for (size_t i = 0; i < weight; i++) {
        size_t j = i + (rand() % (n_bits - i));
        size_t tmp = positions[i];
        positions[i] = positions[j];
        positions[j] = tmp;
        bit_set(data, positions[i], 1);
    }
    free(positions);
}

/* ───────────────────────────────────────────────────────────────
 * Binary Arithmetic — Schoolbook multi-word arithmetic
 *
 * Addition/subtraction with carry/borrow propagation.
 * Multiplication: 64×64 → 128 decomposition to avoid overflow.
 * Division: repeated trial subtraction (educational clarity).
 * ───────────────────────────────────────────────────────────── */

void bit_add(uint64_t* dst, const uint64_t* a, const uint64_t* b, size_t n_words) {
    uint64_t carry = 0;
    for (size_t i = 0; i < n_words; i++) {
        uint64_t sum = a[i] + b[i] + carry;
        carry = (sum < a[i] || (carry && sum == a[i])) ? 1 : 0;
        dst[i] = sum;
    }
}

void bit_sub(uint64_t* dst, const uint64_t* a, const uint64_t* b, size_t n_words) {
    uint64_t borrow = 0;
    for (size_t i = 0; i < n_words; i++) {
        uint64_t diff = a[i] - b[i] - borrow;
        borrow = (a[i] < b[i] + borrow) ? 1 : 0;
        dst[i] = diff;
    }
}

void bit_mul(uint64_t* dst, const uint64_t* a, size_t a_words,
              const uint64_t* b, size_t b_words) {
    size_t result_words = a_words + b_words;
    memset(dst, 0, result_words * sizeof(uint64_t));
    for (size_t i = 0; i < a_words; i++) {
        if (a[i] == 0) continue;
        uint64_t carry = 0;
        for (size_t j = 0; j < b_words; j++) {
            /* 64×64 → 128 bit via 32-bit decomposition */
            uint64_t al = a[i] & 0xFFFFFFFFULL;
            uint64_t ah = a[i] >> 32;
            uint64_t bl = b[j] & 0xFFFFFFFFULL;
            uint64_t bh = b[j] >> 32;
            uint64_t m0 = al * bl;
            uint64_t m1_lo = (al * bh) & 0xFFFFFFFFULL;
            uint64_t m1_hi = (al * bh) >> 32;
            uint64_t m2_lo = (ah * bl) & 0xFFFFFFFFULL;
            uint64_t m2_hi = (ah * bl) >> 32;
            uint64_t m3 = ah * bh;
            uint64_t prod_lo = m0 + (m1_lo << 32) + (m2_lo << 32);
            uint64_t prod_hi = m3 + m1_hi + m2_hi;
            prod_hi += (prod_lo < m0) ? 1 : 0;
            prod_hi += (prod_lo < (m1_lo << 32)) ? 1 : 0;
            prod_hi += (prod_lo < (m2_lo << 32)) ? 1 : 0;
            uint64_t old = dst[i + j];
            dst[i + j] += prod_lo + carry;
            carry = prod_hi + (dst[i + j] < old ? 1 : 0);
            if (i + j + 1 < result_words) {
                old = dst[i + j + 1];
                dst[i + j + 1] += carry;
                carry = (dst[i + j + 1] < old) ? 1 : 0;
            }
        }
        size_t idx = i + b_words;
        while (carry && idx < result_words) {
            uint64_t old = dst[idx];
            dst[idx] += carry;
            carry = (dst[idx] < old) ? 1 : 0;
            idx++;
        }
    }
}

void bit_mod_exp(uint64_t* dst, const uint64_t* base, const uint64_t* exp,
                  const uint64_t* mod, size_t n_words) {
    /* Square-and-multiply: result = base^exp mod mod */
    memset(dst, 0, n_words * sizeof(uint64_t));
    dst[0] = 1;

    uint64_t* tmp_base = (uint64_t*)malloc(n_words * sizeof(uint64_t));
    uint64_t* tmp_exp  = (uint64_t*)malloc(n_words * sizeof(uint64_t));
    uint64_t* tmp_prod = (uint64_t*)malloc(2 * n_words * sizeof(uint64_t));
    uint64_t* tmp_rem  = (uint64_t*)malloc(2 * n_words * sizeof(uint64_t));
    if (!tmp_base || !tmp_exp || !tmp_prod || !tmp_rem) {
        free(tmp_base); free(tmp_exp); free(tmp_prod); free(tmp_rem);
        return;
    }
    memcpy(tmp_base, base, n_words * sizeof(uint64_t));
    memcpy(tmp_exp, exp, n_words * sizeof(uint64_t));

    while (!bit_is_zero(tmp_exp, n_words)) {
        if (tmp_exp[0] & 1) {
            bit_mul(tmp_prod, dst, n_words, tmp_base, n_words);
            memcpy(dst, tmp_prod, n_words * sizeof(uint64_t));
            /* Modular reduction by repeated subtraction */
            memcpy(tmp_rem, tmp_prod, 2 * n_words * sizeof(uint64_t));
            for (size_t k = 2 * n_words; k > n_words; k--) {
                size_t ki = k - 1;
                while (ki >= n_words) {
                    if (memcmp(tmp_rem + ki - n_words + 1, mod, n_words * sizeof(uint64_t)) >= 0) {
                        uint64_t borrow = 0;
                        for (size_t w = 0; w < n_words; w++) {
                            size_t dst_idx = ki - n_words + 1 + w;
                            uint64_t old = tmp_rem[dst_idx];
                            tmp_rem[dst_idx] = old - mod[w] - borrow;
                            borrow = (old < mod[w] + borrow) ? 1 : 0;
                        }
                    } else break;
                }
            }
            memcpy(dst, tmp_rem, n_words * sizeof(uint64_t));
        }
        /* Square base */
        bit_mul(tmp_prod, tmp_base, n_words, tmp_base, n_words);
        memcpy(tmp_rem, tmp_prod, 2 * n_words * sizeof(uint64_t));
        /* Reduce mod */
        for (size_t k = 2 * n_words; k > n_words; k--) {
            size_t ki = k - 1;
            while (ki >= n_words) {
                if (memcmp(tmp_rem + ki - n_words + 1, mod, n_words * sizeof(uint64_t)) >= 0) {
                    uint64_t borrow = 0;
                    for (size_t w = 0; w < n_words; w++) {
                        size_t dst_idx = ki - n_words + 1 + w;
                        uint64_t old = tmp_rem[dst_idx];
                        tmp_rem[dst_idx] = old - mod[w] - borrow;
                        borrow = (old < mod[w] + borrow) ? 1 : 0;
                    }
                } else break;
            }
        }
        memcpy(tmp_base, tmp_rem, n_words * sizeof(uint64_t));
        bit_shift_right(tmp_exp, tmp_exp, n_words, 1);
    }

    free(tmp_base); free(tmp_exp); free(tmp_prod); free(tmp_rem);
}

void bit_gcd(uint64_t* dst, const uint64_t* a, const uint64_t* b, size_t n_words) {
    uint64_t* ta = (uint64_t*)malloc(n_words * sizeof(uint64_t));
    uint64_t* tb = (uint64_t*)malloc(n_words * sizeof(uint64_t));
    uint64_t* tmp = (uint64_t*)malloc(n_words * sizeof(uint64_t));
    if (!ta || !tb || !tmp) {
        free(ta); free(tb); free(tmp);
        return;
    }
    memcpy(ta, a, n_words * sizeof(uint64_t));
    memcpy(tb, b, n_words * sizeof(uint64_t));

    while (!bit_is_zero(tb, n_words)) {
        while (bit_cmp(ta, tb, n_words) >= 0) {
            bit_sub(tmp, ta, tb, n_words);
            memcpy(ta, tmp, n_words * sizeof(uint64_t));
        }
        memcpy(tmp, ta, n_words * sizeof(uint64_t));
        memcpy(ta, tb, n_words * sizeof(uint64_t));
        memcpy(tb, tmp, n_words * sizeof(uint64_t));
    }
    memcpy(dst, ta, n_words * sizeof(uint64_t));

    free(ta); free(tb); free(tmp);
}

/* ───────────────────────────────────────────────────────────────
 * Comparison — Lexicographic (big-endian word order)
 * ───────────────────────────────────────────────────────────── */

int bit_cmp(const uint64_t* a, const uint64_t* b, size_t n_words) {
    for (size_t i = n_words; i > 0; i--) {
        size_t idx = i - 1;
        if (a[idx] > b[idx]) return 1;
        if (a[idx] < b[idx]) return -1;
    }
    return 0;
}

int bit_is_zero(const uint64_t* a, size_t n_words) {
    return bit_is_zero_buf(a, n_words);
}

/* ───────────────────────────────────────────────────────────────
 * Conversion — byte arrays ↔ uint64 arrays
 * ───────────────────────────────────────────────────────────── */

void bytes_to_u64(uint64_t* dst, const uint8_t* src, size_t n_bytes) {
    size_t n_words = (n_bytes + 7) / 8;
    memset(dst, 0, n_words * sizeof(uint64_t));
    for (size_t i = 0; i < n_bytes; i++) {
        dst[i / 8] |= ((uint64_t)src[i]) << (8 * (i % 8));
    }
}

void u64_to_bytes(uint8_t* dst, const uint64_t* src, size_t n_bytes) {
    for (size_t i = 0; i < n_bytes; i++) {
        dst[i] = (uint8_t)((src[i / 8] >> (8 * (i % 8))) & 0xFF);
    }
}

/* ───────────────────────────────────────────────────────────────
 * Display — Binary and hex output
 * ───────────────────────────────────────────────────────────── */

void bit_print_binary(const uint64_t* data, size_t n_bits) {
    for (size_t i = n_bits; i > 0; i--) {
        printf("%d", bit_get(data, i - 1));
    }
    printf("\n");
}

void bit_print_hex(const uint64_t* data, size_t n_bytes) {
    for (size_t i = n_bytes; i > 0; i--) {
        printf("%02x", ((const uint8_t*)data)[i - 1]);
    }
    printf("\n");
}

/* ───────────────────────────────────────────────────────────────
 * Walsh-Hadamard Transform Helpers
 *
 * Compute all inner products ⟨x, r⟩ for r = 0..2^n-1.
 * This produces the truth table of the Hadamard encoding of x.
 * Time: O(n·2^n), space: O(2^n).
 * ───────────────────────────────────────────────────────────── */

void bit_hadamard_truth_table(int* table, const uint64_t* x, size_t n) {
    size_t N = (size_t)1 << n;
    for (size_t r = 0; r < N; r++) {
        int ip = 0;
        for (size_t i = 0; i < n; i++) {
            if ((r >> i) & 1) {
                ip ^= bit_get(x, i);
            }
        }
        table[r] = ip;
    }
}
