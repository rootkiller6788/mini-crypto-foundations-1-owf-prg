/*
 * bit_operations.h — Bit String Operations & Inner Product
 *
 * Core utilities for manipulating bit strings: inner product (mod 2),
 * Hamming weight, XOR, bit counting, and binary arithmetic needed
 * by the Goldreich-Levin algorithm and OWF implementations.
 *
 * Inner Product (mod 2):
 *   ⟨x, y⟩ = Σ_{i=0}^{n-1} x_i · y_i (mod 2)
 *   This is the central operation in the GL hardcore bit.
 *
 *   Properties:
 *   - Bilinear: ⟨a⊕b, c⟩ = ⟨a,c⟩ ⊕ ⟨b,c⟩
 *   - Symmetric: ⟨x, y⟩ = ⟨y, x⟩
 *   - Non-degenerate: ⟨x, y⟩ = 0 ∀y ⇒ x = 0
 *
 * Reference: Arora-Barak §9.3, Goldreich Vol.1 §2.5
 * Courses: MIT 6.875, Stanford CS255
 */

#ifndef BIT_OPERATIONS_H
#define BIT_OPERATIONS_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* ── Bit Counting ────────────────────────────────────────── */
/* Hamming weight (popcount): number of 1 bits */
size_t bit_popcount_u64(uint64_t x);
size_t bit_popcount_buf(const uint64_t* data, size_t n_words);
/* Hamming distance between two bit strings */
size_t bit_hamming_distance(const uint64_t* a, const uint64_t* b, size_t n_words);
/* Parity (popcount mod 2) */
int    bit_parity_u64(uint64_t x);
int    bit_parity_buf(const uint64_t* data, size_t n_words);

/* ── Inner Product (mod 2) ───────────────────────────────── */
/* Compute ⟨a, b⟩ = Σ a_i · b_i mod 2 for bit strings */
int    bit_inner_product(const uint64_t* a, const uint64_t* b, size_t n_words);
/* Inner product over two bit ranges */
int    bit_inner_product_range(const uint64_t* a, size_t a_offset,
                                const uint64_t* b, size_t b_offset,
                                size_t n_bits);
/* Inner product with specific bit position extracted */
int    bit_inner_product_extract(const uint64_t* data, size_t n_bits,
                                  size_t bit_pos, uint64_t* other_data);

/* ── Bit Manipulation ────────────────────────────────────── */
/* Set/Get/Flip individual bits in a packed array */
void   bit_set(uint64_t* data, size_t pos, int value);
int    bit_get(const uint64_t* data, size_t pos);
void   bit_flip(uint64_t* data, size_t pos);
/* Set range of bits */
void   bit_set_range(uint64_t* data, size_t start, size_t len, int value);
/* Fill entire buffer */
void   bit_fill(uint64_t* data, size_t n_words, int value);

/* ── Bitwise Operations on Buffers ───────────────────────── */
void bit_xor_buf(uint64_t* dst, const uint64_t* a, const uint64_t* b, size_t n);
void bit_and_buf(uint64_t* dst, const uint64_t* a, const uint64_t* b, size_t n);
void bit_or_buf(uint64_t* dst, const uint64_t* a, const uint64_t* b, size_t n);
void bit_not_buf(uint64_t* dst, const uint64_t* src, size_t n);
int  bit_equal_buf(const uint64_t* a, const uint64_t* b, size_t n);
int  bit_is_zero_buf(const uint64_t* data, size_t n);

/* ── Shift and Rotate ────────────────────────────────────── */
/* Left shift by k bits across word boundaries */
void bit_shift_left(uint64_t* dst, const uint64_t* src, size_t n_words, size_t k);
/* Right shift by k bits */
void bit_shift_right(uint64_t* dst, const uint64_t* src, size_t n_words, size_t k);

/* ── Unit Vectors and Masks ──────────────────────────────── */
/* Create unit vector e_i (1 at position i, 0 elsewhere) */
void bit_unit_vector(uint64_t* dst, size_t n_bits, size_t i);
/* Create mask with k ones starting at position pos */
void bit_mask(uint64_t* dst, size_t pos, size_t k);
/* Create all-ones buffer */
void bit_ones(uint64_t* dst, size_t n_bits);

/* ── Random Bit Generation ───────────────────────────────── */
/* Fill buffer with random bits */
void bit_random(uint64_t* data, size_t n_bits);
/* Generate random n-bit string with specific weight */
void bit_random_weight(uint64_t* data, size_t n_bits, size_t weight);

/* ── Binary Arithmetic (modular) ─────────────────────────── */
/* Add two n-bit numbers: dst = a + b (mod 2^n) */
void bit_add(uint64_t* dst, const uint64_t* a, const uint64_t* b, size_t n_words);
/* Subtract: dst = a - b (mod 2^n) */
void bit_sub(uint64_t* dst, const uint64_t* a, const uint64_t* b, size_t n_words);
/* Multiply n-bit numbers (result is 2n bits) */
void bit_mul(uint64_t* dst, const uint64_t* a, size_t a_words,
              const uint64_t* b, size_t b_words);
/* Modulo exponentiation: dst = base^exp mod mod */
void bit_mod_exp(uint64_t* dst, const uint64_t* base, const uint64_t* exp,
                  const uint64_t* mod, size_t n_words);
/* GCD */
void bit_gcd(uint64_t* dst, const uint64_t* a, const uint64_t* b, size_t n_words);

/* ── Comparison ──────────────────────────────────────────── */
int bit_cmp(const uint64_t* a, const uint64_t* b, size_t n_words);
int bit_is_zero(const uint64_t* a, size_t n_words);

/* ── Conversion ──────────────────────────────────────────── */
/* Convert between little-endian byte array and uint64 array */
void bytes_to_u64(uint64_t* dst, const uint8_t* src, size_t n_bytes);
void u64_to_bytes(uint8_t* dst, const uint64_t* src, size_t n_bytes);
/* Display */
void bit_print_binary(const uint64_t* data, size_t n_bits);
void bit_print_hex(const uint64_t* data, size_t n_bytes);

/* ── Walsh-Hadamard Transform Helpers ────────────────────── */
/* Compute all inner products ⟨x, r⟩ for r = 0..2^n-1 (truth table) */
void bit_hadamard_truth_table(int* table, const uint64_t* x, size_t n);

#endif /* BIT_OPERATIONS_H */
