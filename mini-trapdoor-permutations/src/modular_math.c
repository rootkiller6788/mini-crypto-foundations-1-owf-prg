/**
 * modular_math.c -- Modular Arithmetic Implementation for TDP
 *
 * Implements big integer arithmetic over fixed-size limb arrays, modular
 * operations (add, mul, exp), number-theoretic functions (GCD, EGCD, inverse,
 * totient, CRT, Legendre/Jacobi symbols), and primality testing (Miller-Rabin).
 *
 * Reference: Shoup, A Computational Introduction to Number Theory and Algebra (2008)
 *            Katz & Lindell, Introduction to Modern Cryptography (2014), Ch. 8
 *            Menezes, van Oorschot, Vanstone, Handbook of Applied Cryptography (1996)
 */

#include "modular_math.h"
#include "rsa_keygen.h"
#include <string.h>
#include <stdio.h>

/* =========================================================================
 * Small Primes Table (first 256 primes for trial division sieve)
 * Reference: OEIS A000040
 * ========================================================================= */

const uint32_t SMALL_PRIMES[NUM_SMALL_PRIMES] = {
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
    59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131,
    137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
    227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311,
    313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
    419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
    509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613,
    617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719,
    727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827,
    829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
    947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049,
    1051, 1061, 1067, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163,
    1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283,
    1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423,
    1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511,
    1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619
};

/* =========================================================================
 * Internal Helpers -- not in header, implementation details only
 * ========================================================================= */

/**
 * Normalize bigint: remove leading zero limbs to maintain canonical form.
 * After normalization, either nlimbs==1 (value 0) or the MSB limb is nonzero.
 * Complexity: O(nlimbs).
 */
static void bigint_normalize(bigint_t *a) {
    while (a->nlimbs > 1 && a->limbs[a->nlimbs - 1] == 0) {
        a->nlimbs--;
    }
    if (a->nlimbs == 0) {
        a->nlimbs = 1;
        a->limbs[0] = 0;
    }
}

/**
 * Compare magnitudes ignoring sign (internal use).
 * Returns -1 if |a| < |b|, 0 if |a| == |b|, 1 if |a| > |b|.
 * Complexity: O(nlimbs).
 */
static int bigint_compare_magnitude(const bigint_t *a, const bigint_t *b) {
    if (a->nlimbs > b->nlimbs) return 1;
    if (a->nlimbs < b->nlimbs) return -1;
    for (int i = (int)a->nlimbs - 1; i >= 0; i--) {
        if (a->limbs[i] > b->limbs[i]) return 1;
        if (a->limbs[i] < b->limbs[i]) return -1;
    }
    return 0;
}

/* =========================================================================
 * Big Integer Construction -- L1 Definitions
 *
 * Each function maps to a fundamental operation on the ring Z of integers.
 * These provide the foundational data structure (bigint_t) used throughout.
 * ========================================================================= */

bigint_t bigint_from_uint64(uint64_t val) {
    bigint_t result;
    memset(&result, 0, sizeof(result));
    if (val == 0) {
        result.nlimbs = 1;
        return result;
    }
    result.limbs[0] = (uint32_t)(val & 0xFFFFFFFFULL);
    if (val > 0xFFFFFFFFULL) {
        result.limbs[1] = (uint32_t)((val >> 32) & 0xFFFFFFFFULL);
        result.nlimbs = 2;
        if (result.limbs[1] == 0) result.nlimbs = 1;
    } else {
        result.nlimbs = 1;
    }
    return result;
}

void bigint_set_zero(bigint_t *a) {
    if (a) { memset(a, 0, sizeof(bigint_t)); a->nlimbs = 1; }
}

void bigint_set_one(bigint_t *a) {
    if (a) { memset(a, 0, sizeof(bigint_t)); a->nlimbs = 1; a->limbs[0] = 1; }
}

void bigint_copy(bigint_t *dst, const bigint_t *src) {
    if (dst && src) {
        memcpy(dst->limbs, src->limbs, src->nlimbs * sizeof(uint32_t));
        dst->nlimbs = src->nlimbs;
    }
}

/* =========================================================================
 * Big Integer Comparison -- Total order on Z
 * ========================================================================= */

int bigint_compare(const bigint_t *a, const bigint_t *b) {
    if (!a || !b) return 0;
    return bigint_compare_magnitude(a, b);
}

bool bigint_is_zero(const bigint_t *a) {
    if (!a) return true;
    return (a->nlimbs == 1 && a->limbs[0] == 0);
}

bool bigint_is_one(const bigint_t *a) {
    if (!a) return false;
    return (a->nlimbs == 1 && a->limbs[0] == 1);
}

bool bigint_is_even(const bigint_t *a) {
    if (!a) return true;
    return (a->limbs[0] & 1) == 0;
}

uint32_t bigint_bit_length(const bigint_t *a) {
    /* Position of the highest set bit + 1.
     * Returns 0 for value 0. */
    if (!a || bigint_is_zero(a)) return 0;
    uint32_t ms_limb = a->limbs[a->nlimbs - 1];
    uint32_t bits = (a->nlimbs - 1) * 32;
    while (ms_limb > 0) { bits++; ms_limb >>= 1; }
    return bits;
}

bool bigint_get_bit(const bigint_t *a, uint32_t bit_index) {
    if (!a) return false;
    uint32_t limb_idx = bit_index / 32;
    if (limb_idx >= a->nlimbs) return false;
    uint32_t bit_in_limb = bit_index % 32;
    return (a->limbs[limb_idx] >> bit_in_limb) & 1;
}

uint64_t bigint_to_uint64(const bigint_t *a) {
    if (!a) return 0;
    uint64_t result = 0;
    if (a->nlimbs >= 1) result |= (uint64_t)a->limbs[0];
    if (a->nlimbs >= 2) result |= (uint64_t)a->limbs[1] << 32;
    return result;
}

/* =========================================================================
 * Big Integer Arithmetic -- Ring operations on Z
 *
 * Addition:    schoolbook carry-ripple, O(max(nlimbs_a, nlimbs_b))
 * Subtraction: schoolbook borrow-ripple, O(max(nlimbs_a, nlimbs_b))
 * Multiplic'n: schoolbook nested-loop, O(nlimbs_a * nlimbs_b)
 * Division:    binary long division, O(nlimbs_a * nlimbs_b)
 *
 * Reference: Knuth, The Art of Computer Programming, Vol. 2
 *            Chapter 4.3 (Multiple-Precision Arithmetic)
 * ========================================================================= */

bool bigint_add(bigint_t *c, const bigint_t *a, const bigint_t *b) {
    if (!c || !a || !b) return false;
    uint32_t max_limbs = (a->nlimbs > b->nlimbs) ? a->nlimbs : b->nlimbs;
    if (max_limbs + 1 > BIGINT_MAX_LIMBS) return false;

    uint64_t carry = 0;
    for (uint32_t i = 0; i < max_limbs; i++) {
        uint64_t sum = carry;
        if (i < a->nlimbs) sum += a->limbs[i];
        if (i < b->nlimbs) sum += b->limbs[i];
        c->limbs[i] = (uint32_t)(sum & 0xFFFFFFFFULL);
        carry = sum >> 32;
    }
    if (carry > 0) {
        if (max_limbs >= BIGINT_MAX_LIMBS) return false;
        c->limbs[max_limbs] = (uint32_t)carry;
        c->nlimbs = max_limbs + 1;
    } else {
        c->nlimbs = max_limbs;
    }
    bigint_normalize(c);
    return true;
}

bool bigint_sub(bigint_t *c, const bigint_t *a, const bigint_t *b) {
    /* Requires a >= b (no negative results in our unsigned representation).
     * Theorem: For a >= b, the standard subtraction algorithm with borrow
     * produces the unique non-negative difference d such that a = b + d. */
    if (!c || !a || !b) return false;
    if (bigint_compare(a, b) < 0) return false;

    uint32_t max_limbs = a->nlimbs;
    int64_t borrow = 0;
    for (uint32_t i = 0; i < max_limbs; i++) {
        int64_t diff = (int64_t)a->limbs[i] - borrow;
        if (i < b->nlimbs) diff -= (int64_t)b->limbs[i];
        if (diff < 0) {
            diff += 0x100000000ULL;
            borrow = 1;
        } else {
            borrow = 0;
        }
        c->limbs[i] = (uint32_t)diff;
    }
    c->nlimbs = max_limbs;
    bigint_normalize(c);
    return true;
}

void bigint_mul(bigint_t *c, const bigint_t *a, const bigint_t *b) {
    /* Schoolbook multiplication with 64-bit intermediate accumulation.
     * Theorem: The product of two integers with L1, L2 limbs requires
     * at most L1+L2 limbs for exact representation.
     * Reference: Knuth, TAOCP Vol. 2, Algorithm M (Section 4.3.1). */
    if (!c || !a || !b) return;
    uint32_t al = a->nlimbs, bl = b->nlimbs;
    uint32_t max_limbs = al + bl;
    if (max_limbs > BIGINT_MAX_LIMBS) max_limbs = BIGINT_MAX_LIMBS;

    uint32_t temp[BIGINT_MAX_LIMBS];
    memset(temp, 0, sizeof(temp));

    for (uint32_t i = 0; i < al; i++) {
        uint64_t carry = 0;
        for (uint32_t j = 0; j < bl; j++) {
            uint32_t k = i + j;
            uint64_t prod = (uint64_t)a->limbs[i] * (uint64_t)b->limbs[j];
            uint64_t sum = (uint64_t)temp[k] + (prod & 0xFFFFFFFFULL) + carry;
            temp[k] = (uint32_t)(sum & 0xFFFFFFFFULL);
            carry = (prod >> 32) + (sum >> 32);
        }
        uint32_t k = i + bl;
        while (carry > 0 && k < BIGINT_MAX_LIMBS) {
            uint64_t sum = (uint64_t)temp[k] + carry;
            temp[k] = (uint32_t)(sum & 0xFFFFFFFFULL);
            carry = sum >> 32;
            k++;
        }
    }

    memcpy(c->limbs, temp, max_limbs * sizeof(uint32_t));
    c->nlimbs = max_limbs;
    bigint_normalize(c);
}

bool bigint_divmod(bigint_t *q, bigint_t *r, const bigint_t *a, const bigint_t *b) {
    /* Binary long division algorithm.
     * For a = q*b + r with 0 <= r < b:
     *   Start with r = a, q = 0.
     *   For k from log2(a)-log2(b) down to 0:
     *     If r >= b*2^k: r -= b*2^k, q += 2^k.
     *
     * Theorem (Division Algorithm): For integers a, b with b > 0, there
     * exist unique integers q, r such that a = qb + r and 0 <= r < b.
     *
     * Complexity: O(nlimbs_a * nlimbs_b).
     * Reference: Knuth, TAOCP Vol. 2, Algorithm D (Section 4.3.1). */
    if (!a || !b || bigint_is_zero(b)) return false;

    if (bigint_compare(a, b) < 0) {
        if (q) bigint_set_zero(q);
        if (r) bigint_copy(r, a);
        return true;
    }

    if (bigint_compare(a, b) == 0) {
        if (q) bigint_set_one(q);
        if (r) bigint_set_zero(r);
        return true;
    }

    bigint_t remainder, quotient, one;
    bigint_copy(&remainder, a);
    bigint_set_zero(&quotient);
    bigint_set_one(&one);

    uint32_t a_bits = bigint_bit_length(a);
    uint32_t b_bits = bigint_bit_length(b);
    uint32_t max_shift = a_bits - b_bits;

    bigint_t b_shifted, shifted_one;
    bigint_copy(&b_shifted, b);
    bigint_shl(&b_shifted, max_shift);
    bigint_copy(&shifted_one, &one);
    bigint_shl(&shifted_one, max_shift);

    for (int shift = (int)max_shift; shift >= 0; shift--) {
        if (bigint_compare(&remainder, &b_shifted) >= 0) {
            bigint_sub(&remainder, &remainder, &b_shifted);
            bigint_add(&quotient, &quotient, &shifted_one);
        }
        bigint_shr(&b_shifted, 1);
        bigint_shr(&shifted_one, 1);
    }

    if (q) bigint_copy(q, &quotient);
    if (r) bigint_copy(r, &remainder);
    return true;
}

void bigint_shr(bigint_t *a, uint32_t n) {
    /* Right shift: a >>= n (equivalent to floor(a / 2^n)).
     * Operates in-place. Complexity: O(nlimbs). */
    if (!a || n == 0) return;
    uint32_t limb_shift = n / 32;
    uint32_t bit_shift = n % 32;

    if (limb_shift >= a->nlimbs) { bigint_set_zero(a); return; }

    for (uint32_t i = 0; i < a->nlimbs - limb_shift; i++) {
        a->limbs[i] = a->limbs[i + limb_shift];
    }
    a->nlimbs -= limb_shift;

    if (bit_shift > 0) {
        uint32_t carry = 0;
        for (int i = (int)a->nlimbs - 1; i >= 0; i--) {
            uint32_t new_carry = a->limbs[i] << (32 - bit_shift);
            a->limbs[i] = (a->limbs[i] >> bit_shift) | carry;
            carry = new_carry;
        }
    }
    bigint_normalize(a);
}

void bigint_shl(bigint_t *a, uint32_t n) {
    /* Left shift: a <<= n (equivalent to a * 2^n).
     * Operates in-place. Complexity: O(nlimbs). */
    if (!a || n == 0) return;
    uint32_t limb_shift = n / 32;
    uint32_t bit_shift = n % 32;

    if (limb_shift > 0) {
        if (a->nlimbs + limb_shift > BIGINT_MAX_LIMBS) {
            uint32_t max_src = BIGINT_MAX_LIMBS - limb_shift;
            if (a->nlimbs > max_src) a->nlimbs = max_src;
        }
        for (int i = (int)a->nlimbs - 1; i >= 0; i--) {
            a->limbs[i + limb_shift] = a->limbs[i];
        }
        memset(a->limbs, 0, limb_shift * sizeof(uint32_t));
        a->nlimbs += limb_shift;
    }

    if (bit_shift > 0) {
        uint32_t carry = 0;
        for (uint32_t i = 0; i < a->nlimbs; i++) {
            uint64_t val = ((uint64_t)a->limbs[i] << bit_shift) | carry;
            a->limbs[i] = (uint32_t)(val & 0xFFFFFFFFULL);
            carry = (uint32_t)(val >> 32);
        }
        if (carry > 0 && a->nlimbs < BIGINT_MAX_LIMBS) {
            a->limbs[a->nlimbs++] = carry;
        }
    }
    bigint_normalize(a);
}

void bigint_inc(bigint_t *a) {
    /* Increment: a += 1. Carry chain, amortized O(1). */
    if (!a) return;
    uint32_t i = 0;
    while (i < a->nlimbs && a->limbs[i] == 0xFFFFFFFF) { a->limbs[i] = 0; i++; }
    if (i < a->nlimbs) { a->limbs[i]++; }
    else if (a->nlimbs < BIGINT_MAX_LIMBS) { a->limbs[a->nlimbs++] = 1; }
    bigint_normalize(a);
}

void bigint_dec(bigint_t *a) {
    /* Decrement: a -= 1. Requires a > 0. */
    if (!a || bigint_is_zero(a)) return;
    uint32_t i = 0;
    while (i < a->nlimbs && a->limbs[i] == 0) { a->limbs[i] = 0xFFFFFFFF; i++; }
    a->limbs[i]--;
    bigint_normalize(a);
}

/* =========================================================================
 * Modular Arithmetic -- Operations in Z/mZ ring
 *
 * Each operation computes the result modulo m. These form the algebraic
 * foundation for RSA, Diffie-Hellman, and other cryptographic primitives.
 *
 * Reference: Shoup (2008), Chapter 2 (Congruences)
 * ========================================================================= */

void mod_add(bigint_t *result, const bigint_t *a, const bigint_t *b, const bigint_t *m) {
    if (!result || !a || !b || !m) return;
    bigint_t sum;
    memset(&sum, 0, sizeof(sum));
    bigint_add(&sum, a, b);
    if (bigint_compare(&sum, m) >= 0) bigint_sub(result, &sum, m);
    else bigint_copy(result, &sum);
}

void mod_sub(bigint_t *result, const bigint_t *a, const bigint_t *b, const bigint_t *m) {
    if (!result || !a || !b || !m) return;
    if (bigint_compare(a, b) >= 0) {
        bigint_sub(result, a, b);
    } else {
        bigint_t temp;
        bigint_add(&temp, a, m);
        bigint_sub(result, &temp, b);
    }
    if (bigint_compare(result, m) >= 0) bigint_sub(result, result, m);
}

void mod_mul(bigint_t *result, const bigint_t *a, const bigint_t *b, const bigint_t *m) {
    /* Modular multiplication: (a * b) mod m.
     * Multiply first, then reduce modulo m.
     * Complexity: O(nlimbs_a * nlimbs_b). */
    if (!result || !a || !b || !m) return;
    bigint_t prod, q, r;
    bigint_mul(&prod, a, b);
    bigint_divmod(&q, &r, &prod, m);
    bigint_copy(result, &r);
}

void mod_exp(bigint_t *result, const bigint_t *base, const bigint_t *exp, const bigint_t *m) {
    /* Modular exponentiation: base^exp mod m using square-and-multiply.
     *
     * Algorithm (binary exponentiation, left-to-right):
     *   result = 1
     *   for i from MSB(exp) down to 0:
     *     result = result^2 mod m
     *     if bit_i(exp) == 1: result = result * base mod m
     *
     * Complexity: O(log(exp) * log^2(m)).
     * Reference: Knuth, TAOCP Vol. 2, Section 4.6.3, Algorithm A. */
    if (!result || !base || !exp || !m) return;

    bigint_t one;
    bigint_set_one(&one);

    if (bigint_is_zero(exp)) { bigint_copy(result, &one); return; }
    if (bigint_is_one(exp)) { mod_mul(result, base, &one, m); return; }

    bigint_t acc;
    bigint_set_one(&acc);

    uint32_t ebits = bigint_bit_length(exp);
    for (int i = (int)ebits - 1; i >= 0; i--) {
        mod_mul(&acc, &acc, &acc, m);
        if (bigint_get_bit(exp, (uint32_t)i)) mod_mul(&acc, &acc, base, m);
    }
    bigint_copy(result, &acc);
}

void mod_exp_crt(bigint_t *result, const bigint_t *y,
                  const bigint_t *d_p, const bigint_t *d_q,
                  const bigint_t *q_inv, const bigint_t *p, const bigint_t *q) {
    /* CRT-accelerated modular exponentiation (Garner's algorithm).
     *
     * Given y, compute x = y^d mod n where n = p*q:
     *   x_p = y^{d_p} mod p    where d_p = d mod (p-1)
     *   x_q = y^{d_q} mod q    where d_q = d mod (q-1)
     *   h   = (x_p - x_q) * q^{-1} mod p
     *   x   = x_q + h * q
     *
     * ~4x faster than naive mod_exp for RSA.
     * Complexity: O(log(d_p) * log^2(p)).
     * Reference: Menezes, van Oorschot, Vanstone, HAC Section 14.75. */
    if (!result || !y || !d_p || !d_q || !q_inv || !p || !q) return;

    bigint_t x_p, x_q;
    mod_exp(&x_p, y, d_p, p);
    mod_exp(&x_q, y, d_q, q);

    bigint_t diff;
    if (bigint_compare(&x_p, &x_q) >= 0) {
        bigint_sub(&diff, &x_p, &x_q);
    } else {
        bigint_t temp;
        bigint_add(&temp, &x_p, p);
        bigint_sub(&diff, &temp, &x_q);
    }

    bigint_t h;
    mod_mul(&h, &diff, q_inv, p);

    bigint_t hq;
    bigint_mul(&hq, &h, q);
    bigint_add(result, &hq, &x_q);
}

/* =========================================================================
 * Number-Theoretic Functions -- L3 Mathematical Structures
 *
 * Core functions for working in the multiplicative group Z_n^*.
 * ========================================================================= */

void bigint_gcd(bigint_t *result, const bigint_t *a, const bigint_t *b) {
    /* Euclidean algorithm for GCD.
     * gcd(a,0) = a; gcd(a,b) = gcd(b, a mod b).
     *
     * Theorem (Euclid): Terminates and produces the GCD.
     * Steps: O(log(min(a,b))).
     *
     * Complexity: O(log(min(a,b)) * log^2(n)).
     * Reference: Euclid, Elements Book VII, Proposition 2 (c. 300 BCE). */
    if (!result || !a || !b) return;
    if (bigint_is_zero(b)) { bigint_copy(result, a); return; }
    if (bigint_is_zero(a)) { bigint_copy(result, b); return; }

    bigint_t x, y;
    bigint_copy(&x, a);
    bigint_copy(&y, b);

    if (bigint_compare(&x, &y) < 0) {
        bigint_t tmp = x; x = y; y = tmp;
    }

    while (!bigint_is_zero(&y)) {
        bigint_t q, r;
        bigint_divmod(&q, &r, &x, &y);
        bigint_copy(&x, &y);
        bigint_copy(&y, &r);
    }
    bigint_copy(result, &x);
}

void bigint_egcd(bigint_t *d, bigint_t *x, bigint_t *y, const bigint_t *a, const bigint_t *b) {
    /* Extended Euclidean Algorithm.
     * Finds d=gcd(a,b) and Bezout coefficients x,y: a*x + b*y = d.
     *
     * Algorithm maintains invariants:
     *   a * old_s + b * old_t = old_r
     *   a * s     + b * t     = r
     *
     * Complexity: O(log(min(a,b)) * log^2(n)).
     * Reference: Knuth, TAOCP Vol. 2, Section 4.5.2, Algorithm X. */
    if (!a || !b) return;

    bigint_t old_r, r, old_s, s, old_t, t;
    bigint_copy(&old_r, a);
    bigint_copy(&r, b);
    bigint_set_one(&old_s);
    bigint_set_zero(&s);
    bigint_set_zero(&old_t);
    bigint_set_one(&t);

    while (!bigint_is_zero(&r)) {
        bigint_t quotient, remainder;
        bigint_divmod(&quotient, &remainder, &old_r, &r);

        bigint_copy(&old_r, &r);
        bigint_copy(&r, &remainder);

        /* s = old_s - quotient * s */
        bigint_t tmp_s, prod;
        bigint_mul(&prod, &quotient, &s);
        if (bigint_compare(&old_s, &prod) >= 0) bigint_sub(&tmp_s, &old_s, &prod);
        else bigint_sub(&tmp_s, &prod, &old_s);
        bigint_copy(&old_s, &s);
        bigint_copy(&s, &tmp_s);

        /* t = old_t - quotient * t */
        bigint_t tmp_t;
        bigint_mul(&prod, &quotient, &t);
        if (bigint_compare(&old_t, &prod) >= 0) bigint_sub(&tmp_t, &old_t, &prod);
        else bigint_sub(&tmp_t, &prod, &old_t);
        bigint_copy(&old_t, &t);
        bigint_copy(&t, &tmp_t);
    }

    if (d) bigint_copy(d, &old_r);
    if (x) bigint_copy(x, &old_s);
    if (y) bigint_copy(y, &old_t);
}

bool mod_inverse(bigint_t *result, const bigint_t *a, const bigint_t *m) {
    /* Modular inverse: a^{-1} mod m such that a * a^{-1} = 1 (mod m).
     *
     * Theorem: a has a multiplicative inverse modulo m iff gcd(a,m) = 1.
     * The inverse is unique modulo m.
     *
     * Uses specialized EEA that tracks only the coefficient we need.
     * Complexity: O(log^2 m). */
    if (!result || !a || !m) return false;

    bigint_t u1, u2, v1, v2;
    bigint_copy(&u1, a);
    bigint_copy(&u2, m);
    bigint_set_one(&v1);
    bigint_set_zero(&v2);
    bigint_t one;
    bigint_set_one(&one);

    while (!bigint_is_zero(&u2)) {
        bigint_t q3, r3;
        bigint_divmod(&q3, &r3, &u1, &u2);
        bigint_copy(&u1, &u2);
        bigint_copy(&u2, &r3);

        /* v3 = v1 - q3*v2, keeping result in [0, m-1] */
        bigint_t prod, v3;
        bigint_mul(&prod, &q3, &v2);
        if (bigint_compare(&v1, &prod) >= 0) {
            bigint_sub(&v3, &v1, &prod);
        } else {
            bigint_t neg_d;
            bigint_sub(&neg_d, &prod, &v1);
            bigint_t q4, r4;
            bigint_divmod(&q4, &r4, &neg_d, m);
            if (bigint_is_zero(&r4)) bigint_set_zero(&v3);
            else bigint_sub(&v3, m, &r4);
        }
        bigint_copy(&v1, &v2);
        bigint_copy(&v2, &v3);
    }

    if (bigint_compare(&u1, &one) != 0) { bigint_set_zero(result); return false; }

    if (bigint_compare(&v1, m) >= 0) {
        bigint_t q4, r4;
        bigint_divmod(&q4, &r4, &v1, m);
        bigint_copy(result, &r4);
    } else {
        bigint_copy(result, &v1);
    }

    bigint_t check;
    mod_mul(&check, a, result, m);
    return bigint_is_one(&check);
}

void euler_totient_rsa(bigint_t *result, const bigint_t *p, const bigint_t *q) {
    /* Euler's totient for RSA modulus n = p*q:
     *   phi(n) = (p-1)(q-1)
     *
     * Theorem (Euler): For coprime p,q, phi(pq) = phi(p)*phi(q).
     * For prime p: phi(p) = p-1.
     *
     * Reference: Euler, "Theoremata circa divisores numerorum" (1760). */
    if (!result || !p || !q) return;
    bigint_t pm1, qm1;
    bigint_copy(&pm1, p); bigint_dec(&pm1);
    bigint_copy(&qm1, q); bigint_dec(&qm1);
    bigint_mul(result, &pm1, &qm1);
}

/* =========================================================================
 * Miller-Rabin Primality Testing -- L5 Algorithms
 *
 * Probabilistic primality test. Given n, determine if n is composite
 * or "probably prime" with error <= 4^{-k} after k rounds.
 *
 * Key insight: For prime p, the only square roots of 1 mod p are +-1.
 * For composite n, there are additional "nontrivial" square roots of 1.
 * Finding one proves n is composite (a "witness").
 *
 * Reference: Miller (1976), Rabin (1980)
 * ========================================================================= */

bool miller_rabin_witness(const bigint_t *n, const bigint_t *a) {
    /* Test if a is a witness to the compositeness of n.
     *
     * Algorithm:
     *   1. Write n-1 = 2^s * d where d is odd.
     *   2. Compute x = a^d mod n.
     *   3. If x == 1 or x == n-1, a is NOT a witness.
     *   4. For r = 1..s-1:
     *        x = x^2 mod n
     *        If x == n-1, NOT a witness.
     *        If x == 1, IS a witness (found nontrivial sqrt of 1).
     *   5. If x != 1 after all rounds, IS a witness.
     *
     * Theorem: For composite n, <= 1/4 of bases are non-witnesses.
     * Complexity: O(log^3 n). */
    if (!n || !a) return true;

    bigint_t two, three;
    bigint_set_one(&two); bigint_inc(&two);
    bigint_set_one(&three); bigint_inc(&three); bigint_inc(&three);

    if (bigint_compare(n, &two) == 0) return false;
    if (bigint_compare(n, &three) == 0) return false;
    if (bigint_is_even(n)) return true;

    bigint_t nm1, d;
    bigint_copy(&nm1, n); bigint_dec(&nm1);
    bigint_copy(&d, &nm1);
    uint32_t s = 0;
    while (bigint_is_even(&d)) { bigint_shr(&d, 1); s++; }

    bigint_t x;
    mod_exp(&x, a, &d, n);

    bigint_t one;
    bigint_set_one(&one);

    if (bigint_is_one(&x) || bigint_compare(&x, &nm1) == 0) return false;

    for (uint32_t r = 0; r < s - 1; r++) {
        mod_mul(&x, &x, &x, n);
        if (bigint_compare(&x, &nm1) == 0) return false;
        if (bigint_is_one(&x)) return true;
    }

    return !bigint_is_one(&x);
}

bool miller_rabin_test(const bigint_t *n, uint32_t k) {
    /* Miller-Rabin primality test with k rounds.
     * Error: <= 4^{-k}. For k=40: error < 2^{-80}.
     * Uses deterministic bases {2,7,61} for n < 2^32.
     * Complexity: O(k * log^3 n). */
    if (!n) return false;

    bigint_t two, three;
    bigint_set_one(&two); bigint_inc(&two);
    bigint_set_one(&three); bigint_inc(&three); bigint_inc(&three);

    if (bigint_compare(n, &two) == 0) return true;
    if (bigint_compare(n, &two) < 0) return false;
    if (bigint_is_even(n)) return false;
    if (bigint_compare(n, &three) == 0) return true;

    uint64_t n64 = bigint_to_uint64(n);
    if (n64 > 0 && n64 < 0x100000000ULL) {
        uint32_t n32 = (uint32_t)n64;
        for (uint32_t i = 0; i < NUM_SMALL_PRIMES; i++) {
            uint32_t sp = SMALL_PRIMES[i];
            if ((uint64_t)sp * sp > n32) break;
            if (n32 % sp == 0) return false;
        }
    }

    uint32_t test_bases[3] = {2, 7, 61};
    uint32_t num_bases = (n64 > 0 && n64 < 0x100000000ULL) ? 3 : k;
    if (num_bases > 3) num_bases = k;

    for (uint32_t i = 0; i < num_bases && i < k; i++) {
        bigint_t a;
        if (i < 3 && n64 > 0 && n64 < 0x100000000ULL) {
            if ((uint64_t)test_bases[i] >= n64) continue;
            a = bigint_from_uint64(test_bases[i]);
        } else {
            bigint_t nm2;
            bigint_copy(&nm2, n); bigint_dec(&nm2); bigint_dec(&nm2);
            bigint_rand_range(&a, &nm2, i + 17);
            bigint_t two_big = bigint_from_uint64(2);
            bigint_add(&a, &a, &two_big);
        }
        if (miller_rabin_witness(n, &a)) return false;
    }
    return true;
}

/* =========================================================================
 * Deterministic PRNG -- for educational/testing only
 *
 * Uses a 64-bit LCG: state = state * 6364136223846793005 + 1442695040888963407
 * NOT cryptographically secure. In production, use CSPRNG.
 * ========================================================================= */

static uint64_t lcg_state = 0xDEADBEEFCAFEBABEULL;

static uint32_t lcg_next(void) {
    lcg_state = lcg_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return (uint32_t)(lcg_state >> 32);
}

void bigint_rand_range(bigint_t *result, const bigint_t *max, uint32_t seed) {
    /* Generate a pseudo-random bigint in range [0, max-1].
     * Seed mixing ensures different seeds produce different sequences.
     * Complexity: O(nlimbs). */
    if (!result || !max || bigint_is_zero(max)) {
        if (result) bigint_set_zero(result);
        return;
    }

    lcg_state = 0xDEADBEEFCAFEBABEULL ^ ((uint64_t)seed << 32) ^ seed;
    for (int i = 0; i < 8; i++) lcg_next();

    uint32_t nlimbs = max->nlimbs;
    memset(result->limbs, 0, sizeof(result->limbs));
    for (uint32_t i = 0; i < nlimbs; i++) result->limbs[i] = lcg_next();
    result->nlimbs = nlimbs;
    bigint_normalize(result);

    if (bigint_compare(result, max) >= 0) {
        bigint_t q, r;
        bigint_divmod(&q, &r, result, max);
        bigint_copy(result, &r);
    }
}

void bigint_rand_odd(bigint_t *result, uint32_t nbits, uint32_t seed) {
    /* Generate a random odd bigint of exactly nbits bits.
     * Sets MSB for exact bit-length and LSB for oddness.
     * Complexity: O(nlimbs). */
    if (!result || nbits == 0) {
        if (result) bigint_set_zero(result);
        return;
    }

    uint32_t nlimbs = (nbits + 31) / 32;
    lcg_state = 0xDEADBEEFCAFEBABEULL ^ ((uint64_t)seed << 32) ^ (seed ^ 0xABCDEF01);
    for (int i = 0; i < 8; i++) lcg_next();

    for (uint32_t i = 0; i < nlimbs && i < BIGINT_MAX_LIMBS; i++)
        result->limbs[i] = lcg_next();
    result->nlimbs = nlimbs;

    uint32_t msb_limb = (nbits - 1) / 32;
    uint32_t msb_bit = (nbits - 1) % 32;
    result->limbs[msb_limb] |= (1U << msb_bit);
    result->limbs[0] |= 1;
    bigint_normalize(result);
}

/* =========================================================================
 * Chinese Remainder Theorem -- L3 Mathematical Structure
 *
 * CRT: For coprime m1,m2, x = a1 (mod m1), x = a2 (mod m2) has a
 * unique solution modulo M = m1*m2.
 *
 * This is the mathematical basis for CRT-accelerated RSA decryption
 * and for building TDP from simpler components.
 *
 * Reference: Gauss, Disquisitiones Arithmeticae (1801), Section 36.
 * ========================================================================= */

void crt_combine(bigint_t *result,
                  const bigint_t *a1, const bigint_t *m1,
                  const bigint_t *a2, const bigint_t *m2) {
    /* CRT combination using Gauss's algorithm:
     *   M = m1 * m2
     *   y1 = m2^{-1} mod m1,  y2 = m1^{-1} mod m2
     *   x = (a1*m2*y1 + a2*m1*y2) mod M
     *
     * Theorem (CRT): Z_M ~= Z_{m1} x Z_{m2} when gcd(m1,m2)=1.
     * The isomorphism is x |-> (x mod m1, x mod m2).
     *
     * Complexity: O(log^2(max(m1,m2))). */
    if (!result || !a1 || !m1 || !a2 || !m2) return;

    bigint_t y1, y2, M;
    mod_inverse(&y1, m2, m1);
    mod_inverse(&y2, m1, m2);
    bigint_mul(&M, m1, m2);

    bigint_t term1, term2, t1;
    mod_mul(&t1, a1, m2, &M); mod_mul(&term1, &t1, &y1, &M);
    mod_mul(&t1, a2, m1, &M); mod_mul(&term2, &t1, &y2, &M);

    mod_add(result, &term1, &term2, &M);
}

/* =========================================================================
 * Legendre and Jacobi Symbols -- L3 Number Theory
 *
 * Legendre symbol (a/p): quadratic residuosity modulo odd prime p.
 * Jacobi symbol (a/n): generalization to odd composite n.
 *
 * Used in Solovay-Strassen primality test, quadratic residuosity
 * assumption (Goldwasser-Micali PKE), and Rabin cryptosystem.
 *
 * Reference: Bach & Shallit, Algorithmic Number Theory (1996), Ch. 5
 * ========================================================================= */

int legendre_symbol(const bigint_t *a, const bigint_t *p) {
    /* Legendre symbol (a/p) for odd prime p.
     *
     * Returns: 1 if a is quadratic residue mod p
     *         -1 if a is quadratic non-residue
     *          0 if p divides a
     *
     * Euler's criterion: (a/p) = a^{(p-1)/2} mod p.
     *
     * Complexity: O(log^3 p). */
    if (!a || !p) return 0;

    bigint_t r, q;
    bigint_divmod(&q, &r, a, p);
    if (bigint_is_zero(&r)) return 0;

    bigint_t exp, pm1;
    bigint_copy(&pm1, p); bigint_dec(&pm1);
    bigint_copy(&exp, &pm1); bigint_shr(&exp, 1);

    bigint_t res;
    mod_exp(&res, a, &exp, p);

    bigint_t one;
    bigint_set_one(&one);

    if (bigint_is_one(&res)) return 1;
    if (bigint_compare(&res, &pm1) == 0) return -1;
    return 0;
}

int jacobi_symbol(const bigint_t *a, const bigint_t *n) {
    /* Jacobi symbol (a/n) for odd n > 0.
     *
     * Generalized from Legendre symbol. For prime n, equals Legendre.
     * For composite n = prod p_i^{e_i}: (a/n) = prod (a/p_i)^{e_i}.
     *
     * Properties:
     *   1. (0/n) = 0 if n > 1
     *   2. (2/n) = 1 if n = +/-1 (mod 8), -1 if n = +/-3 (mod 8)
     *   3. (ab/n) = (a/n)(b/n)
     *   4. Quadratic reciprocity: for odd a,n:
     *        (a/n) = (n/a) if a=1 or n=1 (mod 4), else -(n/a)
     *
     * Complexity: O(log^3 n).
     * Reference: Jacobi (1837). */
    if (!a || !n) return 0;

    bigint_t zero, one, two;
    bigint_set_zero(&zero); bigint_set_one(&one);
    bigint_set_one(&two); bigint_inc(&two);

    if (bigint_is_even(n) || bigint_compare(n, &zero) <= 0) return 0;
    if (bigint_is_zero(a)) return 0;

    bigint_t a_mod, q;
    bigint_divmod(&q, &a_mod, a, n);

    bigint_t g;
    bigint_gcd(&g, &a_mod, n);
    if (!bigint_is_one(&g)) return 0;

    int result = 1;
    bigint_t aa, nn;
    bigint_copy(&aa, &a_mod);
    bigint_copy(&nn, n);

    while (true) {
        if (bigint_is_zero(&aa)) return 0;
        if (bigint_is_one(&aa)) return result;

        uint32_t e2 = 0;
        while (bigint_is_even(&aa)) { bigint_shr(&aa, 1); e2++; }

        if (e2 % 2 == 1) {
            uint32_t nn_mod_8 = nn.limbs[0] & 7;
            if (nn_mod_8 == 3 || nn_mod_8 == 5) result = -result;
        }

        if (bigint_compare(&aa, &nn) >= 0) bigint_divmod(&q, &aa, &aa, &nn);

        if (bigint_is_one(&aa)) return result;
        if (bigint_is_zero(&aa)) return 0;

        if ((aa.limbs[0] & 3) == 3 && (nn.limbs[0] & 3) == 3) result = -result;

        bigint_t tmp = aa; aa = nn; nn = tmp;
    }
}

/* =========================================================================
 * Trial Division Sieve -- fast composite elimination
 *
 * Before running expensive Miller-Rabin, test divisibility by small
 * primes. ~90% of random odd composites have a factor < 256.
 * ========================================================================= */

bool trial_division_sieve(const bigint_t *n, uint32_t num_small) {
    /* Trial division of n by the first num_small primes.
     * Returns true if no small factor found.
     * Complexity: O(num_small * log n). */
    if (!n || bigint_is_zero(n)) return false;

    bigint_t two;
    bigint_set_one(&two); bigint_inc(&two);

    if (bigint_is_even(n) && bigint_compare(n, &two) != 0) return false;

    uint64_t n64 = bigint_to_uint64(n);

    for (uint32_t i = 1; i < num_small && i < NUM_SMALL_PRIMES; i++) {
        uint32_t sp = SMALL_PRIMES[i];
        if (n64 > 0 && n64 < 0x100000000ULL) {
            if (n64 % sp == 0 && n64 != sp) return false;
        } else {
            bigint_t p, q, r;
            p = bigint_from_uint64(sp);
            if (bigint_compare(&p, n) >= 0) break;
            bigint_divmod(&q, &r, n, &p);
            if (bigint_is_zero(&r)) return false;
        }
    }
    return true;
}

/* =========================================================================
 * High-level Primality API
 * ========================================================================= */

bool is_probable_prime(const bigint_t *n, uint32_t rounds) {
    /* Combined primality test:
     *   1. Quick checks (small n, even).
     *   2. Trial division sieve (fast elimination).
     *   3. Miller-Rabin test with specified rounds.
     *
     * Complexity: O(num_small * log n + rounds * log^3 n). */
    if (!n) return false;

    bigint_t two, three;
    bigint_set_one(&two); bigint_inc(&two);
    bigint_set_one(&three); bigint_inc(&three); bigint_inc(&three);

    if (bigint_compare(n, &two) == 0) return true;
    if (bigint_is_even(n)) return false;
    if (bigint_compare(n, &three) == 0) return true;

    if (!trial_division_sieve(n, 64)) return false;
    return miller_rabin_test(n, rounds);
}

bool generate_random_prime(bigint_t *p, uint32_t nbits, uint32_t seed) {
    /* Generate a random prime of exactly nbits bits using rejection sampling.
     *
     * Algorithm:
     *   1. Generate random odd nbits-bit number.
     *   2. Test with trial division + Miller-Rabin.
     *   3. If composite, increment by 2 and retry.
     *
     * Expected iterations: ~ln(2^{nbits})/2 ~= 0.35 * nbits.
     * For RSA-2048 (p=1024 bits): ~350 iterations average.
     *
     * Theorem (Prime Number Theorem): Pr[x is prime] ~= 1/ln(x).
     *
     * Complexity: Expected O(nbits * log^4 n).
     * Reference: Maurer (1995). */
    if (!p || nbits < 2) return false;

    bigint_rand_odd(p, nbits, seed);

    uint32_t max_iterations = nbits * 100;
    uint32_t iter = 0;
    bigint_t two;
    bigint_set_one(&two); bigint_inc(&two);

    while (!is_probable_prime(p, MILLER_RABIN_ROUNDS)) {
        bigint_add(p, p, &two);
        iter++;
        if (iter > max_iterations) return false;
        if (bigint_bit_length(p) > nbits) bigint_rand_odd(p, nbits, seed + iter);
    }
    return true;
}

/* =========================================================================
 * Print Functions -- for educational demonstration
 * ========================================================================= */

void bigint_print_hex(const char *label, const bigint_t *a) {
    if (!a) { printf("%s(null)\n", label ? label : ""); return; }
    printf("%s", label ? label : "");
    for (int i = (int)a->nlimbs - 1; i >= 0; i--) printf("%08x", a->limbs[i]);
    printf("\n");
}

void bigint_print_dec(const char *label, const bigint_t *a) {
    if (!a) { printf("%s(null)\n", label ? label : ""); return; }
    printf("%s", label ? label : "");

    bigint_t tmp;
    bigint_copy(&tmp, a);
    char digits[400];
    int pos = 0;
    bigint_t ten = bigint_from_uint64(10);

    if (bigint_is_zero(&tmp)) { printf("0\n"); return; }

    while (!bigint_is_zero(&tmp)) {
        bigint_t q, r;
        bigint_divmod(&q, &r, &tmp, &ten);
        digits[pos++] = '0' + (char)r.limbs[0];
        bigint_copy(&tmp, &q);
    }

    for (int i = pos - 1; i >= 0; i--) printf("%c", digits[i]);
    printf("\n");
}
