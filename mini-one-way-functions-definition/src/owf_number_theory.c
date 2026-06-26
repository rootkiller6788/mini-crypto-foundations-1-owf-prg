/*
 * owf_number_theory.c — Big Integer Arithmetic for OWF Constructions
 *
 * L3 Mathematical Structures:
 *   - Multi-precision natural numbers (big_nat_t)
 *   - Modular arithmetic (Z_n ring, Z_p field)
 *   - Group Z_p^* under multiplication
 *
 * L5 Algorithms:
 *   - Extended Euclidean Algorithm
 *   - Modular exponentiation (square-and-multiply)
 *   - Miller-Rabin primality test
 *   - Chinese Remainder Theorem
 *   - Legendre/Jacobi symbol computation
 *
 * Implementation uses base-10^9 representation for clarity.
 * Each "digit" is a uint32_t storing 0..999,999,999.
 *
 * Reference:
 *   Cormen-Leiserson-Rivest-Stein §31 (Number-Theoretic Algorithms)
 *   Menezes-van Oorschot-Vanstone (Handbook of Applied Cryptography)
 *   Rabin (1980) — Probabilistic algorithm for primality testing
 */

#include "owf_number_theory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

/* ================================================================
 * Big Natural Number Construction
 * ================================================================ */

big_nat_t big_nat_zero(void) {
    big_nat_t n;
    memset(&n, 0, sizeof(n));
    n.ndigits = 1;
    return n;
}

big_nat_t big_nat_from_uint64(uint64_t val) {
    big_nat_t n;
    memset(&n, 0, sizeof(n));

    if (val == 0) {
        n.ndigits = 1;
        return n;
    }

    int i = 0;
    while (val > 0) {
        n.digits[i++] = (uint32_t)(val % BIG_NAT_BASE);
        val /= BIG_NAT_BASE;
    }
    n.ndigits = i;
    return n;
}

big_nat_t big_nat_from_decimal(const char* dec_str) {
    big_nat_t result = big_nat_zero();

    if (!dec_str || *dec_str == '\0') return result;

    /* Process decimal string digit by digit: result = result * 10 + digit */
    for (const char* p = dec_str; *p; p++) {
        if (*p < '0' || *p > '9') continue;

        /* Multiply by 10 */
        uint64_t carry = (uint64_t)(*p - '0');
        for (int i = 0; i < result.ndigits; i++) {
            uint64_t prod = (uint64_t)result.digits[i] * 10 + carry;
            result.digits[i] = (uint32_t)(prod % BIG_NAT_BASE);
            carry = prod / BIG_NAT_BASE;
        }
        /* Propagate carry to new digits */
        while (carry > 0 && result.ndigits < BIG_NAT_MAX_DIGITS) {
            result.digits[result.ndigits++] = (uint32_t)(carry % BIG_NAT_BASE);
            carry /= BIG_NAT_BASE;
        }
    }

    if (result.ndigits == 0) result.ndigits = 1;
    return result;
}

big_nat_t big_nat_random_bits(size_t nbits) {
    big_nat_t n = big_nat_zero();

    /* Generate nbits random bits, stored base-2^32 then convert */
    size_t nwords = (nbits + 31) / 32;
    uint32_t* words = (uint32_t*)calloc(nwords, sizeof(uint32_t));
    if (!words) return n;

    for (size_t i = 0; i < nwords; i++) {
        words[i] = ((uint32_t)rand() << 16) | ((uint32_t)rand() & 0xFFFF);
    }

    /* Mask the top word to exact bit length */
    size_t excess = nwords * 32 - nbits;
    if (excess > 0) {
        words[nwords - 1] &= (uint32_t)(0xFFFFFFFF >> excess);
    }

    /* Set highest bit to ensure nbits length */
    size_t high_bit_word = (nbits - 1) / 32;
    size_t high_bit_pos = (nbits - 1) % 32;
    words[high_bit_word] |= (1u << high_bit_pos);

    /* Convert from base-2^32 to base-10^9 */
    big_nat_t base = big_nat_from_uint64(1ULL << 32);
    for (size_t i = nwords; i > 0; i--) {
        /* n = n * 2^32 + words[i-1] */
        big_nat_t addend = big_nat_from_uint64(words[i - 1]);
        big_nat_t prod = big_nat_mul(&n, &base);
        n = big_nat_add(&prod, &addend);
    }

    if (n.ndigits == 0) n.ndigits = 1;

    /* Ensure odd (for prime generation) */
    n.digits[0] |= 1;

    free(words);
    return n;
}

/* ================================================================
 * Big Natural Number Comparison
 * ================================================================ */

int big_nat_is_zero(const big_nat_t* a) {
    return a->ndigits == 1 && a->digits[0] == 0;
}

int big_nat_is_one(const big_nat_t* a) {
    return a->ndigits == 1 && a->digits[0] == 1;
}

int big_nat_is_even(const big_nat_t* a) {
    return (a->digits[0] & 1) == 0;
}

int big_nat_compare(const big_nat_t* a, const big_nat_t* b) {
    if (a->ndigits != b->ndigits) {
        return a->ndigits > b->ndigits ? 1 : -1;
    }
    for (int i = a->ndigits - 1; i >= 0; i--) {
        if (a->digits[i] != b->digits[i]) {
            return a->digits[i] > b->digits[i] ? 1 : -1;
        }
    }
    return 0;
}

int big_nat_equal(const big_nat_t* a, const big_nat_t* b) {
    return big_nat_compare(a, b) == 0;
}

/* ================================================================
 * Big Natural Number Addition & Subtraction
 * ================================================================ */

big_nat_t big_nat_add(const big_nat_t* a, const big_nat_t* b) {
    big_nat_t result;
    memset(&result, 0, sizeof(result));

    int max_digits = a->ndigits > b->ndigits ? a->ndigits : b->ndigits;
    uint64_t carry = 0;

    for (int i = 0; i < max_digits; i++) {
        uint64_t sum = carry;
        if (i < a->ndigits) sum += a->digits[i];
        if (i < b->ndigits) sum += b->digits[i];
        result.digits[i] = (uint32_t)(sum % BIG_NAT_BASE);
        carry = sum / BIG_NAT_BASE;
    }

    if (carry > 0 && max_digits < BIG_NAT_MAX_DIGITS) {
        result.digits[max_digits++] = (uint32_t)carry;
    }

    result.ndigits = max_digits;
    if (result.ndigits == 0) result.ndigits = 1;

    /* Remove leading zeros */
    while (result.ndigits > 1 && result.digits[result.ndigits - 1] == 0) {
        result.ndigits--;
    }

    return result;
}

big_nat_t big_nat_sub(const big_nat_t* a, const big_nat_t* b) {
    big_nat_t result;
    memset(&result, 0, sizeof(result));

    /* Assumes a >= b */
    if (big_nat_compare(a, b) < 0) {
        result.ndigits = 1;
        return result; /* return 0 for underflow */
    }

    int64_t borrow = 0;
    for (int i = 0; i < a->ndigits; i++) {
        int64_t diff = (int64_t)a->digits[i] - borrow;
        if (i < b->ndigits) diff -= (int64_t)b->digits[i];

        if (diff < 0) {
            diff += BIG_NAT_BASE;
            borrow = 1;
        } else {
            borrow = 0;
        }
        result.digits[i] = (uint32_t)diff;
    }

    result.ndigits = a->ndigits;
    while (result.ndigits > 1 && result.digits[result.ndigits - 1] == 0) {
        result.ndigits--;
    }

    return result;
}

/* ================================================================
 * Big Natural Number Multiplication
 * ================================================================ */

big_nat_t big_nat_mul(const big_nat_t* a, const big_nat_t* b) {
    big_nat_t result = big_nat_zero();

    if (big_nat_is_zero(a) || big_nat_is_zero(b)) return result;

    int max_digits = a->ndigits + b->ndigits;
    uint64_t* temp = (uint64_t*)calloc(max_digits, sizeof(uint64_t));
    if (!temp) return result;

    /* Schoolbook multiplication */
    for (int i = 0; i < a->ndigits; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < b->ndigits; j++) {
            uint64_t prod = (uint64_t)a->digits[i] * (uint64_t)b->digits[j]
                          + temp[i + j] + carry;
            temp[i + j] = prod % BIG_NAT_BASE;
            carry = prod / BIG_NAT_BASE;
        }
        if (carry > 0) {
            temp[i + b->ndigits] += carry;
        }
    }

    /* Normalize */
    int nd = max_digits;
    while (nd > 1 && temp[nd - 1] == 0) nd--;

    for (int i = 0; i < nd && i < BIG_NAT_MAX_DIGITS; i++) {
        result.digits[i] = (uint32_t)temp[i];
    }
    result.ndigits = nd > 0 ? nd : 1;

    free(temp);
    return result;
}

/* ================================================================
 * Division: a = b * q + r, 0 ≤ r < b
 * ================================================================ */

void big_nat_divmod(const big_nat_t* a, const big_nat_t* b,
                    big_nat_t* q, big_nat_t* r) {
    *q = big_nat_zero();
    *r = big_nat_zero();

    if (big_nat_is_zero(b)) return; /* division by zero → q=0, r=0 */
    if (big_nat_compare(a, b) < 0) {
        *r = *a;
        return;
    }

    /* Long division: base BIG_NAT_BASE */
    big_nat_t rem = big_nat_zero();
    uint64_t* q_digits = (uint64_t*)calloc((size_t)(a->ndigits > 0 ? a->ndigits : 1), sizeof(uint64_t));
    int q_nd = 0;

    for (int i = a->ndigits - 1; i >= 0; i--) {
        /* Bring down next digit: rem = rem * BASE + a->digits[i] */
        big_nat_t rem_scaled;
        if (!big_nat_is_zero(&rem)) {
            big_nat_t base_n = big_nat_from_uint64(BIG_NAT_BASE);
            rem_scaled = big_nat_mul(&rem, &base_n);
        } else {
            rem_scaled = big_nat_zero();
        }
        big_nat_t digit_n = big_nat_from_uint64(a->digits[i]);
        rem = big_nat_add(&rem_scaled, &digit_n);

        /* Find quotient digit by binary search */
        uint64_t low = 0, high = BIG_NAT_BASE - 1, qd = 0;
        while (low <= high) {
            uint64_t mid = low + (high - low) / 2;
            big_nat_t mid_n = big_nat_from_uint64(mid);
            big_nat_t prod = big_nat_mul(b, &mid_n);
            if (big_nat_compare(&prod, &rem) <= 0) {
                qd = mid;
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }

        q_digits[q_nd++] = qd;

        /* Subtract: rem = rem - b * qd */
        big_nat_t qd_n = big_nat_from_uint64(qd);
        big_nat_t prod = big_nat_mul(b, &qd_n);
        rem = big_nat_sub(&rem, &prod);
    }

    /* Build quotient from digits (reversed order) */
    big_nat_t quotient = big_nat_zero();
    for (int i = q_nd - 1; i >= 0; i--) {
        big_nat_t scaled = big_nat_from_uint64(BIG_NAT_BASE);
        big_nat_t prod = big_nat_mul(&quotient, &scaled);
        big_nat_t digit_n = big_nat_from_uint64(q_digits[i]);
        quotient = big_nat_add(&prod, &digit_n);
    }

    /* Remove leading zeros */
    while (quotient.ndigits > 1 && quotient.digits[quotient.ndigits - 1] == 0) {
        quotient.ndigits--;
    }

    *q = quotient;
    *r = rem;

    free(q_digits);
}

big_nat_t big_nat_mod(const big_nat_t* a, const big_nat_t* m) {
    big_nat_t q, r;
    big_nat_divmod(a, m, &q, &r);
    return r;
}

/* ================================================================
 * Greatest Common Divisor (Euclidean Algorithm)
 * ================================================================ */

big_nat_t big_nat_gcd(const big_nat_t* a, const big_nat_t* b) {
    big_nat_t x = *a, y = *b;

    while (!big_nat_is_zero(&y)) {
        big_nat_t q, r;
        big_nat_divmod(&x, &y, &q, &r);
        x = y;
        y = r;
    }
    return x;
}

/* ================================================================
 * Extended Euclidean Algorithm: a·s + b·t = gcd(a,b)
 *
 * L5: This algorithm is fundamental to modular inversion,
 * RSA key generation (computing d from e, φ(N)), and CRT.
 * ================================================================ */

void big_nat_egcd(const big_nat_t* a, const big_nat_t* b,
                  big_nat_t* gcd_out, big_nat_t* s_out, big_nat_t* t_out) {
    big_nat_t one  = big_nat_from_uint64(1);

    big_nat_t zero = big_nat_zero();
    if (big_nat_is_zero(b)) {
        *gcd_out = *a;
        *s_out   = one;
        *t_out   = zero;
        return;
    }

    big_nat_t q, r;
    big_nat_divmod(a, b, &q, &r);

    big_nat_t s_sub, t_sub;
    big_nat_egcd(b, &r, gcd_out, &s_sub, &t_sub);

    /* s = t_sub,  t = s_sub - q * t_sub */
    *s_out = t_sub;
    big_nat_t prod = big_nat_mul(&q, &t_sub);
    *t_out = big_nat_sub(&s_sub, &prod);
}

/* ================================================================
 * Modular Inverse: a^{-1} mod m
 *
 * Requires gcd(a, m) = 1. Returns 0 if no inverse exists.
 * ================================================================ */

big_nat_t big_nat_modinv(const big_nat_t* a, const big_nat_t* m) {
    big_nat_t gcd, s, t;
    big_nat_egcd(a, m, &gcd, &s, &t);

    if (!big_nat_is_one(&gcd)) {
        return big_nat_zero(); /* no inverse exists */
    }

    /* Ensure s is positive: s mod m */
    big_nat_t zero_tmp = big_nat_zero();
    if (big_nat_compare(&s, &zero_tmp) < 0) {
        big_nat_t tmp = big_nat_add(&s, m);
        s = tmp;
    }

    big_nat_t result = big_nat_mod(&s, m);
    return result;
}

/* ================================================================
 * Modular Exponentiation: base^exp mod m
 *
 * L5: Square-and-multiply algorithm.
 * Complexity: O(log exp) modular multiplications.
 *
 * This is the core operation underlying RSA, Diffie-Hellman,
 * and most number-theoretic OWF candidates.
 * ================================================================ */

big_nat_t big_nat_modpow(const big_nat_t* base, const big_nat_t* exp,
                         const big_nat_t* m) {
    big_nat_t result = big_nat_from_uint64(1);
    big_nat_t b      = big_nat_mod(base, m);
    big_nat_t e      = *exp;
    /* zero not used directly */
    /* one not used directly */
    big_nat_t two    = big_nat_from_uint64(2);

    while (!big_nat_is_zero(&e)) {
        if (!big_nat_is_even(&e)) {
            /* result = (result * b) mod m */
            big_nat_t prod = big_nat_mul(&result, &b);
            result = big_nat_mod(&prod, m);
        }

        /* e = e / 2 */
        big_nat_t q, r;
        big_nat_divmod(&e, &two, &q, &r);
        e = q;

        /* b = (b * b) mod m */
        big_nat_t sq = big_nat_mul(&b, &b);
        b = big_nat_mod(&sq, m);
    }

    return result;
}

/* ================================================================
 * Bit String ⇔ Big Natural Conversion
 * ================================================================ */

big_nat_t big_nat_from_bit_string(const bit_string_t* bs) {
    big_nat_t result = big_nat_zero();
    if (!bs || bs->bit_len == 0) return result;

    /* Build from bytes, big-endian */
    big_nat_t base256 = big_nat_from_uint64(256);
    for (size_t i = 0; i < bs->byte_cap; i++) {
        big_nat_t scaled = big_nat_mul(&result, &base256);
        big_nat_t byte_n = big_nat_from_uint64(bs->data[i]);
        result = big_nat_add(&scaled, &byte_n);
    }
    return result;
}

bit_string_t* big_nat_to_bit_string(const big_nat_t* n, size_t pad_bits) {
    if (!n) return NULL;

    /* Determine byte length needed */
    big_nat_t base256 = big_nat_from_uint64(256);
    big_nat_t tmp = *n;
    size_t byte_len = 0;

    while (!big_nat_is_zero(&tmp) && byte_len < OWF_MAX_OUTPUT_BYTES) {
        big_nat_t q, r;
        big_nat_divmod(&tmp, &base256, &q, &r);
        tmp = q;
        byte_len++;
    }

    if (byte_len == 0) byte_len = 1;

    /* Pad to requested length */
    size_t pad_bytes = (pad_bits + 7) / 8;
    if (byte_len < pad_bytes) byte_len = pad_bytes;

    bit_string_t* bs = bs_create(byte_len * 8);
    if (!bs) return NULL;

    /* Fill bytes big-endian */
    tmp = *n;
    size_t idx = byte_len;
    while (idx > 0) {
        big_nat_t q, r;
        big_nat_divmod(&tmp, &base256, &q, &r);
        idx--;
        if (idx < bs->byte_cap) {
            bs->data[idx] = (uint8_t)(r.digits[0] & 0xFF);
        }
        tmp = q;
    }

    return bs;
}

/* ================================================================
 * Big Natural Number Display
 * ================================================================ */

void big_nat_print(const big_nat_t* a, const char* label) {
    if (label) printf("%s", label);
    if (a->ndigits <= 1 && a->digits[0] == 0) {
        printf("0\n");
        return;
    }

    /* Print most significant digits */
    for (int i = a->ndigits - 1; i >= 0; i--) {
        if (i == a->ndigits - 1) {
            printf("%u", a->digits[i]);
        } else {
            printf("%09u", a->digits[i]);
        }
    }
    printf("\n");
}

void big_nat_print_hex(const big_nat_t* a, const char* label) {
    if (label) printf("%s", label);

    /* Convert to byte array for hex printing */
    big_nat_t base256 = big_nat_from_uint64(256);
    uint8_t bytes[256];
    int nbytes = 0;
    big_nat_t tmp = *a;

    while (!big_nat_is_zero(&tmp) && nbytes < 256) {
        big_nat_t q, r;
        big_nat_divmod(&tmp, &base256, &q, &r);
        bytes[nbytes++] = (uint8_t)(r.digits[0] & 0xFF);
        tmp = q;
    }

    if (nbytes == 0) {
        printf("00\n");
        return;
    }

    for (int i = nbytes - 1; i >= 0; i--) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

/* ================================================================
 * Miller-Rabin Primality Test
 *
 * L5: Probabilistic primality test.
 *
 * Write n-1 = 2^s * d where d is odd.
 * For random base a ∈ [2, n-2]:
 *   Compute x = a^d mod n
 *   If x = 1 or x = n-1: probably prime for this base
 *   For r = 1..s-1:
 *     x = x^2 mod n
 *     If x = n-1: probably prime for this base
 *     If x = 1: composite
 *   Composite
 *
 * Rabin (1980): If n is composite, ≥ 3/4 of bases are witnesses.
 * k iterations → error probability < (1/4)^k
 * ================================================================ */

int mr_test_single(const big_nat_t* n, const big_nat_t* a) {
    big_nat_t one  = big_nat_from_uint64(1);
    big_nat_t two  = big_nat_from_uint64(2);

    if (big_nat_is_even(n)) return 0;  /* even → composite */
    if (big_nat_compare(n, &two) <= 0) return 1;  /* 2 is prime */

    /* Check if a is out of range [2, n-2] */
    big_nat_t n_minus_2 = big_nat_sub(n, &two);
    if (big_nat_compare(a, &one) <= 0 || big_nat_compare(a, &n_minus_2) >= 0) {
        return 1; /* skip invalid base */
    }

    /* Write n-1 = 2^s * d */
    big_nat_t n_minus_1 = big_nat_sub(n, &one);
    int s = 0;
    big_nat_t d = n_minus_1;
    while (big_nat_is_even(&d)) {
        big_nat_t q, r;
        big_nat_divmod(&d, &two, &q, &r);
        d = q;
        s++;
    }

    /* x = a^d mod n */
    big_nat_t x = big_nat_modpow(a, &d, n);

    if (big_nat_equal(&x, &one) || big_nat_equal(&x, &n_minus_1)) {
        return 1; /* probably prime for this base */
    }

    for (int r = 1; r < s; r++) {
        big_nat_t sq = big_nat_mul(&x, &x);
        x = big_nat_mod(&sq, n);

        if (big_nat_equal(&x, &one)) {
            return 0; /* composite: nontrivial square root of 1 */
        }
        if (big_nat_equal(&x, &n_minus_1)) {
            return 1; /* probably prime for this base */
        }
    }

    return 0; /* composite (base a is a witness) */
}

int mr_test(const big_nat_t* n, int k_rounds) {
    big_nat_t one = big_nat_from_uint64(1);
    big_nat_t two = big_nat_from_uint64(2);

    if (big_nat_compare(n, &two) < 0) return 0; /* n < 2: not prime */
    if (big_nat_equal(n, &two)) return 1;       /* 2 is prime */
    if (big_nat_is_even(n)) return 0;           /* even > 2: composite */

    /* Small prime divisibility check for efficiency */
    uint64_t small_primes[] = {3, 5, 7, 11, 13, 17, 19, 23, 29, 31};
    for (int i = 0; i < 10; i++) {
        big_nat_t sp = big_nat_from_uint64(small_primes[i]);
        if (big_nat_equal(n, &sp)) return 1;  /* n is a small prime */
        big_nat_t q, r;
        big_nat_divmod(n, &sp, &q, &r);
        if (big_nat_is_zero(&r)) return 0;   /* divisible by small prime */
    }

    /* Miller-Rabin with random bases */
    for (int i = 0; i < k_rounds; i++) {
        /* Select random base a ∈ [2, n-2] */
        big_nat_t range = big_nat_sub(n, &two);
        big_nat_t a;

        /* Simple random base generation for our base-10^9 representation */
        a = big_nat_zero();
        a.ndigits = range.ndigits;
        for (int j = 0; j < range.ndigits; j++) {
            a.digits[j] = (uint32_t)(((uint64_t)rand() * BIG_NAT_BASE) / RAND_MAX);
            if (a.digits[j] >= BIG_NAT_BASE) a.digits[j] = BIG_NAT_BASE - 1;
        }
        /* Ensure a >= 2 */
        a.digits[0] |= 2;
        /* Remove leading zeros */
        while (a.ndigits > 1 && a.digits[a.ndigits - 1] == 0) a.ndigits--;

        if (big_nat_compare(&a, &range) >= 0) {
            a = big_nat_sub(&range, &one);
        }

        if (!mr_test_single(n, &a)) return 0;
    }

    return 1; /* probably prime */
}

int big_nat_is_composite_brute(const big_nat_t* n, big_nat_t* factor) {
    if (big_nat_is_even(n)) {
        *factor = big_nat_from_uint64(2);
        return 1;
    }

    /* Trial division up to sqrt(n) — expensive for large n */
    big_nat_t i = big_nat_from_uint64(3);
    /* limit determined by trial bound */
    /* Using a simple bound: limit = min(sqrt(n), 1000000) */
    big_nat_t max_trial = big_nat_from_uint64(1000000);
    if (big_nat_compare(&max_trial, n) > 0) {
        max_trial = *n;
    }

    big_nat_t two = big_nat_from_uint64(2);
    while (big_nat_compare(&i, &max_trial) < 0) {
        big_nat_t q, r;
        big_nat_divmod(n, &i, &q, &r);
        if (big_nat_is_zero(&r)) {
            *factor = i;
            return 1;
        }
        /* i += 2 */
        i = big_nat_add(&i, &two);

        /* Safety: check if i^2 > n */
        big_nat_t i_sq = big_nat_mul(&i, &i);
        if (big_nat_compare(&i_sq, n) > 0) break;
    }

    return 0;
}

/* ================================================================
 * Prime Generation
 *
 * L5: Generate random n-bit prime using random search + Miller-Rabin.
 *
 * By the Prime Number Theorem, density of primes near 2^n is
 * approximately 1/(n·ln 2) ≈ 1.44/n.
 * Expected trials to find a prime: ~n·ln 2 ≈ 0.693n.
 * ================================================================ */

big_nat_t generate_random_prime(size_t nbits, int k_rounds, uint64_t* attempts) {
    uint64_t count = 0;
    big_nat_t candidate;

    while (1) {
        candidate = big_nat_random_bits(nbits);
        /* Ensure odd */
        candidate.digits[0] |= 1;
        /* Ensure high bit is set (for n-bit length) */
        /* Already handled in big_nat_random_bits */

        count++;

        if (mr_test(&candidate, k_rounds)) {
            if (attempts) *attempts = count;
            return candidate;
        }

        if (count > 10000) {
            /* Safety limit */
            if (attempts) *attempts = count;
            return candidate; /* return whatever we have */
        }
    }
}

big_nat_t generate_safe_prime(size_t nbits, int k_rounds,
                              uint64_t* attempts, big_nat_t* q_out) {
    uint64_t count = 0;
    big_nat_t one = big_nat_from_uint64(1);
    big_nat_t two = big_nat_from_uint64(2);
    big_nat_t p, q;

    while (1) {
        /* Generate Sophie Germain prime q (prime where 2q+1 is also prime) */
        q = generate_random_prime(nbits - 1, k_rounds / 2, NULL);
        big_nat_t prod = big_nat_mul(&q, &two);
        p = big_nat_add(&prod, &one);

        count++;

        if (mr_test(&p, k_rounds)) {
            if (attempts) *attempts = count;
            if (q_out) *q_out = q;
            return p;
        }

        if (count > 5000) break;
    }

    if (attempts) *attempts = count;
    return p;
}

/* ================================================================
 * Chinese Remainder Theorem
 *
 * L5: CRT reconstructs x mod M (M = ∏ m_i) from residues x ≡ a_i (mod m_i).
 *
 * Standard formula: x = Σ a_i · M_i · inv(M_i mod m_i)  mod M
 * where M_i = M / m_i.
 * ================================================================ */

big_nat_t crt_solve(const big_nat_t* residues, const big_nat_t* moduli, int k) {
    if (k <= 0) return big_nat_zero();

    /* Compute M = ∏ m_i */
    big_nat_t M = big_nat_from_uint64(1);
    for (int i = 0; i < k; i++) {
        M = big_nat_mul(&M, &moduli[i]);
    }

    /* Compute x = Σ a_i * M_i * inv(M_i mod m_i) mod M */
    big_nat_t x = big_nat_zero();
    for (int i = 0; i < k; i++) {
        big_nat_t q, r;
        big_nat_divmod(&M, &moduli[i], &q, &r);  /* q = M_i = M / m_i */
        big_nat_t M_i = q;
        big_nat_t inv = big_nat_modinv(&M_i, &moduli[i]);

        /* term = a_i * M_i * inv */
        big_nat_t term = big_nat_mul(&residues[i], &M_i);
        term = big_nat_mul(&term, &inv);
        term = big_nat_mod(&term, &M);

        x = big_nat_add(&x, &term);
        x = big_nat_mod(&x, &M);
    }

    return x;
}

big_nat_t crt_garner(const big_nat_t* residues, const big_nat_t* moduli, int k) {
    /* Garner's algorithm: iterative CRT reconstruction.
     * More efficient than direct formula for many moduli.
     * Uses mixed-radix representation. */

    if (k <= 0) return big_nat_zero();

    /* Precompute inverses: c_{i,j} = inv(m_i mod m_j) */
    big_nat_t* mixed_radix = (big_nat_t*)calloc(k, sizeof(big_nat_t));
    if (!mixed_radix) return crt_solve(residues, moduli, k);

    mixed_radix[0] = residues[0];

    for (int i = 1; i < k; i++) {
        /* v_i = a_i */
        big_nat_t v = residues[i];

        for (int j = 0; j < i; j++) {
            /* v = (v - mixed_radix[j]) * inv(m_j mod m_i) mod m_i */
            big_nat_t diff = big_nat_sub(&v, &mixed_radix[j]);
            big_nat_t inv = big_nat_modinv(&moduli[j], &moduli[i]);
            big_nat_t prod = big_nat_mul(&diff, &inv);
            big_nat_t tmp = big_nat_mod(&prod, &moduli[i]);

            /* Ensure non-negative */
            big_nat_t ztmp = big_nat_zero();
            if (big_nat_compare(&tmp, &ztmp) < 0) {
                tmp = big_nat_add(&tmp, &moduli[i]);
            }
            v = big_nat_mod(&tmp, &moduli[i]);
        }
        mixed_radix[i] = v;
    }

    /* Reconstruct x from mixed-radix representation */
    big_nat_t x = big_nat_zero();
    big_nat_t prod = big_nat_from_uint64(1);

    for (int i = 0; i < k; i++) {
        big_nat_t term = big_nat_mul(&mixed_radix[i], &prod);
        x = big_nat_add(&x, &term);
        if (i + 1 < k) {
            prod = big_nat_mul(&prod, &moduli[i]);
        }
    }

    free(mixed_radix);
    return x;
}

/* ================================================================
 * Legendre & Jacobi Symbols
 *
 * L3: Legendre symbol (a/p) indicates quadratic residuosity mod prime p.
 * Jacobi symbol generalizes to composite modulus.
 *
 * Computing these uses quadratic reciprocity, a deep theorem in
 * number theory (Gauss's theorema aureum).
 * ================================================================ */

int legendre_symbol(const big_nat_t* a, const big_nat_t* p) {
    /* For odd prime p: (a/p) = a^{(p-1)/2} mod p
     * Result: 0 if p|a, 1 if quadratic residue, p-1 (= -1) if non-residue */

    big_nat_t one  = big_nat_from_uint64(1);
    big_nat_t two  = big_nat_from_uint64(2);

    /* Check if p divides a */
    big_nat_t q, rem;
    big_nat_divmod(a, p, &q, &rem);
    if (big_nat_is_zero(&rem)) return 0;

    /* exponent = (p-1)/2 */
    big_nat_t p_minus_1 = big_nat_sub(p, &one);
    big_nat_t exp;
    big_nat_divmod(&p_minus_1, &two, &exp, &rem);

    big_nat_t result = big_nat_modpow(a, &exp, p);

    /* If result == 1: residue, if result == p-1: non-residue */
    if (big_nat_equal(&result, &one)) return 1;
    return -1;
}

int jacobi_symbol(const big_nat_t* a, const big_nat_t* n) {
    /* Jacobi symbol (a/n) computed using the law of quadratic reciprocity.
     *
     * Algorithm:
     *   1. Reduce a mod n
     *   2. Factor out powers of 2: (2/n) = (-1)^{(n^2-1)/8}
     *   3. If a=1: return 1
     *   4. Apply quadratic reciprocity: (a/n) = (n/a) * (-1)^{(a-1)(n-1)/4}
     *   5. Recurse
     */

    big_nat_t one   = big_nat_from_uint64(1);
    big_nat_t two   = big_nat_from_uint64(2);
    big_nat_t eight = big_nat_from_uint64(8);
    big_nat_t four  = big_nat_from_uint64(4);

    big_nat_t A = big_nat_mod(a, n);
    big_nat_t N = *n;

    int result = 1;

    while (big_nat_compare(&A, &one) > 0) {
        /* Factor out 2 from A */
        int e = 0;
        while (big_nat_is_even(&A)) {
            big_nat_t q, r;
            big_nat_divmod(&A, &two, &q, &r);
            A = q;
            e++;
        }

        if (e % 2 == 1) {
            /* (2/N) = (-1)^{(N^2-1)/8} */
            big_nat_t N_sq = big_nat_mul(&N, &N);
            big_nat_t N_sq_minus_1 = big_nat_sub(&N_sq, &one);
            big_nat_t q, r;
            big_nat_divmod(&N_sq_minus_1, &eight, &q, &r);
            if (!big_nat_is_even(&q)) {
                result = -result;
            }
        }

        /* Quadratic reciprocity */
        big_nat_t A_minus_1 = big_nat_sub(&A, &one);
        big_nat_t N_minus_1 = big_nat_sub(&N, &one);

        big_nat_t prod = big_nat_mul(&A_minus_1, &N_minus_1);
        big_nat_t q, r;
        big_nat_divmod(&prod, &four, &q, &r);
        if (!big_nat_is_even(&q)) {
            result = -result;
        }

        /* Swap: (A/N) → (N mod A / A) */
        big_nat_t tmp = A;
        A = big_nat_mod(&N, &tmp);
        N = tmp;
    }

    if (big_nat_is_zero(&A)) {
        return 0;
    }

    return result;
}
