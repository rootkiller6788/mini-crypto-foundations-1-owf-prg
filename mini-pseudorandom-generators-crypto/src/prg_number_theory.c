/*
 * prg_number_theory.c -- Number Theory Implementations for Cryptographic PRGs
 *
 * L3 Mathematical Structures: modular arithmetic, Legendre/Jacobi symbols,
 * quadratic residues, Blum integers, cyclic groups, CRT.
 *
 * Each function implements a distinct number-theoretic concept that
 * underpins the security of cryptographic PRG constructions.
 *
 * Reference: Shoup "A Computational Introduction to Number Theory and Algebra"
 *            Menezes-van Oorschot-Vanstone "Handbook of Applied Cryptography"
 * Courses: MIT 6.875, Stanford CS255, Berkeley CS276, Princeton COS 551
 */
#include "prg_number_theory.h"
#include <string.h>
#include <stdlib.h>

/* ================================================================
 * Basic Modular Arithmetic (Z_n)
 * ================================================================ */

/* L3: Modular addition -- closure of Z_n under addition mod n. */
uint64_t mod_add(uint64_t a, uint64_t b, uint64_t n) {
    if (n == 0) return 0;
    a %= n; b %= n;
    if (a > UINT64_MAX - b) {
        uint64_t diff = n - a;
        return (b >= diff) ? b - diff : n - (diff - b);
    }
    uint64_t s = a + b;
    return (s >= n) ? s - n : s;
}

/* L3: Modular subtraction -- additive inverses in the ring Z_n */
uint64_t mod_sub(uint64_t a, uint64_t b, uint64_t n) {
    if (n == 0) return 0;
    a %= n; b %= n;
    return (a >= b) ? a - b : n - (b - a);
}

/* L3: Modular multiplication -- Russian peasant, overflow-safe */
uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t n) {
    if (n == 0) return 0;
    a %= n; b %= n;
    if (a == 0 || b == 0) return 0;
    uint64_t r = 0;
    while (b > 0) {
        if (b & 1) r = mod_add(r, a, n);
        a = mod_add(a, a, n);
        b >>= 1;
    }
    return r;
}

/* L3: Modular exponentiation by repeated squaring -- O(log e) multiplications */
uint64_t mod_pow(uint64_t a, uint64_t e, uint64_t n) {
    if (n == 0) return 0;
    if (n == 1) return 0;
    a %= n;
    uint64_t r = 1;
    while (e > 0) {
        if (e & 1) r = mod_mul(r, a, n);
        a = mod_mul(a, a, n);
        e >>= 1;
    }
    return r;
}

/* L3: Extended Euclidean Algorithm -- gcd(a,b) = a*x + b*y.
 * Foundation for computing modular inverses. */
uint64_t extended_gcd(uint64_t a, uint64_t b, int64_t* x, int64_t* y) {
    if (b == 0) { if (x) *x = 1; if (y) *y = 0; return a; }
    int64_t x1, y1;
    uint64_t d = extended_gcd(b, a % b, &x1, &y1);
    if (x) *x = y1;
    if (y) *y = x1 - y1 * (int64_t)(a / b);
    return d;
}

/* L3: Modular inverse -- a^{-1} mod n exists iff gcd(a,n)=1 */
uint64_t mod_inv(uint64_t a, uint64_t n) {
    if (n <= 1) return 0;
    a %= n;
    int64_t x, y;
    uint64_t g = extended_gcd(a, n, &x, &y);
    if (g != 1) return 0;
    int64_t result = x % (int64_t)n;
    return (uint64_t)(result < 0 ? result + (int64_t)n : result);
}

/* L3: Greatest Common Divisor */
uint64_t gcd(uint64_t a, uint64_t b) {
    while (b) { uint64_t t = b; b = a % b; a = t; }
    return a;
}

/* ================================================================
 * Legendre and Jacobi Symbols
 * ================================================================ */

/* L3: Legendre symbol (a/p) for odd prime p -- Euler criterion */
int legendre_symbol(uint64_t a, uint64_t p) {
    if (p < 2) return 0;
    a %= p;
    if (a == 0) return 0;
    uint64_t r = mod_pow(a, (p - 1) / 2, p);
    if (r == 1) return 1;
    if (r == p - 1) return -1;
    return 0;
}

/* L3: Jacobi symbol (a/n) for odd n -- computable without factorization.
 * The gap between (a/n)=1 and "a is QR mod n" is the QRP. */
int jacobi_symbol(uint64_t a, uint64_t n) {
    if (n == 0 || n % 2 == 0) return 0;
    a %= n;
    if (a == 0) return 0;
    int t = 1;
    while (a != 0) {
        while (a % 2 == 0) {
            a /= 2;
            uint64_t r = n % 8;
            if (r == 3 || r == 5) t = -t;
        }
        uint64_t tmp = a; a = n; n = tmp;
        if (a % 4 == 3 && n % 4 == 3) t = -t;
        a %= n;
    }
    return (n == 1) ? t : 0;
}

/* ================================================================
 * Quadratic Residues
 * ================================================================ */

int qr_test_prime(uint64_t a, uint64_t p) {
    return (legendre_symbol(a, p) == 1);
}

/* L3: Tonelli-Shanks -- sqrt(a) mod p. p=3 mod 4 case: a^{(p+1)/4} mod p */
uint64_t mod_sqrt_prime(uint64_t a, uint64_t p) {
    if (p == 2) return a % 2;
    a %= p;
    if (a == 0 || a == 1) return a;
    if (legendre_symbol(a, p) != 1) return 0;
    if (p % 4 == 3) return mod_pow(a, (p + 1) / 4, p);
    uint64_t Q = p - 1, S = 0;
    while (Q % 2 == 0) { Q /= 2; S++; }
    uint64_t z = 2;
    while (legendre_symbol(z, p) != -1) z++;
    uint64_t M = S, c = mod_pow(z, Q, p);
    uint64_t t = mod_pow(a, Q, p), R = mod_pow(a, (Q + 1) / 2, p);
    while (t != 1) {
        uint64_t i = 1, tmp = mod_mul(t, t, p);
        while (tmp != 1) { tmp = mod_mul(tmp, tmp, p); i++; }
        uint64_t b = c;
        for (uint64_t j = 0; j < M - i - 1; j++) b = mod_mul(b, b, p);
        M = i; c = mod_mul(b, b, p);
        t = mod_mul(t, c, p); R = mod_mul(R, b, p);
    }
    return R;
}

/* ================================================================
 * Primality Testing
 * ================================================================ */

/* L3: Trial division -- deterministic for n < 2^32 */
int is_prime_bruteforce(uint64_t n) {
    if (n < 2) return 0;
    if (n == 2) return 1;
    if (n % 2 == 0) return 0;
    for (uint64_t i = 3; i * i <= n; i += 2) if (n % i == 0) return 0;
    return 1;
}

/* L3: Miller-Rabin probabilistic test. Error < 4^{-k}. */
int miller_rabin(uint64_t n, int k) {
    if (n < 2) return 0;
    if (n == 2) return 1;
    if (n % 2 == 0) return 0;
    uint64_t d = n - 1, s = 0;
    while (d % 2 == 0) { d /= 2; s++; }
    for (int i = 0; i < k; i++) {
        int64_t range = (n > 4) ? (int64_t)(n - 4) : 1;
        uint64_t a = 2 + (uint64_t)(rand() % range);
        uint64_t x = mod_pow(a, d, n);
        if (x == 1 || x == n - 1) continue;
        int composite = 1;
        for (uint64_t r = 1; r < s; r++) {
            x = mod_mul(x, x, n);
            if (x == n - 1) { composite = 0; break; }
            if (x == 1) return 0;
        }
        if (composite) return 0;
    }
    return 1;
}

/* L3: Safe prime p = 2q+1 generation */
uint64_t safe_prime_generate(uint64_t lo, uint64_t hi) {
    if (lo % 2 == 0) lo++;
    while (lo <= hi) {
        if (is_prime_bruteforce(lo) && is_prime_bruteforce((lo - 1) / 2)) return lo;
        lo += 2;
    }
    return 0;
}

/* ================================================================
 * Blum Integers (n = p*q, p,q = 3 mod 4, distinct primes)
 * ================================================================ */

int blum_check(const BlumInteger* bi) {
    if (!bi) return 0;
    if (bi->p == bi->q || bi->n != bi->p * bi->q) return 0;
    if (!is_prime_bruteforce(bi->p) || !is_prime_bruteforce(bi->q)) return 0;
    return (bi->p % 4 == 3 && bi->q % 4 == 3);
}

BlumInteger blum_integer_generate(uint64_t lo, uint64_t hi) {
    BlumInteger bi = {0, 0, 0};
    uint64_t p = lo;
    while (p <= hi) { if (p % 4 == 3 && is_prime_bruteforce(p)) break; p++; }
    if (p > hi) return bi;
    uint64_t q = p + 1;
    while (q <= hi) { if (q % 4 == 3 && is_prime_bruteforce(q) && q != p) break; q++; }
    if (q > hi) return bi;
    bi.p = p; bi.q = q; bi.n = p * q;
    return bi;
}

/* ================================================================
 * Cyclic Groups and Generators
 * ================================================================ */

/* L3: Test if g generates Z_p^* */
int is_generator_mod_p(uint64_t g, uint64_t p) {
    if (p <= 1) return 0;
    g %= p; if (g == 0) return 0;
    uint64_t phi = p - 1, tmp = phi;
    for (uint64_t q = 2; q * q <= tmp; q++) {
        if (tmp % q == 0) {
            if (mod_pow(g, phi / q, p) == 1) return 0;
            while (tmp % q == 0) tmp /= q;
        }
    }
    if (tmp > 1 && mod_pow(g, phi / tmp, p) == 1) return 0;
    return 1;
}

uint64_t find_generator_mod_p(uint64_t p) {
    if (p <= 2) return 1;
    for (uint64_t g = 2; g < p; g++)
        if (is_generator_mod_p(g, p)) return g;
    return 0;
}

/* L3: Order of a in Z_n^* */
uint64_t element_order(uint64_t a, uint64_t n) {
    if (n <= 1) return 0;
    a %= n; if (gcd(a, n) != 1) return 0;
    uint64_t ord = 1, cur = a;
    while (cur != 1 && ord <= n) { cur = mod_mul(cur, a, n); ord++; }
    return (cur == 1) ? ord : 0;
}

/* L3: Euler totient phi(n) */
uint64_t euler_totient(uint64_t n) {
    if (n == 0) return 0;
    uint64_t r = n, t = n;
    for (uint64_t p = 2; p * p <= t; p++) {
        if (t % p == 0) {
            while (t % p == 0) t /= p;
            r = r / p * (p - 1);
        }
    }
    if (t > 1) r = r / t * (t - 1);
    return r;
}

/* ================================================================
 * Chinese Remainder Theorem (CRT)
 * ================================================================ */

CRTResult crt_solve(uint64_t a1, uint64_t n1, uint64_t a2, uint64_t n2) {
    CRTResult r = {n1, n2, a1 % n1, a2 % n2, 0};
    if (gcd(n1, n2) != 1) return r;
    uint64_t inv = mod_inv(n1, n2);
    if (inv == 0) return r;
    uint64_t diff = mod_sub(a2, a1, n2);
    uint64_t t = mod_mul(diff, inv, n2);
    r.solution = (a1 + n1 * t) % (n1 * n2);
    return r;
}

uint64_t crt_square(uint64_t x, uint64_t p, uint64_t q) {
    uint64_t xp2 = mod_mul(x % p, x % p, p);
    uint64_t xq2 = mod_mul(x % q, x % q, q);
    return crt_solve(xp2, p, xq2, q).solution;
}

/* ================================================================
 * Large Integer Helpers (128-bit intermediate)
 * ================================================================ */

uint64_t mul_hi64(uint64_t a, uint64_t b) {
#ifdef __SIZEOF_INT128__
    return (uint64_t)(((__uint128_t)a * (__uint128_t)b) >> 64);
#else
    uint64_t a32 = (uint32_t)a, ahi = a >> 32;
    uint64_t b32 = (uint32_t)b, bhi = b >> 32;
    uint64_t c1 = ahi * b32, c2 = a32 * bhi, lo = a32 * b32;
    uint64_t mid = (c1 & 0xFFFFFFFFULL) + (c2 & 0xFFFFFFFFULL) + (lo >> 32);
    return ahi * bhi + (c1 >> 32) + (c2 >> 32) + (mid >> 32);
#endif
}

uint64_t mul_mod64(uint64_t a, uint64_t b, uint64_t n) {
    if (n <= 1) return 0;
    a %= n; b %= n;
#ifdef __SIZEOF_INT128__
    return (uint64_t)(((__uint128_t)a * (__uint128_t)b) % (__uint128_t)n);
#else
    return mod_mul(a, b, n);
#endif
}

uint64_t pow_mod64(uint64_t base, uint64_t exp, uint64_t mod) {
    if (mod <= 1) return 0;
    base %= mod;
    uint64_t r = 1;
    while (exp > 0) {
        if (exp & 1) r = mul_mod64(r, base, mod);
        base = mul_mod64(base, base, mod);
        exp >>= 1;
    }
    return r;
}
