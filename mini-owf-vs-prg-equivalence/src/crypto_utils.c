/*
 * crypto_utils.c — Cryptographic Utility Implementations
 *
 * Implements:
 *   - GF(2) vector/linear algebra operations (L3)
 *   - Modular exponentiation and arithmetic (L3)
 *   - Extended Euclidean algorithm and modular inverse (L3)
 *   - Miller-Rabin primality testing (L3)
 *   - Generator verification for Z_p^* (L3)
 *   - Random prime generation (L3)
 *   - Blum integer verification (L3)
 *   - Linear congruential generator (LCG) for tests (L3)
 *   - BitString extended operations: concat, XOR, slice, split (L3)
 *   - Hex conversion (L3)
 *   - FNV hash, key derivation, time-based key gen (L7)
 *
 * Reference:
 *   Menezes, van Oorschot, Vanstone (1996) — Handbook of Applied Cryptography
 *   Goldreich (2001) — Foundations of Cryptography, Vol 1, App A
 *   Rabin (1980) — Probabilistic Algorithm for Testing Primality
 *   Miller (1976) — Riemann's Hypothesis and Tests for Primality
 *
 * Courses: MIT 6.875, Stanford CS255, Princeton COS 522
 */

#include "crypto_utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>

/* ================================================================
 * L3: GF(2) Vector Operations
 * ================================================================
 * The field GF(2) = {0, 1} with:
 *   Addition = XOR
 *   Multiplication = AND
 * Vectors are bit strings.
 *
 * These are fundamental for all of cryptography:
 *   - Goldreich-Levin hardcore bit: inner product <x, r>
 *   - Pairwise independent hashing: Ax + b
 *   - Stream ciphers: keystream XOR plaintext
 *   - LFSRs and linear cryptanalysis
 */

void gf2_add(const BitString *a, const BitString *b, BitString *out) {
    if (!a || !b || !out) return;
    assert(a->bit_len == b->bit_len);
    size_t byte_len = (a->bit_len + 7) / 8;
    for (size_t i = 0; i < byte_len; i++) {
        out->data[i] = a->data[i] ^ b->data[i];
    }
    out->bit_len = a->bit_len;
}

void gf2_scalar_mul(int c, const BitString *v, BitString *out) {
    if (!v || !out) return;
    /* In GF(2), scalar mult is AND with c ∈ {0,1} */
    if (c) {
        size_t byte_len = (v->bit_len + 7) / 8;
        memcpy(out->data, v->data, byte_len);
    } else {
        size_t byte_len = (v->bit_len + 7) / 8;
        memset(out->data, 0, byte_len);
    }
    out->bit_len = v->bit_len;
}

int gf2_dot_product(const BitString *a, const BitString *b) {
    if (!a || !b) return 0;
    assert(a->bit_len == b->bit_len);
    /*
     * <a, b> = sum_{i=0}^{n-1} a_i * b_i mod 2
     * This is the Goldreich-Levin hardcore predicate:
     * Given f(x), it's hard to predict <x, r> better than 1/2.
     */
    int sum = 0;
    for (size_t i = 0; i < a->bit_len; i++) {
        sum ^= (bitstring_get_bit(a, i) & bitstring_get_bit(b, i));
    }
    return sum;
}

int gf2_hamming_weight(const BitString *v) {
    if (!v) return 0;
    int w = 0;
    for (size_t i = 0; i < v->bit_len; i++) {
        w += bitstring_get_bit(v, i);
    }
    return w;
}

void gf2_matrix_mul(const uint8_t *A, int k, int m,
                    const BitString *x, BitString *out) {
    if (!A || !x || !out) return;
    assert((int)x->bit_len == m);
    /*
     * y = A * x  (over GF(2))
     * y_i = sum_{j=0}^{m-1} A[i][j] * x_j  (mod 2)
     * where A[i][j] is bit j of byte A[i * row_bytes + j/8]
     */
    size_t row_bytes = (m + 7) / 8;
    for (int i = 0; i < k; i++) {
        int y_i = 0;
        for (int j = 0; j < m; j++) {
            size_t byte_idx = (size_t)(i) * row_bytes + (size_t)j / 8;
            int bit_idx = 7 - (j % 8);
            int A_ij = (A[byte_idx] >> bit_idx) & 1;
            y_i ^= (A_ij & bitstring_get_bit(x, (size_t)j));
        }
        bitstring_set_bit(out, (size_t)i, y_i);
    }
    out->bit_len = (size_t)k;
}

/* ================================================================
 * L3: Modular Arithmetic
 * ================================================================
 * Foundational for RSA, discrete log, and all algebraic OWF candidates.
 * Square-and-multiply: O(log e) multiplications.
 */

uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t modulus) {
    if (modulus == 0) return 0;
    if (modulus == 1) return 0;
    /*
     * Square-and-multiply algorithm.
     * Compute base^exp mod modulus.
     * Time: O(log exp) modular multiplications.
     * Used in RSA (encryption/verification) and Diffie-Hellman.
     */
    uint64_t result = 1;
    base = base % modulus;
    while (exp > 0) {
        if (exp & 1) {
            result = mod_mul(result, base, modulus);
        }
        exp >>= 1;
        base = mod_mul(base, base, modulus);
    }
    return result;
}

uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t modulus) {
    if (modulus == 0) return 0;
    /*
     * (a * b) mod m with overflow protection using
     * "Russian peasant multiplication" (binary method).
     * For 64-bit: split into halves to avoid overflow.
     */
    a %= modulus;
    b %= modulus;
    uint64_t result = 0;
    while (b > 0) {
        if (b & 1) {
            result = (result + a) % modulus;
        }
        a = (a << 1) % modulus;
        b >>= 1;
    }
    return result;
}

uint64_t extended_gcd(uint64_t a, uint64_t b, int64_t *x, int64_t *y) {
    /*
     * Extended Euclidean Algorithm.
     * Finds gcd(a,b) and Bézout coefficients x,y such that:
     *   a*x + b*y = gcd(a,b)
     *
     * This is the key to:
     *   - RSA private key computation (d ≡ e^{-1} mod φ(N))
     *   - Chinese Remainder Theorem
     *   - Rabin decryption (square roots via CRT)
     */
    if (b == 0) {
        if (x) *x = 1;
        if (y) *y = 0;
        return a;
    }
    int64_t x1, y1;
    uint64_t g = extended_gcd(b, a % b, &x1, &y1);
    if (x) *x = y1;
    if (y) *y = x1 - (int64_t)(a / b) * y1;
    return g;
}

uint64_t mod_inverse(uint64_t a, uint64_t modulus) {
    /*
     * Modular inverse: find x such that a*x ≡ 1 (mod m).
     * Requires gcd(a, m) = 1.
     * Uses Extended Euclidean Algorithm.
     */
    if (modulus <= 1) return 0;
    int64_t x, y;
    uint64_t g = extended_gcd(a, modulus, &x, &y);
    if (g != 1) return 0; /* No inverse exists */
    /* Normalize to [0, modulus) */
    int64_t inv = x % (int64_t)modulus;
    if (inv < 0) inv += (int64_t)modulus;
    return (uint64_t)inv;
}

/* ================================================================
 * L3: Number Theoretic Utilities
 * ================================================================
 * Miller-Rabin: probabilistic primality test used to generate
 * the keys for RSA and Rabin candidates.
 *
 * Theorem (Rabin 1980): For composite n, at most 1/4 of bases
 * a ∈ [1, n-1] are "liars". Thus k iterations give error ≤ 4^{-k}.
 */

/* Modular exponentiation helper for Miller-Rabin */
static uint64_t miller_rabin_pow(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) result = mod_mul(result, base, mod);
        exp >>= 1;
        base = mod_mul(base, base, mod);
    }
    return result;
}

int miller_rabin_prime(uint64_t n, int k) {
    /*
     * Miller-Rabin primality test.
     * Returns 1 if n is probably prime (error ≤ 4^{-k}).
     * Returns 0 if n is definitely composite.
     *
     * Algorithm:
     *   1. Write n-1 = d * 2^s with d odd.
     *   2. For k random bases a:
     *      a. Compute x = a^d mod n
     *      b. If x = 1 or x = n-1, continue (likely prime so far)
     *      c. Square x up to s-1 times, check if x = n-1
     *      d. If never n-1, n is composite.
     */
    if (n < 2) return 0;
    if (n == 2 || n == 3) return 1;
    if (n % 2 == 0) return 0;

    /* Write n-1 = d * 2^s */
    uint64_t d = n - 1;
    int s = 0;
    while (d % 2 == 0) {
        d /= 2;
        s++;
    }

    for (int i = 0; i < k; i++) {
        /* Choose random base a in [2, n-2] */
        uint64_t a = 2 + (uint64_t)rand() % (n - 3);

        uint64_t x = miller_rabin_pow(a, d, n);
        if (x == 1 || x == n - 1) continue;

        int composite = 1;
        for (int r = 0; r < s - 1; r++) {
            x = mod_mul(x, x, n);
            if (x == n - 1) {
                composite = 0;
                break;
            }
        }
        if (composite) return 0;
    }
    return 1;
}

int is_generator(uint64_t g, uint64_t p) {
    /*
     * Verify g is a generator of Z_p^*.
     * For safe prime p = 2q + 1 (q prime), g is a generator iff:
     *   g^2 ≠ 1 mod p  and  g^q ≠ 1 mod p.
     *
     * For general prime p, check g^{(p-1)/q_i} ≠ 1 for each prime factor q_i.
     * Here we implement the simple case: check g^{(p-1)/2} ≠ 1 mod p.
     */
    if (p <= 2) return 0;
    if (g % p == 0) return 0;

    /* For safe prime: check g^((p-1)/2) = g^q ≠ 1 */
    uint64_t exp = (p - 1) / 2;
    uint64_t val = mod_pow(g, exp, p);
    if (val == 1) return 0;

    /* Also verify g^{p-1} = 1 (Fermat's little theorem requires this) */
    if (mod_pow(g, p - 1, p) != 1) return 0;
    return 1;
}

uint64_t generate_random_prime(int bits) {
    /*
     * Generate a random prime in [2^{bits-1}, 2^{bits}).
     * Simple trial: generate random odd number, test with Miller-Rabin.
     */
    if (bits < 2) return 2;
    if (bits > 32) bits = 32;  /* Limit for 64-bit safety */

    uint64_t min_val = (uint64_t)1 << (bits - 1);
    uint64_t max_val = ((uint64_t)1 << bits) - 1;

    int max_attempts = 1000;
    for (int attempt = 0; attempt < max_attempts; attempt++) {
        uint64_t candidate = min_val + ((uint64_t)rand() % (max_val - min_val));
        candidate |= 1; /* Ensure odd */
        if (candidate > max_val) candidate = max_val | 1;

        if (miller_rabin_prime(candidate, 20)) {
            return candidate;
        }
    }
    return 0; /* Failed */
}

int is_blum_integer(uint64_t n, uint64_t p, uint64_t q) {
    /*
     * Blum integer: n = p * q where p ≡ q ≡ 3 (mod 4).
     * Used in Blum-Blum-Shub PRG and Rabin OWF.
     *
     * Properties:
     *   - For each quadratic residue a mod n, exactly one of the four
     *     square roots is also a quadratic residue (principal root).
     *   - Squaring is a permutation on QR_n.
     */
    if (n == 0) return 0;
    if (p * q != n) return 0;
    return (p % 4 == 3) && (q % 4 == 3);
}

/* ================================================================
 * L3: Random Number Generation (LCG for testing)
 * ================================================================
 * Linear Congruential Generator: X_{n+1} = (a*X_n + c) mod m
 * Parameters from Numerical Recipes.
 *
 * NOT cryptographically secure — only for reproducible experiments!
 * Real crypto uses: /dev/urandom, CryptGenRandom, RDRAND, etc.
 */

LCG *lcg_create(uint64_t seed) {
    LCG *lcg = (LCG *)malloc(sizeof(LCG));
    if (!lcg) return NULL;
    lcg->state = seed;
    /* Numerical Recipes parameters for 64-bit */
    lcg->a = 6364136223846793005ULL;
    lcg->c = 1442695040888963407ULL;
    lcg->m = 0;  /* Uses uint64_t overflow as mod 2^64 */
    return lcg;
}

void lcg_free(LCG *lcg) {
    free(lcg);
}

uint64_t lcg_next(LCG *lcg) {
    /* X_{n+1} = a*X_n + c (mod 2^64 via overflow) */
    lcg->state = lcg->a * lcg->state + lcg->c;
    return lcg->state;
}

uint64_t lcg_rand_range(LCG *lcg, uint64_t min, uint64_t max) {
    if (max <= min) return min;
    uint64_t range = max - min;
    return min + (lcg_next(lcg) % range);
}

void seed_random(void) {
    /* Seed standard rand() with time + clock entropy */
    srand((unsigned int)(time(NULL) ^ (clock() << 8)));
}

/* ================================================================
 * L3: BitString Extended Operations
 * ================================================================
 * These extend the basic BitString operations in owf.c.
 * Essential for constructing composite bit strings in
 * cryptographic constructions (PRG iteration, HILL).
 */

void bitstring_concat(const BitString *a, const BitString *b, BitString *out) {
    if (!a || !b || !out) return;
    size_t total_len = a->bit_len + b->bit_len;
    assert(out->bit_len >= total_len);
    out->bit_len = total_len;

    /* Copy bits from a */
    for (size_t i = 0; i < a->bit_len; i++) {
        bitstring_set_bit(out, i, bitstring_get_bit(a, i));
    }
    /* Copy bits from b */
    for (size_t i = 0; i < b->bit_len; i++) {
        bitstring_set_bit(out, a->bit_len + i, bitstring_get_bit(b, i));
    }
}

void bitstring_xor(const BitString *a, const BitString *b, BitString *out) {
    if (!a || !b || !out) return;
    assert(a->bit_len == b->bit_len);
    out->bit_len = a->bit_len;
    size_t byte_len = (a->bit_len + 7) / 8;
    for (size_t i = 0; i < byte_len; i++) {
        out->data[i] = a->data[i] ^ b->data[i];
    }
}

void bitstring_slice(const BitString *bs, size_t start, size_t len, BitString *out) {
    if (!bs || !out) return;
    if (start >= bs->bit_len) {
        out->bit_len = 0;
        return;
    }
    if (start + len > bs->bit_len) {
        len = bs->bit_len - start;
    }
    out->bit_len = len;
    for (size_t i = 0; i < len; i++) {
        bitstring_set_bit(out, i, bitstring_get_bit(bs, start + i));
    }
}

void bitstring_split(const BitString *bs, size_t n, BitString *left, BitString *right) {
    if (!bs || !left || !right) return;
    if (n > bs->bit_len) n = bs->bit_len;
    bitstring_slice(bs, 0, n, left);
    bitstring_slice(bs, n, bs->bit_len - n, right);
}

int bitstring_cmp(const BitString *a, const BitString *b) {
    if (!a && !b) return 0;
    if (!a) return -1;
    if (!b) return 1;
    size_t min_len = (a->bit_len < b->bit_len) ? a->bit_len : b->bit_len;
    for (size_t i = 0; i < min_len; i++) {
        int ab = bitstring_get_bit(a, i);
        int bb = bitstring_get_bit(b, i);
        if (ab < bb) return -1;
        if (ab > bb) return 1;
    }
    if (a->bit_len < b->bit_len) return -1;
    if (a->bit_len > b->bit_len) return 1;
    return 0;
}

void bitstring_to_hex(const BitString *bs, char *hex_out, size_t hex_len) {
    if (!bs || !hex_out || hex_len == 0) return;
    static const char hex_chars[] = "0123456789ABCDEF";
    size_t byte_len = (bs->bit_len + 7) / 8;
    size_t output_pos = 0;
    for (size_t i = 0; i < byte_len && output_pos + 2 < hex_len; i++) {
        hex_out[output_pos++] = hex_chars[(bs->data[i] >> 4) & 0xF];
        hex_out[output_pos++] = hex_chars[bs->data[i] & 0xF];
    }
    if (output_pos < hex_len) hex_out[output_pos] = '\0';
}

int hex_to_bitstring(const char *hex, BitString *out) {
    if (!hex || !out) return 0;
    static const int hex_val[256] = {
        ['0']=0, ['1']=1, ['2']=2, ['3']=3, ['4']=4,
        ['5']=5, ['6']=6, ['7']=7, ['8']=8, ['9']=9,
        ['A']=10,['B']=11,['C']=12,['D']=13,['E']=14,['F']=15,
        ['a']=10,['b']=11,['c']=12,['d']=13,['e']=14,['f']=15
    };
    size_t hex_len = strlen(hex);
    size_t bit_len = hex_len * 4;
    if (out->bit_len < bit_len) bit_len = out->bit_len;
    out->bit_len = bit_len;

    for (size_t i = 0; i < hex_len && i * 4 < bit_len; i++) {
        int val = hex_val[(unsigned char)hex[i]];
        for (int j = 3; j >= 0 && (i * 4 + (size_t)(3 - j)) < bit_len; j--) {
            bitstring_set_bit(out, i * 4 + (size_t)(3 - j), (val >> j) & 1);
        }
    }
    return 1;
}

/* ================================================================
 * L7: Crypto Application Utilities
 * ================================================================
 * Practical utilities: key generation, hash, key derivation.
 * These are demonstration-grade (not production).
 */

int generate_crypto_key(size_t bit_len, BitString *key) {
    /*
     * Generate a key from system entropy for demonstration.
     * Uses time() + clock() + rand() mixing.
     * In production: use platform CSPRNG or /dev/urandom.
     */
    if (!key || bit_len == 0) return -1;
    seed_random();
    key->bit_len = bit_len;
    size_t byte_len = (bit_len + 7) / 8;
    /* Initial seed from time */
    uint64_t tseed = (uint64_t)time(NULL) ^ ((uint64_t)clock() << 16);
    LCG *rng = lcg_create(tseed);
    for (size_t i = 0; i < byte_len; i++) {
        key->data[i] = (uint8_t)(lcg_next(rng) & 0xFF);
        /* Stir in rand() */
        key->data[i] ^= (uint8_t)(rand() & 0xFF);
    }
    lcg_free(rng);
    /* Zero out excess bits */
    size_t extra = byte_len * 8 - bit_len;
    if (extra > 0) {
        key->data[byte_len - 1] &= (uint8_t)(0xFF >> extra);
    }
    return 0;
}

uint64_t fnv_hash(const uint8_t *data, size_t len) {
    /*
     * FNV-1a hash: FNV_offset_basis = 14695981039346656037
     *               FNV_prime = 1099511628211
     * NOT cryptographically secure.
     */
    uint64_t hash = 14695981039346656037ULL;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint64_t)data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

int key_derivation_stretch(const BitString *seed, size_t output_len,
                           BitString *output) {
    /*
     * Simple key derivation: iterative hash-based stretching.
     * K_0 = empty, K_{i+1} = H(K_i || seed || counter)
     *
     * Inspired by HKDF (RFC 5869) but simplified for demonstration.
     * Real applications should use HKDF with HMAC-SHA256.
     */
    if (!seed || !output || output_len == 0) return -1;
    output->bit_len = 0;

    size_t block_size = 64;  /* 512 bits per FNV iteration */
    (void)(output_len + block_size);  /* Suppress unused */

    uint8_t buffer[128];
    memset(buffer, 0, sizeof(buffer));

    /* Copy seed bytes into buffer prefix */
    size_t seed_bytes = (seed->bit_len + 7) / 8;
    if (seed_bytes > 64) seed_bytes = 64;
    memcpy(buffer, seed->data, seed_bytes);

    uint32_t counter = 0;
    size_t bits_produced = 0;
    while (bits_produced < output_len) {
        counter++;
        /* Encode counter into buffer */
        buffer[seed_bytes] = (uint8_t)(counter & 0xFF);
        buffer[seed_bytes + 1] = (uint8_t)((counter >> 8) & 0xFF);
        buffer[seed_bytes + 2] = (uint8_t)((counter >> 16) & 0xFF);
        buffer[seed_bytes + 3] = (uint8_t)((counter >> 24) & 0xFF);

        size_t hash_input_len = seed_bytes + 4;
        uint64_t h = fnv_hash(buffer, hash_input_len);

        /* Expand hash into bits */
        for (int b = 0; b < 64 && bits_produced < output_len; b++) {
            int bit = (int)((h >> (63 - b)) & 1);
            bitstring_set_bit(output, bits_produced, bit);
            bits_produced++;
        }
    }
    return 0;
}
