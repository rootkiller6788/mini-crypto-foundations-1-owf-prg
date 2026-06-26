/*
 * bench_owf.c --- Performance Benchmarks for One-Way Functions
 *
 * L5: Benchmark core number-theoretic operations:
 *   - Modular exponentiation (square-and-multiply) at various bit lengths
 *   - Miller-Rabin primality test scaling
 *   - Prime generation throughput
 *   - CRT reconstruction timing
 *   - RSA/DL/Rabin evaluation throughput
 *
 * Each benchmark measures operations/second and scaling behavior.
 * Output is structured for analysis (CSV-compatible).
 */

#include "owf_core.h"
#include "owf_number_theory.h"
#include "owf_candidates.h"
#include "owf_hardcore.h"
#include "owf_weak_strong.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
static double get_time_sec(void) {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart / (double)freq.QuadPart;
}
#else
#include <sys/time.h>
static double get_time_sec(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec * 1e-6;
}
#endif

static void bench_header(const char* name) {
    printf("\n--- %s ---\n", name);
    printf("%-30s %10s %12s %12s\n", "Operation", "Iterations", "Time(s)", "ops/sec");
}

static void bench_result(const char* op, int iters, double elapsed) {
    double ops_per_sec = (elapsed > 0.0) ? (double)iters / elapsed : 0.0;
    printf("%-30s %10d %12.4f %12.0f\n", op, iters, elapsed, ops_per_sec);
}

/* ================================================================
 * Benchmark 1: Modular Exponentiation at Various Bit Lengths
 * L5: Core operation for RSA, DL, and most OWF candidates.
 * Tests scaling with bit length.
 * ================================================================ */
static void bench_modular_exponentiation(void) {
    bench_header("Modular Exponentiation (Square-and-Multiply)");
    const int iters = 100;
    int bit_lengths[] = {32, 64, 128, 256, 512};

    for (int bi = 0; bi < 5; bi++) {
        size_t bits = (size_t)bit_lengths[bi];
        big_nat_t modulus = generate_random_prime(bits, 20, NULL);
        big_nat_t base    = big_nat_random_bits(bits);
        big_nat_t exp     = big_nat_random_bits(bits);

        /* Ensure base < modulus */
        big_nat_t q, r;
        big_nat_divmod(&base, &modulus, &q, &r);
        base = r;

        char label[64];
        snprintf(label, sizeof(label), "modpow (%zu-bit)", bits);

        double t0 = get_time_sec();
        for (int i = 0; i < iters; i++) {
            big_nat_t tmp = big_nat_modpow(&base, &exp, &modulus);
            /* prevent optimization: accumulate */
            if (i == iters - 1) {
                volatile size_t nd = tmp.ndigits;
                (void)nd;
            }
        }
        double elapsed = get_time_sec() - t0;
        bench_result(label, iters, elapsed);
    }
}

/* ================================================================
 * Benchmark 2: Miller-Rabin Primality Test Scaling
 * L5: Probabilistic primality test with k rounds.
 * Higher k => more confidence, but slower.
 * ================================================================ */
static void bench_miller_rabin(void) {
    bench_header("Miller-Rabin Primality Test");
    const int iters = 50;

    int k_rounds[] = {5, 10, 20, 40};
    size_t bits = 128;

    /* Generate a prime (should pass all rounds) and a composite */
    big_nat_t prime = generate_random_prime(bits, 40, NULL);
    big_nat_t composite = big_nat_mul(&prime, &prime); /* square = composite */
    /* Trim to reasonable size */
    big_nat_t half;
    big_nat_divmod(&composite, &prime, &half, &composite);
    /* Actually use prime*3 for a manageable composite */
    big_nat_t three = big_nat_from_uint64(3);
    composite = big_nat_mul(&prime, &three);

    for (int ki = 0; ki < 4; ki++) {
        int k = k_rounds[ki];
        char label[64];

        /* Test on prime (passes) */
        snprintf(label, sizeof(label), "MR prime k=%d (%zu-bit)", k, bits);
        double t0 = get_time_sec();
        for (int i = 0; i < iters; i++) {
            volatile int result = mr_test(&prime, k);
            (void)result;
        }
        double elapsed = get_time_sec() - t0;
        bench_result(label, iters, elapsed);

        /* Test on composite (fails early) */
        snprintf(label, sizeof(label), "MR composite k=%d (%zu-bit)", k, bits);
        t0 = get_time_sec();
        for (int i = 0; i < iters; i++) {
            volatile int result = mr_test(&composite, k);
            (void)result;
        }
        elapsed = get_time_sec() - t0;
        bench_result(label, iters, elapsed);
    }
}

/* ================================================================
 * Benchmark 3: RSA OWF Evaluation Throughput
 * L6: Measures encryption/signing throughput for RSA candidate.
 * ================================================================ */
static void bench_rsa_owf(void) {
    bench_header("RSA One-Way Function Throughput");

    int bit_lengths[] = {32, 64};
    const int iters = 200;

    for (int bi = 0; bi < 2; bi++) {
        size_t bits = (size_t)bit_lengths[bi];
        rsa_params_t* rsa = rsa_params_generate(bits);
        if (!rsa) continue;

        bit_string_t* x = bs_random(bits);
        if (!x) { rsa_params_free(rsa); continue; }

        /* Benchmark evaluation */
        char label[64];
        snprintf(label, sizeof(label), "RSA eval (%zu-bit)", bits);

        double t0 = get_time_sec();
        for (int i = 0; i < iters; i++) {
            bit_string_t* y = NULL;
            rsa_owf_eval(rsa, x, 256, &y);
            bs_free(y);
        }
        double eval_time = get_time_sec() - t0;
        bench_result(label, iters, eval_time);

        /* Benchmark trapdoor inversion */
        bit_string_t* y = NULL;
        rsa_owf_eval(rsa, x, 256, &y);

        snprintf(label, sizeof(label), "RSA inv (trapdoor, %zu-bit)", bits);
        t0 = get_time_sec();
        for (int i = 0; i < iters; i++) {
            bit_string_t* xp = NULL;
            rsa_owf_invert_trapdoor(rsa, y, &xp);
            bs_free(xp);
        }
        double inv_time = get_time_sec() - t0;
        bench_result(label, iters, inv_time);

        bs_free(x);
        bs_free(y);
        rsa_params_free(rsa);
    }
}

/* Helper functions for Yao amplification benchmark (file scope, not nested) */
static int bench_fake_eval(void* ctx, const bit_string_t* x,
                     sec_param_t n, bit_string_t** y) {
    (void)ctx; (void)n;
    *y = bs_create(x->bit_len);
    return (*y) ? 0 : -1;
}
static int bench_fake_inv(void* ctx, const bit_string_t* y,
                    sec_param_t n, bit_string_t** xp) {
    (void)ctx; (void)y; (void)n;
    *xp = bs_create(8);
    return (*xp) ? 0 : -1;
}

/* ================================================================
 * Benchmark 4: Yao Amplification Overhead
 * L4: Measures cost of weak->strong amplification via parallel repetition.
 * ================================================================ */
static void bench_yao_amplification(void) {
    bench_header("Yao Amplification Overhead");

    owf_scheme_t* base = owf_scheme_create("bench", "none",
        bench_fake_eval, bench_fake_inv, NULL, NULL, 128, 32, 32);

    int t_values[] = {1, 4, 16, 64};
    const int trials = 1000;

    for (int ti = 0; ti < 4; ti++) {
        int t = t_values[ti];
        yao_amplification_t* amp = yao_amp_create(base, (size_t)t, 0.1);
        if (!amp) continue;

        bit_string_t* x = bs_random((size_t)(t * 32));
        if (!x) { yao_amp_free(amp); continue; }

        char label[64];
        snprintf(label, sizeof(label), "Yao t=%d (in=%d bits)", t, t*32);

        double t0 = get_time_sec();
        for (int i = 0; i < trials; i++) {
            bit_string_t* y = NULL;
            yao_amp_eval(amp, x, 128, &y);
            bs_free(y);
        }
        double elapsed = get_time_sec() - t0;
        bench_result(label, trials, elapsed);

        bs_free(x);
        yao_amp_free(amp);
    }
    owf_scheme_free(base);
}

/* ================================================================
 * Benchmark 5: GL Predicate Computation Throughput
 * L4/L8: Throughput for inner product mod 2 computation.
 * ================================================================ */
static void bench_gl_predicate(void) {
    bench_header("Goldreich-Levin Predicate Throughput");
    const int iters = 5000;

    int bit_lengths[] = {64, 128, 256, 512, 1024};
    for (int bi = 0; bi < 5; bi++) {
        size_t bits = (size_t)bit_lengths[bi];
        bit_string_t* x = bs_random(bits);
        bit_string_t* r = bs_random(bits);
        if (!x || !r) { bs_free(x); bs_free(r); continue; }

        char label[64];
        snprintf(label, sizeof(label), "GL predicate (%zu-bit)", bits);

        double t0 = get_time_sec();
        for (int i = 0; i < iters; i++) {
            volatile int b = gl_predicate(x, r);
            (void)b;
        }
        double elapsed = get_time_sec() - t0;
        bench_result(label, iters, elapsed);

        bs_free(x);
        bs_free(r);
    }
}

/* ================================================================
 * Benchmark 6: CRT Reconstruction Throughput
 * L5: Performance of Chinese Remainder Theorem for multi-prime RSA.
 * ================================================================ */
static void bench_crt(void) {
    bench_header("CRT Reconstruction Throughput");
    const int iters = 500;

    /* Test with 2, 3, 4, 5 moduli */
    int k_values[] = {2, 3, 4, 5};
    for (int ki = 0; ki < 4; ki++) {
        int k = k_values[ki];
        big_nat_t residues[5];
        big_nat_t moduli[5];

        /* Generate small coprime moduli (primes) */
        uint64_t small_primes[] = {2, 3, 5, 7, 11};
        for (int j = 0; j < k; j++) {
            moduli[j] = big_nat_from_uint64(small_primes[j]);
            residues[j] = big_nat_from_uint64((uint64_t)rand() % small_primes[j]);
        }

        char label[64];
        snprintf(label, sizeof(label), "CRT (k=%d)", k);

        double t0 = get_time_sec();
        for (int i = 0; i < iters; i++) {
            volatile big_nat_t result = crt_solve(residues, moduli, k);
            (void)result.ndigits;
        }
        double elapsed = get_time_sec() - t0;
        bench_result(label, iters, elapsed);

        /* Garner's algorithm comparison */
        snprintf(label, sizeof(label), "CRT Garner (k=%d)", k);
        t0 = get_time_sec();
        for (int i = 0; i < iters; i++) {
            volatile big_nat_t result = crt_garner(residues, moduli, k);
            (void)result.ndigits;
        }
        elapsed = get_time_sec() - t0;
        bench_result(label, iters, elapsed);
    }
}

int main(void) {
    srand((unsigned)time(NULL));
    printf("=== OWF Performance Benchmarks ===\n");
    printf("Date: %s\n", __DATE__);
    printf("Compiler: %s\n",
#ifdef __GNUC__
        "GCC " __VERSION__
#else
        "Unknown"
#endif
    );

    bench_modular_exponentiation();
    bench_miller_rabin();
    bench_rsa_owf();
    bench_yao_amplification();
    bench_gl_predicate();
    bench_crt();

    printf("\n=== Benchmarks Complete ===\n");
    return 0;
}
