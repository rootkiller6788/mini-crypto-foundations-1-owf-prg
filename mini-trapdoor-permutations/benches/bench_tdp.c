/**
 * bench_tdp.c — Performance Benchmarks for Trapdoor Permutations
 *
 * Measures execution time for core TDP operations:
 *   - RSA key generation (various key sizes)
 *   - Encryption (forward evaluation)
 *   - Decryption (CRT vs naive)
 *   - Modular exponentiation throughput
 *   - Miller-Rabin primality testing throughput
 *
 * Reference: Rivest, Shamir, Adleman (1978), PKCS#1 v2.2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "tdp_core.h"
#include "modular_math.h"
#include "rsa.h"
#include "rsa_keygen.h"
#include "tdp_pke.h"
#include "tdp_signatures.h"

/* ──── Timing Harness ──── */

static double get_time_sec(void) {
    return (double)clock() / (double)CLOCKS_PER_SEC;
}

#define BENCH_ITERATIONS 100
#define REPORT(op, iter, elapsed) \
    printf("  %-40s %8d iters  %10.6f sec  %10.3f us/op\n", \
           op, iter, elapsed, (elapsed * 1e6) / (double)(iter))

/* ──── Benchmark: Modular Exponentiation ──── */

static void bench_modular_exponentiation(void) {
    printf("\n--- Modular Exponentiation ---\n");

    bigint_t base = bigint_from_uint64(123456789);
    bigint_t exp = bigint_from_uint64(65537);
    bigint_t mod = bigint_from_uint64(999999937); /* A 30-bit prime */
    bigint_t result;

    double start = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS * 10; i++) {
        mod_exp(&result, &base, &exp, &mod);
    }
    double elapsed = get_time_sec() - start;
    REPORT("mod_exp (30-bit, e=65537)", BENCH_ITERATIONS * 10, elapsed);
}

/* ──── Benchmark: Miller-Rabin Primality ──── */

static void bench_miller_rabin(void) {
    printf("\n--- Miller-Rabin Primality Testing ---\n");

    /* Test known primes of increasing size */
    bigint_t primes_to_test[5];
    primes_to_test[0] = bigint_from_uint64(999999937ULL);
    primes_to_test[1] = bigint_from_uint64(999999999989ULL);
    /* Build a 64-bit composite: product of two 32-bit primes */
    bigint_t n64;
    bigint_t p32 = bigint_from_uint64(4294967291ULL);
    bigint_t q32 = bigint_from_uint64(4294967029ULL);
    bigint_mul(&n64, &p32, &q32);
    primes_to_test[2] = n64;
    primes_to_test[3] = p32;
    primes_to_test[4] = q32;

    const int k = 10;
    const int total_tests = 5 * 20;

    double start = get_time_sec();
    for (int rep = 0; rep < 20; rep++) {
        for (int j = 0; j < 5; j++) {
            miller_rabin_test(&primes_to_test[j], k);
        }
    }
    double elapsed = get_time_sec() - start;
    REPORT("Miller-Rabin (k=10, 30-64 bit)", total_tests, elapsed);
}

/* ──── Benchmark: RSA Key Generation ──── */

static void bench_rsa_keygen(void) {
    printf("\n--- RSA Key Generation ---\n");

    rsa_keypair_t key;
    unsigned int seed = 42;

    double start = get_time_sec();
    for (int i = 0; i < 10; i++) {
        rsa_generate_keypair(&key, 64, seed + i);
    }
    double elapsed = get_time_sec() - start;
    REPORT("RSA keygen (64-bit)", 10, elapsed);

    start = get_time_sec();
    rsa_generate_keypair(&key, 128, seed + 100);
    elapsed = get_time_sec() - start;
    REPORT("RSA keygen (128-bit)", 1, elapsed);
}

/* ──── Benchmark: RSA Encryption/Decryption ──── */

static void bench_rsa_crypto_ops(void) {
    printf("\n--- RSA Encryption/Decryption ---\n");

    rsa_keypair_t key;
    uint32_t seed = 12345;
    rsa_generate_keypair(&key, 128, seed);

    bigint_t message;
    bigint_t msg_raw = bigint_from_uint64(0xDEADBEEF);
    bigint_copy(&message, &msg_raw);

    /* Benchmark encryption */
    double start = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        rsa_encrypt(&key.params, &message);
    }
    double enc_elapsed = get_time_sec() - start;
    REPORT("RSA Encrypt (128-bit)", BENCH_ITERATIONS, enc_elapsed);

    /* Prepare ciphertext */
    tdp_eval_result_t ct = rsa_encrypt(&key.params, &message);

    /* Benchmark CRT decryption */
    start = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        rsa_decrypt_crt(&key, &ct.value);
    }
    double crt_elapsed = get_time_sec() - start;
    REPORT("RSA Decrypt CRT (128-bit)", BENCH_ITERATIONS, crt_elapsed);

    /* Benchmark naive decryption */
    start = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        rsa_decrypt_naive(&key.params, &ct.value);
    }
    double naive_elapsed = get_time_sec() - start;
    REPORT("RSA Decrypt Naive (128-bit)", BENCH_ITERATIONS, naive_elapsed);

    /* Report CRT speedup */
    double speedup = naive_elapsed / crt_elapsed;
    printf("\n  CRT Speedup: %.2fx (naive/CRT time ratio)\n", speedup);
}

/* ──── Benchmark: GCD and Modular Inverse ──── */

static void bench_number_theory(void) {
    printf("\n--- Number Theory Operations ---\n");

    bigint_t a = bigint_from_uint64(12345678901234567890ULL);
    bigint_t b = bigint_from_uint64(9876543210987654321ULL);
    bigint_t result;

    /* GCD benchmark */
    double start = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS * 100; i++) {
        bigint_gcd(&result, &a, &b);
    }
    double elapsed = get_time_sec() - start;
    REPORT("bigint_gcd (64-bit)", BENCH_ITERATIONS * 100, elapsed);

    /* EGCD benchmark */
    bigint_t x, y;
    start = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS * 100; i++) {
        bigint_egcd(&result, &x, &y, &a, &b);
    }
    double egcd_elapsed = get_time_sec() - start;
    REPORT("bigint_egcd (64-bit)", BENCH_ITERATIONS * 100, egcd_elapsed);

    /* Modular inverse benchmark */
    bigint_t mod = bigint_from_uint64(1000000007ULL); /* 1e9+7 prime */
    start = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS * 100; i++) {
        mod_inverse(&result, &a, &mod);
    }
    double inv_elapsed = get_time_sec() - start;
    REPORT("mod_inverse (30-bit)", BENCH_ITERATIONS * 100, inv_elapsed);
}

/* ──── Benchmark: Big Integer Arithmetic ──── */

static void bench_bigint_ops(void) {
    printf("\n--- Big Integer Arithmetic ---\n");

    bigint_t a = bigint_from_uint64(0xFFFFFFFFFFFFFFFFULL);
    bigint_t b = bigint_from_uint64(0x123456789ABCDEF0ULL);
    bigint_t result;
    double start, elapsed;

    start = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS * 1000; i++) {
        bigint_add(&result, &a, &b);
    }
    elapsed = get_time_sec() - start;
    REPORT("bigint_add (64-bit)", BENCH_ITERATIONS * 1000, elapsed);

    start = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS * 500; i++) {
        bigint_mul(&result, &a, &b);
    }
    elapsed = get_time_sec() - start;
    REPORT("bigint_mul (64-bit)", BENCH_ITERATIONS * 500, elapsed);

    start = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS * 100; i++) {
        bigint_divmod(&result, &b, &a, &b);
    }
    elapsed = get_time_sec() - start;
    REPORT("bigint_divmod (64-bit)", BENCH_ITERATIONS * 100, elapsed);
}

/* ──── Benchmark: TDP Domain Operations ──── */

static void bench_tdp_operations(void) {
    printf("\n--- TDP Core Operations ---\n");

    rsa_keypair_t key;
    rsa_generate_keypair(&key, 128, 9999);

    tdp_public_key_t pk;
    pk.modulus = key.params.n;
    pk.exponent = key.params.e;
    pk.nbits = key.params.nbits;

    tdp_trapdoor_t td;
    td.prime_p = key.params.p;
    td.prime_q = key.params.q;
    td.private_exp = key.params.d;
    td.totient = key.params.phi_n;
    td.d_p = key.d_p;
    td.d_q = key.d_q;
    td.q_inv = key.q_inv;

    /* Sample domain */
    double start = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        tdp_sample_domain(&pk);
    }
    double elapsed = get_time_sec() - start;
    REPORT("tdp_sample_domain (128-bit)", BENCH_ITERATIONS, elapsed);

    /* Check domain membership */
    bigint_t test_val = bigint_from_uint64(12345);
    start = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS * 10; i++) {
        tdp_check_domain_membership(&pk, &test_val);
    }
    elapsed = get_time_sec() - start;
    REPORT("tdp_check_domain (128-bit)", BENCH_ITERATIONS * 10, elapsed);

    /* Verify permutation property */
    tdp_domain_elem_t x = tdp_sample_domain(&pk);
    start = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS / 5; i++) {
        tdp_verify_permutation_property(&pk, &td, &x);
    }
    elapsed = get_time_sec() - start;
    REPORT("tdp_verify_permutation", BENCH_ITERATIONS / 5, elapsed);
}

/* ──── Benchmark: Signature Operations ──── */

static void bench_signatures(void) {
    printf("\n--- Digital Signature Operations ---\n");

    rsa_keypair_t key;
    rsa_generate_keypair(&key, 128, 7777);

    uint8_t message[] = "Benchmark RSA signature performance test message";
    size_t msg_len = sizeof(message);

    uint8_t salt[32];
    for (int i = 0; i < 32; i++) salt[i] = (uint8_t)(i * 7 + 13);

    /* FDH sign benchmark */
    double start = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS / 2; i++) {
        rsa_fdh_sign(&key, message, msg_len);
    }
    double fdh_elapsed = get_time_sec() - start;
    REPORT("FDH Sign (128-bit)", BENCH_ITERATIONS / 2, fdh_elapsed);

    /* PSS sign benchmark */
    start = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS / 2; i++) {
        rsa_pss_sign(&key, message, msg_len, salt, 32);
    }
    double pss_elapsed = get_time_sec() - start;
    REPORT("PSS Sign (128-bit)", BENCH_ITERATIONS / 2, pss_elapsed);
}

/* ──── Benchmark: OAEP Operations ──── */

static void bench_oaep(void) {
    printf("\n--- OAEP Padding Operations ---\n");

    uint8_t message[64];
    memcpy(message, "Benchmark OAEP padding test data", 33);
    uint8_t r[64];
    memcpy(r, "Random seed for OAEP randomization", 35);
    uint8_t padded[128];
    size_t padded_len;
    uint8_t recovered[128];
    size_t recovered_len;

    double start = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS * 10; i++) {
        pke_oaep_pad(padded, &padded_len, message, 32, r, 32, 128);
        pke_oaep_unpad(recovered, &recovered_len, padded, padded_len, 128);
    }
    double elapsed = get_time_sec() - start;
    REPORT("OAEP pad+unpad (256-bit block)", BENCH_ITERATIONS * 10, elapsed);
}

/* ──── Main ──── */

int main(void) {
    printf("========================================\n");
    printf("mini-trapdoor-permutations Benchmarks\n");
    printf("========================================\n");
    printf("Compiler: GCC\n");
    printf("Iterations per test: %d (varies by operation cost)\n", BENCH_ITERATIONS);
    printf("Clock resolution: ~%.0f ns\n", 1e9 / (double)CLOCKS_PER_SEC);

    bench_modular_exponentiation();
    bench_miller_rabin();
    bench_bigint_ops();
    bench_number_theory();
    bench_rsa_keygen();
    bench_rsa_crypto_ops();
    bench_tdp_operations();
    bench_signatures();
    bench_oaep();

    printf("\n========================================\n");
    printf("All Benchmarks Complete\n");
    printf("========================================\n");
    return 0;
}
