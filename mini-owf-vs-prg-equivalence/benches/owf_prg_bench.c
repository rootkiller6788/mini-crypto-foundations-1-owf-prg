/*
 * owf_prg_bench.c — Performance Benchmarks for OWF ⇔ PRG Module
 *
 * Benchmarks measure the computational cost of each component
 * in the OWF ⇔ PRG equivalence pipeline.
 *
 * Benchmarks:
 *   1. OWF candidate evaluation throughput (RSA, DLog, Rabin, SubsetSum)
 *   2. Modular exponentiation (square-and-multiply) vs naive
 *   3. GL inner product computation rate
 *   4. GF(2) hash function throughput
 *   5. PRG iteration throughput (bits/sec)
 *   6. BitString operations
 *   7. Full HILL pipeline end-to-end latency
 *   8. Distribution and entropy operations
 *
 * Reference:
 *   Goldreich (2001) — Foundations of Cryptography, Vol 1
 *   HILL (1999) — A Pseudorandom Generator from any One-way Function
 *
 * Courses: MIT 6.875, Stanford CS255, Berkeley CS276
 */

#include "owf.h"
#include "prg.h"
#include "hardcore_bit.h"
#include "indistinguish.h"
#include "reduction.h"
#include "crypto_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Platform-independent high-resolution timer (approximate) */
static double get_time_seconds(void) {
    return (double)clock() / CLOCKS_PER_SEC;
}

/* Benchmark helper: run function N times and report statistics */
typedef void (*BenchFunc)(void *ctx);

static void run_benchmark(const char *name, BenchFunc func, void *ctx,
                          int iterations) {
    double start = get_time_seconds();
    for (int i = 0; i < iterations; i++) {
        func(ctx);
    }
    double elapsed = get_time_seconds() - start;
    double per_iter = elapsed / iterations;
    double per_sec = (elapsed > 0) ? iterations / elapsed : 0;

    printf("  %-40s ", name);
    printf("%8d iters  %8.3f s  %10.3f us/iter  %10.0f iter/s\n",
           iterations, elapsed, per_iter * 1e6, per_sec);
}

/* ================================================================
 * Benchmark 1: OWF Candidate Evaluation
 * ================================================================ */

typedef struct {
    OWF *owf;
    BitString *x;
    BitString *y;
    int n_iters;
} OWFBenchCtx;

static void bench_owf_eval_func(void *ctx) {
    OWFBenchCtx *c = (OWFBenchCtx *)ctx;
    for (int i = 0; i < c->n_iters; i++) {
        owf_eval(c->owf, c->x, c->y);
    }
}

static void benchmark_owf_candidates(void) {
    printf("\n--- Benchmark 1: OWF Candidate Evaluation ---\n");
    int n_iters = 10000;

    /* RSA */
    {
        void *params = rsa_params_create(7, 11, 5);
        OWF *owf = owf_create(12, rsa_owf_eval, params, "RSA");
        BitString *x = bitstring_create(12);
        BitString *y = bitstring_create(12);
        uint64_to_bitstring(5, 12, x);
        OWFBenchCtx ctx = {owf, x, y, 1};
        run_benchmark("RSA mod_exp (N=77, e=5)", bench_owf_eval_func, &ctx, n_iters);
        bitstring_free(x); bitstring_free(y);
        owf_free(owf);
    }

    /* Discrete Log */
    {
        void *params = dlog_params_create(23, 5);
        OWF *owf = owf_create(12, dlog_owf_eval, params, "DLog");
        BitString *x = bitstring_create(12);
        BitString *y = bitstring_create(12);
        uint64_to_bitstring(3, 12, x);
        OWFBenchCtx ctx = {owf, x, y, 1};
        run_benchmark("DLog mod_exp (p=23, g=5)", bench_owf_eval_func, &ctx, n_iters);
        bitstring_free(x); bitstring_free(y);
        owf_free(owf);
    }

    /* Rabin (squaring is faster than general exponentiation) */
    {
        void *params = rabin_params_create(7, 11);
        OWF *owf = owf_create(12, rabin_owf_eval, params, "Rabin");
        BitString *x = bitstring_create(12);
        BitString *y = bitstring_create(12);
        uint64_to_bitstring(5, 12, x);
        OWFBenchCtx ctx = {owf, x, y, 1};
        run_benchmark("Rabin squaring (N=77)", bench_owf_eval_func, &ctx, n_iters);
        bitstring_free(x); bitstring_free(y);
        owf_free(owf);
    }

    /* Subset Sum */
    {
        uint64_t weights[] = {3, 5, 7, 11, 13, 17};
        void *params = subsetsum_params_create(6, weights, 256);
        OWF *owf = owf_create(12, subset_sum_owf_eval, params, "SubsetSum");
        BitString *x = bitstring_create(6);
        BitString *y = bitstring_create(12);
        bitstring_randomize(x);
        x->bit_len = 6;
        OWFBenchCtx ctx = {owf, x, y, 1};
        run_benchmark("SubsetSum (n=6, 6 addends)", bench_owf_eval_func, &ctx, n_iters);
        bitstring_free(x); bitstring_free(y);
        owf_free(owf);
    }
}

/* ================================================================
 * Benchmark 2: Modular Arithmetic
 * ================================================================ */

static void bench_mod_pow_single_func(void *ctx) {
    (void)ctx;
    mod_pow(7, 13, 77);
}

static void bench_extended_gcd_func(void *ctx) {
    (void)ctx;
    int64_t x, y;
    extended_gcd(240, 46, &x, &y);
}

static void bench_mod_inverse_func(void *ctx) {
    (void)ctx;
    mod_inverse(7, 40);
}

static void bench_miller_rabin_func(void *ctx) {
    (void)ctx;
    miller_rabin_prime(9973, 5);
}

static void benchmark_modular_arithmetic(void) {
    printf("\n--- Benchmark 2: Modular Arithmetic ---\n");
    int n_iters = 50000;

    run_benchmark("mod_pow (square-and-multiply)", bench_mod_pow_single_func, NULL, n_iters);
    run_benchmark("extended_gcd (240, 46)", bench_extended_gcd_func, NULL, n_iters);
    run_benchmark("mod_inverse (7, 40)", bench_mod_inverse_func, NULL, n_iters);
    run_benchmark("Miller-Rabin (9973, k=5)", bench_miller_rabin_func, NULL, n_iters / 10);
}

/* ================================================================
 * Benchmark 3: GL Inner Product
 * ================================================================ */

typedef struct {
    BitString *x;
    BitString *r;
} GLBenchCtx;

static void bench_gl_func(void *ctx) {
    GLBenchCtx *c = (GLBenchCtx *)ctx;
    gl_inner_product(c->x, c->r);
}

static void bench_gf2_dot_func(void *ctx) {
    GLBenchCtx *c = (GLBenchCtx *)ctx;
    gf2_dot_product(c->x, c->r);
}

static void bench_hamming_func(void *ctx) {
    GLBenchCtx *c = (GLBenchCtx *)ctx;
    gf2_hamming_weight(c->x);
}

static void benchmark_gl_inner_product(void) {
    printf("\n--- Benchmark 3: Goldreich-Levin Inner Product ---\n");
    int n_iters = 100000;

    int n = 32;
    BitString *x = bitstring_create((size_t)n);
    BitString *r = bitstring_create((size_t)n);
    bitstring_randomize(x);
    bitstring_randomize(r);
    x->bit_len = (size_t)n;
    r->bit_len = (size_t)n;

    GLBenchCtx ctx = {x, r};
    run_benchmark("GL inner product (n=32)", bench_gl_func, &ctx, n_iters);
    run_benchmark("GF(2) dot product (n=32)", bench_gf2_dot_func, &ctx, n_iters);
    run_benchmark("GF(2) Hamming weight (n=32)", bench_hamming_func, &ctx, n_iters);

    bitstring_free(x); bitstring_free(r);
}

/* ================================================================
 * Benchmark 4: GF(2) Hash Functions
 * ================================================================ */

typedef struct {
    GF2HashFunc *h;
    BitString *x;
    BitString *out;
} HashBenchCtx;

static void bench_hash_func(void *ctx) {
    HashBenchCtx *c = (HashBenchCtx *)ctx;
    gf2_hash_eval(c->h, c->x, c->out);
}

static void benchmark_gf2_hash(void) {
    printf("\n--- Benchmark 4: GF(2) Pairwise Independent Hash ---\n");
    int n_iters = 50000;

    int k = 32, m = 16;
    GF2HashFunc *h = gf2_hash_create(k, m);
    gf2_hash_set_random(h);
    BitString *x = bitstring_create((size_t)k);
    BitString *out = bitstring_create((size_t)m);
    bitstring_randomize(x);
    x->bit_len = (size_t)k;

    HashBenchCtx ctx = {h, x, out};
    run_benchmark("GF(2) hash (32->16 bits)", bench_hash_func, &ctx, n_iters);

    GF2HashFunc *h2 = gf2_hash_create(64, 32);
    gf2_hash_set_random(h2);
    BitString *x2 = bitstring_create(64);
    BitString *out2 = bitstring_create(32);
    bitstring_randomize(x2);
    x2->bit_len = 64;

    HashBenchCtx ctx2 = {h2, x2, out2};
    run_benchmark("GF(2) hash (64->32 bits)", bench_hash_func, &ctx2, n_iters);

    bitstring_free(x); bitstring_free(out);
    bitstring_free(x2); bitstring_free(out2);
    gf2_hash_free(h); gf2_hash_free(h2);
}

/* ================================================================
 * Benchmark 5: PRG Operations
 * ================================================================ */

typedef struct {
    int n;
} SimplePRGParams;

static int bench_simple_prg_eval(const PRG *prg, const BitString *seed,
                                  BitString *output) {
    SimplePRGParams *p = (SimplePRGParams *)prg->params;
    int parity = 0;
    for (int i = 0; i < p->n; i++) {
        bitstring_set_bit(output, (size_t)i, bitstring_get_bit(seed, (size_t)i));
        parity ^= bitstring_get_bit(seed, (size_t)i);
    }
    bitstring_set_bit(output, (size_t)p->n, parity);
    output->bit_len = (size_t)(p->n + 1);
    return 0;
}

typedef struct {
    PRG *prg;
    BitString *seed;
    BitString *output;
} PRGBenchCtx;

static void bench_prg_eval_func(void *ctx) {
    PRGBenchCtx *c = (PRGBenchCtx *)ctx;
    prg_eval(c->prg, c->seed, c->output);
}

typedef struct {
    PRG *prg;
    BitString *key;
    BitString *pt;
    BitString *ct;
} StreamBenchCtx;

static void bench_stream_func(void *ctx) {
    StreamBenchCtx *c = (StreamBenchCtx *)ctx;
    prg_stream_encrypt(c->prg, c->key, c->pt, c->ct);
}

static void benchmark_prg(void) {
    printf("\n--- Benchmark 5: PRG Operations ---\n");

    SimplePRGParams *sp = (SimplePRGParams *)malloc(sizeof(SimplePRGParams));
    sp->n = 16;
    PRG *prg = prg_create(16, 17, bench_simple_prg_eval, sp, "bench-prg");
    BitString *seed = bitstring_create(16);
    BitString *output = bitstring_create(17);
    bitstring_randomize(seed);

    PRGBenchCtx ctx = {prg, seed, output};
    run_benchmark("PRG eval (16->17 bits, parity)", bench_prg_eval_func, &ctx, 50000);

    /* PRG iteration */
    void *ip = prg_iterate_params_create(prg, 64);
    PRG *iter_prg = prg_create(16, 64, prg_iterate_eval, ip, "iter-prg");
    BitString *seed2 = bitstring_create(16);
    BitString *output2 = bitstring_create(64);
    bitstring_randomize(seed2);

    PRGBenchCtx ctx2 = {iter_prg, seed2, output2};
    run_benchmark("PRG iterate (16->64 bits)", bench_prg_eval_func, &ctx2, 10000);

    /* Stream cipher throughput */
    BitString *key = bitstring_create(16);
    BitString *pt = bitstring_create(64);
    BitString *ct = bitstring_create(64);
    bitstring_randomize(key);
    bitstring_randomize(pt);

    StreamBenchCtx sctx = {iter_prg, key, pt, ct};
    run_benchmark("Stream encrypt (64-bit msg)", bench_stream_func, &sctx, 10000);

    bitstring_free(seed); bitstring_free(output);
    bitstring_free(seed2); bitstring_free(output2);
    bitstring_free(key); bitstring_free(pt); bitstring_free(ct);
    prg_free(iter_prg);
}

/* ================================================================
 * Benchmark 6: BitString Operations
 * ================================================================ */

typedef struct {
    BitString *a;
    BitString *b;
    BitString *c;
} BSBencCtx;

static void bench_xor_func(void *ctx) {
    BSBencCtx *c = (BSBencCtx *)ctx;
    bitstring_xor(c->a, c->b, c->c);
}

static void bench_concat_func(void *ctx) {
    BSBencCtx *c = (BSBencCtx *)ctx;
    static BitString *concat_out = NULL;
    if (!concat_out) concat_out = bitstring_create(128);
    bitstring_concat(c->a, c->b, concat_out);
}

static void bench_clone_func(void *ctx) {
    BSBencCtx *c = (BSBencCtx *)ctx;
    BitString *cl = bitstring_clone(c->a);
    bitstring_free(cl);
}

static void bench_equal_func(void *ctx) {
    BSBencCtx *c = (BSBencCtx *)ctx;
    bitstring_equal(c->a, c->b);
}

static void benchmark_bitstring_ops(void) {
    printf("\n--- Benchmark 6: BitString Operations ---\n");
    int n_iters = 100000;

    BitString *a = bitstring_create(64);
    BitString *b = bitstring_create(64);
    BitString *c = bitstring_create(64);
    bitstring_randomize(a);
    bitstring_randomize(b);

    BSBencCtx bs_ctx = {a, b, c};
    run_benchmark("BitString XOR (64-bit)", bench_xor_func, &bs_ctx, n_iters);
    run_benchmark("BitString concat (64+64)", bench_concat_func, &bs_ctx, n_iters);
    run_benchmark("BitString clone (64-bit)", bench_clone_func, &bs_ctx, n_iters);
    run_benchmark("BitString equal (64-bit)", bench_equal_func, &bs_ctx, n_iters);

    bitstring_free(a); bitstring_free(b); bitstring_free(c);
}

/* ================================================================
 * Benchmark 7: Full HILL Pipeline
 * ================================================================ */

typedef struct {
    OWF *base_owf;
} HILLBenchCtx;

static void bench_hill_full_func(void *ctx) {
    HILLBenchCtx *c = (HILLBenchCtx *)ctx;

    OWFWithHardcoreBit *owf_hc = owf_add_hardcore_bit(c->base_owf);
    PRG *prg_1bit = prg_one_bit_stretch(owf_hc);
    PRG *prg_final = prg_arbitrary_stretch(prg_1bit, 32);

    BitString *seed = bitstring_create(prg_final->n);
    BitString *output = bitstring_create(prg_final->output_len);
    bitstring_randomize(seed);
    prg_eval(prg_final, seed, output);

    bitstring_free(seed);
    bitstring_free(output);
    prg_free(prg_final);
    free(owf_hc);
}

static void benchmark_hill_pipeline(void) {
    printf("\n--- Benchmark 7: Full HILL Pipeline (OWF -> PRG) ---\n");
    int n_iters = 500;

    int n = 4;
    uint64_t weights[] = {3, 7, 11, 19};
    void *owf_params = subsetsum_params_create(n, weights, 64);
    OWF *base_owf = owf_create(n, subset_sum_owf_eval, owf_params, "bench-owf");

    HILLBenchCtx hctx = {base_owf};
    run_benchmark("Full HILL (OWF->PRG, 4->32 bits)", bench_hill_full_func, &hctx, n_iters);

    owf_free(base_owf);
}

/* ================================================================
 * Benchmark 8: Distribution and Entropy Operations
 * ================================================================ */

typedef struct {
    DistEnsemble *de;
    int n;
} DistBenchCtx;

static void bench_randomize_func(void *ctx) {
    DistBenchCtx *c = (DistBenchCtx *)ctx;
    dist_ensemble_randomize(c->de, c->n);
}

typedef struct {
    DistEnsemble *a;
    DistEnsemble *b;
} StatBenchCtx;

static void bench_stat_dist_func(void *ctx) {
    StatBenchCtx *c = (StatBenchCtx *)ctx;
    stat_distance_from_samples(c->a, c->b);
}

static void bench_entropy_func(void *ctx) {
    DistEnsemble *d = (DistEnsemble *)ctx;
    entropy_from_samples(d);
}

static int null_distinguisher_func(const BitString *sample, void *ctx) {
    (void)sample; (void)ctx;
    return rand() % 2;
}

typedef struct {
    DistEnsemble *X;
    DistEnsemble *Y;
} CompIndistCtx;

static void bench_comp_indist_func(void *ctx) {
    CompIndistCtx *c = (CompIndistCtx *)ctx;
    comp_indist_experiment(c->X, c->Y, 20, null_distinguisher_func, NULL);
}

static void benchmark_distribution_ops(void) {
    printf("\n--- Benchmark 8: Distribution/Entropy Operations ---\n");

    DistEnsemble *de = dist_ensemble_create(16);
    int n_samples = 100;

    DistBenchCtx dctx = {de, n_samples};
    run_benchmark("DistEnsemble randomize (100x16bit)", bench_randomize_func, &dctx, 500);

    DistEnsemble *de2 = dist_ensemble_create(16);
    dist_ensemble_randomize(de2, 50);

    StatBenchCtx sctx = {de, de2};
    run_benchmark("Statistical distance (50 vs 100)", bench_stat_dist_func, &sctx, 500);
    run_benchmark("Entropy estimation (100 samples)", bench_entropy_func, de, 500);

    CompIndistCtx cctx = {de, de2};
    run_benchmark("Comp indist experiment (20 trials)", bench_comp_indist_func, &cctx, 200);

    dist_ensemble_free(de);
    dist_ensemble_free(de2);
}

/* ================================================================
 * Main
 * ================================================================ */

int main(void) {
    seed_random();
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║  OWF ⇔ PRG Equivalence — Performance Benchmarks   ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");
    printf("Platform: C99, GCC/Clang, no hardware acceleration\n");
    printf("Timer: clock() with CLOCKS_PER_SEC = %ld\n\n",
           (long)CLOCKS_PER_SEC);

    double total_start = get_time_seconds();

    benchmark_owf_candidates();
    benchmark_modular_arithmetic();
    benchmark_gl_inner_product();
    benchmark_gf2_hash();
    benchmark_prg();
    benchmark_bitstring_ops();
    benchmark_hill_pipeline();
    benchmark_distribution_ops();

    double total_elapsed = get_time_seconds() - total_start;
    printf("\n══════════════════════════════════════════════════════\n");
    printf("Total benchmark time: %.3f seconds\n", total_elapsed);
    printf("All benchmarks completed successfully.\n");
    printf("══════════════════════════════════════════════════════\n");

    return 0;
}
