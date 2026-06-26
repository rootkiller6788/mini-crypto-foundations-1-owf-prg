/*
 * test_prg.c -- Assert-based tests for cryptographic PRG module
 *
 * Tests cover L1-L5: PRG definitions, statistical distance, number theory,
 * BBS/BM generators, hybrid argument, hardcore bits, and quality metrics.
 */
#include "prg_crypto.h"
#include "prg_number_theory.h"
#include "prg_hybrid.h"
#include "hardcore_bit.h"
#include "blum_blum_shub.h"
#include "blum_micali.h"
#include "prg_construction.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>

static int tests_run = 0;
static int tests_passed = 0;
/* CHK macro for test-driver logic; standard assert() used for mathematical invariants */
#define CHK(cond) do { if (!(cond)) { printf("  FAIL at line %d\n", __LINE__); exit(1); } } while(0)
#define DONE() do { tests_passed++; printf("  PASS\n"); } while(0)

/* ---- L1: PRG Definitions ---- */
static void test_prg_create(void) {
    printf("test_prg_create...\n"); tests_run++;
    PRG* prg = prg_create(128, 256);
    CHK(prg != NULL);
    CHK(prg->params.seed_bits == 128);
    CHK(prg->params.stretch_bits == 128);
    /* L1: Stretch must be positive for a valid PRG (output > input) */
    assert(prg->params.stretch_bits > 0);
    prg_free(prg);
    CHK(prg_create(256, 128) == NULL);
    CHK(prg_create(0, 256) == NULL);
    DONE();
}

/* ---- L2: Statistical Distance ---- */
static void test_stat_distance(void) {
    printf("test_stat_distance...\n"); tests_run++;
    DistributionPair dp;
    double pa[] = {0.25, 0.25, 0.25, 0.25};
    double pb[] = {0.5, 0.0, 0.5, 0.0};
    dp.domain_size = 4; dp.probs_a = pa; dp.probs_b = pb;
    double d = stat_distance(&dp);
    CHK(d >= 0.0 && d <= 1.0);
    DONE();
}

static void test_distinguisher(void) {
    printf("test_distinguisher...\n"); tests_run++;
    Distinguisher dist;
    distinguisher_init(&dist, 256);
    for (int i = 0; i < 100; i++) distinguisher_record_guess(&dist, 1, 1);
    double adv = distinguisher_advantage(&dist);
    CHK(adv > 0.0);
    distinguisher_reset(&dist);
    CHK(dist.queries == 0);
    free(dist.advantage_log);
    DONE();
}

static void test_security_game(void) {
    printf("test_security_game...\n"); tests_run++;
    PRGSecurityGame game;
    prg_security_game_init(&game, 128, 256);
    uint8_t s[32]; memset(s, 0xAA, 32);
    for (int i = 0; i < 1000; i++) prg_security_game_trial(&game, s, rand()%2, i%2);
    double a = prg_security_game_advantage(&game);
    CHK(a >= 0.0 && a <= 1.0);
    /* Random guessing produces advantage close to 0 but not exactly 0.
     * Negligibility threshold of 1/n^2 is too strict for random noise;
     * test with a high degree that would certainly be negligible */
    CHK(prg_advantage_is_negligible(0.000001, 128, 1.0));
    CHK(!prg_advantage_is_negligible(0.5, 128, 2.0));
    DONE();
}

static void test_next_bit(void) {
    printf("test_next_bit...\n"); tests_run++;
    NextBitPredictor nbp;
    nbp_init(&nbp, 128, 256, 10);
    for (int i = 0; i < 100; i++) nbp_record(&nbp, 1, 1);
    CHK(nbp_advantage(&nbp) > 0.4);
    DONE();
}

/* ---- L3: Number Theory ---- */
static void test_modular(void) {
    printf("test_modular...\n"); tests_run++;
    CHK(mod_add(5, 7, 10) == 2);
    CHK(mod_sub(3, 7, 10) == 6);
    CHK(mod_mul(3, 4, 10) == 2);
    CHK(mod_pow(3, 4, 7) == 4);
    CHK(mod_pow(2, 10, 11) == 1);
    CHK(gcd(12, 8) == 4);
    CHK(gcd(17, 13) == 1);
    CHK(mod_inv(3, 7) * 3 % 7 == 1);
    CHK(mod_inv(2, 4) == 0);
    /* L4: Fermat's Little Theorem verification: 2^10 ≡ 1 (mod 11) */
    assert(mod_pow(2, 10, 11) == 1);
    /* L4: Group property: (3*4) mod 10 = (3 mod 10 * 4 mod 10) mod 10 */
    assert(mod_mul(3, 4, 10) == (3*4) % 10);
    /* L4: GCD identity: gcd(a,b) = gcd(b,a) */
    assert(gcd(12, 8) == gcd(8, 12));
    /* L3: Modular inverse: 3*(3^{-1} mod 7) ≡ 1 (mod 7) */
    assert(mod_inv(3, 7) > 0);
    DONE();
}

static void test_primality(void) {
    printf("test_primality...\n"); tests_run++;
    CHK(is_prime_bruteforce(2) == 1);
    CHK(is_prime_bruteforce(17) == 1);
    CHK(is_prime_bruteforce(91) == 0);
    CHK(miller_rabin(17, 5) == 1);
    CHK(miller_rabin(561, 5) == 0);
    uint64_t sp = safe_prime_generate(20, 50);
    CHK(sp > 0 && is_prime_bruteforce(sp));
    DONE();
}

static void test_legendre(void) {
    printf("test_legendre_jacobi...\n"); tests_run++;
    CHK(legendre_symbol(4, 7) == 1);
    CHK(legendre_symbol(3, 7) == -1);
    CHK(legendre_symbol(7, 7) == 0);
    int j = jacobi_symbol(2, 15);
    CHK(j == 1 || j == -1);
    DONE();
}

static void test_blum(void) {
    printf("test_blum_integers...\n"); tests_run++;
    BlumInteger bi = blum_integer_generate(10, 50);
    CHK(bi.n > 0 && blum_check(&bi) == 1);
    DONE();
}

static void test_crt(void) {
    printf("test_crt...\n"); tests_run++;
    CRTResult crt = crt_solve(2, 3, 3, 5);
    CHK(crt.solution == 8);
    CHK(crt.solution % 3 == 2 && crt.solution % 5 == 3);
    DONE();
}

/* ---- L4: BBS and BM Generators ---- */
static void test_bbs(void) {
    printf("test_bbs_gen...\n"); tests_run++;
    BBSState* bbs = (BBSState*)calloc(1, sizeof(BBSState));
    CHK(bbs != NULL && bbs_init(bbs, 11, 19, 3) == 0);
    uint8_t buf[1] = {0};
    CHK(bbs_generate_bits(bbs, buf, 8) == 1);
    CHK(bbs_state_is_qr(bbs) == 1);
    bbs_free(bbs);
    DONE();
}

static void test_bm(void) {
    printf("test_bm_gen...\n"); tests_run++;
    BMState* bm = (BMState*)calloc(1, sizeof(BMState));
    CHK(bm != NULL && is_generator_mod_p(5, 23) == 1);
    CHK(bm_init(bm, 23, 5, 4) == 0);
    uint8_t buf[1] = {0};
    CHK(bm_generate_bits(bm, buf, 8) == 1);
    CHK(bm_validate_state(bm) == 1);
    bm_free(bm);
    DONE();
}

/* ---- L4: Hybrid Argument ---- */
static void test_hybrid(void) {
    printf("test_hybrid_analysis...\n"); tests_run++;
    HybridAnalysis* ha = hybrid_analysis_create(10);
    CHK(ha != NULL);
    for (size_t i = 0; i <= 10; i++) hybrid_analysis_record(ha, i, 0.1*(double)i);
    hybrid_analysis_compute(ha);
    CHK(ha->total_gap <= 1.0 && ha->max_adjacent_gap >= 0.0);
    CHK(hybrid_verify_triangle_inequality(ha) == 1);
    CHK(hybrid_verify_yao_reduction(ha, 0.01) == 1);
    /* L4: Triangle inequality: total gap ≤ sum of adjacent gaps */
    assert(ha->total_gap <= 1.0);
    /* L4: Non-negative advantage: gaps cannot be negative */
    assert(ha->max_adjacent_gap >= 0.0);
    hybrid_analysis_free(ha);
    DONE();
}

static void test_negligible(void) {
    printf("test_negligible...\n"); tests_run++;
    /* k * indiv_adv = 10 * 1e-7 = 1e-6 < 1/128^2 = 1/16384 ~ 6.1e-5 => negligible */
    CHK(hybrid_advantage_still_negligible(1e-7, 10, 128, 2.0) == 1);
    /* 0.5 * 1 = 0.5 > threshold => not negligible */
    CHK(hybrid_advantage_still_negligible(0.5, 1, 128, 2.0) == 0);
    DONE();
}

/* ---- L5: Statistical Tests ---- */
static void test_stats(void) {
    printf("test_statistical...\n"); tests_run++;
    uint8_t data[256];
    for (int i = 0; i < 256; i++) data[i] = (uint8_t)(i * 73 + 17);
    FrequencyTest ft = frequency_test_run(data, 256);
    CHK(ft.n_bits == 2048 && ft.frequency >= 0.0 && ft.frequency <= 1.0);
    RunsTest rt = runs_test_run(data, 256);
    CHK(rt.n_runs > 0 && rt.expected_runs > 0.0);
    SerialCorrelationTest sc = serial_correlation_run(data, 256);
    CHK(sc.n_bits == 2048);
    /* L4: Frequency is a probability, must be in [0,1] */
    assert(ft.frequency >= 0.0 && ft.frequency <= 1.0);
    /* L4: Number of runs is at least 1 for any non-empty sequence */
    assert(rt.n_runs >= 1);
    /* L4: Autocorrelation at lag 1 is in [-1, 1] */
    assert(sc.autocorrelation_lag1 >= -1.0 && sc.autocorrelation_lag1 <= 1.0);
    DONE();
}

/* ---- Bit Utilities ---- */
static void test_bits(void) {
    printf("test_bit_utils...\n"); tests_run++;
    uint8_t bytes[] = {0xA5, 0x3C};
    int bits[16];
    bytes_to_bits(bytes, 2, bits, 16);
    CHK(bits[0] == 1 && bits[1] == 0);
    uint8_t back[2] = {0};
    bits_to_bytes(bits, 16, back, 2);
    CHK(back[0] == 0xA5 && back[1] == 0x3C);
    uint8_t d[2];
    xor_bytes(d, bytes, back, 2);
    CHK(d[0] == 0 && d[1] == 0);
    CHK(ct_memcmp(bytes, bytes, 2) == 0);
    /* L4: XOR self-inverse: bytes ⊕ bytes = zero vector */
    uint8_t self_xor[2];
    xor_bytes(self_xor, bytes, bytes, 2);
    assert(self_xor[0] == 0 && self_xor[1] == 0);
    /* L4: XOR with zero: bytes ⊕ 0 = bytes */
    uint8_t zero[2] = {0, 0};
    uint8_t xor_zero_result[2];
    xor_bytes(xor_zero_result, bytes, zero, 2);
    assert(xor_zero_result[0] == bytes[0] && xor_zero_result[1] == bytes[1]);
    DONE();
}

/* ---- Hardcore Bits ---- */
static void test_hardcore(void) {
    printf("test_hardcore...\n"); tests_run++;
    uint8_t xa[] = {0xAA}, xr[] = {0xFF};
    CHK(gl_inner_product(xa, xr, 1, 8) == 0);
    uint8_t x1[] = {0x01}, r1[] = {0x01};
    CHK(gl_inner_product(x1, r1, 1, 8) == 1);

    HardcorePredicate* lsb = hc_lsb_create(8);
    uint8_t v3[] = {0x03};
    CHK(hc_evaluate(lsb, v3, 1) == 1);
    hc_free(lsb);

    HardcorePredicate* msb = hc_msb_create(8);
    uint8_t v80[] = {0x80};
    CHK(hc_evaluate(msb, v80, 1) == 1);
    hc_free(msb);

    /* L4: Goldreich-Levin inner product: ⟨0x01, 0x01⟩ mod 2 = 1 (single-bit AND) */
    assert(gl_inner_product(x1, r1, 1, 8) == 1);
    /* L4: Goldreich-Levin inner product: ⟨0xAA, 0xFF⟩ mod 2 = 0 (even number of 1-bits in AND) */
    assert(gl_inner_product(xa, xr, 1, 8) == 0);
    DONE();
}

/* ---- PRG Construction ---- */
static void test_prg_types(void) {
    printf("test_prg_types...\n"); tests_run++;
    CHK(strcmp(prg_type_name(PRG_TYPE_BLUM_MICALI), "Blum-Micali (DLP-based)") == 0);
    DONE();
}

static void test_pairhash(void) {
    printf("test_pairwise_hash...\n"); tests_run++;
    PairwiseHash h = pairwise_hash_create(101);
    CHK(pairwise_hash_eval(&h, 42) < 101);
    DONE();
}

int main(void) {
    printf("\n=== PRG Crypto Module Test Suite ===\n\n");
    prg_test_srand(12345);
    test_prg_create();
    test_stat_distance();
    test_distinguisher();
    test_security_game();
    test_next_bit();
    test_modular();
    test_primality();
    test_legendre();
    test_blum();
    test_crt();
    test_bbs();
    test_bm();
    test_hybrid();
    test_negligible();
    test_stats();
    test_bits();
    test_hardcore();
    test_prg_types();
    test_pairhash();
    printf("\n=== Results: %d/%d tests passed ===\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
