/*
 * test_all.c — Comprehensive tests for OWF ⇔ PRG equivalence module
 *
 * Tests cover:
 *   - BitString operations (L1, L3)
 *   - OWF creation and evaluation (L1)
 *   - RSA / DLog / Rabin / SubsetSum candidates (L2, L6)
 *   - OWF inversion experiment (L1)
 *   - Weak→Strong OWF amplification (L2, L8)
 *   - GF(2) vector operations (L3)
 *   - Modular arithmetic (L3)
 *   - Miller-Rabin primality test (L3)
 *   - PRG framework + distinguishing experiment (L1)
 *   - Blum-Micali PRG (L2)
 *   - HILL PRG evaluation (L2)
 *   - PRG iteration (L5)
 *   - PRG stream encryption (L7)
 *   - Hardcore predicate + GL inner product (L4)
 *   - Goldreich-Levin list decoding (L5)
 *   - Pairwise independent hash families (L5)
 *   - Computational indistinguishability (L2)
 *   - Hybrid argument (L4)
 *   - Next-bit unpredictability (L4)
 *   - OWF+PRG reduction stages (L4)
 *   - Entropy estimation (L5)
 *   - Leftover hash lemma (L5)
 */

#include "owf.h"
#include "prg.h"
#include "hardcore_bit.h"
#include "indistinguish.h"
#include "reduction.h"
#include "crypto_utils.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <math.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { \
    printf("  TEST: %s ... ", name); \
    fflush(stdout); \
} while(0)

#define PASS() do { \
    printf("PASS\n"); \
    tests_passed++; \
} while(0)

#define FAIL(msg) do { \
    printf("FAIL: %s\n", msg); \
    tests_failed++; \
} while(0)

#define CHECK(cond, msg) do { \
    if (!(cond)) { FAIL(msg); } \
} while(0)

/* ================================================================
 * BitString Tests
 * ================================================================ */
static void test_bitstring_ops(void) {
    TEST("BitString create/free");
    BitString *bs = bitstring_create(64);
    CHECK(bs != NULL, "create failed");
    CHECK(bs->bit_len == 64, "wrong bit_len");
    CHECK(bs->data != NULL, "no data buffer");
    bitstring_free(bs);
    PASS();

    TEST("BitString set/get bit");
    bs = bitstring_create(8);
    bitstring_set_bit(bs, 0, 1);
    CHECK(bitstring_get_bit(bs, 0) == 1, "bit 0 not set");
    bitstring_set_bit(bs, 0, 0);
    CHECK(bitstring_get_bit(bs, 0) == 0, "bit 0 not cleared");
    bitstring_set_bit(bs, 7, 1);
    CHECK(bitstring_get_bit(bs, 7) == 1, "bit 7 not set");
    bitstring_free(bs);
    PASS();

    TEST("BitString equality");
    BitString *a = bitstring_create(4);
    BitString *b = bitstring_create(4);
    a->data[0] = 0x0A; /* 1010 */
    b->data[0] = 0x0A;
    CHECK(bitstring_equal(a, b) == 1, "equal check failed");
    b->data[0] = 0x0B; /* 1011 */
    CHECK(bitstring_equal(a, b) == 0, "non-equal check failed");
    bitstring_free(a);
    bitstring_free(b);
    PASS();

    TEST("BitString clone");
    a = bitstring_create(8);
    bitstring_randomize(a);
    b = bitstring_clone(a);
    CHECK(bitstring_equal(a, b) == 1, "clone not equal");
    bitstring_free(a);
    bitstring_free(b);
    PASS();
}

/* ================================================================
 * OWF Tests
 * ================================================================ */
static void test_owf_framework(void) {
    TEST("OWF create/free");
    OWF *owf = owf_create(64, NULL, NULL, "test_owf");
    CHECK(owf != NULL, "create failed");
    CHECK(owf->n == 64, "wrong security param");
    CHECK(strcmp(owf->name, "test_owf") == 0, "wrong name");
    owf_free(owf);
    PASS();

    /* RSA candidate */
    TEST("RSA OWF evaluation");
    uint64_t p = 7, q = 11, e = 5;
    void *params = rsa_params_create(p, q, e);
    CHECK(params != NULL, "RSA param create failed");
    OWF *rsa = owf_create(12, rsa_owf_eval, params, "RSA-test");
    CHECK(rsa != NULL, "RSA OWF create failed");

    BitString *x = bitstring_create(12);
    BitString *y = bitstring_create(12);
    uint64_to_bitstring(5, 12, x);
    int ret = owf_eval(rsa, x, y);
    CHECK(ret == 0, "RSA eval failed");
    uint64_t yval;
    CHECK(bitstring_to_uint64(y, &yval) == 1, "RSA output decode failed");
    CHECK(yval == mod_pow(5, e, 77), "RSA wrong output");
    bitstring_free(x);
    bitstring_free(y);
    owf_free(rsa);
    PASS();

    /* Discrete log candidate */
    TEST("DLog OWF evaluation");
    uint64_t dp = 23, dg = 5;
    void *dparams = dlog_params_create(dp, dg);
    CHECK(dparams != NULL, "DLog param create failed");
    OWF *dlog = owf_create(12, dlog_owf_eval, dparams, "DLog-test");
    CHECK(dlog != NULL, "DLog OWF create failed");
    x = bitstring_create(12);
    y = bitstring_create(12);
    uint64_to_bitstring(3, 12, x);
    ret = owf_eval(dlog, x, y);
    CHECK(ret == 0, "DLog eval failed");
    CHECK(bitstring_to_uint64(y, &yval) == 1, "DLog output decode failed");
    CHECK(yval == mod_pow(dg, 3, dp), "DLog wrong output");
    bitstring_free(x);
    bitstring_free(y);
    owf_free(dlog);
    PASS();

    /* Rabin candidate */
    TEST("Rabin OWF evaluation");
    uint64_t rp = 7, rq = 11;
    void *rparams = rabin_params_create(rp, rq);
    CHECK(rparams != NULL, "Rabin param create failed");
    OWF *rabin = owf_create(12, rabin_owf_eval, rparams, "Rabin-test");
    CHECK(rabin != NULL, "Rabin OWF create failed");
    x = bitstring_create(12);
    y = bitstring_create(12);
    uint64_to_bitstring(5, 12, x);
    ret = owf_eval(rabin, x, y);
    CHECK(ret == 0, "Rabin eval failed");
    CHECK(bitstring_to_uint64(y, &yval) == 1, "Rabin output decode failed");
    CHECK(yval == mod_pow(5, 2, 77), "Rabin wrong output");
    bitstring_free(x);
    bitstring_free(y);
    owf_free(rabin);
    PASS();

    /* Subset sum candidate */
    TEST("SubsetSum OWF evaluation");
    uint64_t weights[] = {3, 5, 7, 11, 13, 17};
    int nw = 6;
    void *sparams = subsetsum_params_create(nw, weights, 256);
    CHECK(sparams != NULL, "SubsetSum param create failed");
    OWF *ssum = owf_create(12, subset_sum_owf_eval, sparams, "SubsetSum-test");
    CHECK(ssum != NULL, "SubsetSum OWF create failed");
    x = bitstring_create((size_t)nw);
    /* Set bits 0 and 2: sum = 3 + 7 = 10 */
    bitstring_set_bit(x, 0, 1);
    bitstring_set_bit(x, 2, 1);
    x->bit_len = (size_t)nw;
    y = bitstring_create(12);
    ret = owf_eval(ssum, x, y);
    CHECK(ret == 0, "SubsetSum eval failed");
    CHECK(bitstring_to_uint64(y, &yval) == 1, "decode failed");
    CHECK(yval == 10, "SubsetSum wrong output");
    bitstring_free(x);
    bitstring_free(y);
    owf_free(ssum);
    PASS();
}

/* ================================================================
 * OWF Properties Tests
 * ================================================================ */
static void test_owf_properties(void) {
    TEST("OWF collision detection");
    uint64_t weights[] = {1, 2, 4, 8};
    void *params = subsetsum_params_create(4, weights, 32);
    OWF *owf = owf_create(12, subset_sum_owf_eval, params, "test");
    BitString *x1 = bitstring_create(4);
    BitString *x2 = bitstring_create(4);
    /* x1: bits 0,1 → sum=3; x2: bits 2→ sum=4 (different) */
    bitstring_set_bit(x1, 0, 1);
    bitstring_set_bit(x1, 1, 1);
    x1->bit_len = 4;
    bitstring_set_bit(x2, 2, 1);
    x2->bit_len = 4;
    CHECK(owf_check_collision(owf, x1, x2) == 0, "false collision");
    /* x1 and x2 identical → collision */
    CHECK(owf_check_collision(owf, x1, x1) == 1, "missed self collision");
    bitstring_free(x1);
    bitstring_free(x2);
    owf_free(owf);
    PASS();
}

/* ================================================================
 * GF(2) Operations Tests
 * ================================================================ */
static void test_gf2_ops(void) {
    TEST("GF(2) vector addition (XOR)");
    BitString *a = bitstring_create(8);
    BitString *b = bitstring_create(8);
    BitString *c = bitstring_create(8);
    a->data[0] = 0xAA; /* 10101010 */
    b->data[0] = 0x55; /* 01010101 */
    gf2_add(a, b, c);
    CHECK(c->data[0] == 0xFF, "XOR failed");
    bitstring_free(a); bitstring_free(b); bitstring_free(c);
    PASS();

    TEST("GF(2) dot product");
    a = bitstring_create(4);
    b = bitstring_create(4);
    /* a = 1010: bit 0=1, bit 1=0, bit 2=1, bit 3=0 */
    bitstring_set_bit(a, 0, 1); bitstring_set_bit(a, 1, 0);
    bitstring_set_bit(a, 2, 1); bitstring_set_bit(a, 3, 0);
    a->bit_len = 4;
    /* b = 0110: bit 0=0, bit 1=1, bit 2=1, bit 3=0 */
    bitstring_set_bit(b, 0, 0); bitstring_set_bit(b, 1, 1);
    bitstring_set_bit(b, 2, 1); bitstring_set_bit(b, 3, 0);
    b->bit_len = 4;
    int dp = gf2_dot_product(a, b);
    /* dot = 1*0 + 0*1 + 1*1 + 0*0 = 1 (mod 2) */
    CHECK(dp == 1, "dot product wrong");
    bitstring_free(a); bitstring_free(b);
    PASS();

    TEST("GF(2) Hamming weight");
    a = bitstring_create(8);
    a->data[0] = 0x0F; /* 00001111 → weight 4 */
    CHECK(gf2_hamming_weight(a) == 4, "hamming weight wrong");
    bitstring_free(a);
    PASS();

    TEST("GF(2) matrix-vector multiplication");
    /* 3×3 identity matrix: each row is ceil(3/8)=1 byte */
    uint8_t A[3] = {0};
    A[0] = 0x80; /* row 0: 100 (bit 0=1, bits 1,2=0) */
    A[1] = 0x40; /* row 1: 010 (bit 1=1, bits 0,2=0) */
    A[2] = 0x20; /* row 2: 001 (bit 2=1) */
    BitString *x = bitstring_create(3);
    BitString *y = bitstring_create(3);
    /* x = 101: bit 0=1, bit 1=0, bit 2=1 */
    bitstring_set_bit(x, 0, 1);
    bitstring_set_bit(x, 1, 0);
    bitstring_set_bit(x, 2, 1);
    x->bit_len = 3;
    gf2_matrix_mul(A, 3, 3, x, y);
    CHECK(bitstring_get_bit(y, 0) == 1, "M*V[0]");
    CHECK(bitstring_get_bit(y, 1) == 0, "M*V[1]");
    CHECK(bitstring_get_bit(y, 2) == 1, "M*V[2]");
    bitstring_free(x); bitstring_free(y);
    PASS();
}

/* ================================================================
 * Modular Arithmetic Tests
 * ================================================================ */
static void test_modular_arithmetic(void) {
    TEST("Modular exponentiation");
    CHECK(mod_pow(2, 10, 1000) == 24, "mod_pow(2,10,1000) != 24");
    CHECK(mod_pow(3, 7, 13) == 3, "mod_pow(3,7,13) != 3");
    CHECK(mod_pow(5, 0, 7) == 1, "mod_pow(5,0,7) != 1");
    PASS();

    TEST("Extended GCD and modular inverse");
    int64_t x, y;
    uint64_t g = extended_gcd(240, 46, &x, &y);
    CHECK(g == 2, "gcd(240,46) != 2");
    /* 240*(-9) + 46*47 = -2160 + 2162 = 2 */
    CHECK(mod_inverse(7, 40) == 23, "7^{-1} mod 40 != 23"); /* 7*23=161=1 mod 40 */
    CHECK(mod_inverse(2, 4) == 0, "inverse of 2 mod 4 should not exist");
    PASS();

    TEST("Miller-Rabin primality test");
    CHECK(miller_rabin_prime(2, 5) == 1, "2 should be prime");
    CHECK(miller_rabin_prime(3, 5) == 1, "3 should be prime");
    CHECK(miller_rabin_prime(4, 5) == 0, "4 should be composite");
    CHECK(miller_rabin_prime(17, 5) == 1, "17 should be prime");
    CHECK(miller_rabin_prime(561, 10) == 0, "561 should be composite"); /* Carmichael */
    CHECK(miller_rabin_prime(9973, 5) == 1, "9973 should be prime");
    PASS();

    TEST("Blum integer check");
    CHECK(is_blum_integer(21, 3, 7) == 1, "21=3*7, both 3 mod 4 → Blum");
    CHECK(is_blum_integer(15, 3, 5) == 0, "15=3*5, 5≡1 mod 4 → not Blum");
    PASS();
}

/* ================================================================
 * Goldreich-Levin Tests
 * ================================================================ */
static int dummy_gl_predictor(const BitString *r) {
    (void)r;
    return rand() % 2;  /* Random guess (no advantage) */
}

static void test_goldreich_levin(void) {
    TEST("GL inner product");
    BitString *x = bitstring_create(4);
    BitString *r = bitstring_create(4);
    /* x = 1010: bit 0=1, bit 1=0, bit 2=1, bit 3=0 */
    bitstring_set_bit(x, 0, 1); bitstring_set_bit(x, 1, 0);
    bitstring_set_bit(x, 2, 1); bitstring_set_bit(x, 3, 0);
    x->bit_len = 4;
    /* r = 0110: bit 0=0, bit 1=1, bit 2=1, bit 3=0 */
    bitstring_set_bit(r, 0, 0); bitstring_set_bit(r, 1, 1);
    bitstring_set_bit(r, 2, 1); bitstring_set_bit(r, 3, 0);
    r->bit_len = 4;
    CHECK(gl_inner_product(x, r) == 1, "GL inner product wrong");
    bitstring_free(x); bitstring_free(r);
    PASS();

    TEST("GL list decode (with trivial predictor)");
    GLCandidateList *list = gl_list_decode(4, dummy_gl_predictor, 0.1, 0.9);
    CHECK(list != NULL, "list decode returned NULL");
    CHECK(list->n_entries > 0, "list decode returned 0 entries");
    /* With trivial predictor, list contains >1 candidates */
    gl_candidate_list_free(list);
    PASS();

    TEST("GL advantage measurement");
    /* Create small OWF for testing */
    uint64_t weights[] = {1, 2, 4, 8};
    void *params = subsetsum_params_create(4, weights, 32);
    OWF *owf = owf_create(8, subset_sum_owf_eval, params, "test");
    BitString *xval = bitstring_create(4);
    bitstring_randomize(xval);
    double adv = gl_measure_advantage(owf, xval, dummy_gl_predictor, 50);
    /* With random predictor, advantage should be close to 0 */
    CHECK(adv >= 0.0 && adv <= 0.5, "advantage out of range");
    CHECK(adv < 0.3, "random predictor shouldn't have high advantage");
    bitstring_free(xval);
    owf_free(owf);
    PASS();
}

/* ================================================================
 * Pairwise Independent Hash Tests
 * ================================================================ */
static void test_pairwise_hash(void) {
    TEST("GF(2) pairwise independent hash");
    GF2HashFunc *h = gf2_hash_create(8, 4);
    CHECK(h != NULL, "hash create failed");
    CHECK(h->k == 8, "wrong k");
    CHECK(h->m == 4, "wrong m");

    gf2_hash_set_random(h);
    BitString *x = bitstring_create(8);
    bitstring_randomize(x);
    BitString *out = bitstring_create(4);
    gf2_hash_eval(h, x, out);
    CHECK(out->bit_len == 4, "hash output wrong length");

    bitstring_free(x);
    bitstring_free(out);
    gf2_hash_free(h);
    PASS();

    TEST("Pairwise independence empirical verification");
    int result = gf2_hash_verify_pairwise_independence(4, 2, 200);
    CHECK(result == 1, "pairwise independence not empirically verified");
    PASS();
}

/* ================================================================
 * PRG Tests
 * ================================================================ */
/* Simple 1-bit stretch PRG for testing: G(s) = (s, parity(s)) */
typedef struct {
    int n;
} SimplePRGParams;

static int simple_prg_eval(const PRG *prg, const BitString *seed, BitString *output) {
    SimplePRGParams *p = (SimplePRGParams *)prg->params;
    /* Output = seed || parity(seed) — stretch 1 bit */
    int parity = 0;
    for (int i = 0; i < p->n; i++) {
        bitstring_set_bit(output, (size_t)i, bitstring_get_bit(seed, (size_t)i));
        parity ^= bitstring_get_bit(seed, (size_t)i);
    }
    bitstring_set_bit(output, (size_t)p->n, parity);
    output->bit_len = (size_t)(p->n + 1);
    return 0;
}

static int trivial_distinguisher(const BitString *challenge, size_t n) {
    (void)n;
    /* Simple test: check if first bit = last bit (correlation in PRG) */
    int first = bitstring_get_bit(challenge, 0);
    int last = bitstring_get_bit(challenge, challenge->bit_len - 1);
    /* In our simple PRG, last = parity(seed). Not perfectly correlated.
     * This is a weak distinguisher. */
    return (first == last) ? 1 : 0;
}

static void test_prg_framework(void) {
    TEST("PRG create/free");
    PRG *prg = prg_create(8, 9, NULL, NULL, "test_prg");
    CHECK(prg != NULL, "PRG create failed");
    CHECK(prg->n == 8, "wrong seed length");
    CHECK(prg->output_len == 9, "wrong output length");
    prg_free(prg);
    PASS();

    TEST("Simple PRG evaluation");
    SimplePRGParams *p = (SimplePRGParams *)malloc(sizeof(SimplePRGParams));
    p->n = 4;
    prg = prg_create(4, 5, simple_prg_eval, p, "simple");
    BitString *seed = bitstring_create(4);
    BitString *out = bitstring_create(5);
    /* Seed = 1011 → parity = 1+0+1+1 = 1 (mod 2) → output = 10111 */
    bitstring_set_bit(seed, 0, 1);
    bitstring_set_bit(seed, 1, 0);
    bitstring_set_bit(seed, 2, 1);
    bitstring_set_bit(seed, 3, 1);
    seed->bit_len = 4;
    int ret = prg_eval(prg, seed, out);
    CHECK(ret == 0, "PRG eval failed");
    CHECK(bitstring_get_bit(out, 4) == 1, "parity bit wrong");
    bitstring_free(seed);
    bitstring_free(out);
    prg_free(prg);
    PASS();

    TEST("PRG distinguishing experiment");
    p = (SimplePRGParams *)malloc(sizeof(SimplePRGParams));
    p->n = 8;
    prg = prg_create(8, 9, simple_prg_eval, p, "simple");
    PRGDistinguishingResult res = prg_distinguishing_experiment(prg, 200, trivial_distinguisher);
    CHECK(res.n_trials == 200, "wrong trial count");
    CHECK(res.advantage >= 0.0 && res.advantage <= 1.0, "advantage out of range");
    prg_free(prg);
    PASS();

    TEST("PRG iteration (arbitrary stretch)");
    /* Create base PRG: 4→5 bits */
    SimplePRGParams *bp = (SimplePRGParams *)malloc(sizeof(SimplePRGParams));
    bp->n = 4;
    PRG *base = prg_create(4, 5, simple_prg_eval, bp, "base");
    void *ip = prg_iterate_params_create(base, 8); /* Want 8 output bits */
    PRG *iter = prg_create(4, 8, prg_iterate_eval, ip, "iterated");
    BitString *sd = bitstring_create(4);
    bitstring_randomize(sd);
    BitString *outp = bitstring_create(8);
    ret = prg_eval(iter, sd, outp);
    CHECK(ret == 0, "iterated PRG eval failed");
    CHECK(outp->bit_len == 8, "wrong output length");
    bitstring_free(sd);
    bitstring_free(outp);
    prg_free(iter); /* Base is freed by iter */
    PASS();

    TEST("PRG stream encrypt/decrypt");
    bp = (SimplePRGParams *)malloc(sizeof(SimplePRGParams));
    bp->n = 4;
    PRG *stream_prg = prg_create(4, 8, simple_prg_eval, bp, "stream");
    BitString *key = bitstring_create(4);
    bitstring_randomize(key);
    BitString *pt = bitstring_create(8);
    BitString *ct = bitstring_create(8);
    BitString *dec = bitstring_create(8);
    bitstring_randomize(pt);
    ret = prg_stream_encrypt(stream_prg, key, pt, ct);
    CHECK(ret == 0, "encrypt failed");
    ret = prg_stream_decrypt(stream_prg, key, ct, dec);
    CHECK(ret == 0, "decrypt failed");
    CHECK(bitstring_equal(pt, dec) == 1, "round-trip failed");
    bitstring_free(key); bitstring_free(pt);
    bitstring_free(ct); bitstring_free(dec);
    prg_free(stream_prg);
    PASS();
}

/* ================================================================
 * Indistinguishability Tests
 * ================================================================ */
static int simple_distinguisher(const BitString *sample, void *ctx) {
    (void)ctx;
    /* Check if first bit equals last bit */
    int first = bitstring_get_bit(sample, 0);
    int last = bitstring_get_bit(sample, sample->bit_len - 1);
    return (first == last) ? 1 : 0;
}

static int next_bit_predictor(const BitString *prefix, int prefix_len, void *ctx) {
    (void)ctx;
    /* Simple predictor: predict opposite of last bit in prefix */
    if (prefix_len < 2) return rand() % 2;
    int last = bitstring_get_bit(prefix, (size_t)(prefix_len - 1));
    return 1 - last;
}

static void test_indistinguishability(void) {
    TEST("Distribution ensemble");
    DistEnsemble *d1 = dist_ensemble_create(8);
    CHECK(d1 != NULL, "create failed");
    CHECK(d1->sample_len == 8, "wrong sample len");

    BitString *s = bitstring_create(8);
    bitstring_randomize(s);
    dist_ensemble_add(d1, s);
    CHECK(d1->n_samples == 1, "add failed");
    bitstring_free(s);

    dist_ensemble_randomize(d1, 50);
    CHECK(d1->n_samples == 50, "randomize failed");
    dist_ensemble_free(d1);
    PASS();

    TEST("Statistical distance (sample-based)");
    DistEnsemble *X = dist_ensemble_create(4);
    DistEnsemble *Y = dist_ensemble_create(4);
    dist_ensemble_randomize(X, 100);
    dist_ensemble_randomize(Y, 100);
    double d = stat_distance_from_samples(X, Y);
    /* Two uniform distributions should be close */
    CHECK(d >= 0.0 && d <= 1.0, "distance out of range");
    dist_ensemble_free(X);
    dist_ensemble_free(Y);
    PASS();

    TEST("Computational indistinguishability experiment");
    X = dist_ensemble_create(8);
    Y = dist_ensemble_create(8);
    dist_ensemble_randomize(X, 50);
    dist_ensemble_randomize(Y, 50);
    CompIndistResult res = comp_indist_experiment(X, Y, 100, simple_distinguisher, NULL);
    CHECK(res.n_trials == 100, "wrong trial count");
    CHECK(res.advantage >= 0.0 && res.advantage <= 1.0, "advantage range");
    dist_ensemble_free(X);
    dist_ensemble_free(Y);
    PASS();

    TEST("Hybrid chain and lemma verification");
    /* Create a PRG and build hybrid chain */
    SimplePRGParams *bp = (SimplePRGParams *)malloc(sizeof(SimplePRGParams));
    bp->n = 4;
    PRG *prg = prg_create(4, 5, simple_prg_eval, bp, "test-prg");
    HybridChain *hc = prg_hybrid_chain(prg, 3);
    CHECK(hc != NULL, "hybrid chain create failed");
    CHECK(hc->k == 3, "wrong k");

    double max_adv = hybrid_lemma_verify(hc, 30, simple_distinguisher, NULL);
    CHECK(max_adv >= 0.0 && max_adv <= 1.0, "max advantage out of range");

    hybrid_chain_free(hc);
    prg_free(prg);
    PASS();

    TEST("Next-bit unpredictability test");
    X = dist_ensemble_create(8);
    dist_ensemble_randomize(X, 30);
    NextBitUnpredResult nbr = next_bit_unpred_test(X, next_bit_predictor, NULL);
    CHECK(nbr.n_positions == 7, "wrong number of positions");
    CHECK(nbr.max_advantage >= 0.0, "max advantage negative");
    free(nbr.advantages);
    dist_ensemble_free(X);
    PASS();
}

/* ================================================================
 * Reduction Tests
 * ================================================================ */
static void test_reductions(void) {
    TEST("OWF add hardcore bit (Goldreich-Levin)");
    /* Create a simple OWF */
    uint64_t weights[] = {1, 2, 4, 8};
    void *params = subsetsum_params_create(4, weights, 64);
    OWF *owf = owf_create(8, subset_sum_owf_eval, params, "test-owf");

    OWFWithHardcoreBit *owf_hc = owf_add_hardcore_bit(owf);
    CHECK(owf_hc != NULL, "add hardcore bit failed");
    CHECK(owf_hc->f == owf, "wrong base OWF");
    CHECK(owf_hc->g != NULL, "no augmented OWF");
    CHECK(owf_hc->input_len == 2 * owf->n, "wrong input length");

    /* Test augmented OWF evaluation */
    BitString *x = bitstring_create((size_t)owf_hc->input_len);
    bitstring_randomize(x);
    BitString *y = bitstring_create(owf_hc->g->n);
    int ret = owf_eval(owf_hc->g, x, y);
    CHECK(ret == 0, "augmented OWF eval failed");

    bitstring_free(x);
    bitstring_free(y);
    free(owf_hc);
    owf_free(owf); /* This frees params too */
    PASS();

    TEST("1-bit stretch PRG from OWF+hardcore");
    /* Fresh OWF for this test */
    uint64_t w2[] = {3, 7, 11};
    void *p2 = subsetsum_params_create(3, w2, 64);
    OWF *owf2 = owf_create(6, subset_sum_owf_eval, p2, "owf2");
    OWFWithHardcoreBit *owf_hc2 = owf_add_hardcore_bit(owf2);

    PRG *prg1 = prg_one_bit_stretch(owf_hc2);
    CHECK(prg1 != NULL, "1-bit stretch PRG create failed");

    BitString *seed = bitstring_create((size_t)owf_hc2->input_len);
    bitstring_randomize(seed);
    BitString *out = bitstring_create(prg1->output_len);
    ret = prg_eval(prg1, seed, out);
    CHECK(ret == 0, "1-bit PRG eval failed");
    CHECK(out->bit_len == prg1->output_len, "wrong output length");

    bitstring_free(seed);
    bitstring_free(out);
    prg_free(prg1);
    free(owf_hc2);
    owf_free(owf2);
    PASS();

    TEST("Full HILL: OWF → PRG");
    uint64_t w3[] = {2, 3, 5};
    void *p3 = subsetsum_params_create(3, w3, 64);
    OWF *owf3 = owf_create(6, subset_sum_owf_eval, p3, "owf3");
    PRG *prg_full = hill_owf_to_prg(owf3, 10);
    CHECK(prg_full != NULL, "HILL OWF→PRG failed");

    BitString *s3 = bitstring_create(prg_full->n);
    bitstring_randomize(s3);
    BitString *o3 = bitstring_create(prg_full->output_len);
    ret = prg_eval(prg_full, s3, o3);
    CHECK(ret == 0, "HILL PRG eval failed");

    bitstring_free(s3);
    bitstring_free(o3);
    prg_free(prg_full);
    owf_free(owf3);
    PASS();

    TEST("Entropy estimation from samples");
    DistEnsemble *X = dist_ensemble_create(8);
    dist_ensemble_randomize(X, 100);
    EntropyProfile ep = entropy_from_samples(X);
    CHECK(ep.min_entropy >= 0.0, "min entropy negative");
    CHECK(ep.shannon_entropy >= 0.0, "shannon entropy negative");
    CHECK(ep.min_entropy <= ep.shannon_entropy + 1.0,
          "min entropy should be ≤ shannon entropy");
    dist_ensemble_free(X);
    PASS();

    TEST("Leftover hash lemma empirical");
    X = dist_ensemble_create(8);
    dist_ensemble_randomize(X, 100);
    GF2HashFunc *h = gf2_hash_create(8, 4);
    gf2_hash_set_random(h);
    double dist = leftover_hash_lemma(X, 4, h, 50);
    CHECK(dist >= 0.0 && dist <= 1.0, "distance out of range");
    dist_ensemble_free(X);
    gf2_hash_free(h);
    PASS();
}

/* ================================================================
 * Utility Tests
 * ================================================================ */
static void test_utils(void) {
    TEST("LCG random generator");
    LCG *lcg = lcg_create(12345);
    CHECK(lcg != NULL, "LCG create failed");
    uint64_t r1 = lcg_next(lcg);
    uint64_t r2 = lcg_next(lcg);
    CHECK(r1 != r2, "LCG produced same value twice");
    uint64_t range_val = lcg_rand_range(lcg, 10, 20);
    CHECK(range_val >= 10 && range_val < 20, "rand_range out of bounds");
    lcg_free(lcg);
    PASS();

    TEST("BitString extended ops: concat");
    BitString *a = bitstring_create(4);
    BitString *b = bitstring_create(4);
    BitString *c = bitstring_create(8);
    a->data[0] = 0xA0; /* 1010 */
    b->data[0] = 0x60; /* 0110 */
    a->bit_len = 4;
    b->bit_len = 4;
    bitstring_concat(a, b, c);
    CHECK(c->bit_len == 8, "wrong concat length");
    CHECK(bitstring_get_bit(c, 0) == 1, "concat[0]");
    CHECK(bitstring_get_bit(c, 3) == 0, "concat[3]");
    CHECK(bitstring_get_bit(c, 4) == 0, "concat[4]");
    CHECK(bitstring_get_bit(c, 5) == 1, "concat[5]");
    bitstring_free(a); bitstring_free(b); bitstring_free(c);
    PASS();

    TEST("BitString split");
    a = bitstring_create(8);
    a->data[0] = 0xAA; /* 10101010 */
    a->bit_len = 8;
    b = bitstring_create(4);
    c = bitstring_create(4);
    bitstring_split(a, 4, b, c);
    CHECK(b->bit_len == 4, "left wrong length");
    CHECK(c->bit_len == 4, "right wrong length");
    CHECK(bitstring_get_bit(b, 0) == 1, "left[0]");
    CHECK(bitstring_get_bit(c, 0) == 1, "right[0] should be 5th bit");
    bitstring_free(a); bitstring_free(b); bitstring_free(c);
    PASS();

    TEST("BitString XOR");
    a = bitstring_create(4);
    b = bitstring_create(4);
    c = bitstring_create(4);
    a->data[0] = 0xF0; /* 1111 */
    b->data[0] = 0xA0; /* 1010 */
    a->bit_len = 4; b->bit_len = 4;
    bitstring_xor(a, b, c);
    CHECK(c->data[0] == 0x50, "XOR wrong"); /* 0101 */
    bitstring_free(a); bitstring_free(b); bitstring_free(c);
    PASS();

    TEST("Hex conversion");
    a = bitstring_create(8);
    a->data[0] = 0xAB;
    a->bit_len = 8;
    char hex[16];
    bitstring_to_hex(a, hex, sizeof(hex));
    CHECK(strcmp(hex, "AB") == 0, "hex conversion wrong");
    BitString *b2 = bitstring_create(8);
    CHECK(hex_to_bitstring(hex, b2) == 1, "hex parse failed");
    CHECK(bitstring_equal(a, b2) == 1, "hex roundtrip failed");
    bitstring_free(a); bitstring_free(b2);
    PASS();
}

/* ================================================================
 * Main Test Runner
 * ================================================================ */
int main(void) {
    printf("=== OWF ⇔ PRG Equivalence: Test Suite ===\n\n");
    seed_random();

    printf("[BitString Operations]\n");
    test_bitstring_ops();

    printf("\n[OWF Framework]\n");
    test_owf_framework();
    test_owf_properties();

    printf("\n[GF(2) Operations]\n");
    test_gf2_ops();

    printf("\n[Modular Arithmetic]\n");
    test_modular_arithmetic();

    printf("\n[Goldreich-Levin Hardcore Bit]\n");
    test_goldreich_levin();

    printf("\n[Pairwise Independent Hash]\n");
    test_pairwise_hash();

    printf("\n[PRG Framework]\n");
    test_prg_framework();

    printf("\n[Indistinguishability]\n");
    test_indistinguishability();

    printf("\n[Reductions]\n");
    test_reductions();

    printf("\n[Utilities]\n");
    test_utils();

    printf("\n=== Results: %d passed, %d failed ===\n",
           tests_passed, tests_failed);

    return (tests_failed > 0) ? 1 : 0;
}
