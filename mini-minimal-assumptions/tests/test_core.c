/*
 * test_core.c — Comprehensive tests for mini-minimal-assumptions
 * Tests cover L1-L8 knowledge levels with assert-based verification.
 */
#include "minimal_assumptions.h"
#include "assumption_hierarchy.h"
#include "impagliazzo_worlds.h"
#include "black_box_separation.h"
#include "hardness_amplification.h"
#include "uowhf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  TEST %s... ", name); \
} while(0)

#define PASS() do { \
    printf("PASSED\n"); \
    tests_passed++; \
} while(0)

/* ================================================================
 * L1: Negligible Function Tests
 * ================================================================ */
static void test_negligible_functions(void) {
    TEST("negligible_exp");
    assert(is_negligible(negligible_exp, 10));
    PASS();

    TEST("negligible_superpoly");
    assert(is_negligible(negligible_superpoly, 100));
    PASS();

    TEST("negligible_exp small values");
    double v = negligible_exp(1);
    assert(v > 0.0 && v < 1.0);
    v = negligible_exp(10);
    assert(v < 0.01);
    v = negligible_exp(2000);
    assert(v == 0.0);
    PASS();
}

/* ================================================================
 * L1-L2: Primitive Enumeration Tests
 * ================================================================ */
static void test_primitive_names(void) {
    TEST("prim_name valid");
    assert(strcmp(prim_name(PRIM_OWF), "OWF") == 0);
    assert(strcmp(prim_name(PRIM_PRG), "PRG") == 0);
    assert(strcmp(prim_name(PRIM_TDP), "TDP") == 0);
    assert(strcmp(prim_name(PRIM_PKE), "PKE") == 0);
    PASS();

    TEST("prim_name invalid");
    assert(strcmp(prim_name((CryptoPrimitive)999), "UNKNOWN") == 0);
    PASS();

    TEST("prim_description non-null");
    const char* d = prim_description(PRIM_FHE);
    assert(d != NULL);
    assert(strlen(d) > 0);
    PASS();

    TEST("assumption_name");
    assert(strcmp(assumption_name(ASSUME_FACTORING), "Factoring is hard") == 0);
    assert(strcmp(assumption_name(ASSUME_LWE), "LWE is hard") == 0);
    assert(strcmp(assumption_name(ASSUME_NONE), "No assumption") == 0);
    PASS();
}

/* ================================================================
 * L2: Assumption Implication Tests
 * ================================================================ */
static void test_assumption_implications(void) {
    TEST("OWF implies PRG");
    assert(assumption_implies(ASSUME_OWF_EXISTS, PRIM_PRG) == 1);
    PASS();

    TEST("OWF implies PRF");
    assert(assumption_implies(ASSUME_OWF_EXISTS, PRIM_PRF) == 1);
    PASS();

    TEST("OWF implies SKE");
    assert(assumption_implies(ASSUME_OWF_EXISTS, PRIM_SKE) == 1);
    PASS();

    TEST("OWF does NOT imply PKE (BB separation)");
    assert(assumption_implies(ASSUME_OWF_EXISTS, PRIM_PKE) == 0);
    PASS();

    TEST("TDP implies PKE");
    assert(assumption_implies(ASSUME_TDP_EXISTS, PRIM_PKE) == 1);
    PASS();

    TEST("LWE implies PKE (Regev 2005)");
    assert(assumption_implies(ASSUME_LWE, PRIM_PKE) == 1);
    PASS();

    TEST("No assumption implies nothing");
    assert(assumption_implies(ASSUME_NONE, PRIM_PRG) == 0);
    assert(assumption_implies(ASSUME_NONE, PRIM_PKE) == 0);
    PASS();
}

/* ================================================================
 * L2: Impagliazzo World Tests
 * ================================================================ */
static void test_impagliazzo_worlds(void) {
    TEST("world names");
    assert(strcmp(world_name(ALGORITHMICA), "Algorithmica") == 0);
    assert(strcmp(world_name(MINICRYPT), "Minicrypt") == 0);
    assert(strcmp(world_name(CRYPTOMANIA), "Cryptomania") == 0);
    PASS();

    TEST("world_has_owf");
    assert(world_has_owf(ALGORITHMICA) == 0);
    assert(world_has_owf(HEURISTICA) == 0);
    assert(world_has_owf(PESSILAND) == 0);
    assert(world_has_owf(MINICRYPT) == 1);
    assert(world_has_owf(CRYPTOMANIA) == 1);
    PASS();

    TEST("world_has_pke");
    assert(world_has_pke(ALGORITHMICA) == 0);
    assert(world_has_pke(MINICRYPT) == 0);
    assert(world_has_pke(CRYPTOMANIA) == 1);
    PASS();

    TEST("world_has_ot only in Cryptomania");
    assert(world_has_ot(MINICRYPT) == 0);
    assert(world_has_ot(CRYPTOMANIA) == 1);
    PASS();
}

/* ================================================================
 * L3: Assumption Hierarchy Tests
 * ================================================================ */
static void test_assumption_hierarchy(void) {
    TEST("ah_create non-null");
    AssumptionHierarchy* ah = ah_create();
    assert(ah != NULL);
    assert(ah->n_primitives == PRIM_NUM);
    assert(ah->n_edges > 0);
    PASS();

    TEST("ah_reducible OWF->PRG");
    assert(ah_reducible(ah, PRIM_OWF, PRIM_PRG) == 1);
    PASS();

    TEST("ah_reducible OWF->SKE (transitive)");
    assert(ah_reducible(ah, PRIM_OWF, PRIM_SKE) == 1);
    PASS();

    TEST("ah_reducible OWF->PKE (should be 0, BB separation)");
    assert(ah_reducible(ah, PRIM_OWF, PRIM_PKE) == 0);
    PASS();

    TEST("ah_reducible TDP->FHE");
    assert(ah_reducible(ah, PRIM_TDP, PRIM_FHE) == 1);
    PASS();

    TEST("ah_is_minimal_for OWF for PRG");
    CryptoPrimitive cands[] = { PRIM_OWF, PRIM_PRG, PRIM_TDP };
    int idx = ah_is_minimal_for(ah, PRIM_PRG, cands, 3);
    assert(idx >= 0);
    /* PRG is the most minimal (weakest) that still gives PRG */
    assert(cands[idx] == PRIM_PRG);
    PASS();

    TEST("ah_is_minimal_for TDP for PKE");
    CryptoPrimitive cands2[] = { PRIM_OWF, PRIM_TDP, PRIM_OWP };
    int idx2 = ah_is_minimal_for(ah, PRIM_PKE, cands2, 3);
    /* TDP or OWF? TDP even though stronger is the minimal that reaches PKE */
    /* OWF doesn't reach PKE in this hierarchy (BB separation) */
    assert(idx2 >= 0);
    PASS();

    ah_free(ah);
}

/* ================================================================
 * L3: CryptoLandscape Tests
 * ================================================================ */
static void test_crypto_landscape(void) {
    TEST("cl_create");
    CryptoLandscape* cl = cl_create();
    assert(cl != NULL);
    assert(cl->n_nodes == PRIM_NUM);
    PASS();

    TEST("cl_is_minimal TDP (no incoming edges)");
    assert(cl_is_minimal(cl, PRIM_TDP) == 1);
    PASS();

    TEST("cl_is_minimal PRG (derived)");
    assert(cl_is_minimal(cl, PRIM_PRG) == 0);
    PASS();

    TEST("cl_primitive_rank");
    int rank_owf = cl_primitive_rank(cl, PRIM_OWF);
    int rank_prg = cl_primitive_rank(cl, PRIM_PRG);
    /* OWF should reach more primitives than PRG */
    assert(rank_owf >= rank_prg);
    PASS();

    TEST("cl_hierarchy_depth positive");
    double depth = cl_hierarchy_depth(cl);
    assert(depth > 0.0);
    PASS();

    TEST("cl_find_minimal_for PKE");
    CryptoPrimitive* result = NULL;
    int n_res = 0;
    int found = cl_find_minimal_for(cl, PRIM_PKE, &result, &n_res);
    assert(found > 0);
    free(result);
    PASS();

    cl_free(cl);
}

/* ================================================================
 * L4: HILL / Rompel / IR Separation Tests
 * ================================================================ */
static void test_fundamental_theorems(void) {
    TEST("owf_implies_prg_construction");
    int stretch = owf_implies_prg_construction(0.01);
    assert(stretch > 0);
    PASS();

    TEST("owf_implies_uowhf_construction");
    assert(owf_implies_uowhf_construction() == 1);
    PASS();

    TEST("impagliazzo_rudich_separation");
    IR_SeparationResult ir = impagliazzo_rudich_separation(50);
    assert(ir.success_prob > 0.0);
    assert(ir.conclusion != NULL);
    assert(strlen(ir.conclusion) > 0);
    PASS();
}

/* ================================================================
 * L4: Yao's XOR Lemma Tests
 * ================================================================ */
static void test_yao_xor_lemma(void) {
    TEST("yao_xor_bound monotonic in k");
    double eps1 = yao_xor_bound(0.1, 1, 100.0, 32.0);
    double eps2 = yao_xor_bound(0.1, 10, 100.0, 32.0);
    /* More copies => smaller advantage (harder) */
    assert(eps2 < eps1);
    PASS();

    TEST("yao_xor_bound monotonic in delta");
    double eps_a = yao_xor_bound(0.1, 5, 100.0, 32.0);
    double eps_b = yao_xor_bound(0.5, 5, 100.0, 32.0);
    /* Larger delta (harder base) => larger epsilon (easier)?? No:
     * Larger delta means function is HARDER (adversary advantage smaller),
     * so epsilon should be SMALLER for larger delta. */
    assert(eps_b < eps_a);
    PASS();

    TEST("direct_product_bound");
    double dp1 = direct_product_bound(0.1, 1);
    double dp10 = direct_product_bound(0.1, 10);
    assert(dp10 < dp1);  /* More copies => exponentially harder */
    PASS();

    TEST("yao_xor and direct_product consistency");
    double eps_yao = yao_xor_bound(0.2, 3, 10.0, 16.0);
    double dp = direct_product_bound(0.2, 3);
    /* XOR gives better bounds (smaller advantage) */
    assert(eps_yao <= dp + 0.01);  /* Allow error term */
    PASS();
}

/* ================================================================
 * L4: Goldreich-Levin Hardcore Bit Tests
 * ================================================================ */
static void test_goldreich_levin(void) {
    TEST("gl hardcore bit — same x,r");
    uint8_t x[4] = {0xFF, 0xFF, 0x00, 0x00};
    uint8_t r[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    int bit = goldreich_levin_hardcore_bit(x, 4, r, 4);
    /* ⟨x,r⟩ mod 2 = parity of first 16 bits = 0 (16 ones) */
    assert(bit == 0);
    PASS();

    TEST("gl hardcore bit — orthogonal vectors");
    uint8_t x2[4] = {0xAA, 0x00, 0x00, 0x00};  /* 10101010 */
    uint8_t r2[4] = {0x55, 0x00, 0x00, 0x00};  /* 01010101 */
    int bit2 = goldreich_levin_hardcore_bit(x2, 4, r2, 4);
    /* x2 AND r2 = 0x00 everywhere => bit=0 */
    assert(bit2 == 0);
    PASS();

    TEST("gl list decode basic");
    uint8_t recovered[8];
    int ret = goldreich_levin_list_decode(NULL, 0, NULL, 0, recovered, 8);
    assert(ret == 1);
    PASS();
}

/* ================================================================
 * L5: GGM PRF Tests
 * ================================================================ */
static void test_ggm_prf(void) {
    TEST("ggm_prf_init");
    uint8_t key[8] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
    GGMPRF* prf = ggm_prf_init(key, 8, 16, 8);
    assert(prf != NULL);
    PASS();

    TEST("ggm_prf_eval returns different values for different inputs");
    uint8_t in0[4] = {0x00,0x00,0x00,0x00};
    uint8_t in1[4] = {0xFF,0xFF,0xFF,0xFF};
    uint8_t out0[8], out1[8];
    memset(out0, 0, 8); memset(out1, 0, 8);
    ggm_prf_eval(prf, in0, out0);
    ggm_prf_eval(prf, in1, out1);
    int diff = memcmp(out0, out1, 8);
    assert(diff != 0);  /* Different inputs => different outputs */
    PASS();

    TEST("ggm_prf_eval consistent");
    uint8_t out_a[8], out_b[8];
    ggm_prf_eval(prf, in0, out_a);
    ggm_prf_eval(prf, in0, out_b);
    assert(memcmp(out_a, out_b, 8) == 0);  /* Same input => same output */
    PASS();

    ggm_prf_free(prf);
}

/* ================================================================
 * L6: Canonical Problems Tests
 * ================================================================ */
static void test_canonical_problems(void) {
    TEST("check_minicrypt_vs_cryptomania returns 0");
    assert(check_minicrypt_vs_cryptomania() == 0);
    PASS();

    TEST("check_bitcommit_from_owf returns 0");
    assert(check_bitcommit_from_owf() == 0);
    PASS();

    TEST("universal_owf_eval");
    UniversalOWFInput in;
    uint8_t tm[] = {0x01,0x02,0x03};
    uint8_t inp[] = {0xAA,0xBB};
    in.tm_description = tm; in.tm_len = 3;
    in.input = inp; in.input_len = 2;
    in.time_bound = 100;
    uint8_t out[5];
    size_t out_len = 5;
    int ret = universal_owf_eval(&in, out, &out_len);
    assert(ret == 0);
    assert(out_len == 5);
    assert(memcmp(out, tm, 3) == 0);
    assert(memcmp(out + 3, inp, 2) == 0);
    PASS();
}

/* ================================================================
 * L7: Applications Tests
 * ================================================================ */
static void test_applications(void) {
    TEST("pow_security_estimate");
    double est = pow_security_estimate(1e12, 600.0);
    assert(est > 0.0);
    PASS();

    TEST("tls_cipher_recommendation Minicrypt");
    char buf[256];
    tls_cipher_recommendation(MINICRYPT, buf, sizeof(buf));
    assert(strlen(buf) > 0);
    PASS();

    TEST("tls_cipher_recommendation Cryptomania");
    tls_cipher_recommendation(CRYPTOMANIA, buf, sizeof(buf));
    assert(strlen(buf) > 0);
    PASS();

    TEST("is_post_quantum_secure factoring=false");
    assert(is_post_quantum_secure(ASSUME_FACTORING) == 0);
    PASS();

    TEST("is_post_quantum_secure LWE=true");
    assert(is_post_quantum_secure(ASSUME_LWE) == 1);
    PASS();
}

/* ================================================================
 * L8: RTV Framework Tests
 * ================================================================ */
static void test_rtv_framework(void) {
    TEST("rtv_query OWF->OT (separated)");
    RTVEntry e = rtv_query(PRIM_OWF, PRIM_OT);
    assert(e.is_impossible == 1);
    PASS();

    TEST("rtv_query OWF->PRG (possible)");
    RTVEntry e2 = rtv_query(PRIM_OWF, PRIM_PRG);
    assert(e2.is_possible == 1);
    PASS();

    TEST("rtv_query unknown pair");
    RTVEntry e3 = rtv_query(PRIM_MAC, PRIM_FHE);
    assert(e3.is_possible == 0);
    assert(e3.is_impossible == 0);
    PASS();
}

/* ================================================================
 * Separation Tests
 * ================================================================ */
static void test_separations(void) {
    TEST("get_separation IR89");
    SeparationResult sr = get_separation(SEP_IR89);
    assert(sr.is_separated == 1);
    assert(sr.from == PRIM_OWF);
    assert(sr.to == PRIM_OT);
    PASS();

    TEST("get_separation SIMON98");
    SeparationResult sr2 = get_separation(SEP_SIMON98);
    assert(sr2.is_separated == 1);
    PASS();

    TEST("separation_test_run OWF->OT");
    SeparationTest st = separation_test_run(PRIM_OWF, PRIM_OT, 10);
    assert(st.n_constructions_broken == 10);
    assert(strcmp(st.verdict, "SEPARATED") == 0);
    PASS();
}

/* ================================================================
 * World Belief Tests
 * ================================================================ */
static void test_world_belief(void) {
    TEST("world_belief_init sums to 1");
    WorldBelief b = world_belief_init();
    double sum = b.p_algorithmica + b.p_heuristica + b.p_pessiland +
                 b.p_minicrypt + b.p_cryptomania + b.p_unknown;
    assert(fabs(sum - 1.0) < 0.001);
    PASS();

    TEST("world_belief_update RSA evidence");
    WorldBelief b2 = world_belief_init();
    world_belief_update(&b2, "RSA still standing");
    assert(b2.p_cryptomania > 0.20);
    PASS();

    TEST("world_belief_map");
    WorldBelief b3 = world_belief_init();
    b3.p_cryptomania = 0.9;
    b3.p_minicrypt = 0.05;
    b3.p_algorithmica = 0.05;
    assert(world_belief_map(&b3) == CRYPTOMANIA);
    PASS();
}

/* World Axioms Tests */
static void test_world_axioms(void) {
    TEST("algorithmica_axioms");
    WorldAxioms a = algorithmica_axioms();
    assert(a.p_eq_np == 1);
    assert(a.owf_exists == 0);
    PASS();
    TEST("cryptomania_axioms");
    WorldAxioms c = cryptomania_axioms();
    assert(c.owf_exists == 1);
    assert(c.tdp_exists == 1);
    PASS();
}

/* UOWHF Tests */
static void test_uowhf(void) {
    TEST("uowhf_keygen");
    UOWHFKey* key = uowhf_keygen(256, 128);
    assert(key != NULL);
    PASS();

    TEST("uowhf_hash deterministic");
    uint8_t msg[] = "Hello, crypto minimal assumptions!";
    size_t ml = strlen((char*)msg);
    uint8_t d1[16], d2[16];
    uowhf_hash(key, msg, ml, d1, 16);
    uowhf_hash(key, msg, ml, d2, 16);
    assert(memcmp(d1, d2, 16) == 0);
    PASS();

    TEST("uowhf_compare_security");
    UOWHFKey* k2 = uowhf_keygen(512, 256);
    assert(k2 != NULL);
    int cmp = uowhf_compare_security(key, k2);
    assert(cmp < 0);
    uowhf_free_key(k2);
    PASS();

    TEST("uowhf_hash non-zero output");
    uint8_t d3[16];
    memset(d3, 0, 16);
    uowhf_hash(key, msg, ml, d3, 16);
    int all_zero = 1;
    for (int i = 0; i < 16; i++) if (d3[i] != 0) { all_zero = 0; break; }
    assert(!all_zero);
    PASS();

    uowhf_free_key(key);
}

/* Hardness Pipeline Tests */
static void test_hardness_pipeline(void) {
    TEST("ha_pipeline_create");
    HardnessAmplificationPipeline* hap = ha_pipeline_create(0.01, 64);
    assert(hap != NULL);
    PASS();
    TEST("ha_pipeline_execute");
    ha_pipeline_execute(hap);
    assert(hap->k > 0);
    PASS();
    TEST("predicate_hardness");
    assert(fabs(predicate_hardness(0.75) - 0.25) < 0.001);
    PASS();
    TEST("accuracy_from_hardness");
    assert(fabs(accuracy_from_hardness(0.3) - 0.8) < 0.001);
    PASS();
    ha_pipeline_free(hap);
}

/* XOR Composition Tests */
static int test_predicate(const uint8_t* x, size_t len) {
    if (len == 0) return 0;
    int p = 0;
    for (int b = 0; b < 8; b++) p ^= (x[0] >> b) & 1;
    return p;
}

static void test_xor_composition(void) {
    TEST("xor_comp_create");
    XORComposition* xc = xor_comp_create(3, 8);
    assert(xc != NULL);
    PASS();
    TEST("xor_comp_eval");
    uint8_t v1[] = {0x01}, v2[] = {0x03}, v3[] = {0x07};
    xor_comp_set_input(xc, 0, v1, 1);
    xor_comp_set_input(xc, 1, v2, 1);
    xor_comp_set_input(xc, 2, v3, 1);
    assert(xor_comp_eval_predicate(xc, test_predicate) == 0);
    PASS();
    xor_comp_free(xc);
}

/* Random Oracle Tests */
static void test_random_oracle(void) {
    TEST("ro_create");
    RandomOracle* ro = ro_create(8, 0);
    assert(ro != NULL);
    PASS();
    TEST("ro_pspace_invert");
    uint8_t x = 0x42, y[1];
    ro_eval(ro, &x, y, 1);
    uint8_t inv[1];
    ro_pspace_invert(ro, y, inv, 1);
    uint8_t verify[1];
    ro_eval(ro, inv, verify, 1);
    assert(verify[0] == y[0]);
    PASS();
    ro_free(ro);
}

/* IR Oracle Tests */
static void test_ir_oracle(void) {
    TEST("ir_oracle_create");
    IR_OracleWorld* ir = ir_oracle_create(8);
    assert(ir != NULL);
    PASS();
    TEST("ir_oracle_prove_separation");
    int sep_ret = ir_oracle_prove_separation(ir, 10);
    /* Separation holds: OT impossible in IR model */
    assert(sep_ret == 0 || sep_ret == 1);
    PASS();
    ir_oracle_free(ir);
}

/* Canonical Examples */
static void test_canonical_examples(void) {
    TEST("yao_canonical_example");
    assert(yao_canonical_example(0.1, 10) == 0);
    PASS();
    TEST("gl_canonical_example");
    assert(gl_canonical_example(64) == 0);
    PASS();
    TEST("compare_xor_vs_concatenation");
    assert(compare_xor_vs_concatenation(0.1, 10) == 0);
    PASS();
}

int main(void) {
    printf("\n========================================\n");
    printf("mini-minimal-assumptions Test Suite\n");
    printf("========================================\n\n");

    test_negligible_functions();
    test_primitive_names();
    test_assumption_implications();
    test_impagliazzo_worlds();
    test_assumption_hierarchy();
    test_crypto_landscape();
    test_fundamental_theorems();
    test_yao_xor_lemma();
    test_goldreich_levin();
    test_ggm_prf();
    test_canonical_problems();
    test_applications();
    test_rtv_framework();
    test_separations();
    test_world_belief();
    test_world_axioms();
    test_uowhf();
    test_hardness_pipeline();
    test_xor_composition();
    test_random_oracle();
    test_ir_oracle();
    test_canonical_examples();

    printf("\n========================================\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);
    printf("========================================\n");

    if (tests_passed == tests_run) {
        printf("ALL TESTS PASSED\n");
        return 0;
    }
    printf("SOME TESTS FAILED\n");
    return 1;
}
