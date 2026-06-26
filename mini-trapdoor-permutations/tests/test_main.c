/**
 * test_main.c -- Comprehensive tests for mini-trapdoor-permutations
 *
 * Tests cover:
 *   - Big integer arithmetic (L3: Mathematical Structures)
 *   - Modular arithmetic (L3)
 *   - Number-theoretic functions (L3)
 *   - Miller-Rabin primality (L5)
 *   - RSA key generation (L5)
 *   - RSA encrypt/decrypt correctness (L4: Fundamental Law)
 *   - TDP permutation property (L4)
 *   - RSA homomorphism (L2: Core Concept)
 *   - TDP security definitions (L1)
 *   - RSA-OAEP padding roundtrip (L7)
 *   - FDH signature roundtrip (L7)
 *   - Forgery demonstrations (L6)
 *
 * All tests use assert() for immediate failure on error.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <math.h>

#include "tdp_core.h"
#include "modular_math.h"
#include "rsa.h"
#include "rsa_keygen.h"
#include "tdp_pke.h"
#include "tdp_signatures.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  TEST %s... ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASSED\n"); } while(0)
#define FAIL(msg) do { printf("FAILED: %s\n", msg); } while(0)

/* =========================================================================
 * L3: Big Integer Arithmetic Tests
 * ========================================================================= */

static void test_bigint_construction(void) {
    TEST("bigint_from_uint64(0)");
    bigint_t a = bigint_from_uint64(0);
    assert(bigint_is_zero(&a));
    PASS();

    TEST("bigint_from_uint64(42)");
    a = bigint_from_uint64(42);
    assert(!bigint_is_zero(&a));
    assert(bigint_to_uint64(&a) == 42);
    PASS();

    TEST("bigint_from_uint64(0x1FFFFFFFF)");
    a = bigint_from_uint64(0x1FFFFFFFFULL);
    assert(!bigint_is_zero(&a));
    PASS();

    TEST("bigint_set_zero / bigint_set_one");
    bigint_t b;
    bigint_set_zero(&b);
    assert(bigint_is_zero(&b));
    bigint_set_one(&b);
    assert(bigint_is_one(&b));
    PASS();
}

static void test_bigint_comparison(void) {
    TEST("bigint_compare equality");
    bigint_t a = bigint_from_uint64(100);
    bigint_t b = bigint_from_uint64(100);
    assert(bigint_compare(&a, &b) == 0);
    PASS();

    TEST("bigint_compare less");
    b = bigint_from_uint64(50);
    assert(bigint_compare(&b, &a) < 0);
    assert(bigint_compare(&a, &b) > 0);
    PASS();

    TEST("bigint_is_even / bit_length");
    bigint_t c = bigint_from_uint64(16);
    assert(bigint_is_even(&c));
    assert(bigint_bit_length(&c) == 5); /* 16 = 0b10000, 5 bits */
    PASS();
}

static void test_bigint_arithmetic(void) {
    TEST("bigint_add small");
    bigint_t a = bigint_from_uint64(42);
    bigint_t b = bigint_from_uint64(58);
    bigint_t c;
    assert(bigint_add(&c, &a, &b));
    assert(bigint_to_uint64(&c) == 100);
    PASS();

    TEST("bigint_sub");
    assert(bigint_sub(&c, &c, &a)); /* 100 - 42 = 58 */
    assert(bigint_to_uint64(&c) == 58);
    PASS();

    TEST("bigint_mul small");
    bigint_t d;
    bigint_mul(&d, &a, &b); /* 42 * 58 = 2436 */
    assert(bigint_to_uint64(&d) == 2436);
    PASS();

    TEST("bigint_divmod");
    bigint_t q, r;
    assert(bigint_divmod(&q, &r, &d, &a)); /* 2436 / 42 = 58, r = 0 */
    assert(bigint_to_uint64(&q) == 58);
    assert(bigint_is_zero(&r));
    PASS();

    TEST("bigint_divmod with remainder");
    bigint_t seven = bigint_from_uint64(7);
    bigint_t three = bigint_from_uint64(3);
    assert(bigint_divmod(&q, &r, &seven, &three)); /* 7/3 = 2, r=1 */
    assert(bigint_to_uint64(&q) == 2);
    assert(bigint_to_uint64(&r) == 1);
    PASS();

    TEST("bigint_shr / bigint_shl");
    bigint_t e = bigint_from_uint64(8);
    bigint_shl(&e, 2); /* 8 << 2 = 32 */
    assert(bigint_to_uint64(&e) == 32);
    bigint_shr(&e, 3); /* 32 >> 3 = 4 */
    assert(bigint_to_uint64(&e) == 4);
    PASS();

    TEST("bigint_inc / bigint_dec");
    bigint_t f = bigint_from_uint64(0);
    bigint_inc(&f);
    assert(bigint_is_one(&f));
    bigint_inc(&f);
    assert(bigint_to_uint64(&f) == 2);
    bigint_dec(&f);
    assert(bigint_is_one(&f));
    PASS();
}

/* =========================================================================
 * L3: Modular Arithmetic Tests
 * ========================================================================= */

static void test_modular_arithmetic(void) {
    bigint_t m = bigint_from_uint64(17);
    bigint_t a = bigint_from_uint64(10);
    bigint_t b = bigint_from_uint64(8);
    bigint_t result;

    TEST("mod_add (10+8 mod 17 = 1)");
    mod_add(&result, &a, &b, &m);
    assert(bigint_to_uint64(&result) == 1);
    PASS();

    TEST("mod_sub (10-8 mod 17 = 2)");
    mod_sub(&result, &a, &b, &m);
    assert(bigint_to_uint64(&result) == 2);
    PASS();

    TEST("mod_mul (10*8 mod 17 = 12)");
    mod_mul(&result, &a, &b, &m);
    assert(bigint_to_uint64(&result) == 12);
    PASS();

    TEST("mod_exp (3^4 mod 17 = 13)");
    bigint_t base = bigint_from_uint64(3);
    bigint_t exp = bigint_from_uint64(4);
    mod_exp(&result, &base, &exp, &m);
    assert(bigint_to_uint64(&result) == 13);
    PASS();

    TEST("mod_exp (2^0 mod 17 = 1)");
    bigint_t zero_exp;
    bigint_set_zero(&zero_exp);
    mod_exp(&result, &base, &zero_exp, &m);
    assert(bigint_is_one(&result));
    PASS();
}

/* =========================================================================
 * L3: Number-Theoretic Functions Tests
 * ========================================================================= */

static void test_number_theory(void) {
    TEST("bigint_gcd(48, 18) = 6");
    bigint_t a = bigint_from_uint64(48);
    bigint_t b = bigint_from_uint64(18);
    bigint_t g;
    bigint_gcd(&g, &a, &b);
    assert(bigint_to_uint64(&g) == 6);
    PASS();

    TEST("bigint_egcd + mod_inverse");
    bigint_t d, x, y;
    bigint_egcd(&d, &x, &y, &a, &b);
    assert(bigint_to_uint64(&d) == 6);
    PASS();

    TEST("mod_inverse 3^{-1} mod 11 = 4");
    bigint_t three = bigint_from_uint64(3);
    bigint_t eleven = bigint_from_uint64(11);
    bigint_t inv;
    assert(mod_inverse(&inv, &three, &eleven));
    assert(bigint_to_uint64(&inv) == 4); /* 3*4=12 ≡ 1 mod 11 */
    PASS();

    TEST("mod_inverse fails when gcd != 1");
    bigint_t six = bigint_from_uint64(6);
    bigint_t nine = bigint_from_uint64(9);
    assert(!mod_inverse(&inv, &six, &nine));
    PASS();

    TEST("euler_totient_rsa(3, 5) = 8");
    bigint_t p = bigint_from_uint64(3);
    bigint_t q = bigint_from_uint64(5);
    bigint_t phi;
    euler_totient_rsa(&phi, &p, &q);
    assert(bigint_to_uint64(&phi) == 8); /* (3-1)*(5-1) = 2*4 = 8 */
    PASS();

    TEST("crt_combine");
    bigint_t two = bigint_from_uint64(2);
    bigint_t three2 = bigint_from_uint64(3);
    bigint_t five = bigint_from_uint64(5);
    bigint_t crt_res;
    /* x ≡ 2 mod 3, x ≡ 3 mod 5 */
    crt_combine(&crt_res, &two, &three2, &three2, &five);
    /* Solution: x = 8 (since 8 mod 3 = 2, 8 mod 5 = 3) */
    assert(bigint_to_uint64(&crt_res) == 8);
    PASS();

    TEST("legendre_symbol(4, 7) = 1 (4=2^2 is QR mod 7)");
    bigint_t four = bigint_from_uint64(4);
    bigint_t seven = bigint_from_uint64(7);
    assert(legendre_symbol(&four, &seven) == 1);
    PASS();

    TEST("legendre_symbol(3, 7) = -1 (3 is QNR mod 7)");
    bigint_t three3 = bigint_from_uint64(3);
    assert(legendre_symbol(&three3, &seven) == -1);
    PASS();
}

/* =========================================================================
 * L5: Miller-Rabin Primality Tests
 * ========================================================================= */

static void test_miller_rabin(void) {
    TEST("Miller-Rabin: 2 is prime");
    bigint_t two = bigint_from_uint64(2);
    assert(miller_rabin_test(&two, 10));
    PASS();

    TEST("Miller-Rabin: 3 is prime");
    bigint_t three = bigint_from_uint64(3);
    assert(miller_rabin_test(&three, 10));
    PASS();

    TEST("Miller-Rabin: 4 is composite");
    bigint_t four = bigint_from_uint64(4);
    assert(!miller_rabin_test(&four, 10));
    PASS();

    TEST("Miller-Rabin: 97 is prime");
    bigint_t p97 = bigint_from_uint64(97);
    assert(miller_rabin_test(&p97, 10));
    PASS();

    TEST("Miller-Rabin: 561 (Carmichael) is composite");
    bigint_t carmichael = bigint_from_uint64(561);
    assert(!miller_rabin_test(&carmichael, 10));
    PASS();

    TEST("is_probable_prime on 7");
    bigint_t p7 = bigint_from_uint64(7);
    assert(is_probable_prime(&p7, 5));
    PASS();

    TEST("is_probable_prime on 100");
    bigint_t p100 = bigint_from_uint64(100);
    assert(!is_probable_prime(&p100, 5));
    PASS();
}

/* =========================================================================
 * L5: RSA Key Generation Tests
 * ========================================================================= */

static void test_rsa_keygen(void) {
    TEST("rsa_generate_keypair small (64-bit)");
    rsa_keypair_t key;
    tdp_status_t status = rsa_generate_keypair(&key, 64, 12345);
    assert(status == TDP_SUCCESS);
    assert(key.params.nbits >= 60);
    PASS();

    TEST("rsa_validate_keypair");
    assert(rsa_validate_keypair(&key));
    PASS();

    TEST("rsa_keypair_from_primes with known primes");
    rsa_keypair_t key2;
    bigint_t p = bigint_from_uint64(11);
    bigint_t q = bigint_from_uint64(17);
    bigint_t e = bigint_from_uint64(3);
    status = rsa_keypair_from_primes(&key2, &p, &q, &e);
    assert(status == TDP_SUCCESS);
    assert(bigint_to_uint64(&key2.params.n) == 187); /* 11*17 = 187 */
    assert(bigint_to_uint64(&key2.params.phi_n) == 160); /* 10*16 = 160 */
    PASS();

    TEST("rsa_compute_private_exponent");
    bigint_t d;
    bigint_t phi = bigint_from_uint64(160);
    bigint_t e2 = bigint_from_uint64(3);
    assert(rsa_compute_private_exponent(&d, &e2, &phi));
    /* 3*d ≡ 1 mod 160 => d = 107 (3*107 = 321 = 2*160 + 1) */
    assert(bigint_to_uint64(&d) == 107);
    PASS();
}

/* =========================================================================
 * L4: RSA Correctness (Fundamental Law) Tests
 * ========================================================================= */

static void test_rsa_correctness(void) {
    TEST("RSA encrypt/decrypt roundtrip (CRT)");
    rsa_keypair_t key;
    bigint_t p = bigint_from_uint64(11);
    bigint_t q = bigint_from_uint64(17);
    bigint_t e = bigint_from_uint64(3);
    assert(rsa_keypair_from_primes(&key, &p, &q, &e) == TDP_SUCCESS);

    bigint_t msg = bigint_from_uint64(42);
    tdp_eval_result_t ct = rsa_encrypt(&key.params, &msg);
    assert(ct.valid);
    tdp_domain_elem_t dec = rsa_decrypt_crt(&key, &ct.value);
    assert(dec.in_domain);
    assert(bigint_compare(&dec.value, &msg) == 0);
    PASS();

    TEST("RSA encrypt/decrypt roundtrip (naive)");
    tdp_domain_elem_t dec_naive = rsa_decrypt_naive(&key.params, &ct.value);
    assert(dec_naive.in_domain);
    assert(bigint_compare(&dec_naive.value, &msg) == 0);
    PASS();

    TEST("RSA correctness: x^{ed} ≡ x (mod n) for x=1");
    bigint_t one;
    bigint_set_one(&one);
    tdp_eval_result_t ct_one = rsa_encrypt(&key.params, &one);
    assert(ct_one.valid);
    tdp_domain_elem_t dec_one = rsa_decrypt_crt(&key, &ct_one.value);
    assert(dec_one.in_domain);
    assert(bigint_is_one(&dec_one.value));
    PASS();
}

/* =========================================================================
 * L2: RSA Homomorphism Test
 * ========================================================================= */

static void test_rsa_homomorphism(void) {
    TEST("RSA multiplicative homomorphism");
    rsa_keypair_t key;
    bigint_t p = bigint_from_uint64(11);
    bigint_t q = bigint_from_uint64(17);
    bigint_t e = bigint_from_uint64(3);
    assert(rsa_keypair_from_primes(&key, &p, &q, &e) == TDP_SUCCESS);

    bigint_t x1 = bigint_from_uint64(5);
    bigint_t x2 = bigint_from_uint64(7);
    assert(rsa_verify_homomorphism(&key.params, &x1, &x2));
    PASS();
}

/* =========================================================================
 * L1: TDP Core API Tests
 * ========================================================================= */

static void test_tdp_core(void) {
    TEST("tdp_is_negligible");
    assert(tdp_is_negligible(0.0, 128));
    assert(tdp_is_negligible(pow(2.0, -129), 128));
    assert(!tdp_is_negligible(0.5, 128));
    PASS();

    TEST("tdp_one_way_advantage");
    double adv = tdp_one_way_advantage(1, 100, 128);
    assert(adv > 0.0 && adv < 1.0);
    PASS();

    TEST("tdp_advantage_is_significant");
    assert(tdp_advantage_is_significant(0.5, 128));
    assert(!tdp_advantage_is_significant(pow(2.0, -80), 128));
    PASS();

    TEST("tdp_keypair_init / clear");
    tdp_keypair_t kp = tdp_keypair_init();
    assert(kp.pk.nbits == 0);
    tdp_keypair_clear(&kp);
    PASS();

    TEST("tdp_check_domain_membership");
    rsa_keypair_t key;
    bigint_t p = bigint_from_uint64(11);
    bigint_t q = bigint_from_uint64(17);
    bigint_t e = bigint_from_uint64(3);
    assert(rsa_keypair_from_primes(&key, &p, &q, &e) == TDP_SUCCESS);

    tdp_public_key_t pk;
    pk.modulus = key.params.n;
    pk.exponent = key.params.e;
    pk.nbits = key.params.nbits;

    bigint_t one;
    bigint_set_one(&one);
    assert(tdp_check_domain_membership(&pk, &one));

    bigint_t zero;
    bigint_set_zero(&zero);
    assert(!tdp_check_domain_membership(&pk, &zero));
    PASS();

    TEST("tdp_verify_permutation_property");
    tdp_domain_elem_t dom_elem;
    bigint_t two;
    bigint_set_one(&two); bigint_inc(&two);
    dom_elem.value = two;
    dom_elem.in_domain = tdp_check_domain_membership(&pk, &two);

    tdp_trapdoor_t td;
    td.prime_p = key.params.p;
    td.prime_q = key.params.q;
    td.private_exp = key.params.d;
    td.totient = key.params.phi_n;
    td.d_p = key.d_p;
    td.d_q = key.d_q;
    td.q_inv = key.q_inv;

    if (dom_elem.in_domain) {
        assert(tdp_verify_permutation_property(&pk, &td, &dom_elem));
    }
    PASS();

    TEST("tdp_collection_describe");
    tdp_collection_info_t info = tdp_collection_describe(2048);
    assert(info.lambda == 2048);
    PASS();
}

/* =========================================================================
 * L7: PKE Application Tests
 * ========================================================================= */

static void test_pke(void) {
    TEST("Textbook PKE roundtrip");
    rsa_keypair_t key;
    bigint_t p = bigint_from_uint64(11);
    bigint_t q = bigint_from_uint64(17);
    bigint_t e = bigint_from_uint64(3);
    assert(rsa_keypair_from_primes(&key, &p, &q, &e) == TDP_SUCCESS);

    bigint_t msg = bigint_from_uint64(50);
    pke_ciphertext_t ct = pke_textbook_encrypt(&key.params, &msg);
    bigint_t dec;
    assert(pke_textbook_decrypt(&key, &ct, &dec));
    assert(bigint_compare(&dec, &msg) == 0);
    PASS();

    TEST("OAEP pad/unpad roundtrip");
    const char *test_msg = "Hello, RSA-OAEP!";
    uint8_t padded[256];
    size_t padded_len;
    size_t k0 = 128;
    size_t r_len = k0 / 8;  /* r_len must equal k0_bytes for OAEP */
    uint8_t r[16];
    memset(r, 0xAA, r_len);
    assert(pke_oaep_pad(padded, &padded_len, (const uint8_t *)test_msg,
                         strlen(test_msg), r, r_len, k0));
    uint8_t recovered[256];
    size_t recovered_len;
    assert(pke_oaep_unpad(recovered, &recovered_len, padded, padded_len, k0));
    assert(recovered_len == strlen(test_msg));
    assert(memcmp(recovered, test_msg, recovered_len) == 0);
    PASS();

    TEST("PKE security level names");
    assert(strcmp(pke_security_level_name(PKE_SEC_IND_CPA), "IND-CPA") == 0);
    assert(strcmp(pke_security_level_name(PKE_SEC_IND_CCA2), "IND-CCA2") == 0);
    PASS();

    TEST("pke_check_security_level");
    assert(pke_check_security_level(PKE_SEC_IND_CCA2, PKE_SEC_IND_CPA));
    assert(!pke_check_security_level(PKE_SEC_IND_CPA, PKE_SEC_IND_CCA2));
    PASS();
}

/* =========================================================================
 * L7: Signature Application Tests
 * ========================================================================= */

static void test_signatures(void) {
    TEST("Textbook RSA sign/verify roundtrip");
    rsa_keypair_t key;
    bigint_t p = bigint_from_uint64(11);
    bigint_t q = bigint_from_uint64(17);
    bigint_t e = bigint_from_uint64(3);
    assert(rsa_keypair_from_primes(&key, &p, &q, &e) == TDP_SUCCESS);

    bigint_t msg = bigint_from_uint64(42);
    signature_t sig = rsa_textbook_sign(&key, &msg);
    assert(rsa_textbook_verify(&key.params, &msg, &sig));
    PASS();

    TEST("FDH sign/verify roundtrip");
    const char *str_msg = "Sign me with FDH!";
    signature_t sig2 = rsa_fdh_sign(&key, (const uint8_t *)str_msg,
                                     strlen(str_msg));
    assert(rsa_fdh_verify(&key.params, (const uint8_t *)str_msg,
                           strlen(str_msg), &sig2));
    PASS();

    TEST("PSS sign/verify roundtrip");
    uint8_t salt[8] = {1,2,3,4,5,6,7,8};
    signature_t sig3 = rsa_pss_sign(&key, (const uint8_t *)str_msg,
                                     strlen(str_msg), salt, 8);
    assert(rsa_pss_verify(&key.params, (const uint8_t *)str_msg,
                           strlen(str_msg), &sig3));
    PASS();

    TEST("Existential forgery demonstration (textbook RSA)");
    bigint_t forged_msg;
    signature_t forged_sig;
    rsa_demonstrate_existential_forgery(&key.params, &forged_msg, &forged_sig);
    /* The forgery should verify: check forged_sig^e mod n == forged_msg */
    assert(rsa_textbook_verify(&key.params, &forged_msg, &forged_sig));
    PASS();

    TEST("Multiplicative forgery demonstration");
    bigint_t m1 = bigint_from_uint64(5);
    bigint_t m2 = bigint_from_uint64(7);
    signature_t sig_m1 = rsa_textbook_sign(&key, &m1);
    signature_t sig_m2 = rsa_textbook_sign(&key, &m2);
    bigint_t forged_msg2;
    signature_t forged_sig2;
    rsa_demonstrate_multiplicative_forgery(&key.params,
                                            &m1, &sig_m1, &m2, &sig_m2,
                                            &forged_msg2, &forged_sig2);
    /* Verify the multiplicative forgery */
    assert(rsa_textbook_verify(&key.params, &forged_msg2, &forged_sig2));
    PASS();

    TEST("sig_security_level_name");
    assert(strcmp(sig_security_level_name(SIG_SEC_EUF_CMA), "EUF-CMA") == 0);
    PASS();

    TEST("sig_fdh_security_bound");
    double bound = sig_fdh_security_bound(0.01, 100, 50);
    assert(bound == 0.01 * 100 * 50);
    PASS();
}

/* =========================================================================
 * Main
 * ========================================================================= */

int main(void) {
    printf("========================================\n");
    printf("mini-trapdoor-permutations Test Suite\n");
    printf("========================================\n\n");

    printf("--- L3: Big Integer Arithmetic ---\n");
    test_bigint_construction();
    test_bigint_comparison();
    test_bigint_arithmetic();

    printf("\n--- L3: Modular Arithmetic ---\n");
    test_modular_arithmetic();

    printf("\n--- L3: Number Theory ---\n");
    test_number_theory();

    printf("\n--- L5: Miller-Rabin ---\n");
    test_miller_rabin();

    printf("\n--- L5: RSA Key Generation ---\n");
    test_rsa_keygen();

    printf("\n--- L4: RSA Correctness ---\n");
    test_rsa_correctness();

    printf("\n--- L2: RSA Homomorphism ---\n");
    test_rsa_homomorphism();

    printf("\n--- L1: TDP Core API ---\n");
    test_tdp_core();

    printf("\n--- L7: PKE Application ---\n");
    test_pke();

    printf("\n--- L7: Signature Application ---\n");
    test_signatures();

    printf("\n========================================\n");
    printf("RESULTS: %d/%d tests passed\n", tests_passed, tests_run);
    printf("========================================\n");

    if (tests_passed == tests_run) {
        printf("ALL TESTS PASSED\n");
        return 0;
    } else {
        printf("%d TESTS FAILED\n", tests_run - tests_passed);
        return 1;
    }
}
