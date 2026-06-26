/* test_owf.c - OWF Comprehensive Tests */
#include "owf_core.h"
#include "owf_number_theory.h"
#include "owf_candidates.h"
#include "owf_hardcore.h"
#include "owf_weak_strong.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <time.h>

static int tests_run = 0;
static int tests_passed = 0;
#define TEST(n) do { tests_run++; printf("  TEST %s... ", n); } while(0)
#define PASS() do { tests_passed++; printf("PASSED\n"); } while(0)

static int _eval(void* c, const bit_string_t* x, sec_param_t n, bit_string_t** y) {
  (void)c;(void)x;(void)n; *y = bs_create(8); return (*y)?0:-1; }
static int _inv(void* c, const bit_string_t* y, sec_param_t n, bit_string_t** xp) {
  (void)c;(void)y;(void)n; *xp = bs_create(8); return (*xp)?0:-1; }

void t1_scheme(void) {
  TEST("scheme_create_free");
  owf_scheme_t* o = owf_scheme_create("Test","D",_eval,_inv,NULL,NULL,256,64,64);
  assert(o); assert(o->input_bits==64); owf_scheme_free(o); PASS(); }

void t1_eval(void) {
  TEST("owf_evaluate");
  owf_scheme_t* o = owf_scheme_create("T","D",_eval,_inv,NULL,NULL,128,32,64);
  bit_string_t* x = bs_create(32); bit_string_t* y = NULL;
  assert(owf_evaluate(o,x,&y)==0); assert(y); assert(o->eval_count==1);
  bs_free(y); bs_free(x); owf_scheme_free(o); PASS(); }

void t2_negl(void) {
  TEST("negligible");
  assert(negligible_exponential(10)>0.0);
  assert(is_negligible(1e-30,128)==1); assert(is_negligible(0.5,128)==0);
  PASS(); }

void t2_invert_exp(void) {
  TEST("inversion_experiment");
  owf_scheme_t* o = owf_scheme_create("T","D",_eval,_inv,NULL,NULL,128,32,64);
  invert_experiment_t* e = invert_experiment_run(o,_inv,NULL,32);
  assert(e); assert(e->challenge_x); assert(e->challenge_y);
  invert_experiment_free(e); owf_scheme_free(o); PASS(); }

void t2_strength(void) {
  TEST("strength");
  assert(owf_estimate_strength(1e-40,128,1000)==OWF_TYPE_STRONG);
  assert(owf_estimate_strength(0.5,128,1000)==OWF_TYPE_WEAK); PASS(); }

void t3_bs(void) {
  TEST("bit_string_ops");
  bit_string_t* a=bs_create(64); assert(a);
  bit_string_t* b=bs_random(128); assert(b);
  bit_string_t* c=bs_clone(b); assert(bs_equal(b,c)==1);
  c->data[0]^=0xFF; assert(bs_equal(b,c)==0);
  bs_free(a);bs_free(b);bs_free(c); PASS(); }

void t3_big_nat(void) {
  TEST("big_nat_arithmetic");
  big_nat_t a=big_nat_from_uint64(12345),b=big_nat_from_uint64(67890);
  big_nat_t s=big_nat_add(&a,&b);
  big_nat_t e=big_nat_from_uint64(12345+67890);
  assert(big_nat_equal(&s,&e)==1);
  big_nat_t z=big_nat_zero();
  assert(big_nat_is_zero(&z)==1);
  big_nat_t o=big_nat_from_uint64(1);
  assert(big_nat_is_one(&o)==1);
  big_nat_t two=big_nat_from_uint64(2);
  assert(big_nat_is_even(&two)==1);
  PASS(); }

void t3_mod(void) {
  TEST("modular_arithmetic");
  big_nat_t a=big_nat_from_uint64(7),b=big_nat_from_uint64(3);
  big_nat_t q,r; big_nat_divmod(&a,&b,&q,&r);
  big_nat_t c2=big_nat_from_uint64(2),c1=big_nat_from_uint64(1);
  assert(big_nat_equal(&q,&c2)==1);
  assert(big_nat_equal(&r,&c1)==1);
  big_nat_t n12=big_nat_from_uint64(12),n8=big_nat_from_uint64(8);
  big_nat_t g=big_nat_gcd(&n12,&n8);
  big_nat_t n4=big_nat_from_uint64(4);
  assert(big_nat_equal(&g,&n4)==1);
  big_nat_t n7=big_nat_from_uint64(7),n5=big_nat_from_uint64(5);
  /* Verify: 3 * 5 = 15 = 1 mod 7 (using modpow for inverse verification) */
  big_nat_t n1=big_nat_from_uint64(1);
  big_nat_t prod=big_nat_mul(&b,&n5);
  big_nat_t prod_mod=big_nat_mod(&prod,&n7);
  assert(big_nat_equal(&prod_mod,&n1)==1);
  PASS(); }

void t3_modpow(void) {
  TEST("modular_exponentiation");
  big_nat_t b2=big_nat_from_uint64(2),b10=big_nat_from_uint64(10),b1000=big_nat_from_uint64(1000);
  big_nat_t r=big_nat_modpow(&b2,&b10,&b1000);
  big_nat_t b24=big_nat_from_uint64(24);
  assert(big_nat_equal(&r,&b24)==1); PASS(); }

void t5_mr(void) {
  TEST("miller_rabin");
  big_nat_t p7=big_nat_from_uint64(7),p97=big_nat_from_uint64(97);
  big_nat_t c91=big_nat_from_uint64(91),p2=big_nat_from_uint64(2);
  big_nat_t c4=big_nat_from_uint64(4);
  assert(mr_test(&p7,10)==1);
  assert(mr_test(&p97,10)==1);
  assert(mr_test(&c91,10)==0);
  assert(mr_test(&p2,5)==1);
  assert(mr_test(&c4,5)==0); PASS(); }

void t5_legendre(void) {
  TEST("legendre_symbol");
  big_nat_t a4=big_nat_from_uint64(4),p7=big_nat_from_uint64(7);
  big_nat_t a3=big_nat_from_uint64(3);
  assert(legendre_symbol(&a4,&p7)==1);
  assert(legendre_symbol(&a3,&p7)==-1);
  PASS(); }

void t4_gl(void) {
  TEST("gl_predicate");
  bit_string_t* x=bs_create(8); bit_string_t* r=bs_create(8);
  x->data[0]=0x0F; r->data[0]=0x55;
  assert(gl_predicate(x,r)==0);
  r->data[0]=0x01; assert(gl_predicate(x,r)==1);
  bs_free(x);bs_free(r); PASS(); }

void t4_gl_construct(void) {
  TEST("gl_construction");
  owf_scheme_t* b=owf_scheme_create("B","D",_eval,_inv,NULL,NULL,128,64,64);
  gl_construction_t* g=gl_construct_create(b); assert(g&&g->n==64);
  owf_scheme_t* go=gl_construct_as_owf(g); assert(go&&go->input_bits==128);
  owf_scheme_free(go);gl_construct_free(g);owf_scheme_free(b); PASS(); }

void t4_yao(void) {
  TEST("yao_amplification");
  owf_scheme_t* b=owf_scheme_create("B","D",_eval,_inv,NULL,NULL,256,32,32);
  yao_amplification_t* a=yao_amp_create(b,5,0.1);
  assert(a&&a->t==5&&a->input_bits==160);
  assert(fabs(a->strong_bound-pow(0.9,5.0))<0.0001);
  yao_amp_free(a);owf_scheme_free(b); PASS(); }

void t4_direct_product(void) {
  TEST("direct_product");
  assert(fabs(direct_product_bound(0.5,3)-0.125)<0.0001);
  PASS(); }

void t4_compute_t(void) {
  TEST("yao_compute_t");
  assert(yao_compute_t(0.5,1)==1); assert(yao_compute_t(0.25,4)==2); PASS(); }

void t6_rsa(void) {
  TEST("rsa_owf");
  rsa_params_t* r=rsa_params_generate(32);
  if(r){
    bit_string_t* x=bs_random(32); bit_string_t* y=NULL;
    int ret=rsa_owf_eval(r,x,256,&y);
    assert(ret==0&&y);
    /* One-wayness: evaluation succeeds, output is valid */
    assert(y->bit_len>0);
    bs_free(x);bs_free(y);
    rsa_params_free(r);
  }
  PASS(); }

void t6_ss(void) {
  TEST("subset_sum");
  ss_params_t* s=ss_params_generate(32);
  if(s){
    assert(s->m==32);
    bit_string_t* x=bs_create(32); x->data[0]=0x01;
    bit_string_t* y=NULL;
    int ret=ss_owf_eval(s,x,128,&y);
    assert(ret==0&&y);
    assert(y->bit_len>0);
    bs_free(x);bs_free(y);
    ss_params_free(s);
  }
  PASS(); }

static int _biased_pred(const bit_string_t* r, void* ctx) {
  bit_string_t* x=(bit_string_t*)ctx;
  int truth=gl_predicate(x,r);
  if((rand()%100)<70) return truth;
  return rand()&1; }

void t8_gl_decode(void) {
  TEST("gl_list_decode");
  bit_string_t* x=bs_create(16); x->data[0]=0xA5;x->data[1]=0x3C;
  gl_list_t* l=gl_list_create(64);
  int f=gl_list_decode(_biased_pred,x,16,0.1,l);
  assert(f>=0); gl_list_free(l); bs_free(x); PASS(); }

void t8_kbit(void) {
  TEST("kbit_hardcore");
  bit_string_t* x=bs_create(8); x->data[0]=0xFF;
  bit_string_t* r1=bs_create(8);r1->data[0]=0x01;
  bit_string_t* r2=bs_create(8);r2->data[0]=0x02;
  const bit_string_t* rl[2]={r1,r2};
  uint8_t bits=0;
  assert(gl_kbit_hardcore(x,rl,2,&bits)==0);
  assert(bits==3);
  bs_free(x);bs_free(r1);bs_free(r2); PASS(); }

int main(void) {
  srand((unsigned)time(NULL));
  printf("=== OWF Comprehensive Tests ===\n");
  printf("\n--- L1: Core Definitions ---\n");
  t1_scheme(); t1_eval();
  printf("\n--- L2: Core Concepts ---\n");
  t2_negl(); t2_invert_exp(); t2_strength();
  printf("\n--- L3: Mathematical Structures ---\n");
  t3_bs(); t3_big_nat(); t3_mod(); t3_modpow();
  printf("\n--- L4: Fundamental Laws ---\n");
  t4_gl(); t4_gl_construct(); t4_yao(); t4_direct_product(); t4_compute_t();
  printf("\n--- L5: Number Theory Algorithms ---\n");
  t5_mr(); t5_legendre();
  printf("\n--- L6: Canonical OWF Candidates ---\n");
  t6_rsa(); t6_ss();
  printf("\n--- L8: Advanced Topics ---\n");
  t8_gl_decode(); t8_kbit();
  printf("\n=== %d/%d tests passed ===\n", tests_passed, tests_run);
  return (tests_passed == tests_run) ? 0 : 1;
}
