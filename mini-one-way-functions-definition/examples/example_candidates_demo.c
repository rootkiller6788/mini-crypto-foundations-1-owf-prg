/* example_candidates_demo.c - OWF Candidates Demo */
#include "owf_candidates.h"
#include "owf_core.h"
#include "owf_number_theory.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(void) {
  srand((unsigned)time(NULL));
  printf("=== OWF Candidate Constructions Demo ===\n\n");

  printf("--- RSA-OWF ---\n");
  rsa_params_t* rsa = rsa_params_generate(32);
  if(rsa){
    rsa_params_print(rsa);
    bit_string_t* x=bs_random(32);bit_string_t* y=NULL;
    if(rsa_owf_eval(rsa,x,256,&y)==0&&y){
      printf("RSA: f(x) computed\n");
      bs_print_hex(y,"  y = ");
      bit_string_t* xp=NULL;
      if(rsa_owf_invert_trapdoor(rsa,y,&xp)==0&&xp){
        printf("  Trapdoor inversion OK\n");
        bs_free(xp); } bs_free(y); }
    bs_free(x); rsa_params_free(rsa); }

  printf("\n--- DL-OWF ---\n");
  dl_params_t* dl=dl_params_generate(32);
  if(dl){ dl_params_print(dl);
    bit_string_t* x=bs_random(31);bit_string_t* y=NULL;
    if(dl_owf_eval(dl,x,128,&y)==0&&y){
      printf("DL: g^x mod p computed\n");
      bs_print_hex(y,"  y = "); bs_free(y); }
    bs_free(x); dl_params_free(dl); }

  printf("\n--- Subset-Sum OWF ---\n");
  ss_params_t* ss=ss_params_generate(32);
  if(ss){ ss_params_print(ss);
    bit_string_t* x=bs_create(32);x->data[0]=0x55;
    bit_string_t* y=NULL;
    if(ss_owf_eval(ss,x,128,&y)==0&&y){
      printf("SS-OWF: sum computed\n");
      big_nat_t sn=big_nat_from_bit_string(y);
      printf("  Sum = ");big_nat_print(&sn,NULL);
      bs_free(y); }
    bs_free(x); ss_params_free(ss); }

  printf("\n--- Rabin OWF ---\n");
  rabin_params_t* rab=rabin_params_generate(32);
  if(rab){ rabin_params_print(rab);
    bit_string_t* x=bs_random(32);bit_string_t* y=NULL;
    if(rabin_owf_eval(rab,x,256,&y)==0&&y){
      printf("Rabin: x^2 mod N computed\n");
      bit_string_t* roots[4]={NULL};
      if(rabin_owf_invert_trapdoor(rab,y,roots)==0){
        printf("  Found 4 square roots\n");
        for(int i=0;i<4;i++){if(roots[i])bs_free(roots[i]);} }
      bs_free(y); }
    bs_free(x); rabin_params_free(rab); }

  printf("\n=== Candidates Demo Complete ===\n");
  return 0; }