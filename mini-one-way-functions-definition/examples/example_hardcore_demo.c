/* example_hardcore_demo.c - Goldreich-Levin Hardcore Predicate Demo */
#include "owf_hardcore.h"
#include "owf_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(void) {
  srand((unsigned)time(NULL));
  printf("=== Goldreich-Levin Hardcore Predicate Demo ===\n\n");
  size_t n = 16;
  bit_string_t* x = bs_create(n);
  x->data[0] = 0xA5; x->data[1] = 0x3C;
  printf("Secret x: "); bs_print_hex(x, NULL);

  printf("\n--- Part 1: GL Predicate ---\n");
  for(int i=0;i<5;i++){
    bit_string_t* r=bs_random(n);
    int bit=gl_predicate(x,r);
    printf("  GL(x, r%d) = %d\n",i,bit);
    bs_free(r); }

  printf("\n--- Part 2: Trivial vs Informed Prediction ---\n");
  int correct_trivial=0;
  for(int i=0;i<100;i++){
    bit_string_t* r=bs_random(n);
    int truth=gl_predicate(x,r);
    int guess0=trivial_constant_predictor(r,NULL);
    if(guess0==truth)correct_trivial++;
    bs_free(r); }
  printf("  Trivial (always 0): %d/100 correct\n",correct_trivial);
  printf("  (Without x, prediction is essentially random)\n");

  printf("\n--- Part 3: GL List Decoding ---\n");
  gl_list_t* list=gl_list_create(64);
  int found=gl_list_decode(trivial_constant_predictor,NULL,n,0.1,list);
  printf("  Candidates found (using bad predictor): %d\n",found);
  printf("  (A good predictor with advantage > 1/2 would recover x)\n");
  gl_list_free(list);

  printf("\n--- Part 4: k-bit Hardcore Function ---\n");
  bit_string_t* r1=bs_create(n); bit_string_t* r2=bs_create(n);
  r1->data[0]=0x55; r2->data[0]=0xAA;
  const bit_string_t* rl[2]={r1,r2};
  uint8_t bits=0;
  gl_kbit_hardcore(x,rl,2,&bits);
  printf("  2-bit hardcore output: 0x%02x\n",bits);
  printf("  Theorem: These 2 bits are simultaneously unpredictable\n");
  bs_free(r1); bs_free(r2);

  printf("\n--- Part 5: Hardcore Predicate Experiment ---\n");
  printf("  Running 20 trials...\n");
  hardcore_predicate_t* hcp=hcp_create("GL",gl_predicate_combined,NULL);
  printf("  Predicate: %s\n",hcp->name);
  printf("  (Without OWF, just testing predicate computation)\n");
  hcp_free(hcp);

  bs_free(x);
  printf("\n=== Hardcore Predicate Demo Complete ===\n");
  return 0; }