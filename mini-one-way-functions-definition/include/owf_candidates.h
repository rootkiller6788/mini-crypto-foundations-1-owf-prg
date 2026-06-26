/*
 * owf_candidates.h — Candidate One-Way Functions
 *
 * L6 Canonical Problems realized as OWF candidates:
 *   - RSA-OWF:    f_{N,e}(x) = x^e mod N  (Factoring Assumption)
 *   - DL-OWF:     f_{p,g}(x) = g^x mod p   (Discrete Log Assumption)
 *   - SS-OWF:     f_{a}(x) = (a·x, x)     (Subset Sum / Knapsack)
 *   - RABIN-OWF:  f_N(x) = x^2 mod N       (Factoring, stronger)
 *
 * L5 Algorithms:
 *   - Modular exponentiation with multi-precision
 *   - Prime/group parameter generation
 *   - Subset sum evaluation with large integers
 *
 * L1 Definitions:
 *   Each candidate is a concrete owf_scheme_t with all metadata.
 *
 * Reference:
 *   Rivest-Shamir-Adleman (1978), Diffie-Hellman (1976),
 *   Merkle-Hellman (1978), Rabin (1979)
 *   Goldreich Vol 1 §2.4.3-2.4.4,
 *   Katz-Lindell §7.3
 *
 * Courses: All nine institutions
 */

#ifndef OWF_CANDIDATES_H
#define OWF_CANDIDATES_H

#include "owf_core.h"
#include "owf_number_theory.h"

/* ================================================================
 * RSA One-Way Function:  f_{N,e}(x) = x^e mod N
 * ================================================================ */

/*
 * RSA Assumption: Given (N, e, y) where N = p·q for random primes p,q,
 * e coprime to φ(N) = (p-1)(q-1), and y = x^e mod N for
 * random x ∈ Z_N^*, it is computationally hard to find x.
 *
 * The RSA-OWF is a trapdoor permutation: with d = e^{-1} mod φ(N),
 * one can compute x = y^d mod N.
 */

typedef struct {
    big_nat_t N;        /* modulus N = p * q */
    big_nat_t e;        /* public exponent (typically 65537) */
    big_nat_t d;        /* private exponent d = e^{-1} mod φ(N) */
    big_nat_t p;        /* prime factor p */
    big_nat_t q;        /* prime factor q */
    big_nat_t phi_N;    /* φ(N) = (p-1)(q-1) */
    size_t    nbits;    /* bit-length of N */
} rsa_params_t;

/* Generate RSA parameters with n-bit modulus */
rsa_params_t* rsa_params_generate(size_t nbits);
void          rsa_params_free(rsa_params_t* rsa);
void          rsa_params_print(const rsa_params_t* rsa);

/* RSA-OWF evaluation: y = x^e mod N */
int rsa_owf_eval(void* ctx, const bit_string_t* x,
                 sec_param_t n, bit_string_t** y);

/* RSA-OWF inversion with trapdoor: x = y^d mod N */
int rsa_owf_invert_trapdoor(const rsa_params_t* rsa,
                             const bit_string_t* y, bit_string_t** x);

/* RSA-OWF as owf_scheme_t */
owf_scheme_t* rsa_owf_create(rsa_params_t* rsa);

/* ================================================================
 * Discrete Logarithm One-Way Function:  f_{p,g}(x) = g^x mod p
 * ================================================================ */

/*
 * DL Assumption: Given (p, g, y) where p is prime, g is generator
 * of Z_p^* (or large subgroup), and y = g^x mod p for random x,
 * it is computationally hard to find x.
 *
 * The DL-OWF is a candidate OWF over the group Z_p^*.
 * It is NOT a trapdoor (unless using specific groups).
 */

typedef struct {
    big_nat_t p;        /* prime modulus */
    big_nat_t g;        /* generator of subgroup */
    big_nat_t q;        /* order of g (prime dividing p-1) */
    size_t    nbits;    /* bit-length of p */
} dl_params_t;

/* Generate DL parameters (p, g) with n-bit prime p.
 * q = (p-1)/2 (safe prime subgroup). */
dl_params_t* dl_params_generate(size_t nbits);
void         dl_params_free(dl_params_t* dl);
void         dl_params_print(const dl_params_t* dl);

/* DL-OWF evaluation: y = g^x mod p */
int dl_owf_eval(void* ctx, const bit_string_t* x,
                sec_param_t n, bit_string_t** y);

/* DL-OWF as owf_scheme_t */
owf_scheme_t* dl_owf_create(dl_params_t* dl);

/* ================================================================
 * Subset Sum One-Way Function:  f_{a_1,...,a_m}(x_1,...,x_m) = Σ a_i·x_i
 * ================================================================ */

/*
 * Subset Sum Assumption: Given (a_1,...,a_m) and S = Σ a_i·x_i
 * where a_i are random n-bit integers and x_i ∈ {0,1},
 * it is computationally hard to find x.
 *
 * This is an early candidate OWF (Merkle-Hellman knapsack, broken
 * in its trapdoor form, but the general subset sum remains hard).
 *
 * For parameters m ≈ n, the density a = n / log2(max a_i) ≈ 1
 * makes this a hard instance.
 */

typedef struct {
    big_nat_t* a;       /* array of m integer weights */
    size_t     m;       /* number of weights */
    size_t     nbits;   /* bit-length of each weight */
} ss_params_t;

/* Generate subset sum parameters: m = nbits, weights are nbits-bit random */
ss_params_t* ss_params_generate(size_t nbits);
void         ss_params_free(ss_params_t* ss);
void         ss_params_print(const ss_params_t* ss);

/* Subset Sum OWF evaluation: S = Σ a_i * x_i */
int ss_owf_eval(void* ctx, const bit_string_t* x,
                sec_param_t n, bit_string_t** y);

/* Subset Sum OWF as owf_scheme_t */
owf_scheme_t* ss_owf_create(ss_params_t* ss);

/* ================================================================
 * Rabin One-Way Function: f_N(x) = x^2 mod N
 * ================================================================ */

/*
 * Rabin OWF: f_N(x) = x^2 mod N where N = p·q, p≡q≡3 mod 4.
 *
 * Inverting this is provably as hard as factoring N (Rabin 1979).
 * This is a STRONGER result than RSA: equivalence, not just reduction.
 *
 * However, f_N is 4-to-1, so it's not a permutation.
 */

typedef struct {
    big_nat_t N;        /* modulus N = p * q */
    big_nat_t p;        /* prime p ≡ 3 mod 4 */
    big_nat_t q;        /* prime q ≡ 3 mod 4 */
    size_t    nbits;
} rabin_params_t;

/* Generate Rabin parameters: n-bit N = p·q, p≡q≡3 mod 4 */
rabin_params_t* rabin_params_generate(size_t nbits);
void            rabin_params_free(rabin_params_t* rab);
void            rabin_params_print(const rabin_params_t* rab);

/* Rabin OWF evaluation: y = x^2 mod N */
int rabin_owf_eval(void* ctx, const bit_string_t* x,
                   sec_param_t n, bit_string_t** y);

/* Rabin inversion with trapdoor: finds all 4 square roots */
int rabin_owf_invert_trapdoor(const rabin_params_t* rab,
                               const bit_string_t* y,
                               bit_string_t* roots[4]);

/* Rabin OWF as owf_scheme_t */
owf_scheme_t* rabin_owf_create(rabin_params_t* rab);

/* ================================================================
 * Candidate Benchmark: empirical inversion experiment
 * ================================================================ */

/*
 * Run a complete inversion experiment for any OWF candidate:
 *   1. Sample random x
 *   2. Compute y = f(x)
 *   3. Attempt to invert using the scheme's inverter
 *   4. Report success rate and timing
 */
typedef struct {
    owf_scheme_t*  owf;
    int            num_trials;
    int            successes;
    double         success_rate;
    double         avg_eval_time_ms;
    double         avg_invert_time_ms;
    double         best_advantage;
} owf_benchmark_t;

owf_benchmark_t* owf_benchmark_run(owf_scheme_t* owf, int num_trials);
void             owf_benchmark_free(owf_benchmark_t* bench);
void             owf_benchmark_print(const owf_benchmark_t* bench);

#endif /* OWF_CANDIDATES_H */
