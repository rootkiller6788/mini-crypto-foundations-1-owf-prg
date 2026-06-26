/*
 * owf_candidates.c — Candidate One-Way Function Implementations
 *
 * L1 Definitions: Each candidate instantiates the formal OWF interface.
 * L5 Algorithms: Modular exponentiation, prime generation for each scheme.
 * L6 Canonical Problems: RSA, Discrete Log, Subset Sum, Rabin as OWF.
 *
 * Every function implements a specific knowledge point:
 *   - RSA OWF: Cryptosystem based on factoring hardness (Rivest-Shamir-Adleman 1978)
 *   - DL OWF: Discrete log-based OWF (Diffie-Hellman 1976)
 *   - SS OWF: Subset sum / knapsack-based OWF (Merkle-Hellman 1978)
 *   - Rabin OWF: Squaring mod N, provably as hard as factoring (Rabin 1979)
 *   - Benchmark: Empirical measurement of OWF hardness
 *
 * Reference:
 *   Goldreich Vol 1 §2.4.3-2.4.4, Katz-Lindell §7.3
 *   Menezes-van Oorschot-Vanstone Ch.3,8
 */

#include "owf_candidates.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

/* ================================================================
 * RSA Parameters
 *
 * L3: RSA is defined over Z_N where N = p·q for distinct primes.
 * phi(N) = (p-1)(q-1). Public exponent e with gcd(e, phi(N)) = 1.
 * Private exponent d = e^{-1} mod phi(N).
 *
 * The RSA function f_{N,e}(x) = x^e mod N is a trapdoor permutation
 * on Z_N^*. The trapdoor is d.
 * ================================================================ */

rsa_params_t* rsa_params_generate(size_t nbits) {
    rsa_params_t* rsa = (rsa_params_t*)calloc(1, sizeof(rsa_params_t));
    if (!rsa) return NULL;

    rsa->nbits = nbits;
    size_t half_bits = nbits / 2;
    uint64_t attempts_p = 0, attempts_q = 0;

    rsa->p = generate_random_prime(half_bits, 40, &attempts_p);

    do {
        rsa->q = generate_random_prime(half_bits, 40, &attempts_q);
        attempts_q++;
    } while (big_nat_equal(&rsa->p, &rsa->q) && attempts_q < 100);

    rsa->N = big_nat_mul(&rsa->p, &rsa->q);

    big_nat_t one  = big_nat_from_uint64(1);
    big_nat_t pm1  = big_nat_sub(&rsa->p, &one);
    big_nat_t qm1  = big_nat_sub(&rsa->q, &one);
    rsa->phi_N = big_nat_mul(&pm1, &qm1);
    rsa->e = big_nat_from_uint64(65537);
    rsa->d = big_nat_modinv(&rsa->e, &rsa->phi_N);

    return rsa;
}

void rsa_params_free(rsa_params_t* rsa) {
    free(rsa);
}

void rsa_params_print(const rsa_params_t* rsa) {
    if (!rsa) { printf("RSA params: NULL\n"); return; }
    printf("=== RSA Parameters (%zu bits) ===\n", rsa->nbits);
    big_nat_print_hex(&rsa->N, "N = ");
    big_nat_print_hex(&rsa->e, "e = ");
    printf("  (d, p, q not shown for security)\n");
}

/* ================================================================
 * RSA OWF Evaluation
 *
 * L5: f_{N,e}(x) = x^e mod N
 *
 * Input x must be in Z_N (0 <= x < N). Easy to compute
 * via O(log e · log^2 N) modular exponentiation.
 * Inverting believed to require factoring N (RSA Assumption).
 * ================================================================ */

int rsa_owf_eval(void* ctx, const bit_string_t* x,
                 sec_param_t n, bit_string_t** y) {
    (void)n;
    if (!ctx || !x || !y) return -1;

    rsa_params_t* rsa = (rsa_params_t*)ctx;
    big_nat_t mx = big_nat_from_bit_string(x);

    if (big_nat_compare(&mx, &rsa->N) >= 0) {
        mx = big_nat_mod(&mx, &rsa->N);
    }
    if (big_nat_is_zero(&mx)) {
        mx = big_nat_from_uint64(1);
    }

    big_nat_t my = big_nat_modpow(&mx, &rsa->e, &rsa->N);
    *y = big_nat_to_bit_string(&my, rsa->nbits);
    return (*y) ? 0 : -1;
}

/* ================================================================
 * RSA OWF Inversion (with trapdoor)
 *
 * L5: x = y^d mod N. Correctness by Euler theorem:
 * (x^e)^d = x^{ed} = x^{1 + k*phi(N)} = x (mod N)
 * ================================================================ */

int rsa_owf_invert_trapdoor(const rsa_params_t* rsa,
                             const bit_string_t* y, bit_string_t** x) {
    if (!rsa || !y || !x) return -1;

    big_nat_t my = big_nat_from_bit_string(y);
    big_nat_t mx = big_nat_modpow(&my, &rsa->d, &rsa->N);

    *x = big_nat_to_bit_string(&mx, rsa->nbits);
    return (*x) ? 0 : -1;
}

owf_scheme_t* rsa_owf_create(rsa_params_t* rsa) {
    return owf_scheme_create(
        "RSA-OWF",
        "Factoring Assumption (RSA)",
        rsa_owf_eval,
        NULL, NULL,
        rsa,
        SEC_PARAM_STD,
        rsa->nbits,
        rsa->nbits
    );
}

/* ================================================================
 * Discrete Log Parameters
 *
 * L3: DL-OWF operates in multiplicative group Z_p^*.
 * f_{p,g}(x) = g^x mod p where g generates a large subgroup.
 * Safe primes p = 2q + 1 are used for the subgroup of order q.
 * ================================================================ */

dl_params_t* dl_params_generate(size_t nbits) {
    dl_params_t* dl = (dl_params_t*)calloc(1, sizeof(dl_params_t));
    if (!dl) return NULL;

    dl->nbits = nbits;
    uint64_t attempts = 0;

    dl->p = generate_safe_prime(nbits, 40, &attempts, &dl->q);
    dl->g = big_nat_from_uint64(2);

    big_nat_t test = big_nat_modpow(&dl->g, &dl->q, &dl->p);
    big_nat_t one = big_nat_from_uint64(1);
    if (!big_nat_equal(&test, &one)) {
        dl->g = big_nat_from_uint64(3);
    }

    return dl;
}

void dl_params_free(dl_params_t* dl) {
    free(dl);
}

void dl_params_print(const dl_params_t* dl) {
    if (!dl) { printf("DL params: NULL\n"); return; }
    printf("=== Discrete Log Parameters (%zu bits) ===\n", dl->nbits);
    big_nat_print_hex(&dl->p, "p = ");
    big_nat_print_hex(&dl->g, "g = ");
    printf("  q order: %u bits\n", (unsigned)(dl->nbits - 1));
}

/* ================================================================
 * DL OWF Evaluation
 *
 * L5: f_{p,g}(x) = g^x mod p.
 * Foundation of Diffie-Hellman key exchange, ElGamal, DSA.
 * ================================================================ */

int dl_owf_eval(void* ctx, const bit_string_t* x,
                sec_param_t n, bit_string_t** y) {
    (void)n;
    if (!ctx || !x || !y) return -1;

    dl_params_t* dl = (dl_params_t*)ctx;
    big_nat_t mx = big_nat_from_bit_string(x);

    if (big_nat_compare(&mx, &dl->q) >= 0) {
        mx = big_nat_mod(&mx, &dl->q);
    }

    big_nat_t my = big_nat_modpow(&dl->g, &mx, &dl->p);
    *y = big_nat_to_bit_string(&my, dl->nbits);
    return (*y) ? 0 : -1;
}

owf_scheme_t* dl_owf_create(dl_params_t* dl) {
    return owf_scheme_create(
        "DL-OWF",
        "Discrete Log Assumption",
        dl_owf_eval, NULL, NULL,
        dl,
        SEC_PARAM_STD,
        dl->nbits,
        dl->nbits
    );
}

/* ================================================================
 * Subset Sum Parameters
 *
 * L6: Subset Sum Problem: given a_1..a_m and S, find x in {0,1}^m
 * such that sum a_i*x_i = S.
 * OWF: f(x) = sum a_i*x_i. Density d = m / log2(max a_i) ~ 1.
 * ================================================================ */

ss_params_t* ss_params_generate(size_t nbits) {
    ss_params_t* ss = (ss_params_t*)calloc(1, sizeof(ss_params_t));
    if (!ss) return NULL;

    ss->nbits = nbits;
    ss->m = nbits;

    ss->a = (big_nat_t*)calloc(ss->m, sizeof(big_nat_t));
    if (!ss->a) {
        free(ss);
        return NULL;
    }

    for (size_t i = 0; i < ss->m; i++) {
        ss->a[i] = big_nat_random_bits(nbits);
        if (big_nat_is_zero(&ss->a[i])) {
            ss->a[i] = big_nat_from_uint64(i + 1);
        }
    }

    return ss;
}

void ss_params_free(ss_params_t* ss) {
    if (ss) {
        free(ss->a);
        free(ss);
    }
}

void ss_params_print(const ss_params_t* ss) {
    if (!ss) { printf("SS params: NULL\n"); return; }
    printf("=== Subset Sum Parameters ===\n");
    printf("  m = %zu weights, %zu bits each\n", ss->m, ss->nbits);
    printf("  Density = %.2f\n", (double)ss->m / (double)ss->nbits);
    printf("  First weight: ");
    big_nat_print_hex(&ss->a[0], NULL);
    printf("  Last weight: ");
    big_nat_print_hex(&ss->a[ss->m - 1], NULL);
}

/* ================================================================
 * Subset Sum OWF Evaluation
 *
 * L5: f(x) = sum_{i=1}^m a_i * x_i
 * Computation: O(m * log^2 N). Inversion is NP-complete in general.
 * ================================================================ */

int ss_owf_eval(void* ctx, const bit_string_t* x,
                sec_param_t n, bit_string_t** y) {
    (void)n;
    if (!ctx || !x || !y) return -1;

    ss_params_t* ss = (ss_params_t*)ctx;
    big_nat_t sum = big_nat_zero();
    size_t max_m = x->bit_len < ss->m ? x->bit_len : ss->m;

    for (size_t i = 0; i < max_m; i++) {
        size_t byte_idx = i / 8;
        size_t bit_idx  = i % 8;
        if (byte_idx >= x->byte_cap) break;

        int bit = (x->data[byte_idx] >> bit_idx) & 1;
        if (bit) {
            sum = big_nat_add(&sum, &ss->a[i]);
        }
    }

    *y = big_nat_to_bit_string(&sum, ss->nbits);
    return (*y) ? 0 : -1;
}

owf_scheme_t* ss_owf_create(ss_params_t* ss) {
    return owf_scheme_create(
        "Subset-Sum-OWF",
        "Subset Sum (Knapsack) Hardness",
        ss_owf_eval, NULL, NULL,
        ss,
        SEC_PARAM_STD,
        ss->m,
        ss->nbits
    );
}

/* ================================================================
 * Rabin Parameters
 *
 * L6: Rabin OWF f_N(x) = x^2 mod N, N = p*q, p = q = 3 mod 4.
 *
 * Theorem (Rabin 1979): Inverting f_N is polynomially equivalent
 * to factoring N — stronger guarantee than RSA.
 * The function is 4-to-1: each y has 4 square roots mod N.
 * ================================================================ */

rabin_params_t* rabin_params_generate(size_t nbits) {
    rabin_params_t* rab = (rabin_params_t*)calloc(1, sizeof(rabin_params_t));
    if (!rab) return NULL;

    rab->nbits = nbits;
    size_t half_bits = nbits / 2;
    uint64_t attempts_p = 0, attempts_q = 0;
    big_nat_t four  = big_nat_from_uint64(4);
    big_nat_t three = big_nat_from_uint64(3);

    do {
        rab->p = generate_random_prime(half_bits, 40, &attempts_p);
        big_nat_t q, r;
        big_nat_divmod(&rab->p, &four, &q, &r);
        if (big_nat_equal(&r, &three)) break;
    } while (1);

    do {
        rab->q = generate_random_prime(half_bits, 40, &attempts_q);
        big_nat_t q2, r;
        big_nat_divmod(&rab->q, &four, &q2, &r);
        if (big_nat_equal(&r, &three) && !big_nat_equal(&rab->q, &rab->p)) break;
    } while (1);

    rab->N = big_nat_mul(&rab->p, &rab->q);
    return rab;
}

void rabin_params_free(rabin_params_t* rab) {
    free(rab);
}

void rabin_params_print(const rabin_params_t* rab) {
    if (!rab) { printf("Rabin params: NULL\n"); return; }
    printf("=== Rabin Parameters (%zu bits) ===\n", rab->nbits);
    big_nat_print_hex(&rab->N, "N = ");
    printf("  (p, q satisfy p = q = 3 mod 4)\n");
}

/* ================================================================
 * Rabin OWF Evaluation
 *
 * L5: f_N(x) = x^2 mod N. Single modular squaring.
 * ================================================================ */

int rabin_owf_eval(void* ctx, const bit_string_t* x,
                   sec_param_t n, bit_string_t** y) {
    (void)n;
    if (!ctx || !x || !y) return -1;

    rabin_params_t* rab = (rabin_params_t*)ctx;
    big_nat_t two = big_nat_from_uint64(2);
    big_nat_t mx = big_nat_from_bit_string(x);

    if (big_nat_compare(&mx, &rab->N) >= 0) {
        mx = big_nat_mod(&mx, &rab->N);
    }

    big_nat_t my = big_nat_modpow(&mx, &two, &rab->N);
    *y = big_nat_to_bit_string(&my, rab->nbits);
    return (*y) ? 0 : -1;
}

/* ================================================================
 * Rabin OWF Inversion (with trapdoor)
 *
 * L5: Find all 4 square roots of y mod N using CRT.
 * Since p = q = 3 mod 4: rp = y^{(p+1)/4} mod p,
 * rq = y^{(q+1)/4} mod q. Roots: CRT(+/-rp, +/-rq).
 * ================================================================ */

int rabin_owf_invert_trapdoor(const rabin_params_t* rab,
                               const bit_string_t* y,
                               bit_string_t* roots[4]) {
    if (!rab || !y || !roots) return -1;

    big_nat_t four = big_nat_from_uint64(4);
    big_nat_t one  = big_nat_from_uint64(1);
    big_nat_t my   = big_nat_from_bit_string(y);

    big_nat_t mp = big_nat_mod(&my, &rab->p);
    big_nat_t mq = big_nat_mod(&my, &rab->q);

    big_nat_t p_plus_1 = big_nat_add(&rab->p, &one);
    big_nat_t qq, rr;
    big_nat_divmod(&p_plus_1, &four, &qq, &rr);
    big_nat_t exp_p = qq;

    big_nat_t q_plus_1 = big_nat_add(&rab->q, &one);
    big_nat_divmod(&q_plus_1, &four, &qq, &rr);
    big_nat_t exp_q = qq;

    big_nat_t rp  = big_nat_modpow(&mp, &exp_p, &rab->p);
    big_nat_t rq  = big_nat_modpow(&mq, &exp_q, &rab->q);
    big_nat_t nrp = big_nat_sub(&rab->p, &rp);
    big_nat_t nrq = big_nat_sub(&rab->q, &rq);

    big_nat_t moduli[2] = {rab->p, rab->q};
    big_nat_t res1[2] = {rp, rq};
    big_nat_t res2[2] = {nrp, rq};
    big_nat_t res3[2] = {rp, nrq};
    big_nat_t res4[2] = {nrp, nrq};

    big_nat_t roots_n[4];
    roots_n[0] = crt_solve(res1, moduli, 2);
    roots_n[1] = crt_solve(res2, moduli, 2);
    roots_n[2] = crt_solve(res3, moduli, 2);
    roots_n[3] = crt_solve(res4, moduli, 2);

    for (int i = 0; i < 4; i++) {
        roots[i] = big_nat_to_bit_string(&roots_n[i], rab->nbits);
    }
    return 0;
}

owf_scheme_t* rabin_owf_create(rabin_params_t* rab) {
    return owf_scheme_create(
        "Rabin-OWF",
        "Factoring Equivalence (Rabin 1979)",
        rabin_owf_eval, NULL, NULL,
        rab,
        SEC_PARAM_STD,
        rab->nbits,
        rab->nbits
    );
}

/* ================================================================
 * OWF Candidate Benchmark
 *
 * L2: Empirical measurement of one-wayness via repeated
 * inversion experiments. Measures success rate and timing.
 * ================================================================ */

owf_benchmark_t* owf_benchmark_run(owf_scheme_t* owf, int num_trials) {
    if (!owf || num_trials <= 0) return NULL;

    owf_benchmark_t* bench = (owf_benchmark_t*)calloc(1, sizeof(owf_benchmark_t));
    if (!bench) return NULL;

    bench->owf = owf;
    bench->num_trials = num_trials;

    clock_t total_eval = 0, total_invert = 0;

    for (int i = 0; i < num_trials; i++) {
        bit_string_t* x = bs_random(owf->input_bits);
        if (!x) continue;

        clock_t t0 = clock();
        bit_string_t* y = NULL;
        owf_evaluate(owf, x, &y);
        clock_t t1 = clock();
        total_eval += (t1 - t0);

        if (y && owf->invert) {
            t0 = clock();
            bit_string_t* x_prime = NULL;
            int ret = owf_attempt_invert(owf, y, &x_prime);
            t1 = clock();
            total_invert += (t1 - t0);

            if (ret == 0 && x_prime) {
                bench->successes++;
                bs_free(x_prime);
            }
        }
        bs_free(x);
        bs_free(y);
    }

    bench->success_rate = (double)bench->successes / (double)num_trials;
    bench->avg_eval_time_ms =
        (double)total_eval / (double)num_trials * 1000.0 / CLOCKS_PER_SEC;
    bench->avg_invert_time_ms =
        (double)total_invert / (double)num_trials * 1000.0 / CLOCKS_PER_SEC;
    bench->best_advantage = bench->success_rate
        - (1.0 / pow(2.0, (double)owf->input_bits));
    if (bench->best_advantage < 0.0) bench->best_advantage = 0.0;

    return bench;
}

void owf_benchmark_free(owf_benchmark_t* bench) {
    free(bench);
}

void owf_benchmark_print(const owf_benchmark_t* bench) {
    if (!bench) { printf("Benchmark: NULL\n"); return; }
    printf("=== OWF Candidate Benchmark ===\n");
    printf("  OWF: %s\n", bench->owf ? bench->owf->name : "unknown");
    printf("  Assumption: %s\n", bench->owf ? bench->owf->assumption : "unknown");
    printf("  Trials: %d\n", bench->num_trials);
    printf("  Successes: %d (%.4f%%)\n",
           bench->successes, bench->success_rate * 100.0);
    printf("  Advantage: %.6f\n", bench->best_advantage);
    printf("  Avg eval time: %.3f ms\n", bench->avg_eval_time_ms);
    printf("  Avg invert time: %.3f ms\n", bench->avg_invert_time_ms);
}
