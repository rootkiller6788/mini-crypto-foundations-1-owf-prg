/*
 * example_owf_candidates.c — Demonstrate all four OWF candidates
 *
 * L6 Canonical Problems:
 *   - RSA function: modular exponentiation
 *   - Discrete logarithm: exponentiation in Z_p^*
 *   - Rabin squaring: provably as hard as factoring
 *   - Subset sum: average-case hard
 *
 * Each candidate is evaluated with random inputs and the
 * inversion experiment is run to demonstrate one-wayness.
 */

#include "owf.h"
#include "crypto_utils.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    seed_random();
    printf("=== OWF Candidates Demonstration ===\n\n");

    /* ================================================================
     * Candidate 1: RSA Function
     * f_{N,e}(x) = x^e mod N
     * N = p*q = 7*11 = 77, e = 5 (public exponent)
     * Domain: x ∈ [0, 76]
     * ================================================================ */
    printf("--- RSA OWF (N=77, e=5) ---\n");
    {
        void *params = rsa_params_create(7, 11, 5);
        OWF *rsa = owf_create(12, rsa_owf_eval, params, "RSA(77,5)");
        printf("  N = 77, e = 5, phi = 60\n");

        uint64_t test_inputs[] = {2, 5, 10, 13, 42};
        int n_tests = 5;
        for (int i = 0; i < n_tests; i++) {
            uint64_t x_val = test_inputs[i];
            BitString *x = bitstring_create(12);
            BitString *y = bitstring_create(12);
            uint64_to_bitstring(x_val, 12, x);
            owf_eval(rsa, x, y);

            uint64_t y_val;
            bitstring_to_uint64(y, &y_val);
            printf("  f(%2llu) = %2llu^5 mod 77 = %2llu\n",
                   (unsigned long long)x_val,
                   (unsigned long long)x_val,
                   (unsigned long long)y_val);

            bitstring_free(x);
            bitstring_free(y);
        }
        owf_free(rsa);
    }

    /* ================================================================
     * Candidate 2: Discrete Logarithm
     * f_{p,g}(x) = g^x mod p
     * p = 23 (prime), g = 5 (generator)
     * ================================================================ */
    printf("\n--- Discrete Log OWF (p=23, g=5) ---\n");
    {
        void *params = dlog_params_create(23, 5);
        OWF *dlog = owf_create(12, dlog_owf_eval, params, "DLog(23,5)");
        printf("  p = 23, g = 5, order = 22\n");

        uint64_t test_inputs[] = {1, 2, 5, 10, 21};
        int n_tests = 5;
        for (int i = 0; i < n_tests; i++) {
            uint64_t x_val = test_inputs[i];
            BitString *x = bitstring_create(12);
            BitString *y = bitstring_create(12);
            uint64_to_bitstring(x_val, 12, x);
            owf_eval(dlog, x, y);

            uint64_t y_val;
            bitstring_to_uint64(y, &y_val);
            printf("  f(%2llu) = 5^%2llu mod 23 = %2llu\n",
                   (unsigned long long)x_val,
                   (unsigned long long)x_val,
                   (unsigned long long)y_val);

            bitstring_free(x);
            bitstring_free(y);
        }
        owf_free(dlog);
    }

    /* ================================================================
     * Candidate 3: Rabin Squaring Function
     * f_N(x) = x^2 mod N
     * N = 3*7 = 21 (Blum integer: 3≡7≡3 mod 4)
     * ================================================================ */
    printf("\n--- Rabin OWF (N=21, Blum integer) ---\n");
    {
        void *params = rabin_params_create(3, 7);
        OWF *rabin = owf_create(12, rabin_owf_eval, params, "Rabin(21)");
        printf("  N = 21 = 3×7 (Blum: 3≡7≡3 mod 4)\n");

        uint64_t test_inputs[] = {2, 4, 5, 8, 10};
        int n_tests = 5;
        for (int i = 0; i < n_tests; i++) {
            uint64_t x_val = test_inputs[i];
            BitString *x = bitstring_create(12);
            BitString *y = bitstring_create(12);
            uint64_to_bitstring(x_val, 12, x);
            owf_eval(rabin, x, y);

            uint64_t y_val;
            bitstring_to_uint64(y, &y_val);
            printf("  f(%2llu) = %2llu^2 mod 21 = %2llu\n",
                   (unsigned long long)x_val,
                   (unsigned long long)x_val,
                   (unsigned long long)y_val);

            bitstring_free(x);
            bitstring_free(y);
        }
        printf("  Note: Inverting requires factoring N — provably hard.\n");
        owf_free(rabin);
    }

    /* ================================================================
     * Candidate 4: Subset Sum
     * f_{a}(x) = Σ x_i · a_i mod M
     * Weights: {3, 5, 7, 11, 13, 17}, M = 100
     * ================================================================ */
    printf("\n--- Subset Sum OWF (weights={3,5,7,11,13,17}, M=100) ---\n");
    {
        uint64_t weights[] = {3, 5, 7, 11, 13, 17};
        void *params = subsetsum_params_create(6, weights, 100);
        OWF *ssum = owf_create(12, subset_sum_owf_eval, params, "SubsetSum");

        printf("  Weights: 3, 5, 7, 11, 13, 17\n");

        /* Test various subsets */
        struct { int bits[6]; uint64_t expected; } tests[] = {
            {{1,0,0,0,0,0}, 3},
            {{0,1,0,0,0,0}, 5},
            {{1,1,0,0,0,0}, 8},
            {{0,0,0,0,0,1}, 17},
            {{1,1,1,1,1,1}, 56},
        };
        int n_tests = 5;

        for (int t = 0; t < n_tests; t++) {
            BitString *x = bitstring_create(6);
            for (int b = 0; b < 6; b++) {
                bitstring_set_bit(x, (size_t)b, tests[t].bits[b]);
            }
            x->bit_len = 6;
            BitString *y = bitstring_create(12);
            owf_eval(ssum, x, y);

            uint64_t y_val;
            bitstring_to_uint64(y, &y_val);
            printf("  f(");
            for (int b = 0; b < 6; b++) printf("%d", tests[t].bits[b]);
            printf(") = %2llu (expected %2llu) %s\n",
                   (unsigned long long)y_val,
                   (unsigned long long)tests[t].expected,
                   (y_val == tests[t].expected) ? "✓" : "✗");

            bitstring_free(x);
            bitstring_free(y);
        }
        printf("  Note: Random subset sum is average-case hard (Impagliazzo-Naor 1996).\n");
        owf_free(ssum);
    }

    /* ================================================================
     * OWF Inversion Experiment
     * ================================================================ */
    printf("\n--- OWF Inversion Experiment (RSA, brute-force adversary) ---\n");
    {
        void *params = rsa_params_create(7, 11, 5); /* N=77, small for brute-force */
        OWF *rsa = owf_create(12, rsa_owf_eval, params, "RSA-test");

        /* Simple brute-force adversary (only works for small domains!) */
        OWFInversionResult result = owf_inversion_experiment(rsa, 10, NULL);
        printf("  Trials: %d\n", result.n_trials);
        printf("  Successes (brute-force): %d\n", result.n_successes);
        printf("  Success probability: %.4f\n", result.success_probability);
        printf("  (With real parameters, brute-force would be infeasible)\n");

        owf_free(rsa);
    }

    printf("\n=== Demonstration Complete ===\n");
    return 0;
}
