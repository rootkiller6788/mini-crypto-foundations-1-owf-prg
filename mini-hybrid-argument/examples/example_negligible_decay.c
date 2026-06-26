/*
 * example_negligible_decay.c - Demo: Negligible Function Decay Rates
 *
 * Compares different negligible functions and shows their decay.
 * Demonstrates concrete security parameter selection.
 */
#include "negligible.h"
#include <stdio.h>
#include <math.h>

int main(void) {
    printf("=== Negligible Function Decay Comparison ===\n\n");

    NegligibleFunction funcs[] = {
        negl_exp(),
        negl_near_exp(),
        negl_superpoly(),
        negl_exp_sqrt()
    };
    const char* names[] = {"2^{-n}", "n*2^{-n}", "n^{-log n}", "2^{-sqrt(n)}"};

    printf("%-14s %12s %12s %12s %12s\n",
           "Type", "n=10", "n=20", "n=50", "n=100");
    printf("--------------------------------------------------------------\n");
    for (int i = 0; i < 4; i++) {
        printf("%-14s %12.2e %12.2e %12.2e %12.2e\n",
               names[i],
               negl_eval(&funcs[i], 10),
               negl_eval(&funcs[i], 20),
               negl_eval(&funcs[i], 50),
               negl_eval(&funcs[i], 100));
    }

    printf("\n--- Concrete Security Parameter Selection ---\n");
    NegligibleFunction f = negl_exp();
    security_param_t n80 = negl_security_parameter_for_target(&f, 1e-24, 200);
    printf("For 2^{-n} < 2^{-80} ~ 8.27e-25: n >= %u\n", n80);

    f = negl_exp_sqrt();
    security_param_t n640 = negl_security_parameter_for_target(&f, 1e-24, 10000);
    printf("For 2^{-sqrt(n)} < 2^{-80}: n >= %u (much larger!)\n", n640);

    printf("\n--- Negligibility Check Against Polynomials ---\n");
    f = negl_exp();
    negl_print_polynomial_check_report(&f, 100);

    printf("\n--- Negligible Function Closures ---\n");
    NegligibleFunction f1 = negl_exp();
    NegligibleFunction f2 = negl_superpoly();
    NegligibleClosure nc = negl_closure_check(&f1, &f2, 20, 2.0, 3.0);
    negl_closure_print(&nc);

    printf("\n=== Demo Complete ===\n");
    return 0;
}
