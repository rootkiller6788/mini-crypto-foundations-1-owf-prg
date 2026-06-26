/*
 * test_security_reduction.c - Tests for security reduction framework
 */
#include "security_reduction.h"
#include <assert.h>
#include <stdio.h>
#include <math.h>

static int tests_run = 0, tests_passed = 0;

#define TEST(n) do { tests_run++; printf("  TEST: %s ... ", n); } while(0)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(m) do { printf("FAIL: %s\n", m); } while(0)

static void test_adv_profile(void) {
    TEST("adversary profile creation");
    AdversaryProfile ap = adv_profile_create(1000.0, 0.01);
    assert(ap.running_time == 1000.0);
    assert(ap.advantage == 0.01);
    assert(ap.is_ppt);
    PASS();
}

static void test_adv_profile_negligible(void) {
    TEST("adversary profile negligible check");
    AdversaryProfile ap = adv_profile_create(1.0, 1e-6);
    assert(adv_profile_is_negligible_advantage(&ap, 100));
    ap.advantage = 0.5;
    assert(!adv_profile_is_negligible_advantage(&ap, 100));
    PASS();
}

static void test_reduction_cost(void) {
    TEST("reduction cost creation");
    ReductionCost rc = reduction_cost_create(2.0, 10.0, 100.0);
    assert(rc.time_factor == 2.0);
    assert(rc.advantage_factor == 10.0);
    assert(rc.time_overhead == 100.0);
    assert(!rc.is_tight);
    assert(rc.tightness_score < 1.0);
    PASS();
}

static void test_reduction_apply(void) {
    TEST("reduction apply");
    AdversaryProfile in = adv_profile_create(500.0, 0.1);
    ReductionCost rc = reduction_cost_create(1.0, 5.0, 0.0);
    ReductionResult rr = reduction_apply(&in, &rc);
    assert(rr.output_profile.advantage <= in.advantage);
    assert(rr.security_loss == 5.0);
    PASS();
}

static void test_difference_lemma(void) {
    TEST("difference lemma");
    DifferenceLemma dl = difference_lemma_check(0.5, 0.55, 0.1);
    assert(dl.satisfies_lemma);
    dl = difference_lemma_check(0.3, 0.8, 0.1);
    assert(!dl.satisfies_lemma);
    PASS();
}

static void test_game_hopping(void) {
    TEST("game hopping sequence");
    GameHoppingSequence* gs = game_hop_create(10);
    assert(gs != NULL);
    game_hop_add(gs, "Game0: real", 0.7, 0.05);
    game_hop_add(gs, "Game1: modified", 0.65, 0.03);
    assert(gs->num_steps == 2);
    game_hop_compute_bound(gs);
    assert(gs->bound_holds);
    game_hop_free(gs);
    PASS();
}

static void test_repetition_amplify(void) {
    TEST("repetition amplification");
    RepetitionAmplification ra = repetition_amplify(0.1, 0.99, 0.001);
    assert(ra.repetitions_needed > 0);
    assert(ra.amplified_advantage > ra.base_advantage);
    PASS();
}

static void test_concrete_security(void) {
    TEST("concrete security estimate");
    ConcreteSecurityEstimate cse = concrete_security_estimate(100.0, 80.0, 1024);
    assert(cse.reduction_loss_bits > 0.0);
    assert(cse.effective_security_bits < cse.target_security_bits);
    PASS();
}

static double dummy_runner(int trial) {
    (void)trial;
    return 0.05;
}

static void test_bound_verification(void) {
    TEST("bound verification monte carlo");
    BoundVerification bv = bound_verify_monte_carlo(dummy_runner, 0.1, 100);
    assert(bv.num_trials == 100);
    assert(bv.measured_advantage >= 0.0);
    assert(bv.bound_holds);
    PASS();
}

int main(void) {
    printf("=== test_security_reduction ===\n");
    rand_seed(42);

    test_adv_profile();
    test_adv_profile_negligible();
    test_reduction_cost();
    test_reduction_apply();
    test_difference_lemma();
    test_game_hopping();
    test_repetition_amplify();
    test_concrete_security();
    test_bound_verification();

    printf("\n=== RESULTS: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
