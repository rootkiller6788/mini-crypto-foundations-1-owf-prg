# mini-hybrid-argument

The Hybrid Argument -- the fundamental proof technique in modern cryptography for establishing computational indistinguishability between probability ensembles.

## Module Status: COMPLETE ✅

- L1-L6: Complete
- L7: Complete (5 applications: stream cipher, KDF, statistical analysis, concrete parameter selection, prediction-based PRG assessment)
- L8: Partial (3/5 advanced topics: random oracle model, distinguisher composition, Yao equivalence theorem)
- L9: Partial (documented, not implemented)

## Core Definitions

| Term | Definition |
|------|-----------|
| Distribution Ensemble | {X_n}_{n in N} where X_n is a distribution over {0,1}^{l(n)} |
| PPT Distinguisher D | D: {0,1}^* -> {0,1} computable in poly(n) time |
| Advantage | Adv_D(X,Y) = |Pr[D(X)=1] - Pr[D(Y)=1]| |
| Computational Indist. | X ~=_c Y iff for all PPT D: Adv_D(X,Y) <= negl(n) |
| Hybrid Sequence | H_0, H_1, ..., H_m ordered sequence of distributions |
| Negligible Function | mu(n) < 1/p(n) for all poly p and large enough n |
| PRG | G: {0,1}^n -> {0,1}^{l(n)}, l(n) > n, output ~=_c uniform |
| Statistical Distance | Delta(P,Q) = (1/2) * sum |P(w) - Q(w)| |
| Next-Bit Predictor | A(i, prefix) -> {0,1}: predicts bit i+1 given bits 0..i-1 |
| Prediction Advantage | pred_adv = |Pr[A predicts correctly] - 1/2| |
| Next-Bit Test | G passes if max_i pred_adv_A(i,n) <= negl(n) for all PPT A |

## Core Theorems

### Hybrid Argument Lemma
If Adv_D(H_i, H_{i+1}) <= epsilon for all i,
then Adv_D(H_0, H_m) <= m * epsilon.

Proof (telescoping sum):
|Pr[D(H_0)=1] - Pr[D(H_m)=1]|
= |Sum_{i=0}^{m-1} (Pr[D(H_i)=1] - Pr[D(H_{i+1})=1])|
<= Sum_{i=0}^{m-1} |Pr[D(H_i)=1] - Pr[D(H_{i+1})=1]|
<= m * epsilon

### PRG Length Extension (Blum-Micali-Yao)
If G_1: {0,1}^n -> {0,1}^{n+1} is a secure PRG,
then G_k: {0,1}^n -> {0,1}^{n+k} is a secure PRG for any k = poly(n).
Advantage loss: Adv(G_k) <= k * Adv(G_1)

### Negligible Function Closure
1. mu + nu negligible if both negligible
2. mu * nu negligible if both negligible
3. p(n) * mu(n) negligible for any polynomial p

### Yao's Theorem (1982): Indistinguishability = Next-Bit Unpredictability
A PRG G is secure (computationally indistinguishable from uniform)
IF AND ONLY IF no PPT predictor can predict its next bit with
non-negligible advantage.

Direction 1 (Predictor => Distinguisher):
  Given P with pred_adv delta at position i,
  construct D: output 1 iff P predicts correctly.
  Adv(D) = delta.

Direction 2 (Distinguisher => Predictor, via hybrid argument):
  Given D with Adv(D) = epsilon,
  define H_i = (first i bits of G(U_n)) || (l(n)-i random bits).
  Since epsilon = |p_0 - p_l| = |Sum (p_i - p_{i+1})|,
  there exists i with |p_i - p_{i+1}| >= epsilon / l(n).
  Construct predictor with advantage >= epsilon / l(n).

## Core Algorithms

| Algorithm | Description | File |
|-----------|-------------|------|
| BMY Iteration | Extends PRG from 1-bit to k-bit stretch | prg_hybrid.c |
| Monte Carlo Advantage | Estimates Adv_D(X,Y) with confidence | hybrid_argument.c |
| Hybrid Verification | Empirically checks hybrid argument bound | hybrid_argument.c |
| Distinguisher Constructions | 10 canonical distinguisher types | distinguisher.c |
| Statistical Tests | KS, chi-squared, KL divergence | hybrid_argument.c |
| Entropy Estimation | Shannon, min-entropy, collision | hybrid_argument.c |
| Negligible Analysis | Closure, comparison, polynomial check | negligible.c |
| Yao's Theorem | Predictor<=>Distinguisher equivalence | next_bit_unpredictable.c |
| Next-Bit Prediction Game | Full next-bit test across positions | next_bit_unpredictable.c |
| Predictor Constructions | 6 canonical predictor types | next_bit_unpredictable.c |
| PRG Prediction Assessment | Battery of predictors for PRG eval | next_bit_unpredictable.c |
| Security Reductions | (t,eps)-adversary, game-hopping, tightness | security_reduction.c |
| Difference Lemma | Shoup's fundamental game-hopping lemma | security_reduction.c |
| Repetition Amplification | Chernoff-based advantage amplification | security_reduction.c |
| Concrete Security Estimation | Bits of security with reduction loss | security_reduction.c |

## Nine-School Course Mapping

MIT 6.875 · Stanford CS355 · Princeton COS 522 · Berkeley CS276 · CMU 15-859 · ETH 263-4660 · Cambridge Part II · Oxford Advanced CT · Caltech CS 151

## Build and Test

```
make        # Build library objects
make test   # Build and run all tests (6 test suites: 62 tests)
make examples  # Build all examples (4 demos)
make clean  # Clean build artifacts
```

## File Structure

```
mini-hybrid-argument/
  Makefile
  README.md
  include/
    hybrid_argument.h           -- Core framework
    distinguisher.h             -- Distinguisher taxonomy
    negligible.h                -- Negligible functions
    prg_hybrid.h                -- PRG and hybrid argument
    next_bit_unpredictable.h    -- Next-bit prediction & Yao's theorem
    security_reduction.h        -- Concrete security reductions
  src/
    hybrid_argument.c           -- Core implementation
    distinguisher.c             -- Distinguisher implementations
    negligible.c                -- Negligible analysis
    prg_hybrid.c                -- PRG and BMY construction
    next_bit_unpredictable.c    -- Yao's theorem & predictor constructions
    security_reduction.c        -- Reduction framework & game-hopping
    hybrid_argument.lean        -- Lean 4 formalization
  tests/
    test_hybrid_argument.c        -- 14 tests
    test_distinguisher.c          -- 8 tests
    test_negligible.c             -- 9 tests
    test_prg_hybrid.c             -- 10 tests
    test_next_bit_unpredictable.c -- 12 tests
    test_security_reduction.c     -- 9 tests
  examples/
    example_hybrid_proof.c        -- Hybrid argument demo
    example_prg_stretch.c         -- BMY construction demo
    example_distinguisher_game.c  -- PRG security game demo
    example_negligible_decay.c    -- Negligible function comparison
  docs/
    knowledge-graph.md
    coverage-report.md
    gap-report.md
    course-alignment.md
    course-tree.md
```

## Line Count Summary

| Category | Lines |
|----------|-------|
| include/ | ~1118 |
| src/ | ~3121 |
| Total | ~4239 |

## Completion Criteria Met

- [x] include/ + src/ >= 3000 lines (4239)
- [x] make compiles successfully (zero warnings)
- [x] All 62 tests pass
- [x] All 4 examples run
- [x] No TODO/FIXME/stub/placeholder
- [x] L1-L6 Complete
- [x] L7 Complete (5 applications)
- [x] L8 Partial (4 topics: random oracle model, distinguisher composition, Yao equivalence, concrete security reduction framework)
- [x] L9 Partial (documented)
- [x] 6 include/ headers >= 4
- [x] 6 src/ .c files >= 4
- [x] 5 docs/ files present
- [x] Lean 4 formalization present
