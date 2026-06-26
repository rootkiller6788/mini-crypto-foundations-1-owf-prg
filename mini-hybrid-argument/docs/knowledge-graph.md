# Knowledge Graph: Hybrid Argument

## L1: Definitions (Complete)
- Hybrid Sequence: H_0, H_1, ..., H_m ordered list of distributions
- Hybrid Argument Lemma: Adv(H_0, H_m) <= m * max pairwise
- Advantage: Adv_D(X,Y) = |Pr[D(X)=1] - Pr[D(Y)=1]|
- PPT Distinguisher: D: {0,1}^* -> {0,1} in probabilistic polynomial time
- Negligible Function: mu(n) < 1/p(n) for all poly p, sufficiently large n
- Noticeable Function: NOT negligible
- Overwhelming Probability: p(n) -> 1 as n -> infinity
- Distribution Ensemble: {X_n} over {0,1}^{l(n)}
- PRG: G: {0,1}^n -> {0,1}^{l(n)}, l(n) > n
- Statistical Distance: (1/2) * sum |P(w) - Q(w)|

## L2: Core Concepts (Complete)
- Computational Indistinguishability: X ~=_c Y iff for all PPT D, Adv_D <= negl
- Statistical Indistinguishability: Delta(X,Y) <= negl(n)
- Concrete vs Asymptotic Security
- Hybrid Argument Proof Technique: telescoping sum
- Distinguisher Taxonomy: trivial, structural, linear, composite
- PRG Security Game: PrivK^{prg} experiment
- 1-bit stretch => polynomial stretch reduction

## L3: Mathematical Structures (Complete)
- BoolDist: Boolean probability distribution
- DistributionSample: bit array with length metadata
- DistributionEnsemble: name + output_length + sampler
- HybridSeq: List BoolDist with pairwise/total advantage
- NegligibleClosure: closure property verification
- PRGSpec: structural record type
- Entropy: Shannon H, Min-entropy H_inf, Collision H_2
- Statistical tests: KS, Chi-squared, KL divergence, correlation

## L4: Fundamental Laws (Complete)
- Hybrid Argument Lemma: Adv(H_0,H_m) <= Sum Adv(H_i,H_{i+1}) <= m*eps
- Triangle Inequality: Delta(X,Z) <= Delta(X,Y) + Delta(Y,Z)
- PRG Length Extension (BMY): Adv(G_k) <= k * Adv(G_1)
- Negligible Closure: sum, product, poly-multiplication
- Chernoff Bound: majority distinguisher amplification
- Yao's XOR Lemma: distinguisher composition
- Union Bound: multiple distinguisher advantage

## L5: Algorithms/Methods (Complete)
- Monte Carlo advantage estimation
- BMY iteration for PRG extension
- Hybrid sequence construction
- 10 distinguisher types: trivial, first-k-zero, bit-count, bit-pattern, linear, repeat-pattern, runs, majority, conjunction, XOR
- Adaptive distinguisher
- Negligible function evaluation series
- PRG security game simulation
- Statistical tests: KS, chi-squared, KL divergence, correlation

## L6: Canonical Problems (Complete)
- PRG distinguishing game
- Hybrid argument proof verification
- Negligible function decay comparison
- Stream cipher encryption/decryption
- KDF key derivation

## L7: Applications (Complete)
- Stream Cipher: C = M XOR G(key) -- IND-CPA secure
- Key Derivation: sub-key = G(salt || mk)
- PRG Statistical Analysis: entropy, runs, bit fraction
- Concrete Security Parameter Selection

## L8: Advanced Topics (Partial)
- Random Oracle Model: Hash-chain PRG security
- Distinguisher Composition: Chernoff amplification

## L9: Research Frontiers (Partial)
- Documented: post-quantum PRG, lattice-based constructions, UC composition
