# Knowledge Graph: mini-pseudorandom-functions-ggm

## L1: Definitions (Complete)
- Pseudorandom Generator (PRG): G: {0,1}^n -> {0,1}^{l(n)}, l(n) > n
- Length-Doubling PRG: G: {0,1}^n -> {0,1}^{2n}
- Pseudorandom Function (PRF): F = {f_k : {0,1}^n -> {0,1}^m}_{k in {0,1}^s}
- PRF Oracle: Black-box access to either real PRF or random function
- One-Way Function: Easy f(x), hard to invert
- Hard-Core Predicate: <x,r> mod 2 (Goldreich-Levin)
- GGM Construction: F_k(x) = G_{x_m}(G_{x_{m-1}}(...G_{x_1}(k)...))
- BitString: GF(2) vector data structure

## L2: Core Concepts (Complete)
- Computational indistinguishability
- Oracle access model (black-box queries)
- Distinguisher (PPT adversary with oracle access)
- Adaptive vs non-adaptive queries
- Advantage (statistical distance between experiments)
- Negligible function: f(n) < 1/p(n) for all polynomials p
- Security parameter n

## L3: Mathematical Structures (Complete)
- GF(2) vector space: XOR addition, AND multiplication
- Binary tree (GGM construction)
- Feistel network: L_{i+1}=R_i, R_{i+1}=L_i XOR F(R_i,K_i)
- Merkle-Damgard hash construction
- Davies-Meyer compression function
- S-box substitution (nibble-based)
- CTR mode stream cipher

## L4: Fundamental Theorems (Complete)
- GGM Theorem: PRG => PRF (existential equivalence)
- Hybrid Argument: m * q * Adv^{PRG} bound
- Goldreich-Levin Theorem: OWF => hard-core predicate
- Security Reduction: PRF breaker => PRG breaker
- Luby-Rackoff Theorem (reference): PRF => PRP via Feistel

## L5: Algorithms/Methods (Complete)
- GGM PRF evaluation (binary tree walk)
- Full GGM tree construction (explicit 2^m leaves)
- Pipelined GGM evaluation (shared prefix optimization)
- Incremental GGM update (reuse common path)
- Toy Hash-based PRG
- Simplified AES-CTR PRG
- Toy Feistel cipher (8 rounds)
- Davies-Meyer hash implementation
- Statistical test battery (NIST-style)

## L6: Canonical Problems (Complete)
- Build PRF from PRG (GGM construction)
- Prove PRF security (hybrid argument)
- Key derivation from PRF (GGM-KDF)
- Distinguish PRF from random function
- Compute PRF advantage bounds

## L7: Applications (Complete)
- Key Derivation Function (KDF) via GGM-PRF
- Incremental key update for adjacent inputs
- Secure memory zeroing (key protection)
- Constant-time comparison (timing resistance)
- Statistical randomness testing

## L8: Advanced Topics (Partial)
- Hybrid argument simulation (H_0...H_m)
- Tightness of security reduction (m*q factor)
- Non-length-doubling PRG adaptation

## L9: Research Frontiers (Partial)
- Naor-Reingold (NR) PRF construction (improved efficiency)
- Post-quantum PRF constructions
- Tight security bounds for GGM variants
- Applications in fully homomorphic encryption
