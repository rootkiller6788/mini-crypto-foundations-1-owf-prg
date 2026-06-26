# Knowledge Graph — OWF ⇔ PRG Equivalence

## L1: Definitions

| Concept | Definition | Implementation |
|---------|------------|---------------|
| One-Way Function (OWF) | f: {0,1}^* → {0,1}^*, easy to compute, hard to invert | `owf.h`, `src/owf.c` |
| Pseudorandom Generator (PRG) | G: {0,1}^n → {0,1}^{l(n)}, l(n) > n, output comp. indist. from uniform | `prg.h`, `src/prg.c` |
| Hardcore Predicate | b(x): given f(x), hard to predict b(x) better than 1/2 + negl | `hardcore_bit.h`, `src/hardcore_bit.c` |
| Security Parameter | n ∈ N, measures input length / security level | `SecurityParam` in `owf.h` |
| Computational Indistinguishability | {X_n} ≈_c {Y_n}: no PPT D tells them apart | `indistinguish.h`, `src/indistinguish.c` |
| Negligible Function | μ(n) < 1/p(n) for every polynomial p, for large n | Used throughout |
| Distribution Ensemble | Sequence {X_n} of distributions indexed by n | `DistEnsemble` in `indistinguish.h` |
| BitString | Variable-length bit string with MSB-first encoding | `BitString` in `owf.h` |

## L2: Core Concepts

| Concept | Description | Implementation |
|---------|-------------|---------------|
| OWF Inversion Experiment | Exp_{A,f}^{inv}(n): choose x, compute f(x), A tries to find preimage | `owf_inversion_experiment()` |
| PRG Distinguishing Experiment | Exp_{D,G}^{prg}(n): D distinguishes G(U_n) from U_{l(n)} | `prg_distinguishing_experiment()` |
| Candidate OWF: RSA | f_{N,e}(x) = x^e mod N | `rsa_owf_eval()` |
| Candidate OWF: Discrete Log | f_{p,g}(x) = g^x mod p | `dlog_owf_eval()` |
| Candidate OWF: Rabin | f_N(x) = x^2 mod N (Blum integer) | `rabin_owf_eval()` |
| Candidate OWF: Subset Sum | f_a(x) = Σ x_i·a_i mod M | `subset_sum_owf_eval()` |
| Weak vs Strong OWF | Weak: hardness ≥ 1/p(n); Strong: hardness ≤ negl(n) | Yao amplification |
| OWF Composition | (f∘g)(x) = f(g(x)) preserves one-wayness | `owf_compose()` |
| Stretch | l(n) - n: how many extra bits PRG produces | PRG parameter |
| Blum-Micali Construction | PRG from OWF permutation + hardcore bit | `blum_micali_prg_eval()` |
| HILL Construction | PRG from any OWF (Goldreich-Levin + hashing + iteration) | `hill_prg_eval()`, `hill_owf_to_prg()` |
| Pseudoentropy | Distribution computationally indistinguishable from high-entropy distribution | `EntropyProfile` |
| Reduction Tightness | Security loss in OWF ⇒ PRG reduction | `measure_reduction_tightness()` |

## L3: Mathematical Structures

| Structure | Description | Implementation |
|-----------|-------------|---------------|
| GF(2) | Field {0,1} with XOR/AND; vectors, matrices | `crypto_utils.h` |
| Z_N^* | Multiplicative group modulo N (RSA, Rabin) | `mod_pow`, `mod_mul` |
| Z_p^* | Cyclic group of order p-1 (Discrete Log) | `is_generator()` |
| Blum Integers | n = p·q, p ≡ q ≡ 3 (mod 4) | `is_blum_integer()` |
| BitString Vector Space | GF(2)^n with XOR and inner product | `gf2_add`, `gf2_dot_product` |
| Pairwise Independent Hash | h_{A,b}(x) = Ax + b over GF(2) | `gf2_hash_create()` |
| Distribution Metrics | Total variation distance, entropy measures | `stat_distance_exact()`, `entropy_from_samples()` |

## L4: Fundamental Theorems

| Theorem | Statement | Implementation |
|---------|-----------|---------------|
| Goldreich-Levin (1989) | ∀ OWF f, g(x,r)=(f(x),r) is OWF and h(x,r)=<x,r> is hardcore | `owf_add_hardcore_bit()` |
| HILL (1999) | OWF exist ⇒ PRG exist | `hill_owf_to_prg()` |
| PRG ⇒ OWF (trivial) | If PRG G exists, G is a OWF | `prg_to_owf()` |
| OWF ⇔ PRG | The two primitives are existentially equivalent | Combined in `reduction.c` |
| Yao (1982) | Next-bit unpredictability ⇔ pseudorandomness | `next_bit_unpred_test()`, `yao_predictor_to_distinguisher()` |
| Hybrid Lemma | If H_i ≈_c H_{i+1} with adv ≤ ε, then H_0 ≈_c H_k with adv ≤ k·ε | `hybrid_lemma_verify()` |
| Leftover Hash Lemma | Universal hashing extracts uniform bits from high-entropy source | `leftover_hash_lemma()` |
| Yao Amplification (1982) | Weak OWF ⇒ Strong OWF via parallel repetition | `yao_amplify_owf_eval()` |

## L5: Algorithms/Methods

| Algorithm | Description | Implementation |
|-----------|-------------|---------------|
| Goldreich-Levin List Decoding | Recover x from predictor with advantage ε | `gl_list_decode()` |
| Miller-Rabin Primality | Probabilistic primality test, error ≤ 4^{-k} | `miller_rabin_prime()` |
| Extended Euclidean Algorithm | gcd + Bézout coefficients | `extended_gcd()` |
| Square-and-Multiply | Modular exponentiation in O(log e) | `mod_pow()` |
| PRG Iteration | Expand 1-bit stretch PRG to arbitrary stretch | `prg_iterate_eval()` |
| Hybrid Argument Construction | Build hybrid chain for PRG/encryption proofs | `prg_hybrid_chain()` |
| Entropy Estimation | Min-entropy, Shannon, collision entropy from samples | `entropy_from_samples()` |

## L6: Canonical Problems

| Problem | Description | Implementation |
|---------|-------------|---------------|
| RSA Inversion | Given (N,e,y), find x: x^e ≡ y (mod N) | `rsa_owf_eval()` — forward direction |
| Discrete Logarithm | Given (p,g,y), find x: g^x ≡ y (mod p) | `dlog_owf_eval()` — forward direction |
| Integer Factoring | Given N = p·q, find p,q | Rabin OWF — provably factoring-hard |
| Subset Sum (random) | Given weights a_i and sum S, find subset | `subset_sum_owf_eval()` — forward direction |
| PRG Distinguishing | Distinguish G(U_n) from U_{l(n)} | `prg_distinguishing_experiment()` |
| Hardcore Bit Prediction | Predict <x,r> given (f(x), r) | `gl_measure_advantage()` |

## L7: Applications

| Application | Description | Implementation |
|-------------|-------------|---------------|
| Stream Cipher from PRG | Keystream = G(k), Enc(m) = m ⊕ G(k) | `prg_stream_encrypt()` / `prg_stream_decrypt()` |
| IND-CPA Encryption | Hybrid argument proof of security | `indist_encrypt()` / `indist_decrypt()` |
| Key Derivation | HKDF-like stretching from seed | `key_derivation_stretch()` |
| BPP Derandomization | If PRG exists, BPP ⊆ P/poly | `prg_derandomize_bpp()` |
| Crypto Key Generation | Time-based entropy key generation | `generate_crypto_key()` |

## L8: Advanced Topics

| Topic | Description | Implementation |
|-------|-------------|---------------|
| Pseudoentropy Generator | Extract hidden entropy via universal hashing | `pseudoentropy_gen_create()` |
| Reduction Tightness | HILL cubic loss → HRV near-linear improvement | `measure_reduction_tightness()` |
| GL Hardcore Bit Analysis | Advantage measurement against predictors | `gl_measure_advantage()` |
| Yao Weak→Strong Amplification | Parallel repetition amplifies hardness | `yao_amplify_owf_eval()` |
| Pairwise Independent Hash Verification | Empirical validation of pairwise independence | `gf2_hash_verify_pairwise_independence()` |

## L9: Research Frontiers

- Meta-complexity: OWF from average-case hardness assumptions (Impagliazzo's five worlds)
- Holenstein (2006): Quadratic security loss improvement
- Haitner-Reingold-Vadhan (2010): Near-linear tightness
- Pass-Shelat (2010): OWF from NP-hardness? (remains open)
- Quantum OWF: Post-quantum candidates (lattice-based, code-based)
