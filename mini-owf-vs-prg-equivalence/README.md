# mini-owf-vs-prg-equivalence

**OWF ⇔ PRG Equivalence** — One-Way Functions and Pseudorandom Generators are existentially equivalent.

## Module Status: COMPLETE ✅

| Metric | Value | Threshold | Status |
|--------|-------|-----------|--------|
| include/ + src/ lines | 4,695 | ≥ 3,000 | ✅ |
| `make` compile | 0 warnings | 0 errors | ✅ |
| `make test` | 43 passed, 0 failed | all pass | ✅ |
| `make examples` | 3/3 run | ≥ 3 | ✅ |
| `make demos` | 1/1 run | ≥ 1 | ✅ |
| `make benches` | 1/1 run (8 benchmarks) | ≥ 1 | ✅ |
| TODO/FIXME/stub | 0 matches | 0 | ✅ |
| include/ headers | 6 | ≥ 4 | ✅ |
| src/ source files | 6C + 1 Lean | ≥ 4C + 1 Lean | ✅ |
| Lean 4 formalization | 554 lines, 30+ theorems | ≥ 1 .lean | ✅ |

## Knowledge Coverage

| Level | Name | Status | Items |
|-------|------|--------|-------|
| **L1** | Definitions | ✅ Complete | OWF, PRG, hardcore predicate, BitString, computational indist., security parameter, negligible function, distribution ensemble |
| **L2** | Core Concepts | ✅ Complete | 4 OWF candidates (RSA, DLog, Rabin, SubsetSum), Blum-Micali, HILL, weak↔strong, composition, iteration |
| **L3** | Math Structures | ✅ Complete | GF(2) linear algebra, Z_N^*, Z_p^*, Blum integers, pairwise indep. hash, modular arithmetic |
| **L4** | Fundamental Laws | ✅ Complete | Goldreich-Levin (1989), HILL (1999), OWF⇔PRG, Yao (1982), Hybrid Lemma, Leftover Hash Lemma, Yao Amplification |
| **L5** | Algorithms | ✅ Complete | GL list decoding, Miller-Rabin, extended Euclidean, square-and-multiply, PRG iteration, hybrid chains |
| **L6** | Canonical Problems | ✅ Complete | RSA inversion, discrete log, factoring, subset sum, PRG distinguishing, HC prediction |
| **L7** | Applications | ✅ Complete | Stream cipher, IND-CPA encryption, key derivation, BPP derandomization, key generation (5 apps) |
| **L8** | Advanced Topics | ✅ Complete | Pseudoentropy gen, reduction tightness, GL analysis, Yao amplification, pairwise hash verification (5 topics) |
| **L9** | Research Frontiers | ⚠️ Partial | Quantum OWF, tighter reductions, meta-complexity (documented only) |

**Score: 17/18** (Complete=2, Partial=1 per level)

## Core Definitions

- **OWF**: f: {0,1}^* → {0,1}^*, PPT-computable, ∀ PPT A: Pr[A(f(x)) ∈ f⁻¹(f(x))] < negl(n)
- **PRG**: G: {0,1}^n → {0,1}^{l(n)}, l(n)>n, ∀ PPT D: |Pr[D(G(U_n))=1] - Pr[D(U_{l(n)})=1]| < negl(n)
- **Hardcore Predicate**: b(x) unpredictable given f(x) with advantage ≤ 1/2 + negl(n)
- **Computational Indist.** : {X_n} ≈_c {Y_n} if ∀ PPT D, |Pr[D(X_n)=1] - Pr[D(Y_n)=1]| < negl(n)

## Core Theorems

| Theorem | Statement | Reference |
|---------|-----------|-----------|
| **Goldreich-Levin** | ∀ OWF f, g(x,r)=(f(x),r) is OWF and h(x,r)=⟨x,r⟩ is hardcore | GL 1989 |
| **HILL** | OWF exist ⇒ PRG exist | HILL 1999 |
| **PRG⇒OWF** | PRG G is itself a OWF (trivial) | — |
| **OWF⇔PRG** | OWF exist ⇔ PRG exist | HILL+trivial |
| **Yao** | Next-bit unpredictable ⇔ pseudorandom | Yao 1982 |
| **Hybrid Lemma** | H_0 ≈_c H_k with advantage ≤ k·max_adj | — |
| **Leftover Hash** | Universal hash extracts uniform bits from high-entropy | ILL 1989 |
| **Yao Amplification** | Weak OWF ⇒ Strong OWF via parallel repetition | Yao 1982 |

## Core Algorithms

| Algorithm | Complexity | Description |
|-----------|------------|-------------|
| GL List Decoding | poly(n, 1/ε) | Recover x from HC predictor with advantage ε |
| Miller-Rabin | O(k·log³n) | Primality test, error ≤ 4^{-k} |
| Extended Euclidean | O(log n) | gcd + Bézout coefficients |
| Square-and-Multiply | O(log e) | Modular exponentiation |
| PRG Iteration | O(l) | 1-bit stretch → l-bit stretch |

## Classic Problems

- RSA inversion: Given (N,e,y), find x: x^e ≡ y mod N
- Discrete logarithm: Given (p,g,y), find x: g^x ≡ y mod p
- Integer factoring: Given N = p·q, find p,q
- Subset sum: Given weights a_i and sum S, find subset
- PRG distinguishing: Tell G(U_n) from U_{l(n)}

## Directory Structure

```
mini-owf-vs-prg-equivalence/
├── Makefile              # make, make test, make examples, make clean
├── README.md             # This file
├── include/
│   ├── owf.h             # OWF definitions, candidates, properties
│   ├── prg.h             # PRG definitions, constructions, applications
│   ├── hardcore_bit.h    # Hardcore predicates, Goldreich-Levin
│   ├── indistinguish.h   # Computational indist., hybrid arguments
│   ├── reduction.h       # OWF⇔PRG reduction, entropy analysis
│   └── crypto_utils.h    # GF(2) algebra, modular arithmetic, utilities
├── src/
│   ├── owf.c             # OWF implementation (461 lines)
│   ├── prg.c             # PRG implementation (482 lines)
│   ├── hardcore_bit.c    # Hardcore bit + GL list decode (474 lines)
│   ├── indistinguish.c   # Indistinguishability + hybrid arg (517 lines)
│   ├── reduction.c       # HILL reduction + entropy (507 lines)
│   ├── crypto_utils.c    # Crypto utilities (574 lines)
│   └── owf_prg.lean      # Lean 4 formalization: Bit, BitVec, OWF,
│                          #   PRG, HardcorePred, GL inner product,
│                          #   hybrid lemma, PRG⇒OWF, Yao theorem,
│                          #   square-and-multiply, extended Euclid. (554 lines)
├── tests/
│   └── test_all.c        # 43 comprehensive tests
├── examples/
│   ├── example_owf_candidates.c        # All 4 OWF candidates
│   ├── example_prg_stream_cipher.c     # Stream cipher end-to-end
│   └── example_owf_prg_equivalence.c   # Full equivalence demo
├── demos/
│   └── owf_prg_demo.c    # Interactive step-by-step HILL pipeline walkthrough
├── benches/
│   └── owf_prg_bench.c   # 8 benchmark categories: OWF eval, modular arith,
│                          #   GL inner product, GF(2) hash, PRG ops,
│                          #   BitString ops, full HILL pipeline, entropy
├── docs/
│   ├── knowledge-graph.md     # L1-L9 knowledge map
│   ├── coverage-report.md     # Coverage assessment (17/18)
│   ├── gap-report.md          # Remaining gaps
│   ├── course-alignment.md    # 9-school course mapping
│   └── course-tree.md         # Prerequisites and dependencies
├── build/                  # Build artifacts
```

## Course Mapping

| School | Course | Coverage |
|--------|--------|----------|
| MIT | 6.875 Cryptography | OWF, PRG, GL, HILL (L1-L8) |
| Stanford | CS255 Cryptography | OWF candidates, stream ciphers, HC bits |
| Berkeley | CS276 Cryptography | HILL construction, PRG applications |
| Princeton | COS 522 Complexity | OWF⇔PRG as complexity result |
| CMU | 15-855 Grad Complexity | Reduction tightness, pseudoentropy |
| ETH | 263-4650 Adv Complexity | GL list decoding |
| Cambridge | Part III Adv Complexity | Hardness amplification |
| Oxford | Adv Complexity Theory | Entropy extraction, OWF foundations |
| Caltech | CS 151 Complexity | Derandomization connections |

## Building

```bash
make          # Build static library libowfprg.a
make test     # Run 43 tests (all must pass)
make examples # Build and run 3 end-to-end examples
make demos    # Build and run 1 interactive demo
make benches  # Build and run 8 performance benchmarks
make clean    # Remove build artifacts
```

## References

- Goldreich, O. (2001). *Foundations of Cryptography, Vol 1: Basic Tools*. Cambridge.
- Arora, S. & Barak, B. (2009). *Computational Complexity: A Modern Approach*. Cambridge.
- Håstad, J., Impagliazzo, R., Levin, L., & Luby, M. (1999). *A Pseudorandom Generator from any One-way Function*. SIAM J. Comput.
- Goldreich, O. & Levin, L. (1989). *A Hard-Core Predicate for All One-Way Functions*. STOC.
- Yao, A. (1982). *Theory and Applications of Trapdoor Functions*. FOCS.
- Blum, M. & Micali, S. (1984). *How to Generate Cryptographically Strong Sequences*. SIAM J. Comput.
