# mini-pseudorandom-generators-crypto

Cryptographic Pseudorandom Generators: Foundations from One-Way Functions.

## Module Status: COMPLETE

- L1-L8: Complete
- L9: Partial (documented)
- Score: 17/18

## Nine-Layer Knowledge Coverage

| Level | Name | Status |
|-------|------|--------|
| L1 | Definitions | Complete |
| L2 | Core Concepts | Complete |
| L3 | Mathematical Structures | Complete |
| L4 | Fundamental Laws | Complete |
| L5 | Algorithms/Methods | Complete |
| L6 | Canonical Problems | Complete |
| L7 | Applications | Complete |
| L8 | Advanced Topics | Complete |
| L9 | Research Frontiers | Partial |

## Core Definitions

- **PRG**: G: {0,1}^n -> {0,1}^{l(n)}, l(n) > n, output indistinguishable from uniform
- **OWF**: f easy to compute, hard to invert for PPT adversary
- **OWP**: bijective OWF: {0,1}^n -> {0,1}^n
- **Hardcore Predicate**: B(x) unpredictable given f(x)
- **Computational Indistinguishability**: X ~_c Y if no PPT D can tell them apart
- **Next-bit Unpredictability**: no PPT A predicts bit i from prefix with advantage > negl(n)
- **Statistical Distance**: Delta(X,Y) = 1/2 * sum_x |Pr[X=x] - Pr[Y=x]|
- **PRG Security Game**: D distinguishes G(U_n) from U_{l(n)}

## Core Theorems

1. **Yao (1982)**: PRG security <=> Next-bit unpredictability
   - Proved via hybrid argument: |Pr[D(H_k)=1] - Pr[D(H_0)=1]| <= sum_i |Pr[D(H_i)=1] - Pr[D(H_{i-1})=1]|

2. **Blum-Blum-Shub (1986)**: If QRP is hard for Blum integers, BBS is a secure PRG
   - Construction: x_{i+1} = x_i^2 mod N, output LSB(x_{i+1})

3. **Blum-Micali (1984)**: If DLP is hard in Z_p^*, BM is a secure PRG
   - Construction: x_{i+1} = g^{x_i} mod p, output MSB(x_{i+1})

4. **Goldreich-Levin (1989)**: For any OWF f, B(x,r) = <x,r> mod 2 is hardcore for g(x,r) = (f(x), r)

5. **OWP + Hardcore => PRG**: G(s) = f(s) || B(s) gives stretch 1

6. **PRG Stretch 1 => Arbitrary Stretch**: Iterated composition preserves security

7. **HILL (1999)**: OWF exists => PRG exists (most general result)

8. **GGM (1986)**: PRG => PRF via binary tree construction

## Core Algorithms

- BBS key generation + LSB extraction + CRT acceleration
- BM key generation + MSB extraction + simultaneous hardcore
- Goldreich-Levin list decoding (Walsh-Hadamard based)
- PRG from OWP + hardcore predicate
- Iterated PRG (Blum-Micali/Yao iteration)
- Miller-Rabin primality testing
- Tonelli-Shanks modular square root
- NIST-like statistical test battery (frequency, runs, autocorrelation)

## Canonical Problems

- **BBS PRG**: Generate pseudorandom bits from quadratic residuosity assumption
- **BM PRG**: Generate pseudorandom bits from discrete logarithm assumption
- **Hybrid Argument**: Simulate and verify the hybrid decomposition for PRG security

## Applications

- Stream cipher (PRG keystream XOR plaintext)
- Key derivation (stretch master key into subkeys)
- Cryptographic nonce generation
- Challenge-response authentication

## Nine-School Course Mapping

| School | Course | Coverage |
|--------|--------|----------|
| MIT | 6.875 Cryptography | PRG, OWF, hardcore, BBS, BM, GL |
| Stanford | CS255 Cryptography | PRG defs, hybrid, Yao |
| Berkeley | CS276 Cryptography | Goldreich-Levin, PRG constructions |
| Princeton | COS 551 Advanced Complexity | OWF-PRG, HILL |
| CMU | 15-859 Cryptography | BBS, BM, number-theoretic PRGs |
| ETH | 263-4650 Advanced Complexity | Hybrid argument, computational ind |
| Cambridge | Part II Complexity Theory | PRG foundations |
| Oxford | Advanced Complexity Theory | OWF/PRG theory |
| Caltech | CS 151 Complexity Theory | Hardcore predicates |

## Build & Test

```bash
make          # build and run all tests
make examples # build and run examples
make clean    # remove build artifacts
```

## References

- Goldreich (2001) "Foundations of Cryptography" Vol 1
- Arora & Barak (2009) "Computational Complexity: A Modern Approach" Ch 9
- Katz & Lindell (2015) "Introduction to Modern Cryptography"
- Blum, Blum, Shub (1986) "A Simple Unpredictable Pseudo-Random Number Generator"
- Blum & Micali (1984) "How to Generate Cryptographically Strong Sequences"
- Goldreich & Levin (1989) "A Hard-Core Predicate for All One-Way Functions"
- Hastad, Impagliazzo, Levin, Luby (1999) "A Pseudorandom Generator from any One-Way Function"

## File Structure

```
mini-pseudorandom-generators-crypto/
  include/    (7 headers)
    prg_crypto.h          -- PRG base definitions, distinguisher, security game
    prg_number_theory.h   -- Modular arithmetic, primality, CRT, generators
    hardcore_bit.h         -- OWF, OWP, Goldreich-Levin hardcore predicate
    prg_hybrid.h           -- Hybrid argument framework and verification
    blum_blum_shub.h       -- BBS PRG definitions and API
    blum_micali.h          -- Blum-Micali PRG definitions and API
    prg_construction.h     -- PRG from OWP, iterated PRG, quality metrics
  src/        (9 files, include+src total: 4839 lines)
    prg_crypto.c           -- PRG base, statistical distance, security game
    prg_number_theory.c    -- Number theory implementations
    hardcore_bit.c         -- OWF, OWP, GL inner product, list decoding
    prg_hybrid.c           -- Hybrid generation, gap analysis, Yao theorem
    blum_blum_shub.c       -- BBS keygen, LSB extraction, CRT acceleration
    blum_micali.c          -- BM keygen, MSB extraction, simultaneous hardcore
    prg_construction.c     -- PRG from OWP, iterated PRG, quality tests
    prg_applications.c     -- Stream cipher, KDF, nonce, challenge, GGM PRF
    prg_formal.lean        -- Lean 4 formalization (27 theorems, 19 with proofs)
  tests/       test_prg.c (19 tests, 15 assert() + CHK assertions)
  examples/    example_bbs.c, example_bm.c, example_hybrid.c
  docs/        knowledge-graph.md, coverage-report.md, gap-report.md,
               course-alignment.md, course-tree.md
```
