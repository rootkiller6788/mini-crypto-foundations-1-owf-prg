# Course Tree — OWF ⇔ PRG Equivalence

## Prerequisites

```
Computational Complexity Basics
├── Turing machines, polynomial time (P, BPP)
├── Negligible functions, asymptotic notation
└── Basic probability theory

Number Theory
├── Modular arithmetic
├── Groups Z_N^*, Z_p^*
├── Chinese Remainder Theorem
└── Primality testing (Miller-Rabin)

Complexity Theory
├── Cook-Levin Theorem (NP-completeness)
├── Average-case vs worst-case complexity
└── Non-uniform computation (P/poly)
```

## Dependency Graph

```
OWF Definition
├── OWF Candidates (RSA, DLog, Rabin, SubsetSum)
│   ├── Modular Arithmetic
│   ├── Miller-Rabin Primality
│   └── Blum Integers
├── Weak vs Strong OWF (Yao Amplification)
│   └── Parallel Repetition
├── Goldreich-Levin Theorem
│   ├── GL Inner Product Hardcore Bit
│   ├── List Decoding Algorithm
│   └── Pairwise Independent Hashing
│
└── HILL Construction (OWF ⇒ PRG)
    ├── Stage 1: OWF + Hardcore Bit
    ├── Stage 2: 1-Bit Stretch PRG
    ├── Stage 3: Arbitrary Stretch (Iteration)
    └── Stage 4: Entropy Preservation

PRG Definition
├── Blum-Micali Construction
├── HILL Construction (see above)
├── PRG ⇒ OWF (Trivial Direction)
├── Yao's Theorem (Next-bit ⇔ Pseudorandom)
├── Hybrid Argument
└── Applications
    ├── Stream Cipher
    ├── IND-CPA Encryption
    ├── Key Derivation
    └── BPP Derandomization
```

## What This Module Depends On

1. **mini-complexity-foundations**: Complexity classes, polynomial time
2. **mini-cook-levin-theorem**: NP-completeness (background for average-case hardness)
3. Number theory basics (modular arithmetic, groups)

## What Depends On This Module

1. **mini-crypto-foundations-2**: Advanced PRG constructions
2. **mini-pcp-theorem**: PCP uses cryptographic techniques
3. **mini-natural-proofs-barrier**: OWF ⇔ PRG is a barrier result
