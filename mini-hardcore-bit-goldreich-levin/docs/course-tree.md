# Course Tree — Goldreich-Levin Hardcore Bit

Prerequisite dependency tree for the GL theorem module.

## Prerequisites (must know before)

```
Computability Theory (L0)
  ├── Turing machines, decidability
  └── Reduction basics

Complexity Theory Basics (L0-L1)
  ├── P, NP, polynomial time
  ├── Probabilistic polynomial time (PPT)
  └── Negligible functions

Linear Algebra over F₂ (L3)
  ├── Vector spaces over GF(2)
  ├── Inner product, bilinearity
  └── Walsh-Hadamard basis

Probability Theory (L3)
  ├── Random variables, expectation
  ├── Chernoff/Hoeffding bounds
  └── Statistical distance
```

## This Module (Goldreich-Levin Hardcore Bit)

```
One-Way Functions (owf.c)
  ├── Definition: easy to compute, hard to invert
  ├── Candidate constructions
  │   ├── Integer multiplication (factoring)
  │   ├── Modular exponentiation (discrete log)
  │   ├── RSA function
  │   ├── Subset sum (knapsack)
  │   └── Squaring (Rabin)
  └── Weak vs Strong OWF (Yao 1982)

Hardcore Bits (hardcore_bit.c)
  ├── Definition: hard to predict given f(x)
  ├── GL inner product bit: ⟨x,r⟩ mod 2
  ├── Specific hardcore bits (MSB, LSB)
  └── GL construction: g(x,r) = (f(x), r)

Goldreich-Levin Theorem (goldreich_levin.c)
  ├── Statement: ⟨x,r⟩ is hardcore for (f(x), r)
  ├── Self-correction lemma: ⟨x,r⟩⊕⟨x,r⊕e_i⟩=x_i
  ├── Bit recovery algorithm (majority vote)
  ├── Full inversion algorithm
  └── Query complexity analysis

Hadamard Code (list_decoding.c)
  ├── Definition: RM(1,n), [2^n, n, 2^{n-1}] code
  ├── Fast Walsh-Hadamard Transform
  ├── List decoding algorithm
  ├── Johnson bound
  └── Fourier analysis over Boolean cube

Security Analysis (security_proof.c)
  ├── Negligible functions
  ├── Chernoff/Hoeffding bounds
  ├── Sample complexity
  └── Security level estimation

Applications
  ├── PRG from OWF (prg_from_owf.c)
  │   ├── Blum-Micali construction
  │   ├── Statistical test battery
  │   └── Forward security
  └── Cryptographic Primitives (crypto_primitives.c)
      ├── Merkle-Damgård hash
      ├── Naor commitment
      ├── Lamport OTS
      └── KDF from hardcore bits
```

## Dependent Modules (can study after)

```
Advanced Cryptography
  ├── PRG → PRF → Block Ciphers (GGM construction)
  ├── Trapdoor Permutations
  └── CCA-secure encryption

Complexity Theory
  ├── OWF → Natural Proofs Barrier
  ├── MCSP (Minimum Circuit Size Problem)
  └── Impagliazzo's Five Worlds

Coding Theory
  ├── List decoding beyond Johnson bound
  ├── Folded Reed-Solomon codes
  └── Capacity-achieving list decoding
```
