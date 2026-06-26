# Course Tree — mini-trapdoor-permutations

## Prerequisites (this module depends on)

```
Number Theory
  ├── Modular arithmetic (Z/nZ ring structure)
  ├── Greatest common divisor (Euclidean algorithm)
  ├── Prime numbers and factorization
  ├── Euler's totient function φ(n)
  └── Chinese Remainder Theorem

Computational Complexity
  ├── Polynomial time (PPT algorithms)
  ├── Negligible functions
  ├── One-way functions (OWF)
  └── Hardness assumptions (RSA Assumption, Factoring)

Group Theory
  ├── Multiplicative group Z_n^*
  ├── Group homomorphisms (RSA is a ring homomorphism)
  └── Quadratic residues

Algorithms
  ├── Binary exponentiation (square-and-multiply)
  ├── Extended Euclidean algorithm
  └── Probabilistic primality testing (Miller-Rabin)
```

## Dependents (modules that need this one)

```
mini-crypto-foundations-2-prg
  ├── TDP → PRG construction (hard-core bits)
  └── OWF → PRG via Goldreich-Levin

mini-crypto-foundations-3-pke
  ├── TDP → Public-Key Encryption
  ├── RSA-OAEP full scheme
  └── IND-CCA2 constructions

mini-crypto-foundations-4-signatures
  ├── TDP → Digital Signatures
  ├── FDH and PSS constructions
  └── EUF-CMA security proofs

mini-complexity-foundations
  └── TDP as complexity-theoretic primitive
```

## Learning Path

```
1. Start: Number theory basics (modular arithmetic, GCD)
     ↓
2. Understand: Z_n^* group structure, Euler's theorem
     ↓
3. Learn: RSA function (forward = x^e mod n, inverse = y^d mod n)
     ↓
4. Abstract: Trapdoor permutation formal definition
     ↓
5. Apply: TDP → PKE (encryption)
     ↓
6. Apply: TDP → Signatures (reverse direction)
     ↓
7. Secure: OAEP padding, PSS encoding
     ↓
8. Advanced: Security proofs in ROM, tight reductions
```
