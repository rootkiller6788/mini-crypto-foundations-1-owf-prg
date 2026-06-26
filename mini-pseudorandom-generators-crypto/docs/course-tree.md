# Course Tree -- mini-pseudorandom-generators-crypto

## Prerequisites (what this module depends on)

```
Number Theory Basics
  ├── Modular arithmetic (Z_n, Z_n^*)
  ├── Legendre/Jacobi symbols
  ├── Quadratic residues
  ├── Chinese Remainder Theorem
  └── Cyclic groups

Computational Complexity Basics
  ├── Polynomial time (PPT)
  ├── Negligible functions
  └── Computational indistinguishability

Cryptography Foundations
  ├── One-way functions (OWF)
  ├── One-way permutations (OWP)
  └── Hardcore predicates
```

## Dependents (what depends on this module)

```
mini-pseudorandom-generators-crypto (this module)
  ├── Pseudorandom Functions (PRF)
  │   └── GGM construction (prg_applications.c)
  ├── Pseudorandom Permutations (PRP)
  │   └── Luby-Rackoff construction (future)
  ├── Symmetric Encryption
  │   └── Stream ciphers (prg_applications.c)
  ├── Message Authentication Codes (MAC)
  │   └── PRF-based MAC (future)
  └── Key Derivation Functions
      └── PRG-based KDF (prg_applications.c)
```

## Internal Dependencies

```
prg_crypto.h (base definitions)
  ├── prg_number_theory.h (L3 math structures)
  │   ├── blum_blum_shub.h (BBS construction)
  │   └── blum_micali.h (BM construction)
  ├── hardcore_bit.h (OWF, OWP, GL)
  │   └── prg_construction.h (PRG from OWP)
  └── prg_hybrid.h (hybrid argument)
```
