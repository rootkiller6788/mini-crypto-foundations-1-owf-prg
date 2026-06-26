# Course Tree: mini-pseudorandom-functions-ggm

## Prerequisites (Dependencies)

```
Complexity Theory Foundations
©À©¤©¤ P vs NP, polynomial-time algorithms
©À©¤©¤ Turing machines, circuit families
©À©¤©¤ Asymptotic notation (O, poly, negl)
©¸©¤©¤ Probability theory basics

Cryptography Foundations
©À©¤©¤ One-Way Functions (OWF)
©¦   ©À©¤©¤ Definition: easy to compute, hard to invert
©¦   ©À©¤©¤ Candidates: factoring, discrete log
©¦   ©¸©¤©¤ Hard-core predicates (Goldreich-Levin)
©À©¤©¤ Pseudorandom Generators (PRG)
©¦   ©À©¤©¤ Definition: stretch + indistinguishability
©¦   ©À©¤©¤ Yao's Theorem: next-bit unpredictability
©¦   ©À©¤©¤ Blum-Micali (1984): PRG from discrete log
©¦   ©¸©¤©¤ Goldreich-Levin: PRG from OWF + hard-core bit
©¸©¤©¤ Pseudorandom Functions (PRF) ¡û THIS MODULE
    ©À©¤©¤ GGM Theorem: PRG => PRF
    ©À©¤©¤ Hybrid argument proof
    ©À©¤©¤ Applications: KDF, MAC, symmetric encryption
    ©¸©¤©¤ Extensions: Luby-Rackoff (PRF => PRP)
```

## Knowledge Dependencies Within This Module

```
GGM PRF Module
©À©¤©¤ prg.h / prg.c
©¦   ©À©¤©¤ BitString operations (L3: GF(2) vectors)
©¦   ©À©¤©¤ PRG abstraction (L1: definition)
©¦   ©À©¤©¤ Length-doubling PRG (L2: crucial for GGM)
©¦   ©À©¤©¤ Toy/AES-CTR PRG (L5: concrete implementations)
©¦   ©¸©¤©¤ Statistical tests (L5: quality assessment)
©À©¤©¤ prf.h / prf.c
©¦   ©À©¤©¤ PRF family abstraction (L1: definition)
©¦   ©À©¤©¤ Oracle interface (L2: black-box model)
©¦   ©À©¤©¤ Distinguisher framework (L2: advantage computation)
©¦   ©À©¤©¤ Truly random function (L5: lazy sampling)
©¦   ©¸©¤©¤ Insecure PRFs for pedagogy (L2: linear, trivial)
©À©¤©¤ crypto_utils.h / crypto_utils.c
©¦   ©À©¤©¤ Deterministic PRNG (L3: reproducibility)
©¦   ©À©¤©¤ Davies-Meyer hash (L3: Merkle-Damgard)
©¦   ©À©¤©¤ Toy Feistel cipher (L3: PRP structure)
©¦   ©À©¤©¤ CTR mode (L5: stream cipher for PRG)
©¦   ©À©¤©¤ OWF template (L2: factoring-based)
©¦   ©À©¤©¤ Hard-core bit GL (L4: Goldreich-Levin)
©¦   ©À©¤©¤ GF(2) operations (L3: inner product, weight)
©¦   ©¸©¤©¤ Secure utils (L7: constant-time, zeroing)
©¸©¤©¤ ggm.h / ggm.c
    ©À©¤©¤ GGM PRF construction (L4: PRG => PRF)
    ©À©¤©¤ Binary tree data structure (L3: full tree)
    ©À©¤©¤ PRF evaluation (L5: tree walk algorithm)
    ©À©¤©¤ Tree consistency verification (L5)
    ©À©¤©¤ Hybrid argument (L4: security proof)
    ©À©¤©¤ Security experiment (L5: empirical verification)
    ©À©¤©¤ KDF application (L7: key derivation)
    ©À©¤©¤ Pipelined evaluation (L5: prefix sharing)
    ©À©¤©¤ Truncated output (L5: output shortening)
    ©¸©¤©¤ Incremental update (L7: adjacent input reuse)
```

## Downstream Dependencies

```
This Module (GGM PRF)
    ©¦
    ©À©¤©¤ mini-owf-from-prg/        ¡û PRG => OWF (hard-core construction)
    ©À©¤©¤ mini-encryption-schemes/  ¡û PRF => symmetric encryption
    ©À©¤©¤ mini-mac-constructions/   ¡û PRF => message authentication codes
    ©À©¤©¤ mini-luby-rackoff/        ¡û PRF => PRP (Feistel network)
    ©¸©¤©¤ mini-commitment-schemes/  ¡û OWF => commitment schemes
```

## Knowledge Level Prerequisites by Topic

| Topic | Minimum Prerequisites |
|-------|----------------------|
| Understand GGM theorem | L1-L3 (PRG, PRF definitions) |
| Follow hybrid argument | L2 (indistinguishability), probability |
| Implement GGM construction | L3 (binary trees, GF(2)), C programming |
| Prove GGM security | L4 (reduction techniques), hybrid argument |
| Statistical tests on PRG | L2 (hypothesis testing), chi-squared |
| KDF from GGM-PRF | L1-L4 complete, key management concepts |
| Feistel network cipher | L3 (permutations, S-boxes), block cipher design |
