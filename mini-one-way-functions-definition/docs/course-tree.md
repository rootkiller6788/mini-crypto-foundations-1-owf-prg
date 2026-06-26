# Course Tree: One-Way Functions

## Prerequisites (Dependencies)

### Required Knowledge
```
mini-complexity-foundations/
  mini-p-np-np-completeness/       # P vs NP, polynomial time
    |
    +-- mini-one-way-functions-definition/  # THIS MODULE
          |
          +-- Requires: polynomial-time algorithms (P)
          +-- Requires: probabilistic computation (BPP)
          +-- Requires: basic number theory (modular arithmetic)
          +-- Requires: basic probability (negligible functions)
```

### Internal Dependency Tree
```
owf_core.h (core definitions, bit_string)
  |
  +-- owf_number_theory.h (big_nat, modular arithmetic, primality)
  |     |
  |     +-- owf_candidates.h (RSA, DL, SS, Rabin OWF)
  |
  +-- owf_hardcore.h (Goldreich-Levin, hardcore predicates)
  |
  +-- owf_weak_strong.h (Yao amplification)
```

### What This Module Enables
```
mini-one-way-functions-definition/
  |
  +-- mini-pseudorandom-generators/     # PRG from OWF
  +-- mini-pseudorandom-functions/      # PRF from PRG
  +-- mini-symmetric-encryption/        # Encryption from PRF
  +-- mini-digital-signatures/          # Signatures from OWF
  +-- mini-zero-knowledge-proofs/       # ZK from OWF
  +-- mini-secure-multiparty-computation/ # MPC from OWF
```

## Learning Path

1. **Start**: owf_core.h/c — Formal OWF definition, security game
2. **Foundation**: owf_number_theory.h/c — Multi-precision arithmetic
3. **Instances**: owf_candidates.h/c — Concrete OWF constructions
4. **Theory**: owf_hardcore.h/c — GL theorem and hardcore predicates
5. **Amplification**: owf_weak_strong.h/c — Weak to strong OWF
6. **Advanced**: GL list decoding, security analysis

## Course Mapping to Learning Path

| Step | MIT 6.875 | Stanford CS255 | Berkeley CS276 | Princeton COS 433 |
|------|-----------|----------------|----------------|-------------------|
| 1 | Lecture 1-2 | Lecture 1-2 | Lecture 1-2 | Lecture 1-3 |
| 2 | — | Lecture 3-4 | Lecture 3-5 | — |
| 3 | Lecture 3 | Lecture 5 | Lecture 6 | Lecture 4 |
| 4 | Lecture 4-5 | Lecture 6-7 | — | Lecture 5-6 |
| 5 | Lecture 5 | Lecture 8 | — | — |
