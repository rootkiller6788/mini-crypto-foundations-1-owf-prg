# Course Dependency Tree: Hybrid Argument

## Prerequisites
1. Computational Complexity: P, PPT, asymptotic notation
2. Probability Theory: spaces, random variables, Chernoff
3. Cryptography Foundations: perfect secrecy, OWF definitions

## Core Dependencies (internal)
hybrid_argument.h -> distinguisher.h, negligible.h, prg_hybrid.h
prg_hybrid.h -> BMY Construction, PRG Security Game

## Downstream Dependencies
1. OWF -> PRG Construction (HILL 1999)
2. Symmetric Encryption (IND-CPA)
3. Zero-Knowledge Proofs (composition)
4. Secure Multi-Party Computation (simulation)
5. Derandomization (NW-generator, IW-theorem)
