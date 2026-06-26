# Coverage Report — OWF ⇔ PRG Equivalence

## Summary

| Level | Name | Status | Score |
|-------|------|--------|-------|
| L1 | Definitions | **Complete** | 2 |
| L2 | Core Concepts | **Complete** | 2 |
| L3 | Mathematical Structures | **Complete** | 2 |
| L4 | Fundamental Laws | **Complete** | 2 |
| L5 | Algorithms/Methods | **Complete** | 2 |
| L6 | Canonical Problems | **Complete** | 2 |
| L7 | Applications | **Complete** | 2 |
| L8 | Advanced Topics | **Complete** | 2 |
| L9 | Research Frontiers | **Partial** | 1 |

**Total Score: 17/18 — COMPLETE**

## Detail

### L1 — Complete
- OWF, PRG, hardcore predicate, computational indistinguishability, security parameter, negligible function, distribution ensemble, BitString — all defined with C types

### L2 — Complete
- Inversion and distinguishing experiments, 4 OWF candidates (RSA, DLog, Rabin, SubsetSum), weak vs strong OWF, Blum-Micali, HILL, PRG iteration, composition

### L3 — Complete
- GF(2) linear algebra, Z_N^*, Z_p^*, Blum integers, pairwise independent hash families, modular arithmetic, entropy measures

### L4 — Complete
- Goldreich-Levin (1989), HILL (1999), PRG⇒OWF (trivial), OWF⇔PRG equivalence, Yao (1982) next-bit ⇔ pseudorandomness, Hybrid Lemma, Leftover Hash Lemma, Yao amplification

### L5 — Complete
- GL list decoding, Miller-Rabin, extended Euclidean, square-and-multiply modular exponentiation, PRG iteration, hybrid chain construction, entropy estimation

### L6 — Complete
- RSA inversion, discrete log, integer factoring, subset sum, PRG distinguishing, hardcore bit prediction — all demonstrated in examples/

### L7 — Complete
- Stream cipher from PRG (encrypt/decrypt), IND-CPA security proof, key derivation, BPP derandomization (Nisan-Wigderson), crypto key generation — 5 applications

### L8 — Complete
- Pseudoentropy generator, reduction tightness analysis, GL hardcore bit analysis, Yao amplification, pairwise independent hash verification — 5 advanced topics

### L9 — Partial
- Research frontier directions documented in knowledge-graph.md
- No code implementation for quantum OWF, meta-complexity, or improved reduction tightness constructions
