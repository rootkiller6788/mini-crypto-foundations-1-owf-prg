# Course Alignment: mini-pseudorandom-functions-ggm

## Nine-School Curriculum Mapping

### MIT ！ 6.875 Cryptography
- **PRG Definition**: Yao (1982), Blum-Micali (1984)
- **PRF Definition**: GGM (1986), keyed function families
- **GGM Construction**: PRG => PRF transformation
- **Hybrid Argument**: Security proof technique
- **Goldreich-Levin**: Hard-core predicate theorem

### Stanford ！ CS255 Introduction to Cryptography
- **OWF Chain**: OWF => PRG (GL) => PRF (GGM)
- **Security Definitions**: Indistinguishability, advantage
- **PRG Constructions**: From hard-core bits
- **PRF Applications**: KDF, MAC, symmetric crypto

### Berkeley ！ CS276 Cryptography
- **Foundations**: One-way functions, pseudorandomness
- **GGM Construction**: Full proof via hybrid argument
- **Oracle Model**: Black-box access, adaptive queries
- **Luby-Rackoff**: PRP from PRF (Feistel network)

### CMU ！ 15-859 Advanced Cryptography
- **PRF Security**: Adaptive vs non-adaptive adversaries
- **GGM Proof**: Tightness analysis of m*q factor
- **Efficient PRFs**: Naor-Reingold, NR constructions
- **PRF Compositions**: Cascade, XOR constructions

### Princeton ！ COS 522 Computational Complexity
- **Complexity Foundations**: OWF existence, P vs NP
- **Cryptographic Reductions**: OWF => PRG => PRF
- **GGM Theorem**: Complexity class implications
- **Hard-Core Predicates**: GL Theorem and applications

### Caltech ！ CS 151 / CS 286
- **Information-Theoretic Foundations**: Entropy, min-entropy
- **Pseudorandomness**: Yao's definition, next-bit test
- **PRG/PRF Constructions**: From complexity assumptions
- **Security Proofs**: Reductions, hybrids, advantage bounds

### Cambridge ！ Part II Cryptography
- **Symmetric Crypto**: PRGs, PRFs, PRPs, stream ciphers
- **Feistel Networks**: DES, Luby-Rackoff theorem
- **GGM Construction**: Tree-based PRF, hybrid proof
- **KDF**: Key derivation from PRFs

### Oxford ！ Advanced Security
- **Provable Security**: Definitional approaches
- **Reductionist Proofs**: OWF => PRG => PRF chain
- **PRF Applications**: Secure protocols, key management
- **Post-Quantum**: Lattice-based PRFs

### ETH ！ 263-4650 Cryptography
- **Formal Definitions**: PRG, PRF, PRP with precise syntax
- **Security Notions**: IND, CPA, CCA, adaptive security
- **GGM Construction**: Detailed proof walkthrough
- **Hybrid Argument**: Application to various constructions

## Topic Coverage Matrix

| Topic | MIT | Stan | Berk | CMU | Prin | Cal | Cam | Oxf | ETH |
|-------|-----|------|------|-----|------|-----|-----|-----|-----|
| PRG Definition | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| PRF Definition | ? | ? | ? | ? | ? | ！ | ? | ? | ? |
| GGM Construction | ? | ? | ? | ? | ? | ！ | ? | ！ | ? |
| Hybrid Argument | ? | ? | ? | ? | ? | ！ | ? | ！ | ? |
| Goldreich-Levin | ? | ? | ！ | ? | ? | ！ | ！ | ！ | ！ |
| Luby-Rackoff | ！ | ！ | ? | ? | ！ | ！ | ? | ！ | ? |
| KDF Applications | ? | ? | ！ | ！ | ！ | ！ | ！ | ? | ！ |
| Statistical Tests | ！ | ！ | ！ | ！ | ！ | ！ | ！ | ！ | ！ |
| Feistel Network | ！ | ！ | ? | ? | ！ | ！ | ? | ！ | ? |
| OWF Base | ? | ? | ? | ? | ? | ！ | ? | ? | ? |
