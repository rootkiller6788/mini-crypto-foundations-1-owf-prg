# mini-pseudorandom-functions-ggm

**Goldreich-Goldwasser-Micali (GGM) Pseudorandom Function Construction**

> If length-doubling pseudorandom generators exist, then pseudorandom functions exist.
> �� Goldreich, Goldwasser, Micali, STOC 1984 / JACM 1986

## Module Status: COMPLETE ✅

- **L1-L6**: Complete
- **L7**: Complete (2 applications: KDF, incremental update)
- **L8**: Partial (1 advanced topic: hybrid argument)
- **L9**: Partial (documented, not implemented)

### Build Status
```
make          → builds libggm.a library (0 warnings)
make test     → 44/44 tests pass
make examples → 3 end-to-end examples run
```

---

## 1. Core Definitions (L1)

| Term | Definition | Implementation |
|------|-----------|----------------|
| **Pseudorandom Generator (PRG)** | Deterministic poly-time function G: {0,1}^n -> {0,1}^{l(n)} where l(n) > n, output computationally indistinguishable from uniform | `include/prg.h:84-97` |
| **Pseudorandom Function (PRF)** | Keyed function family F = {f_k} where no efficient oracle adversary can distinguish f_k from truly random f | `include/prf.h:52-71` |
| **GGM Construction** | F_k(x_1...x_m) = G_{x_m}(G_{x_{m-1}}(...G_{x_1}(k)...)) �� binary tree walk | `include/ggm.h:1-38` |
| **One-Way Function (OWF)** | Easy to compute f(x), hard to invert: Pr[A(f(x)) in f^{-1}(f(x))] <= negl(n) | `include/crypto_utils.h:129-149` |
| **Hard-Core Predicate** | Bit <x,r> mod 2 is hard to predict given f(x) and r (Goldreich-Levin) | `include/crypto_utils.h:159-178` |
| **Length-Doubling PRG** | Special case: G: {0,1}^n -> {0,1}^{2n}, required for GGM | `include/prg.h:19-21` |
| **PRF Oracle** | Black-box interface providing either real PRF (hidden key) or random function | `include/prf.h:77-110` |
| **BitString** | GF(2)-vector: sequence of bits stored as packed bytes | `include/prg.h:46-50` |

---

## 2. Core Theorems (L4)

### GGM Theorem (PRG => PRF)
```
If length-doubling PRGs exist, then PRFs exist.

Construction:
  F_k(x_1...x_m) = G_{x_m}(G_{x_{m-1}}(...G_{x_1}(k)...))

Security:
  Adv^{PRF}_A(n) <= m(n) * q(n) * Adv^{PRG}_G(n)
```
**Proof**: Hybrid argument over m+1 distributions H_0, ..., H_m.

### Hybrid Argument
```
H_0: All levels use PRG (real PRF)
H_i: First i levels random, remaining use PRG
H_m: All levels random (truly random function)

|Pr[A(H_{i-1})=1] - Pr[A(H_i)=1]| <= Adv^{PRG}
=> Adv^{PRF} <= m * q * Adv^{PRG}
```

### Goldreich-Levin Theorem
```
If f is a OWF, then <x,r> mod 2 is a hard-core predicate.
=> OWF + hard-core bit => PRG (by iteration)
```

---

## 3. Core Algorithms (L5)

| Algorithm | Complexity | Description |
|-----------|------------|-------------|
| **GGM PRF Evaluation** | O(m * T_PRG) | Binary tree walk from root to leaf |
| **GGM Tree Construction** | O(2^{m}) | Build complete binary tree (feasible for m <= 20) |
| **GGM Pipelined Evaluation** | O(q * m * T_PRG) | Reuse common prefixes across q inputs |
| **GGM Incremental Update** | O(m * T_PRG) | Recompute only differing suffix |
| **Toy PRG (Hash-based)** | O(blocks * T_hash) | Iterated hash G(s) = H(s||0) || H(s||1) || ... |
| **AES-CTR PRG** | O(blocks * T_AES) | G(k) = AES_k(0) || AES_k(1) || ... |
| **Davies-Meyer Hash** | O(blocks) | H_i = E_{m_i}(H_{i-1}) XOR H_{i-1} |
| **Feistel Network Cipher** | O(rounds) | 8-round Feistel with S-box substitution |
| **GGM-based KDF** | O(m * T_PRG) | F_{master}(salt || context) for key derivation |
| **Statistical Test Battery** | O(n) | Monobit, runs, serial, poker tests (NIST SP 800-22) |

---

## 4. Canonical Problems (L6)

| Problem | Solution | Example |
|---------|----------|---------|
| Build PRF from PRG | GGM construction | `examples/example_ggm_demo.c` |
| Prove PRF security | Hybrid argument | `examples/example_security.c` |
| Key derivation from master key | GGM-KDF | `examples/example_kdf.c` |

---

## 5. Applications (L7)

- **Key Derivation Function (KDF)**: F_master(salt || context) �� HKDF-style
- **Incremental Key Update**: Compute F_k(x') from F_k(x) when x' ~ x
- **Pipelined PRF Evaluation**: Efficiently evaluate PRF on multiple inputs sharing prefixes
- **Timing-resistant Comparison**: Constant-time MAC verification
- **Secure Memory Zeroing**: Prevention of key recovery from freed memory

---

## 6. Advanced Topics (L8)

- **Hybrid Argument Proof**: Full simulation of m+1 hybrids with advantage bound
- **Security Reduction Tightness**: Adv_PRF <= m*q*Adv_PRG (not tight; improved constructions exist)

---

## 7. Research Frontiers (L9)

- **NR Constructions** (Naor-Reingold 1997): O(m/log m) efficiency improvement
- **Luby-Rackoff** (1988): PRP from PRF (Feistel network, 3/4 rounds)
- **Tight security bounds**: Can we achieve Adv_PRF <= O(Adv_PRG) without m factor?
- **Post-quantum PRFs**: GGM from lattice/learning-with-errors assumptions

---

## 8. Curriculum Mapping (Nine Schools)

| School | Course | Topics Covered |
|--------|--------|----------------|
| **MIT** | 6.875 Cryptography | PRG, PRF, GGM, hybrid argument |
| **Stanford** | CS255 Introduction to Cryptography | OWF => PRG => PRF chain |
| **Berkeley** | CS276 Cryptography | GGM construction, security proof |
| **Princeton** | COS 522 Computational Complexity | Cryptographic reductions |
| **CMU** | 15-859 Advanced Cryptography | PRF definitions, adaptive security |
| **Caltech** | CS 151/286 | Complexity-theoretic foundations |
| **Cambridge** | Part II Cryptography | Feistel, Luby-Rackoff, GGM |
| **Oxford** | Advanced Security | PRF constructions and applications |
| **ETH** | 263-4650 Cryptography | Formal PRG/PRF definitions |

---

## 9. File Structure

```
mini-pseudorandom-functions-ggm/
������ Makefile                    # make test: 44/44 pass
������ README.md                   # This file (COMPLETE)
������ include/
��   ������ prg.h                   # PRG definition, BitString, statistical tests
��   ������ prf.h                   # PRF definition, oracle, distinguisher, advantage
��   ������ ggm.h                   # GGM construction, hybrid argument, security proof
��   ������ crypto_utils.h          # Hash, cipher, OWF, hard-core bit, GF(2) ops
������ src/
��   ������ prg.c                   # PRG implementation (BitString, toy/AES-CTR PRG)
��   ������ prf.c                   # PRF implementation (oracle, distinguisher, random func)
��   ������ crypto_utils.c          # Crypto utilities (RNG, hash, cipher, CTR, OWF, GF(2))
��   ������ ggm.c                   # GGM implementation (tree, hybrid, KDF, pipelined)
������ tests/
��   ������ test_prg.c              # 13 tests for PRG + BitString
��   ������ test_prf.c              # 9 tests for PRF oracle/distinguisher
��   ������ test_crypto.c           # 10 tests for hash/cipher/OWF/GF(2)
��   ������ test_ggm.c              # 12 tests for GGM tree/hybrid/KDF
������ examples/
    ������ example_ggm_demo.c      # Full GGM construction walkthrough
    ������ example_kdf.c           # Key derivation function application
    ������ example_security.c      # Security proof demonstration
```

---

## 10. References

1. Goldreich, Goldwasser, Micali (1986). "How to Construct Random Functions." *JACM* 33(4):792-807.
2. Arora, Barak (2009). *Computational Complexity: A Modern Approach*. Section 9.2-9.3.
3. Katz, Lindell (2014). *Introduction to Modern Cryptography*. Sections 3.5-3.6, 7.5.
4. Goldreich (2001). *Foundations of Cryptography, Volume 1*. Section 2.4.
5. Goldreich, Levin (1989). "A Hard-Core Predicate for All One-Way Functions." *STOC* 1989.
6. Yao (1982). "Theory and Applications of Trapdoor Functions." *FOCS* 1982.
7. Blum, Micali (1984). "How to Generate Cryptographically Strong Sequences." *SIAM J. Comput.* 13(4).
8. NIST SP 800-22 Rev 1a (2010). "A Statistical Test Suite for Random and Pseudorandom Number Generators."
