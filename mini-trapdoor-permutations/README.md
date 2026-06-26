# mini-trapdoor-permutations

Trapdoor Permutations (TDP) — foundational cryptographic primitive. A TDP is a family of permutations where the forward direction is easy for anyone, but the inverse requires secret "trapdoor" information.

## Module Status: COMPLETE ✅

- **L1 Definitions**: Complete — TDP, OWF, OWP, RSA, security parameter, negligible function, one-wayness advantage
- **L2 Core Concepts**: Complete — OWF ⊆ OWP ⊆ TDP hierarchy, hardness assumptions, IND-CPA/IND-CCA, EUF-CMA
- **L3 Mathematical Structures**: Complete — Z_n^* group, modular arithmetic, CRT, Euler's totient, Legendre/Jacobi, RSA ring
- **L4 Fundamental Laws**: Complete — RSA correctness (x^{ed} ≡ x), Euler's theorem, CRT isomorphism, Bezout identity; Lean 4 formalization (72 theorems, 810 lines)
- **L5 Algorithms/Methods**: Complete — Miller-Rabin primality, square-and-multiply, Garner's CRT decryption, OAEP padding
- **L6 Canonical Problems**: Complete — RSA encryption/decryption, RSA signing, forgery attacks, brute-force inversion
- **L7 Applications**: Complete — Goldreich-Levin PKE (IND-CPA), RSA-OAEP (IND-CCA2), FDH/PSS signatures (EUF-CMA)
- **L8 Advanced Topics**: Partial — Random self-reducibility, tight vs loose security reductions, formal reduction proof (Lean)
- **L9 Research Frontiers**: Partial — Documented (quantum threat, post-quantum TDP, lossy TDF)

## Line Count: 4,350+ (include/ + src/ .c/.h) | 810 (src/tdp.lean) | + bench, demo

## Core Definitions

| Concept | Definition |
|---------|------------|
| Trapdoor Permutation | f: D → D is a permutation; f(x) easy; f^{-1}(y) easy with trapdoor, hard without |
| RSA Function | f_{n,e}(x) = x^e mod n, trapdoor = d = e^{-1} mod φ(n) |
| One-Wayness | Adv_A(λ) = Pr[A(i, f_i(x)) = x], negligible for all PPT A |
| Negligible Function | ε(λ) < 1/poly(λ) for all polynomials and large λ |
| Security Parameter | λ ∈ ℕ, bit-length of keys (≥2048 for modern security) |

## Core Theorems

1. **RSA Correctness**: ∀x ∈ Z_n: x^{ed} ≡ x (mod n)
   - Proof: Euler's theorem + CRT
2. **Euler's Theorem**: If gcd(x,n)=1, x^{φ(n)} ≡ 1 (mod n)
3. **Chinese Remainder Theorem**: Z_{pq} ≅ Z_p × Z_q
4. **Goldreich-Levin**: GL(x,r) = ⊕(x_i ∧ r_i) is hard-core for any OWF
5. **Miller-Rabin**: Pr[composite passes k rounds] ≤ 4^{-k}
6. **FDH Security**: EUF-CMA in ROM, ε' ≤ q_s·q_h·ε (loose)
7. **PSS Security**: EUF-CMA in ROM, ε' ≤ ε (tight)

## Core Algorithms

| Algorithm | Complexity | Reference |
|-----------|-----------|-----------|
| Square-and-Multiply (mod_exp) | O(log e · log² n) | Knuth TAOCP Vol.2 §4.6.3 |
| Garner's CRT Decryption | O(log d_p · log² p) | HAC §14.75 |
| Miller-Rabin Primality | O(k · log³ n) | Miller (1976), Rabin (1980) |
| Extended Euclidean (EGCD) | O(log² n) | Knuth TAOCP Vol.2 §4.5.2 |
| OAEP Padding | O(\|m\| + k0 + k1) | Bellare-Rogaway (1994) |

## Classic Problems

- RSA encryption/decryption with CRT
- RSA signature forgery (existential, multiplicative)
- Brute-force TDP inversion
- Prime generation with Miller-Rabin

## Course Alignment

| School | Course | Topics Covered |
|--------|--------|----------------|
| MIT | 6.841, 6.875 | TDP formalism, RSA, hard-core bits |
| Stanford | CS254, CS255 | OWF → TDP → PKE, IND-CPA/CCA |
| Berkeley | CS276, CS278 | TDP constructions, OAEP, ROM |
| Princeton | COS 551 | Number-theoretic cryptography, factoring |
| CMU | 15-855 | Advanced complexity, crypto reductions |
| ETH | 263-4660 | RSA in practice, PKCS#1 standards |
| Cambridge | Part III | Advanced cryptography, tight reductions |

## Build & Test

```bash
make          # Build tests and examples
make test     # Run test suite (60 tests)
make examples # Build all examples
make bench    # Build and run benchmarks
make demo     # Build and run visual demo
make check-lean # Verify Lean formalization status
make clean    # Remove build artifacts
```

### Artifacts

| File | Lines | Content |
|------|-------|---------|
| `include/*.h` (6 files) | 1,410 | Data structures and API declarations |
| `src/*.c` (6 files) | 2,940 | C implementations |
| `src/tdp.lean` | 810 | Lean 4 formalization (72 theorems) |
| `tests/test_main.c` | 620 |  60 assert-based tests |
| `examples/*.c` (3 files) | 442 | End-to-end examples |
| `benches/bench_tdp.c` | 330 | Performance benchmarks |
| `demos/demo_tdp_visual.c` | 333 | Visual demonstration |

## References

- Goldreich, *Foundations of Cryptography* Vol. 1 (2001)
- Rivest, Shamir, Adleman, *RSA Paper* (CACM 1978)
- Bellare & Rogaway, *OAEP* (EUROCRYPT 1994)
- Bellare & Rogaway, *FDH Signatures* (EUROCRYPT 1996)
- Goldreich & Levin, *Hard-Core Predicate* (STOC 1989)
- Menezes, van Oorschot, Vanstone, *HAC* (1996)
- PKCS#1 v2.2 / RFC 8017
