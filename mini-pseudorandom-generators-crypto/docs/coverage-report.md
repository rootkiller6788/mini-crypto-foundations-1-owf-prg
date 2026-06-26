# Coverage Report -- mini-pseudorandom-generators-crypto

| Level | Name | Rating | Justification |
|-------|------|--------|---------------|
| L1 | Definitions | **Complete** | 8 core definitions: PRG, OWF, OWP, hardcore predicate, computational indistinguishability, statistical distance, NBU, security game |
| L2 | Core Concepts | **Complete** | 6 concepts: PRG expansion/stretch, advantage, negligibility, PRG composition, hybrid argument, generic hybrid game |
| L3 | Math Structures | **Complete** | 10 structures: Z_n arithmetic, Legendre/Jacobi, QR, Blum integers, cyclic groups, CRT, Miller-Rabin, Tonelli-Shanks, pairwise independent hash, Euler totient |
| L4 | Fundamental Laws | **Complete** | 8 theorems: Yao PRG<=>NBU, hybrid argument, BBS security, BM security, Goldreich-Levin, OWP+HC=>PRG, stretch iteration, poly-composition negligibility |
| L5 | Algorithms | **Complete** | 13 algorithms: BBS keygen/extraction/CRT, BM keygen/extraction/simultaneous, GL list decode, PRG from OWP, iterated PRG, frequency/runs/autocorrelation tests |
| L6 | Canonical Problems | **Complete** | 3 end-to-end examples: BBS generation, BM generation, hybrid argument simulation |
| L7 | Applications | **Complete** | 4 applications: stream cipher, key derivation, nonce generation, challenge-response authentication |
| L8 | Advanced Topics | **Complete** | 3 advanced: HILL construction outline, computational hybrid argument, GGM PRF from PRG |
| L9 | Research Frontiers | **Partial** | Documented: quantum PRG, OWF-to-PRG reductions |

**Score**: L1(2)+L2(2)+L3(2)+L4(2)+L5(2)+L6(2)+L7(2)+L8(2)+L9(1) = **17/18**

**Rating**: **COMPLETE** (>=16/18, L1!=Missing, L4!=Missing, 8 layers Complete)
