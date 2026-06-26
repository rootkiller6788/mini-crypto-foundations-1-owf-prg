# Knowledge Graph — mini-trapdoor-permutations

## L1: Definitions (Complete)
- Trapdoor Permutation (TDP): family of permutations with trapdoor for efficient inversion
- One-Way Function (OWF): easy to compute, hard to invert
- One-Way Permutation (OWP): bijective OWF
- Security parameter λ: determines key length and security level
- Negligible function ε(λ): decays faster than any inverse polynomial
- One-wayness advantage Adv^{OW}(A): success probability of inverting without trapdoor
- Hard-core predicate: bit that is unpredictable given only f(x)
- Public-key encryption (PKE): (Gen, Enc, Dec) triple
- Digital signature scheme: (Gen, Sign, Verify) triple
- IND-CPA/IND-CCA security: indistinguishability under chosen attack
- EUF-CMA security: existential unforgeability under chosen-message attack

## L2: Core Concepts (Complete)
- TDP ⊆ OWP ⊆ OWF hierarchy: every TDP is an OWP, every OWP is an OWF
- RSA Assumption: computing e-th roots modulo n is hard without d
- Factoring Assumption: factoring n = pq is hard; implies RSA is hard
- Random self-reducibility of RSA: average-case solver ⇒ worst-case solver
- Malleability: textbook RSA is multiplicatively homomorphic (dangerous)
- Padding necessity: deterministic encryption cannot be IND-CPA
- Random oracle model (ROM): idealized hash function for security proofs
- Tight vs loose security reductions

## L3: Mathematical Structures (Complete)
- Ring Z_n: integers modulo n with addition and multiplication
- Multiplicative group Z_n^*: elements coprime to n
- Euler's totient φ(n) = |Z_n^*|
- Chinese Remainder Theorem: Z_{pq} ≅ Z_p × Z_q (ring isomorphism)
- Carmichael function λ(n) = lcm(p-1, q-1)
- Quadratic residuosity: Legendre symbol (a/p), Jacobi symbol (a/n)
- Modular exponentiation ring structure
- Garner's formula for CRT-based exponentiation

## L4: Fundamental Laws (Complete)
- **RSA Correctness Theorem**: ∀x ∈ Z_n, x^{ed} ≡ x (mod n) when ed ≡ 1 (mod φ(n))
- **Euler's Theorem**: x^{φ(n)} ≡ 1 (mod n) for gcd(x,n)=1
- **Bezout's Identity**: ∃x,y: ax + by = gcd(a,b)
- **Division Algorithm**: ∃!q,r: a = qb + r, 0 ≤ r < b
- **CRT Isomorphism**: Bijection between Z_{m1m2} and Z_{m1}×Z_{m2}
- **Prime Number Theorem**: π(x) ~ x/ln x
- Self-reducibility of RSA proven

## L5: Algorithms/Methods (Complete)
- Square-and-multiply (binary exponentiation): O(log exp · log² mod)
- Extended Euclidean algorithm: O(log² n) for modular inverse
- Miller-Rabin probabilistic primality test: O(k·log³ n), error ≤ 4^{-k}
- Trial division sieve: fast composite elimination before MR
- Random prime generation by rejection sampling
- Garner's CRT decryption: ~4× faster than naive RSA
- RSA key generation from random primes
- OAEP padding/unpadding
- PSS encoding/decoding for signatures

## L6: Canonical Problems (Complete)
- RSA encryption/decryption roundtrip
- Textbook RSA signature + existential forgery
- Multiplicative forgery on textbook RSA
- Brute-force TDP inversion (exponential complexity)
- RSA-OAEP encryption with label
- FDH signature with hash-to-domain
- PSS probabilistic signature with salt
- CRT vs naive performance comparison

## L7: Applications (Complete — 5 applications)
1. **Textbook RSA PKE**: Demonstrates why padding is essential (deterministic, malleable)
2. **Goldreich-Levin PKE**: IND-CPA secure bit encryption from any TDP
3. **RSA-OAEP**: Industry-standard IND-CCA2 secure encryption (PKCS#1 v2.2)
4. **Full Domain Hash (FDH)**: EUF-CMA secure signatures in ROM
5. **RSA-PSS**: Tightly-secure probabilistic signatures (RFC 8017)

## L8: Advanced Topics (Partial — 2 topics)
1. **Random Self-Reducibility**: RSA problem is random self-reducible (implemented in rsa.c)
2. **Loose vs Tight Security**: FDH has loose reduction (q_s·q_h factor), PSS has tight reduction
3. Coppersmith's attacks on small-exponent RSA (documented, not implemented)
4. Bleichenbacher's padding oracle attack (documented, not implemented)
5. Quantum threat: Shor's algorithm breaks factoring/RSA (documented)

## L9: Research Frontiers (Partial — documented)
- Post-quantum trapdoor permutations (lattice-based)
- Lossy trapdoor functions (Peikert-Waters)
- Correlated-product TDP security
- Deterministic PKE from TDP with auxiliary inputs
- Memory-tight reductions for RSA-based signatures
