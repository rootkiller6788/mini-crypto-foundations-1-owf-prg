# Gap Report — mini-trapdoor-permutations

## Current Gaps

### L8: Advanced Topics (3 missing)
1. **Coppersmith's Low-Exponent Attack** (Priority: Medium)
   - Finding small roots of polynomial equations modulo n
   - Affects RSA with e=3 without proper padding
   - Reference: Coppersmith, "Small Solutions to Polynomial Equations" (1997)

2. **Bleichenbacher's Padding Oracle Attack** (Priority: Medium)
   - Adaptive chosen-ciphertext attack on PKCS#1 v1.5 padding
   - ~1 million queries to decrypt arbitrary RSA ciphertext
   - Reference: Bleichenbacher, CRYPTO 1998

3. **Quantum Computing Threat** (Priority: Low)
   - Shor's algorithm factors n in polynomial time on quantum computer
   - Breaks RSA and all factoring-based TDPs
   - Post-quantum alternatives: lattice-based TDPs

### L9: Research Frontiers (all documented, no code)
- Lossy Trapdoor Functions (Peikert-Waters, STOC 2008)
- Correlated-Product TDP security (Rosen-Segev, TCC 2009)
- Deterministic PKE from TDP (Bellare-Boldyreva-O'Neill, CRYPTO 2007)
- Post-quantum TDP from lattices (Gentry-Peikert-Vaikuntanathan, STOC 2008)

## No Critical Gaps
All L1-L7 levels are Complete. Remaining gaps are in L8 (Partial) and L9 (Partial as expected per SKILL.md).
