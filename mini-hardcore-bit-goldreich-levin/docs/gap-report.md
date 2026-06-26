# Gap Report — Goldreich-Levin Hardcore Bit

## Identified Gaps

### L8: Advanced Topics

| Gap | Priority | Description |
|-----|----------|-------------|
| GL Reduction Tightness | Low | Query complexity lower bounds for GL reduction (Ω(n/ε²) tightness proof) |

### L9: Research Frontiers

| Gap | Priority | Description |
|-----|----------|-------------|
| Quantum GL Theorem | Low | Goldreich-Levin in the quantum random oracle model |
| Meta-complexity connections | Low | Relationship between OWF and MCSP (Minimum Circuit Size Problem) |
| Fine-grained GL | Low | Sub-exponential vs exponential hardness in GL reduction |

## Resolved Gaps (from previous audit)

| Gap | Resolution |
|-----|------------|
| OWF candidate implementations | ✅ 5 candidates implemented |
| GL full reduction code | ✅ `gl_invert()`, `gl_recover_bit()`, `gl_self_correct()` |
| Hadamard list decoding | ✅ `hadamard_list_decode()`, FWHT implemented |
| PRG construction from OWF | ✅ Blum-Micali + forward security |
| Security parameter framework | ✅ Chernoff/Hoeffding, negligible functions |
| Test coverage | ✅ 69 tests across 5 test files |

## Action Items

1. **None critical** — All L1-L7 are Complete. Only advanced topics (L8-L9) have minor gaps.

2. **Optional enhancements**:
   - Add tightness proofs for GL query complexity
   - Implement quantum-safe OWF candidates (lattice-based)
   - Add GL variant for non-Boolean alphabets (generalized GL)
