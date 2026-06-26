# Gap Report — OWF ⇔ PRG Equivalence

## Current Gaps

### L9: Research Frontiers (Partial)

| Gap | Priority | Notes |
|-----|----------|-------|
| Quantum OWF candidates | Medium | Lattice-based (LWE, SIS) not implemented |
| Tight reduction (HRV 2010) | Medium | Current: HILL basic; HRV near-linear tightness not implemented |
| Meta-complexity perspective | Low | Impagliazzo's worlds documented but not coded |
| NIZK from OWF | Low | Non-interactive zero-knowledge from OWF not implemented |

## Resolved Gaps

All L1-L8 gaps have been resolved. The module has complete coverage of:
- OWF definitions and 4 candidate constructions
- PRG definitions and Blum-Micali/HILL constructions
- Goldreich-Levin hardcore bit with list decoding
- Computational indistinguishability and hybrid arguments
- Full HILL reduction (OWF ⇒ PRG) in 4 stages
- PRG ⇒ OWF trivial direction
- Stream cipher application
- BPP derandomization
- Entropy/pseudoentropy analysis
