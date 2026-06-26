# Gap Report — Mini Cryptographic Minimal Assumptions

## Missing Knowledge Points

### L8: Advanced Topics (2 missing)
1. **Stochastic modeling of cryptographic ecosystems** — agent-based simulation of assumption breaks and cascading failures. Would model the transition between Impagliazzo worlds as a dynamic process.
2. **Time-varying security parameter adaptation** — adaptive security based on real-time estimates of computational power growth (Moore's Law effects on cryptographic assumptions).

### L9: Research Frontiers (allowed Partial)
1. **i∅ (Indistinguishability Obfuscation)** — the strongest known cryptographic primitive. Implications for minimal assumptions: if i∅ exists, P=NP oracle separation results may be bypassed.
2. **Quantum OWF** — post-quantum minimal assumption landscape. Are quantum OWF strictly weaker than classical OWF?
3. **Fine-grained cryptography** — sub-exponential vs polynomial hardness for specific assumptions.

## Priority Queue

| Priority | Item | Level | Effort |
|----------|------|-------|--------|
| P1 | Stochastic assumption modeling | L8 | Medium |
| P2 | Time-varying security parameters | L8 | Medium |
| P3 | i∅ and minimal assumptions | L9 | Large |
| P4 | Quantum OWF hierarchy | L9 | Large |

## Known Limitations

1. The GGM PRF uses a deterministic mixing function instead of a provably secure PRG. This is acceptable for demonstration but not for production use.
2. The random oracle model uses bounded input size (≤16 bits) for tractable simulation. Real cryptanalysis requires asymptotic treatment.
3. The world belief updating uses heuristic likelihood ratios rather than formal Bayesian posteriors computed from protocol-level analysis.
4. Security parameter relationships are estimated, not rigorously derived from concrete hardness assumptions.
