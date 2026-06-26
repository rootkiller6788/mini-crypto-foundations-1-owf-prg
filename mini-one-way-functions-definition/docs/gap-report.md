# Gap Report: One-Way Functions

## Identified Gaps

### L7: Applications (2 missing)

| Priority | Gap | Description |
|----------|-----|-------------|
| Medium | PRG from OWF | Pseudorandom generator construction from one-way functions |
| Low | Commitment Schemes | Bit commitment from one-way functions |

### L8: Advanced Topics (2 missing)

| Priority | Gap | Description |
|----------|-----|-------------|
| Medium | Universal OWF | Levin's construction of a universal one-way function |
| Low | OWF Completeness | Impagliazzo-Luby proof of OWF completeness for crypto |

### Implementation Limitations

| Issue | Severity | Description |
|-------|----------|-------------|
| unsigned arithmetic | Medium | big_nat_t does not support negative numbers, limiting EGCD/modinv |
| small-prime generation | Low | 32-bit prime generation is unreliable; production needs >= 128-bit |
| GL list decode | Low | Full 2^k enumeration not feasible; current implementation uses heuristic sampling |

## Resolution Plan

1. **PRG from OWF**: Extend hardcore module with Blum-Micali or Goldreich-Levin PRG construction
2. **Universal OWF**: Implement Levin's construction as an exercise in OWF theory
3. **Signed arithmetic**: Extend big_nat to support signed values for complete EGCD
4. **Large primes**: Add support for >= 1024-bit primes via optimized generation
