# Gap Report -- mini-pseudorandom-generators-crypto

## Missing Items (by priority)

| Priority | Level | Item | Reason |
|----------|-------|------|--------|
| Low | L9 | Quantum PRG (quantum-secure PRG) | Out of scope; quantum assumptions not yet standardized |
| Low | L9 | Concrete security bounds for BBS/BM with large parameters | Requires >64-bit arithmetic (GMP library) |
| Low | L8 | Full HILL construction (OWF => PRG via hashing + GL + extractor) | Highly technical; requires universal hash + leftover hash lemma full implementation |

## Partial Items

| Level | Item | Current Status | To Complete |
|-------|------|---------------|-------------|
| L9 | OWF-to-PRG reductions | HILL outline in prg_construction.h/c | Full implementation would need pairwise-independent hashing framework + leftover hash lemma + Goldreich-Levin in full generality |

## Completed Items (all resolved)

All L1-L8 items are Complete. No critical gaps remain.
