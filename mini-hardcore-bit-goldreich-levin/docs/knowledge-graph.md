# Knowledge Graph — Goldreich-Levin Hardcore Bit

## L1: Definitions

| Term | C Definition | Lean Definition | Status |
|------|-------------|-----------------|--------|
| One-Way Function (OWF) | `OWF` struct in `owf.h` | `OWF` structure in `gl_theorem.lean` | Complete |
| Hardcore Predicate | `HardcorePredicate` struct in `hardcore_bit.h` | `HardcorePredicate` Prop | Complete |
| Inner Product mod 2 | `bit_inner_product()` in `bit_operations.h` | `innerProduct` def | Complete |
| Pseudorandom Generator (PRG) | `PRGFromOWF` struct in `prg_from_owf.c` | — | Complete |
| Negligible Function | `is_negligible()` in `security_params.h` | `Negligible` def | Complete |
| Hadamard Code | `HadamardCode` struct in `list_decoding.h` | `HadamardEncode` def | Complete |
| Security Parameter | `SecParam` struct in `owf.h` | — | Complete |
| Bit String | `BitString` struct in `owf.h` | `BitString` type alias | Complete |
| GL Construction | `GLConstruction` struct in `hardcore_bit.h` | `GLConstruction` def | Complete |

## L2: Core Concepts

| Concept | Implementation | Status |
|---------|---------------|--------|
| Polynomial-Time Computability | `EasyToCompute` predicate, OWF.eval is PPT by construction | Complete |
| Inversion Hardness | `owf_inversion_probability()`, `owf_verify_oneway_property()` | Complete |
| Advantage (over random guessing) | `hc_predictor_estimate_advantage()` | Complete |
| Stretch Factor (PRG) | `prg_check_expansion()` | Complete |
| Computational Indistinguishability | `statistical_distance()`, `compute_advantage_distinguisher()` | Complete |
| Self-Correctability | `gl_self_correct()`, `hadamard_self_correct()` | Complete |
| Security Amplification | `owf_parallel_repeat()` (Yao) | Complete |

## L3: Mathematical Structures

| Structure | Implementation | Status |
|-----------|---------------|--------|
| F₂ Vector Space (bit strings) | `uint64_t*` bit-packed representation | Complete |
| Inner Product over F₂ | `bit_inner_product()` with bilinearity property | Complete |
| Multi-Word Binary Arithmetic | `bit_add()`, `bit_sub()`, `bit_mul()`, `bit_mod_exp()` | Complete |
| Walsh-Hadamard Transform | `hadamard_transform()`, `hadamard_transform_real()` | Complete |
| Fourier over Boolean Cube | `fourier_coefficient()`, `fourier_transform()` | Complete |
| Hadamard Code RM(1,n) | `HadamardCode`, `HadamardCodeword` | Complete |
| Chernoff/Hoeffding Inequalities | `chernoff_upper()`, `hoeffding_bound()` | Complete |

## L4: Fundamental Theorems

| Theorem | C Verification | Lean Statement | Status |
|---------|---------------|----------------|--------|
| Goldreich-Levin Theorem | `gl_invert()`, `gl_validate_reduction()` | `goldreich_levin_theorem` | Complete |
| GL Self-Correction Lemma | Verified in `example_gl_theorem.c` | `innerProduct_self_correct` | Complete |
| Yao Weak→Strong OWF | `owf_parallel_repeat()`, `owf_is_weak_to_strong_reduction()` | — | Complete |
| HILL OWF→PRG | `prg_evaluate()`, PRG chain in `prg_from_owf.c` | — | Complete |
| Johnson Bound | `hadamard_list_size_bound()` | `hadamard_list_size` | Complete |
| Chernoff Concentration | `chernoff_two_sided()`, `majority_correct_prob()` | — | Complete |
| Bilinearity of Inner Product | Verified in `test_bit_operations.c` | `innerProduct_add_left` | Complete |

## L5: Algorithms

| Algorithm | Implementation | Complexity |
|-----------|---------------|------------|
| GL Bit Recovery | `gl_recover_bit()` | O(n/ε²) queries |
| GL Full Inversion | `gl_invert()` | O(n²/ε²) queries |
| Hadamard List Decode | `hadamard_list_decode()` | O(n·2^n) |
| Fast Walsh-Hadamard Transform | `hadamard_transform()` | O(n·2^n) |
| Blum-Micali PRG | `prg_evaluate()` | O(stretch) |
| Parallel Repetition | `owf_parallel_repeat()` | O(k) evaluations |
| Square-and-Multiply | `bit_mod_exp()` | O(n³) |
| Miller-Rabin Primality | `bs_is_prime()` | O(k·n³) |

## L6: Canonical Problems

| Problem | Example | Status |
|---------|---------|--------|
| OWF Inversion | `example_gl_theorem.c` | Complete |
| Hadamard List Decoding | `example_list_decoding.c` | Complete |
| PRG Construction | `example_prg_construction.c` | Complete |

## L7: Applications

| Application | Implementation | Status |
|-------------|---------------|--------|
| PRG from OWF | `prg_from_owf.c` — full Blum-Micali + GL | Complete |
| Commitment Scheme | `crypto_primitives.c` — Naor commitment | Complete |
| Lamport OTS | `crypto_primitives.c` — one-time signatures | Complete |
| Hash from OWF | `crypto_primitives.c` — Merkle-Damgård | Complete |
| Key Derivation | `crypto_primitives.c` — KDF from hardcore bits | Complete |

## L8: Advanced Topics

| Topic | Implementation | Status |
|-------|---------------|--------|
| Johnson Bound Analysis | `hadamard_list_size_bound()`, `gl_list_size_bound()` | Complete |
| Fourier Analysis | `fourier_coefficient()`, `fourier_transform()` | Complete |
| Forward Security | `prg_forward_secure_step()` | Complete |
| Concrete Security | `estimate_security_level()`, `keylen_for_level()` | Partial |

## L9: Research Frontiers

| Topic | Status |
|-------|--------|
| Meta-complexity connections (OWF ↔ natural proofs) | Documented |
| Quantum implications (quantum OWF, GL in quantum setting) | Documented |
| Tightness of GL reduction (query complexity lower bounds) | Documented |
