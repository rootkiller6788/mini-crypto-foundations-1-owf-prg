# Knowledge Graph -- mini-pseudorandom-generators-crypto

## L1: Definitions (Complete)

| Concept | C Implementation | Location |
|---------|-----------------|----------|
| Pseudorandom Generator (PRG) | `PRG`, `PRGParams` struct | `prg_crypto.h` |
| Computational Indistinguishability | `Distinguisher`, `DistributionPair` | `prg_crypto.h` |
| Statistical Distance | `stat_distance()` | `prg_crypto.h` |
| Next-bit Unpredictability | `NextBitPredictor` | `prg_crypto.h` |
| PRG Security Game | `PRGSecurityGame` | `prg_crypto.h` |
| One-Way Function (OWF) | `OWF` struct | `hardcore_bit.h` |
| One-Way Permutation (OWP) | `OWP` struct | `hardcore_bit.h` |
| Hardcore Predicate | `HardcorePredicate` | `hardcore_bit.h` |

## L2: Core Concepts (Complete)

| Concept | Implementation | Location |
|---------|---------------|----------|
| PRG Expansion (stretch factor) | `PRGParams.stretch_bits` | `prg_crypto.h` |
| Advantage calculation | `distinguisher_advantage()` | `prg_crypto.c` |
| Negligibility test | `prg_advantage_is_negligible()` | `prg_crypto.c` |
| PRG composition (stretch amplification) | `IteratedPRG` | `prg_construction.h` |
| Hybrid argument | `HybridAnalysis` | `prg_hybrid.h` |
| Generic hybrid game | `HybridGame` | `prg_hybrid.h` |

## L3: Mathematical Structures (Complete)

| Structure | Implementation | Location |
|-----------|---------------|----------|
| Z_n modular arithmetic | `mod_add`, `mod_mul`, `mod_pow` | `prg_number_theory.h` |
| Legendre symbol | `legendre_symbol()` | `prg_number_theory.h` |
| Jacobi symbol | `jacobi_symbol()` | `prg_number_theory.h` |
| Quadratic residues | `qr_test_prime()`, `mod_sqrt_prime()` | `prg_number_theory.h` |
| Blum integers | `BlumInteger`, `blum_check()` | `prg_number_theory.h` |
| Cyclic groups Z_p^* | `is_generator_mod_p()`, `find_generator_mod_p()` | `prg_number_theory.h` |
| Chinese Remainder Theorem | `CRTResult`, `crt_solve()` | `prg_number_theory.h` |
| Miller-Rabin primality | `miller_rabin()` | `prg_number_theory.h` |
| Extended Euclidean Algorithm | `extended_gcd()` | `prg_number_theory.h` |
| Pairwise independent hash | `PairwiseHash` | `prg_construction.h` |

## L4: Fundamental Laws (Complete)

| Theorem | C Implementation | Location |
|---------|-----------------|----------|
| Yao (1982): PRG <=> Next-bit unpredictability | `yao_forward_distinguisher()`, `yao_reverse_predictor_advantage()` | `prg_hybrid.c` |
| Hybrid argument triangle inequality | `hybrid_analysis_compute()`, `hybrid_verify_triangle_inequality()` | `prg_hybrid.c` |
| Blum-Blum-Shub (1986): QRP-hard => BBS PRG | `bbs_next_bit()`, `bbs_to_prg()` | `blum_blum_shub.c` |
| Blum-Micali (1984): DLP-hard => BM PRG | `bm_next_bit()`, `bm_to_prg()` | `blum_micali.c` |
| Goldreich-Levin (1989): GL hardcore for any OWF | `gl_inner_product()`, `gl_list_decode()` | `hardcore_bit.c` |
| OWP + Hardcore => PRG stretch 1 | `prg_owp_create()`, `prg_owp_next()` | `prg_construction.c` |
| PRG stretch 1 => arbitrary stretch (iteration) | `iterated_prg_create()`, `iterated_prg_next_bit()` | `prg_construction.c` |
| Computational indistinguishability under poly-composition | `hybrid_advantage_still_negligible()` | `prg_hybrid.c` |

## L5: Algorithms/Methods (Complete)

| Algorithm | Implementation | Location |
|-----------|---------------|----------|
| BBS key generation | `bbs_keygen()` | `blum_blum_shub.c` |
| BBS LSB extraction | `bbs_next_bit()`, `bbs_generate_bytes()` | `blum_blum_shub.c` |
| BBS CRT acceleration | `bbs_crt_init()`, `bbs_crt_next_bit()` | `blum_blum_shub.c` |
| BM key generation | `bm_keygen()` | `blum_micali.c` |
| BM MSB extraction | `bm_next_bit()`, `bm_generate_bytes()` | `blum_micali.c` |
| Simultaneous hardcore bits | `bm_next_bits_simultaneous()` | `blum_micali.c` |
| GL list decoding | `gl_list_decode()` | `hardcore_bit.c` |
| PRG from OWP+hardcore | `prg_owp_create()`, `prg_owp_next()` | `prg_construction.c` |
| Iterated PRG | `iterated_prg_create()`, `iterated_prg_next_bit()` | `prg_construction.c` |
| Tonelli-Shanks sqrt | `mod_sqrt_prime()` | `prg_number_theory.c` |
| Frequency test (NIST monobit) | `frequency_test_run()` | `prg_construction.c` |
| Runs test | `runs_test_run()` | `prg_construction.c` |
| Serial correlation test | `serial_correlation_run()` | `prg_construction.c` |

## L6: Canonical Problems (Complete)

| Problem | Example | Location |
|---------|---------|----------|
| BBS PRG generation | `example_bbs.c` | `examples/` |
| BM PRG generation | `example_bm.c` | `examples/` |
| Hybrid argument simulation | `example_hybrid.c` | `examples/` |

## L7: Applications (Complete)

| Application | Status | Location |
|-------------|--------|----------|
| Stream cipher (PRG keystream XOR plaintext) | `prg_stream_encrypt()`, `prg_stream_decrypt()` | `prg_applications.c` |
| Key derivation function (KDF from PRG) | `prg_derive_keys()` | `prg_applications.c` |
| Cryptographic nonce generation | `prg_generate_nonce()` | `prg_applications.c` |
| Challenge-response authentication | `prg_generate_challenge()` | `prg_applications.c` |
| GGM PRF construction (PRG => PRF) | `ggm_prf_evaluate()` | `prg_applications.c` |

## L8: Advanced Topics (Complete)

| Topic | Status | Location |
|-------|--------|----------|
| HILL construction (OWF => PRG) structural outline | `PRGFromOWFOutline`, `prg_owf_outline_create()` | `prg_construction.h/c` |
| Computational hybrid argument | `hybrid_advantage_still_negligible()` | `prg_hybrid.c` |
| GGM binary tree PRF construction | `ggm_prf_evaluate()` | `prg_applications.c` |
| Goldreich-Levin list decoding (Walsh-Hadamard) | `gl_inner_product()`, `gl_list_decode()` | `hardcore_bit.c` |
| Yao PRG <=> NBU (forward + reverse) | `yao_forward_distinguisher()`, `yao_reverse_predictor_advantage()` | `prg_hybrid.c` |
| Lean 4 formalization of PRG primitives | 24+ theorems in `prg_formal.lean` | `src/prg_formal.lean` |

## L9: Research Frontiers (Partial)

| Topic | Status | Location |
|-------|--------|----------|
| OWF-to-PRG reductions | HILL outline (documented) | `docs/course-alignment.md` |
| Quantum PRG | Not implemented | -- |
