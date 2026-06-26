# Knowledge Graph — Mini Cryptographic Minimal Assumptions

## L1: Definitions (Complete ✅)

| Concept | C Implementation | Header |
|---------|-----------------|--------|
| Security Parameter λ | `security_param_t` (uint64) | minimal_assumptions.h |
| Negligible Function ν(n) | `negligible_t`, `is_negligible()` | minimal_assumptions.h |
| One-Way Function (OWF) | `OWFParams` struct | minimal_assumptions.h |
| Pseudorandom Generator (PRG) | `PRGParams` struct | minimal_assumptions.h |
| Trapdoor Permutation (TDP) | `TDPParams` struct | minimal_assumptions.h |
| Oblivious Transfer (OT) | `OTType` enum | minimal_assumptions.h |
| Universal OWF | `UniversalOWFInput`, `universal_owf_eval()` | minimal_assumptions.h |
| PRF | `GGMPRF` struct, `ggm_prf_eval()` | minimal_assumptions.h |
| UOWHF | `UOWHFKey`, `uowhf_hash()` | uowhf.h |
| Hardcore Predicate | `goldreich_levin_hardcore_bit()` | minimal_assumptions.h |
| Black-Box Reduction | `BBReductionType` enum | black_box_separation.h |

## L2: Core Concepts (Complete ✅)

| Concept | Implementation |
|---------|---------------|
| Impagliazzo's Five Worlds | `ImpagliazzoWorld` enum, `world_name()`, world queries |
| Cryptographic Primitive Enumeration | `CryptoPrimitive` enum, `prim_name()`, `prim_description()` |
| Assumption Types | `CryptoAssumption` enum, `assumption_name()`, `assumption_implies()` |
| World Belief (Bayesian) | `WorldBelief` struct, `world_belief_update()` |
| World Axioms | `WorldAxioms` struct, 5 standard axiom sets |
| World Capabilities | `WorldCapabilities` struct, `world_capabilities()` |

## L3: Mathematical Structures (Complete ✅)

| Structure | Implementation |
|-----------|---------------|
| Assumption Hierarchy DAG | `AssumptionHierarchy` with adjacency matrix & transitive closure |
| Primitive Landscape Graph | `CryptoLandscape` with nodes, reductions, separations |
| XOR Composition | `XORComposition` struct for k independent inputs |
| Hardness Parameters | `HardnessParameters` struct |
| Random Oracle Model | `RandomOracle` struct, `ro_eval()`, `ro_pspace_invert()` |
| Relativized World | `RelativizedWorld`, `IR_OracleWorld` |
| Hardness Amplification Pipeline | `HardnessAmplificationPipeline` struct |

## L4: Fundamental Laws (Complete ✅)

| Theorem | C Implementation | Lean Formalization |
|---------|-----------------|-------------------|
| HILL 1999: OWF → PRG | `owf_implies_prg_construction()` | `owf_reduces_to_prg` |
| Rompel 1990: OWF → UOWHF | `owf_implies_uowhf_construction()` | `owf_reduces_to_uowhf` |
| Impagliazzo-Rudich 1989: OWF ↛ OT (BB) | `impagliazzo_rudich_separation()` | `owf_not_reduce_to_pke`, `ir89Separation` |
| Yao's XOR Lemma | `yao_xor_bound()`, `yao_xor_bound_full()` | `xor_k_monotonic`, `yao_xor_amplification_possible` |
| Direct Product Theorem | `direct_product_bound()`, `direct_product_prob()` | `direct_product_conservative_bound` |
| Goldreich-Levin Hardcore Bit | `goldreich_levin_hardcore_bit()` | `gl_inner_product_zero_r`, `gl_hardcore_bit_balanced` |
| Naor 1991: OWF → BitCommit | `check_bitcommit_from_owf()` | `owf_reduces_to_bitcommit` |
| Simon 1998: OWF ↛ CRHF | `get_separation(SEP_SIMON98)` | `simon98Separation` |
| World Monotonicity | `world_has_owf()` | `world_monotonic_owf` |
| Minicrypt ≠ Cryptomania | `check_minicrypt_vs_cryptomania()` | `minicrypt_not_cryptomania` |
| TDP stronger than OWF | `assumption_implies()` | `tdp_stronger_than_owf` |
| SKE ↔ Minicrypt+ | `world_has_ske()` | `ske_iff_minicrypt_or_above` |
| PKE ↔ Cryptomania | `world_has_pke()` | `pke_iff_cryptomania` |

## L5: Algorithms/Methods (Complete ✅)

| Algorithm | Implementation |
|-----------|---------------|
| GGM PRF (binary tree) | `ggm_prf_init()`, `ggm_prf_eval()`, `ggm_prf_free()` |
| Goldreich-Levin List Decoding | `gl_list_decode()`, `gl_verify_candidate()` |
| Hardness Amplification Pipeline | `ha_pipeline_create()`, `ha_pipeline_execute()` |
| Yao XOR Optimal k | `yao_xor_optimal_k()`, `yao_xor_epsilon_optimal()` |
| PSPACE Adversary | `pspace_adversary_create()`, `pspace_adversary_attack()` |
| IR Oracle Protocol Testing | `ir_test_ot_protocol()` |
| UOWHF Chain Composition | `uowhf_compose_hash_chain()` |

## L6: Canonical Problems (Complete ✅)

| Problem | Implementation |
|---------|---------------|
| Minicrypt vs Cryptomania | `check_minicrypt_vs_cryptomania()`, `print_minicrypt_cryptomania_boundary()` |
| BitCommit from OWF | `check_bitcommit_from_owf()` |
| Universal OWF (Levin) | `universal_owf_eval()` |
| Which World Do We Live In? | `print_current_consensus()`, `print_post_quantum_analysis()` |
| Yao Canonical Example | `yao_canonical_example()` |
| GL Canonical Example | `gl_canonical_example()` |
| XOR vs Concatenation | `compare_xor_vs_concatenation()` |

## L7: Applications (Complete ✅ — 3 applications)

| Application | Implementation |
|-------------|---------------|
| PoW Security Estimate | `pow_security_estimate()` |
| TLS Cipher Recommendation | `tls_cipher_recommendation()` |
| Post-Quantum Security | `is_post_quantum_secure()` |
| Deployment Advice | `advise_deployment()`, `print_deployment_advice()` |

## L8: Advanced Topics (Partial+ ✅)

| Topic | Implementation |
|-------|---------------|
| RTV Framework (BB taxonomy) | `rtv_query()`, `BBReductionType` |
| Meta-Complexity Perspective | `meta_complexity_perspective()` |
| Non-BB vs BB Constructions | `ConstructionType` enum |
| Separation Testing Framework | `SeparationTest`, `separation_test_run()` |

## L9: Research Frontiers (Partial ✅)

| Topic | Documentation |
|-------|--------------|
| MCSP ↔ OWF connection | `meta_complexity_perspective()` |
| Natural Proofs Barrier | `meta_complexity_perspective()` |
| Post-Quantum World Analysis | `print_post_quantum_analysis()` |
| iO and minimal assumptions | Referenced in print functions |
