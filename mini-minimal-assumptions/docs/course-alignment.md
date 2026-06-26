# Course Alignment — Mini Cryptographic Minimal Assumptions

## MIT (6.875 Cryptography and Cryptanalysis)
- **OWF and PRG**: `owf_implies_prg_construction()` — HILL construction
- **Trapdoor Permutations**: `TDPParams`, `world_has_tdp()` — RSA-based TDP
- **BB vs Non-BB**: `ConstructionType`, `rtv_query()` — RTV taxonomy

## Stanford (CS255 Introduction to Cryptography)
- **Symmetric crypto from OWF**: `assumption_implies(OWF, SKE)` — complete chain
- **PRF from PRG**: `ggm_prf_init()`, `ggm_prf_eval()` — GGM tree construction
- **Bit Commitment**: `check_bitcommit_from_owf()` — Naor 1991

## Berkeley (CS276 Cryptography)
- **Minimal assumptions**: Full assumption hierarchy with transitive closure
- **LWE implications**: `assumption_implies(LWE, PKE)` — Regev 2005
- **Post-quantum**: `is_post_quantum_secure()`, `print_post_quantum_analysis()`

## Princeton (COS 433 Cryptography)
- **Impagliazzo's Five Worlds**: Complete formalization with belief updating
- **OWF vs TDP**: `ah_reducible()`, boundary analysis
- **IR89 separation**: `impagliazzo_rudich_separation()`, oracle construction

## CMU (15-855 Graduate Complexity)
- **Hardness amplification**: Yao's XOR Lemma with quantitative bounds
- **Goldreich-Levin**: Hardcore bit extraction, list decoding
- **Universal OWF**: `universal_owf_eval()` — Levin 1987

## Caltech (CS 151 Complexity Theory)
- **Average-case complexity**: Five worlds as average-case conjectures
- **Relativization**: Random oracle model for separations
- **Meta-complexity**: `meta_complexity_perspective()` — MCSP connection

## Cambridge (Part III Advanced Complexity)
- **Black-box separations**: `get_separation()`, complete separation database
- **RTV framework**: Full taxonomy with 4 reduction types
- **Open problems**: Minicrypt vs Cryptomania boundary analysis

## Oxford (Advanced Complexity Theory)
- **Quantum threats**: Post-quantum world analysis
- **LWE assumption**: LWE → PKE reduction tracking
- **Deployment advice**: `advise_deployment()` with security bits

## ETH (263-4660 Foundations of Cryptography)
- **OWF → PRG**: HILL construction stages
- **UOWHF from OWF**: Rompel construction, security proof
- **CRHF limitations**: Simon 1998 separation
