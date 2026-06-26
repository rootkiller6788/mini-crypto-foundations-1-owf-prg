# Prerequisite Dependency Tree — Mini Cryptographic Minimal Assumptions

## External Dependencies

```
Complexity Theory Basics
  ├── P, NP, PPT definitions
  ├── Negligible functions
  ├── Polynomial-time reductions
  └── Oracle Turing machines

Cryptography Foundations
  ├── One-Way Functions (definition, candidates)
  ├── Pseudorandomness (computational indistinguishability)
  ├── Hardcore predicates
  └── Commitment schemes (definition)
```

## Internal Dependency Tree

```
L1: Definitions
  ├── security_param_t, negligible_t
  ├── OWFParams, PRGParams, TDPParams
  ├── OWF → all primitives defined
  └── UOWHF, PRF, OT etc.
      │
L2: Core Concepts ──────────────────┐
  ├── Impagliazzo Worlds            │
  ├── Primitive Enumeration         │
  ├── Assumption Types              │
  └── World Belief                  │
      │                             │
L3: Math Structures ────────────────┤
  ├── Assumption Hierarchy DAG      │
  ├── CryptoLandscape graph         │
  ├── XOR Composition               │
  ├── Random Oracle Model           │
  └── Hardness Parameters           │
      │                             │
L4: Fundamental Laws ◄──────────────┘
  ├── HILL: OWF → PRG
  │   └── depends on: L1(OWF,PRG), L3(HardnessParams)
  ├── Yao's XOR Lemma
  │   └── depends on: L1(hardness), L3(XORComposition)
  ├── Goldreich-Levin
  │   └── depends on: L1(hardcore bit), L5(list decode)
  ├── Impagliazzo-Rudich
  │   └── depends on: L1(OWF,OT), L3(RandomOracle)
  ├── Rompel: OWF → UOWHF
  │   └── depends on: L1(OWF, UOWHF)
  └── Naor: OWF → BitCommit
      └── depends on: L1(OWF, BitCommit), L4(HILL)
          │
L5: Algorithms ◄────────────────────┘
  ├── GGM PRF Construction
  │   └── depends on: L1(PRG,PRF), L4(HILL)
  ├── Goldreich-Levin List Decode
  │   └── depends on: L4(GL hardcore bit)
  ├── Hardness Amplification Pipeline
  │   └── depends on: L4(Yao, GL), L3(HardnessParams)
  └── PSPACE Adversary
      └── depends on: L3(RandomOracle)
          │
L6: Canonical Problems ◄────────────┘
  ├── Minicrypt vs Cryptomania
  ├── BitCommit from OWF
  ├── Universal OWF
  └── Which World?
      │
L7: Applications ◄──────────────────┘
  ├── PoW Security Estimate
  ├── TLS Recommendation
  ├── Post-Quantum Security
  └── Deployment Advice
      │
L8: Advanced Topics ◄───────────────┘
  ├── RTV Framework
  ├── Meta-Complexity
  └── Separation Testing
      │
L9: Research Frontiers ◄────────────┘
  ├── MCSP ↔ OWF
  ├── Natural Proofs
  └── Post-Quantum Hierarchy
```

## Key: Which Function Calls Which

```
main() examples
  └── world_belief_init/update/print/map
  │   └── world_name()
  ├── advise_deployment()
  │   └── assumption_name(), prim_name()
  ├── ah_create()
  │   └── calloc, EDGE macro
  ├── ah_reducible()
  │   └── transitive_closure check
  ├── ggm_prf_init/eval/free
  │   └── Murmur3 mixer (deterministic)
  ├── yao_canonical_example()
  │   └── yao_xor_bound(), direct_product_bound()
  └── check_minicrypt_vs_cryptomania()
      └── printf analysis
```
