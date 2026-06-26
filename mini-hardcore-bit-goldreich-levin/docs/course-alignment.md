# Course Alignment — Goldreich-Levin Hardcore Bit

Nine-school curriculum mapping for the Goldreich-Levin theorem module.

## MIT — 6.875 Cryptography & Cryptanalysis

| Topic | GL Module Coverage |
|-------|-------------------|
| One-way functions (Lecture 3-4) | 5 candidate OWFs implemented |
| Hardcore predicates (Lecture 5) | GL bit, MSB, LSB, GL construction |
| Goldreich-Levin theorem (Lecture 6) | Full reduction: bit recovery + inversion |
| PRG from OWF (Lecture 7-8) | Blum-Micali construction, HILL chain |

## Stanford — CS255 Introduction to Cryptography

| Topic | GL Module Coverage |
|-------|-------------------|
| OWF definitions and examples | `OWF` struct, 5 types, parallel repetition |
| Hardcore bits | `HardcorePredicate`, predictor framework |
| PRG definitions | `PRGFromOWF`, expansion property |
| GL theorem proof | Self-correction lemma, bit recovery algorithm |

## Princeton — COS 551 Advanced Cryptography

| Topic | GL Module Coverage |
|-------|-------------------|
| Hadamard code and list decoding | Complete Hadamard codec, FWHT |
| Fourier analysis over Boolean cube | `fourier_coefficient()`, `fourier_transform()` |
| Advanced reductions | GL reduction with query complexity bounds |

## CMU — 15-859 Foundations of Cryptography

| Topic | GL Module Coverage |
|-------|-------------------|
| Weak vs Strong OWF | Yao's parallel repetition implemented |
| GL bit recovery | `gl_recover_bit()` with Chernoff analysis |
| Security proofs via reduction | End-to-end GL reduction |

## Berkeley — CS276 Cryptography

| Topic | GL Module Coverage |
|-------|-------------------|
| Number-theoretic OWFs | Multiplication, modular exponentiation, RSA |
| Concrete security | `estimate_security_level()`, key length recommendations |
| Negligible functions | Multiple negligible function families |

## ETH — 263-4650 Advanced Cryptography

| Topic | GL Module Coverage |
|-------|-------------------|
| PRG construction from OWF | Full Blum-Micali + GL implementation |
| Forward security | `prg_forward_secure_step()` |
| Statistical tests | Battery: bias, runs, longest run, autocorrelation |

## Cambridge — Part III Cryptography

| Topic | GL Module Coverage |
|-------|-------------------|
| Asymptotic vs concrete security | Both frameworks supported |
| Chernoff/Hoeffding bounds | 4 bound types with sample complexity |
| One-way function theory | Complete OWF taxonomy |

## Oxford — Advanced Security

| Topic | GL Module Coverage |
|-------|-------------------|
| Randomness extraction | KDF from hardcore bits |
| Probabilistic analysis | Chernoff, Hoeffding, majority vote bounds |
| Commitment schemes | Naor commitment from OWF |

## Caltech — CS 151 Complexity Theory

| Topic | GL Module Coverage |
|-------|-------------------|
| OWF in complexity theory | OWF ↔ PRG as complexity connection |
| Hardness assumptions | 5 candidate OWFs with hardness estimates |
| Reduction techniques | GL self-correction as complexity reduction |
