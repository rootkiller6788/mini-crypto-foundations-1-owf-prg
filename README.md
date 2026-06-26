# Mini Crypto Foundations — OWF & PRG

A collection of **from-scratch, zero-dependency C implementations** of the foundational theory of one-way functions (OWF), pseudorandom generators (PRG), and their equivalence — the cornerstone of modern cryptography. Each sub-module maps to MIT, Stanford, Princeton, and other top-tier university courses, covering formal definitions, hardcore predicates, hybrid arguments, minimal cryptographic assumptions, GGM pseudorandom functions, and trapdoor permutations.

## Sub-Modules

| Sub-Module | Topics | Key Courses |
|------------|--------|-------------|
| [mini-one-way-functions-definition](mini-one-way-functions-definition/) | OWF formal definition, RSA/DL/subset-sum/Rabin candidates, weak vs strong OWF, security parameter, negligible functions, inversion experiment | MIT 6.875, Stanford CS255, Berkeley CS276 |
| [mini-hardcore-bit-goldreich-levin](mini-hardcore-bit-goldreich-levin/) | Goldreich-Levin theorem, hardcore predicates, inner product mod 2, list decoding of Hadamard code, OWF→hardcore reduction, self-correctability | MIT 6.875, Stanford CS255, Princeton COS 551 |
| [mini-hybrid-argument](mini-hybrid-argument/) | Hybrid argument lemma, distinguisher taxonomy, negligible functions, computational indistinguishability, advantage bounds, PRG security via hybrids, next-bit unpredictability | MIT 6.875, Stanford CS355, Princeton COS 522 |
| [mini-owf-vs-prg-equivalence](mini-owf-vs-prg-equivalence/) | OWF⇔PRG equivalence (HILL 1999), computational indistinguishability, stretch, seed expansion, deterministic expansion, Yao's theorem, stream cipher applications | MIT 6.875, Stanford CS255, Berkeley CS276, Princeton COS 522 |
| [mini-pseudorandom-generators-crypto](mini-pseudorandom-generators-crypto/) | PRG formal definition, Blum-Blum-Shub (BBS) generator, Blum-Micali generator, quadratic residuosity, discrete log assumption, hardcore predicates (LSB), next-bit unpredictability | MIT 6.875, Stanford CS255, Princeton COS 551 |
| [mini-pseudorandom-functions-ggm](mini-pseudorandom-functions-ggm/) | Goldreich-Goldwasser-Micali (GGM) theorem, PRG⇒PRF construction, binary tree evaluation, PRF definitions, hybrid argument security proof, OWF⇒PRG⇒PRF chain | MIT 6.875, Princeton COS 522, Stanford CS255 |
| [mini-minimal-assumptions](mini-minimal-assumptions/) | Impagliazzo's five worlds, OWF⇒PRG (HILL), black-box separations, UOWHF, Yao's XOR lemma, hardness amplification, assumption hierarchy, cryptographic minimality | MIT 6.875, Stanford CS255, Princeton COS 433, ETH 263-4660 |
| [mini-trapdoor-permutations](mini-trapdoor-permutations/) | TDP formal definition, RSA trapdoor permutation, key generation, modular arithmetic (CRT, Euler's totient), public-key encryption from TDP, digital signatures from TDP | MIT 6.875, Stanford CS255, Princeton COS 551, Berkeley CS278 |

## Design Philosophy

- **Zero external dependencies** — pure C99/C11, only standard library headers
- **Self-contained sub-modules** — each has its own `include/`, `src/`, `CMakeLists.txt`, and smoke tests
- **Theory-to-code mapping** — every module includes inline references to textbook sections (Goldreich, Katz-Lindell, Arora-Barak) and lecture notes
- **Cryptographic rigor** — formal security definitions with distinguisher advantage, negligible functions, and reduction proofs as executable code

## Building

Each sub-module is standalone. Build with CMake:

```bash
cd mini-one-way-functions-definition
mkdir build && cd build
cmake ..
make
./smoke_test
```

Requires a **C99-compliant compiler** and **CMake ≥ 3.14**.

## Project Structure

```
10. mini-crypto-foundations-1-owf-prg/
├── mini-one-way-functions-definition/    # OWF definition, RSA/DL/subset-sum/Rabin candidates, weak vs strong
├── mini-hardcore-bit-goldreich-levin/    # Goldreich-Levin theorem, hardcore predicates, list decoding
├── mini-hybrid-argument/                 # Hybrid argument lemma, distinguishers, computational indistinguishability
├── mini-owf-vs-prg-equivalence/          # OWF⇔PRG equivalence (HILL), Yao's theorem, stretch
├── mini-pseudorandom-generators-crypto/  # BBS generator, Blum-Micali, hardcore LSB, next-bit unpredictability
├── mini-pseudorandom-functions-ggm/      # GGM PRF construction, PRG⇒PRF, binary tree evaluation
├── mini-minimal-assumptions/             # Impagliazzo's worlds, black-box separation, hardness amplification
├── mini-trapdoor-permutations/           # RSA TDP, key generation, PKE/signatures from TDP
├── .gitignore
├── README.md
└── README-CN.md
```

## License

MIT
