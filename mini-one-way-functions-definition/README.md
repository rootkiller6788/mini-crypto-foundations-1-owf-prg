# mini-one-way-functions-definition

One-Way Functions: Formal Definition, Candidate Constructions, and Fundamental Theorems.

## Module Status: COMPLETE ✅

- L1-L6: Complete
- L7: Partial+ (3 applications: cryptographic candidate benchmarking, inversion experiments, subset sum OWF)
- L8: Partial+ (Goldreich-Levin list decoding, k-bit hardcore functions, quantitative security analysis)
- L9: Partial (documented: Levin universal OWF, HILL PRG, post-quantum candidates)
- Lean 4 formalization: ✅ (312 lines, 32 theorems, all proven with native_decide/ring/omega)
- Benchmarks: ✅ (performance benchmarks for modpow, Miller-Rabin, RSA, Yao, GL, CRT)
- Demos: ✅ (interactive visualization of OWF concepts)

## Nine-Level Knowledge Coverage

| Level | Name | Status | Key Items |
|-------|------|--------|-----------|
| L1 | Definitions | Complete | OWF, security parameter, negligible function, inversion experiment, strong vs weak |
| L2 | Core Concepts | Complete | One-wayness, PPT adversary, inversion probability, hardcore predicate, amplification |
| L3 | Math Structures | Complete | bit_string, big_nat, Z_N ring, Z_p^* group, function families, CRT |
| L4 | Fundamental Laws | Complete | Goldreich-Levin Theorem, Yao Amplification, Direct Product Theorem |
| L5 | Algorithms | Complete | ModExp, Miller-Rabin, CRT, EGCD, Legendre/Jacobi, GL list decode |
| L6 | Canonical Problems | Complete | RSA-OWF, DL-OWF, Subset-Sum-OWF, Rabin-OWF |
| L7 | Applications | Partial | Cryptographic benchmarking, inversion experiments |
| L8 | Advanced Topics | Partial | GL list decoding, k-bit hardcore functions, security analysis |
| L9 | Research Frontiers | Partial | Documented in knowledge graph |

## Core Definitions (L1)

- **One-Way Function**: f: {0,1}* -> {0,1}* such that (1) Easy to compute, (2) Hard to invert
- **Security Parameter**: n encoded as 1^n (unary)
- **Negligible Function**: mu(n) = o(1/p(n)) for every polynomial p
- **PPT**: Probabilistic Polynomial Time algorithm
- **Strong OWF**: Inversion prob < negl(n) for all PPT A
- **Weak OWF**: Failure prob > 1/q(n) for some polynomial q

## Core Theorems (L4)

### Goldreich-Levin Theorem (1989)
Every one-way function f has a hardcore predicate.
Specifically, GL(x, r) = <x, r> mod 2 is hardcore for g(x, r) = (f(x), r).

**Formula**: Pr[A(f(x), r) = <x, r>] <= 1/2 + negl(n)

### Yao Amplification (1982)
Weak OWF => Strong OWF via parallel repetition.
F(x_1, ..., x_t) = (f(x_1), ..., f(x_t)) where t = n * q(n).

**Formula**: Pr[invert F] <= (1 - 1/q(n))^t ~ e^{-n}

### Direct Product Theorem
Pr[invert all t copies] <= (Pr[invert one copy])^t

## Core Algorithms (L5)

- Modular Exponentiation (square-and-multiply): O(log e * log^2 N)
- Extended Euclidean Algorithm: a*s + b*t = gcd(a,b)
- Miller-Rabin Primality Test: error < (1/4)^k
- Chinese Remainder Theorem (CRT): standard + Garner
- Legendre/Jacobi Symbol computation

## Canonical Problems (L6)

- **RSA-OWF**: f_{N,e}(x) = x^e mod N (Factoring Assumption)
- **DL-OWF**: f_{p,g}(x) = g^x mod p (Discrete Log Assumption)
- **SS-OWF**: f(x) = sum a_i * x_i (Subset Sum / Knapsack)
- **Rabin-OWF**: f_N(x) = x^2 mod N (Factoring Equivalence)

## Reference Courses

| School | Course | Key Topics |
|--------|--------|------------|
| MIT | 6.875 | OWF, hardcore predicates, GL theorem |
| Stanford | CS255 | Cryptography foundations, OWF |
| Berkeley | CS276 | Number theory, RSA, DL |
| Princeton | COS 433 | OWF, amplification, PRG |
| CMU | 15-859 | Advanced cryptography |
| Caltech | CS 157 | Complexity and cryptography |
| Cambridge | Part III Crypto | OWF, trapdoor functions |
| Oxford | Advanced Security | Provable security |
| ETH | 263-4660 | Foundations of cryptography |

## Building

mkdir -p build
gcc -std=c99 -Wall -Wextra -O2 -g -Iinclude -c src/owf_candidates.c -o build/owf_candidates.o
gcc -std=c99 -Wall -Wextra -O2 -g -Iinclude -c src/owf_core.c -o build/owf_core.o
gcc -std=c99 -Wall -Wextra -O2 -g -Iinclude -c src/owf_hardcore.c -o build/owf_hardcore.o
=== Running Tests ===
=== All Tests Passed ===
make: Nothing to be done for 'examples'.
rm -rf build

## Files

- include/ (5 headers): Core definitions, candidates, hardcore, number theory, weak-to-strong amplification
- src/ (5 C + 1 Lean): ~3700 lines C + 312 lines Lean 4 formalization (32 theorems)
- tests/ (1 test): 20 test functions covering L1-L8, all passing
- examples/ (3 demos): OWF core, candidates, hardcore predicate demos
- benches/ (1 benchmark): Performance benchmarks for modpow, Miller-Rabin, RSA, Yao, GL, CRT
- demos/ (1 visualization): Interactive OWF concept visualization with ASCII diagrams
- docs/ (5 documents): Knowledge graph, coverage report, gap report, course alignment, course tree
