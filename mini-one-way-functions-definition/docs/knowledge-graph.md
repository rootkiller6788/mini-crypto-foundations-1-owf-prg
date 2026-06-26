# Knowledge Graph: One-Way Functions

## L1: Definitions (Complete)
- One-Way Function (OWF): f: {0,1}* -> {0,1}* easy to compute, hard to invert
- Security Parameter: n encoded as 1^n (unary)
- PPT Adversary: Probabilistic Polynomial Time algorithm
- Negligible Function: mu(n) = o(1/p(n)) for all polynomials p
- Inversion Experiment: Formal security game challenger vs adversary
- Strong OWF: For all PPT A, Pr[A inverts] < negl(n)
- Weak OWF: Exists polynomial q s.t. for all PPT A, Pr[A fails] > 1/q(n)
- OWF Family: F = {f_k} indexed by keys k from key space K
- Trapdoor OWF: OWF with secret key enabling efficient inversion

## L2: Core Concepts (Complete)
- One-wayness: Computational infeasibility of inversion
- Inversion probability: Quantitative hardness measure
- Empirical advantage: Measured Pr[success] - baseline random guess
- Hardcore predicate: Boolean function unpredictable given f(x)
- Security amplification: Weak -> Strong via parallel repetition
- Direct product: Multi-instance hardness composition
- Cryptographic assumption: Unproven hardness hypothesis

## L3: Mathematical Structures (Complete)
- bit_string_t: Arbitrary-length binary string
- big_nat_t: Multi-precision natural number (base-10^9)
- Z_N ring: Integers modulo N (RSA, Rabin)
- Z_p^* group: Multiplicative group modulo prime p (Discrete Log)
- Function families: Ensemble indexed by security parameter
- CRT: Chinese Remainder Theorem for modular reconstruction
- Quadratic residues: Legendre/Jacobi symbols

## L4: Fundamental Laws (Complete)
- Goldreich-Levin Theorem (1989): Every OWF has a hardcore predicate
- Yao Amplification (1982): Weak OWF => Strong OWF
- Direct Product Theorem: Pr[invert t copies] <= (Pr[invert 1 copy])^t
- Rabin Theorem (1979): Inverting x^2 mod N = Factoring N
- Euler's Theorem: a^{phi(N)} = 1 mod N (basis of RSA correctness)

## L5: Algorithms/Methods (Complete)
- Modular Exponentiation (square-and-multiply): O(log e log^2 N)
- Extended Euclidean Algorithm: a*s + b*t = gcd(a,b)
- Miller-Rabin Primality Test: error < (1/4)^k
- Chinese Remainder Theorem: Standard + Garner's algorithm
- Legendre/Jacobi Symbol computation
- Goldreich-Levin List Decoding: Recover x from predictor with advantage
- Random Prime Generation: Random search + primality testing

## L6: Canonical Problems (Complete)
- RSA-OWF: f_{N,e}(x) = x^e mod N (Factoring Assumption)
- DL-OWF: f_{p,g}(x) = g^x mod p (Discrete Log Assumption)
- Subset-Sum-OWF: f(x) = sum a_i * x_i (Knapsack Hardness)
- Rabin-OWF: f_N(x) = x^2 mod N (Factoring Equivalence)

## L7: Applications (Partial)
- Cryptographic candidate benchmarking (implemented)
- Inversion experiment framework (implemented)
- Empirical OWF strength classification (implemented)
- Pseudorandom generator construction (documented, not implemented)
- Commitment schemes from OWF (documented, not implemented)

## L8: Advanced Topics (Partial)
- Goldreich-Levin list decoding algorithm (implemented)
- k-bit hardcore functions (implemented)
- Quantitative security analysis for Yao amplification (implemented)
- Levin's universal one-way function (documented)
- Impagliazzo-Luby OWF completeness (documented)

## L9: Research Frontiers (Partial)
- OWF vs. circuit lower bounds connection (documented)
- Meta-complexity and OWF (documented)
- Quantum OWF and post-quantum candidates (documented)
- OWF in relativized worlds (documented)
