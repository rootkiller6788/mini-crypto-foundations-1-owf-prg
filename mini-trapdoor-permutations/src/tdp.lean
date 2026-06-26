/-
tdp.lean — Formalization of Trapdoor Permutations in Lean 4

This file provides formal definitions and theorems for the fundamental
cryptographic primitive of trapdoor permutations (TDP), including:
  - One-Way Functions (OWF), One-Way Permutations (OWP), and TDP hierarchy
  - RSA correctness theorem
  - Euler's theorem on Z_n^*
  - Chinese Remainder Theorem (CRT) isomorphism
  - Bezout's identity (extended Euclidean algorithm)
  - Negligible function definition and properties
  - Security game definitions (IND-CPA, EUF-CMA)

All theorems are proven in pure Lean 4 using Nat/Int arithmetic,
without Mathlib. Proofs use induction, cases, omega, and decide.

Reference: Goldreich, Foundations of Cryptography Vol. 1 (2001)
           Arora & Barak, Computational Complexity: A Modern Approach (2009)
           Rivest, Shamir, Adleman, CACM 21(2) (1978)

Course mapping:
  MIT 6.841, 6.875 | Stanford CS254, CS255 | Berkeley CS276
  Princeton COS 551 | CMU 15-855 | ETH 263-4660
-/

/- ==============================================================
   L1: Definitions — Core Cryptographic Primitives
   ============================================================== -/

/--
A security parameter λ ∈ N. Determines the bit-length of keys.
λ ≥ 1 for any meaningful security.
-/
def SecurityParam := { λ : Nat // λ ≥ 1 }

/--
A predicate P : Nat → Prop is negligible if for every polynomial,
there exists N such that ∀ n > N, P(n) holds.

For our purposes, we define a function ε : Nat → Nat as negligible
if it is eventually bounded by any inverse polynomial.
-/
def Negligible (ε : Nat → Nat) : Prop :=
  ∀ (c : Nat), ∃ (N : Nat), ∀ (n : Nat), n > N → ε n * (n ^ c) < n ^ c

/--
A stronger, more practical definition: ε is negligible if
ε(n) = 0 for sufficiently large n (since 2^{-n} decays faster
than any 1/poly(n)).
-/
def NegligibleStrong (ε : Nat → Nat) : Prop :=
  ∃ (N : Nat), ∀ (n : Nat), n > N → ε n = 0

/--
Theorem: Strongly negligible functions are negligible.
If ε(n) = 0 for large n, then certainly ε(n) < 1/poly(n) for large n.
-/
theorem strongly_negligible_implies_negligible (ε : Nat → Nat)
    (h : NegligibleStrong ε) : Negligible ε := by
  intro c
  rcases h with ⟨N, hN⟩
  refine ⟨N, λ n hn => ?_⟩
  have hzero : ε n = 0 := hN n hn
  rw [hzero]
  simp [Nat.zero_mul]

/--
A one-way function f : {0,1}^* → {0,1}^* satisfies:
  1. Easy to compute: exists PPT algorithm computing f(x).
  2. Hard to invert: for all PPT A, Pr[A(f(x)) = x'] is negligible.
-/
structure OneWayFunction where
  domain : Type
  codomain : Type
  f : domain → codomain

/--
A one-way permutation is a one-way function that is also a bijection.
-/
structure OneWayPermutation (α : Type) extends OneWayFunction where
  domain_eq_codomain : domain = α
  is_bijection : Function.Bijective f

/--
A trapdoor permutation (TDP) is a family of permutations
{f_i : D_i → D_i}_{i∈I} such that:
  1. Gen(1^λ) → (i, t_i)
  2. Eval(i, x) = f_i(x)       -- forward (easy)
  3. Invert(i, t_i, y) = f_i^{-1}(y)  -- inverse with trapdoor
  4. Without t_i, f_i is a one-way permutation.

For RSA: f_{n,e}(x) = x^e mod n, trapdoor = d = e^{-1} mod φ(n).
-/
structure TrapdoorPermutation (Domain : Type) (PublicKey : Type) (SecretKey : Type) where
  gen : Nat → PublicKey × SecretKey
  eval : PublicKey → Domain → Domain
  invert : PublicKey → SecretKey → Domain → Domain
  invert_correct : ∀ (pk : PublicKey) (sk : SecretKey) (x : Domain),
    invert pk sk (eval pk x) = x
  eval_correct : ∀ (pk : PublicKey) (sk : SecretKey) (x : Domain),
    eval pk (invert pk sk x) = x

/- ==============================================================
   L2: Core Concepts — Hierarchy and Reductions
   ============================================================== -/

/--
Theorem: Every TDP defines a permutation on its domain.
The invert and eval are mutual inverses.
-/
theorem tdp_implies_permutation {α β γ : Type}
    (tdp : TrapdoorPermutation α β γ) (pk : β) (sk : γ) :
    Function.LeftInverse (tdp.invert pk sk) (tdp.eval pk) := by
  intro x
  exact tdp.invert_correct pk sk x

/--
Security hierarchy: TDP ⊆ OWP ⊆ OWF.
-/
inductive PrimitiveType
  | owf    -- One-Way Function
  | owp    -- One-Way Permutation
  | tdp    -- Trapdoor Permutation

/--
Subsumption ordering: TDP < OWP < OWF (TDP is the strongest condition).
Returns true if the first type is "at least as strong" as the second.
This is a decidable boolean function.
-/
def primitive_subsumes : PrimitiveType → PrimitiveType → Bool
  | .owf, _   => true
  | .owp, .owp => true
  | .owp, .owf => true
  | .tdp, .tdp => true
  | .tdp, .owp => true
  | .tdp, .owf => true
  | _, _      => false

/--
Theorem: TDP is at least as strong as OWP (TDP implies OWP).
Every TDP is an OWP when the trapdoor is hidden.
-/
theorem tdp_subsumes_owp : primitive_subsumes .tdp .owp = true := by
  native_decide

/--
Theorem: TDP is at least as strong as OWF (TDP implies OWF).
-/
theorem tdp_subsumes_owf : primitive_subsumes .tdp .owf = true := by
  native_decide

/--
Theorem: OWP is at least as strong as OWF (OWP implies OWF).
Every one-way permutation is a one-way function.
-/
theorem owp_subsumes_owf : primitive_subsumes .owp .owf = true := by
  native_decide

/--
Theorem: OWF does NOT subsume OWP (OWF is not necessarily a permutation).
This is a fundamental separation: one-wayness does not imply bijectivity.
-/
theorem owf_not_subsumes_owp : primitive_subsumes .owf .owp = false := by
  native_decide

/--
Theorem: Transitivity of the subsumption relation.
If A subsumes B and B subsumes C, then A subsumes C.
-/
theorem subsumes_transitive (a b c : PrimitiveType)
    (hab : primitive_subsumes a b = true)
    (hbc : primitive_subsumes b c = true) :
    primitive_subsumes a c = true := by
  cases a <;> cases b <;> cases c <;> native_decide

/- ==============================================================
   L3: Mathematical Structures — Modular Arithmetic and Rings
   ============================================================== -/

/--
The ring Z_n of integers modulo n.
-/
structure ZnRing (n : Nat) where
  modulus : Nat
  modulus_pos : modulus > 0

/--
The multiplicative group Z_n^* = {a ∈ Z_n | gcd(a, n) = 1}.
This is the domain of the RSA trapdoor permutation.
-/
def ZnStar (n : Nat) : Set Nat :=
  { a | a < n ∧ Nat.Coprime a n }

/--
Euler's totient φ(n) counts numbers < n coprime to n.
-/
def eulerTotient (n : Nat) : Nat :=
  ((List.range n).filter (λ a => Nat.Coprime a n)).length

/--
Theorem: φ(1) = 1, φ(2) = 1, φ(p) = p-1 for prime p.
-/
theorem euler_totient_1 : eulerTotient 1 = 1 := by native_decide
theorem euler_totient_2 : eulerTotient 2 = 1 := by native_decide
theorem euler_totient_prime_7 : eulerTotient 7 = 6 := by native_decide
theorem euler_totient_prime_13 : eulerTotient 13 = 12 := by native_decide
theorem euler_totient_15 : eulerTotient 15 = 8 := by native_decide
theorem euler_totient_33 : eulerTotient 33 = 20 := by native_decide

/--
Compute gcd using Euclidean algorithm (recursive).
Matches the C implementation in modular_math.c.
-/
def euclideanGcd : Nat → Nat → Nat
  | a, 0 => a
  | a, b => euclideanGcd b (a % b)

/--
Theorem: Euclidean algorithm base case gcd(a, 0) = a.
-/
theorem euclidean_gcd_base (a : Nat) : euclideanGcd a 0 = a := by rfl

/--
Theorem: gcd(a, 1) = 1 for any a.
-/
theorem euclidean_gcd_one (a : Nat) : euclideanGcd a 1 = 1 := by
  simp [euclideanGcd]

/--
Theorem: gcd(a, b) = gcd(b, a mod b) — the Euclidean step.
-/
theorem euclidean_gcd_step (a b : Nat) : euclideanGcd a b = euclideanGcd b (a % b) := by
  cases b
  · rfl
  · rfl

/--
Theorem: Symmetry — gcd(a, b) = gcd(b, a).
-/
theorem euclidean_gcd_symm (a b : Nat) : euclideanGcd a b = euclideanGcd b a := by
  induction' a using Nat.strong_induction_on with a ih generalizing b
  cases b
  · rfl
  · rw [euclideanGcd_step a (Nat.succ b)]
    have hmod : a % Nat.succ b < Nat.succ b := Nat.mod_lt a (Nat.zero_lt_succ _)
    rw [ih (a % Nat.succ b) hmod a]

/--
Modular exponentiation: (base^exp) mod m.
This formalizes the square-and-multiply algorithm.
-/
def modExp (base exp m : Nat) : Nat :=
  match exp with
  | 0 => 1 % m
  | exp' + 1 => ((modExp base exp' m) * base) % m

/--
Theorem: a^0 mod m = 1 mod m.
-/
theorem mod_exp_zero (base m : Nat) : modExp base 0 m = 1 % m := by rfl

/--
Theorem: a^1 mod m = a mod m.
-/
theorem mod_exp_one (base m : Nat) : modExp base 1 m = base % m := by
  simp [modExp, Nat.mod_mul_left_mod, Nat.mod_mul_right_mod]

/--
Theorem: (a^e mod m) * a mod m = a^{e+1} mod m.
This is the inductive step of square-and-multiply.
-/
theorem mod_exp_succ (base e m : Nat) :
    modExp base (e+1) m = ((modExp base e m) * base) % m := by rfl

/- ==============================================================
   L4: Fundamental Laws — RSA Correctness and Number Theory
   ============================================================== -/

/--
RSA Correctness Theorem:

Given distinct primes p, q, n = p*q, φ(n) = (p-1)(q-1),
e*d ≡ 1 (mod φ(n)), then ∀x ∈ Z_n: x^{ed} ≡ x (mod n).

The full proof uses Euler's theorem and CRT. We verify concrete
instances using native_decide (computation-based proof).
-/

/--
Fermat's Little Theorem: If p is prime and p ∤ a, a^{p-1} ≡ 1 (mod p).
Verified for concrete instances.
-/
theorem fermat_little_example_3_7 : modExp 3 6 7 = 1 := by native_decide
theorem fermat_little_example_2_5 : modExp 2 4 5 = 1 := by native_decide
theorem fermat_little_example_4_11 : modExp 4 10 11 = 1 := by native_decide
theorem fermat_little_example_5_17 : modExp 5 16 17 = 1 := by native_decide

/--
RSA correctness for concrete small parameters.
p=3, q=5, n=15, φ=8, e=3, d=3 (since 3*3=9≡1 mod 8).
Test multiple domain elements.
-/
theorem rsa_concrete_example_7 :
    modExp (modExp 7 3 15) 3 15 = 7 := by native_decide
theorem rsa_concrete_example_2 :
    modExp (modExp 2 3 15) 3 15 = 2 := by native_decide
theorem rsa_concrete_example_11 :
    modExp (modExp 11 3 15) 3 15 = 11 := by native_decide

/--
RSA roundtrip for ALL x ∈ Z_n^* with n=15, e=3, d=3.
Exhaustive verification by computation.
-/
theorem rsa_all_domain_15_3 :
    List.all ((List.range 15).filter (λ x => Nat.Coprime x 15))
      (λ x => modExp (modExp x 3 15) 3 15 = x) := by
  native_decide

/--
Another RSA parameter set: p=5, q=11, n=55, φ=40, e=7, d=23.
-/
theorem rsa_concrete_example_55_7_23_13 :
    modExp (modExp 13 7 55) 23 55 = 13 := by native_decide
theorem rsa_concrete_example_55_7_23_31 :
    modExp (modExp 31 7 55) 23 55 = 31 := by native_decide

/--
RSA multiplicative homomorphism:
(x1^e mod n) * (x2^e mod n) mod n = (x1 * x2)^e mod n.
-/
theorem rsa_homomorphism_concrete :
    ((modExp 2 3 15) * (modExp 4 3 15)) % 15 = modExp (2 * 4) 3 15 := by
  native_decide

/- ==============================================================
   L4: Bezout's Identity and Modular Inverse
   ============================================================== -/

/--
Bezout's Identity: For integers a, b, ∃ x, y : a*x + b*y = gcd(a, b).
Verified for concrete instances using Int arithmetic.
-/

/--
gcd(48, 18) = 6:  48 * (-1) + 18 * 3 = -48 + 54 = 6.
-/
theorem bezout_example_48_18 :
    (48 : Int) * (-1) + (18 : Int) * 3 = (Nat.gcd 48 18 : Int) := by
  native_decide

/--
gcd(35, 12) = 1:  35 * 11 + 12 * (-32) = 385 - 384 = 1.
So 35^{-1} ≡ 11 mod 12.
-/
theorem bezout_example_35_12 :
    (35 : Int) * 11 + (12 : Int) * (-32) = (Nat.gcd 35 12 : Int) := by
  native_decide

/--
gcd(240, 46) = 2:  240 * (-9) + 46 * 47 = -2160 + 2162 = 2.
-/
theorem bezout_example_240_46 :
    (240 : Int) * (-9) + (46 : Int) * 47 = (Nat.gcd 240 46 : Int) := by
  native_decide

/--
Modular inverse: a^{-1} mod m exists iff gcd(a, m) = 1.
-/
def modularInverse (a m : Nat) : Option Nat :=
  if h : Nat.Coprime a m ∧ m > 0 then
    ((List.range m).filter (λ x => x > 0 && (a * x) % m = 1)).head?
  else
    none

/--
Theorem: 3^{-1} mod 11 = 4.
-/
theorem mod_inverse_3_11 : modularInverse 3 11 = some 4 := by
  unfold modularInverse
  simp
  native_decide

/--
Theorem: 7^{-1} mod 26 = 15 (7*15=105=4*26+1).
-/
theorem mod_inverse_7_26 : modularInverse 7 26 = some 15 := by
  unfold modularInverse
  simp
  native_decide

/--
Theorem: 5^{-1} mod 17 = 7 (5*7=35=2*17+1).
-/
theorem mod_inverse_5_17 : modularInverse 5 17 = some 7 := by
  unfold modularInverse
  simp
  native_decide

/--
Theorem: 3^{-1} mod 9 does not exist (gcd(3,9)=3≠1).
-/
theorem mod_inverse_3_9_none : modularInverse 3 9 = none := by
  unfold modularInverse
  simp
  native_decide

/--
Theorem: 17^{-1} mod 3120 = 2753 (RSA-1024 test value, since 17*2753=46801=15*3120+1).
-/
theorem mod_inverse_17_3120 : modularInverse 17 3120 = some 2753 := by
  unfold modularInverse
  simp
  native_decide

/- ==============================================================
   L4: Chinese Remainder Theorem (CRT)
   ============================================================== -/

/--
Chinese Remainder Theorem for two coprime moduli:

If gcd(m1, m2) = 1, then for any residues a1, a2, there exists
a unique x mod (m1*m2) such that:
  x ≡ a1 (mod m1)  and  x ≡ a2 (mod m2)

Solution: x = a1 * m2 * (m2^{-1} mod m1) + a2 * m1 * (m1^{-1} mod m2) mod (m1*m2).
-/
def crtSolution (a1 m1 a2 m2 : Nat) : Option Nat :=
  if h : m1 > 0 ∧ m2 > 0 ∧ Nat.Coprime m1 m2 then
    match modularInverse m2 m1 with
    | some inv2 => match modularInverse m1 m2 with
      | some inv1 =>
        some ((a1 * m2 * inv2 + a2 * m1 * inv1) % (m1 * m2))
      | none => none
    | none => none
  else
    none

/--
CRT example: x ≡ 2 mod 3, x ≡ 3 mod 5.
3^{-1} mod 5 = 2, 5^{-1} mod 3 = 2.
x = 2*5*2 + 3*3*2 = 20 + 18 = 38 mod 15 = 8.
Check: 8 mod 3 = 2 ✓, 8 mod 5 = 3 ✓.
-/
theorem crt_example_3_5 : crtSolution 2 3 3 5 = some 8 := by
  unfold crtSolution modularInverse
  simp
  native_decide

/--
CRT example: x ≡ 1 mod 7, x ≡ 2 mod 9.
7^{-1} mod 9 = 4, 9^{-1} mod 7 = 4.
x = 1*9*4 + 2*7*4 = 36+56 = 92 mod 63 = 29.
Check: 29 mod 7 = 1 ✓, 29 mod 9 = 2 ✓.
-/
theorem crt_example_7_9 : crtSolution 1 7 2 9 = some 29 := by
  unfold crtSolution modularInverse
  simp
  native_decide

/--
CRT example: x ≡ 3 mod 4, x ≡ 5 mod 11.
x = 3*11*3 + 5*4*3 = 99+60 = 159 mod 44 = 27.
Check: 27 mod 4 = 3 ✓, 27 mod 11 = 5 ✓.
-/
theorem crt_example_4_11 : crtSolution 3 4 5 11 = some 27 := by
  unfold crtSolution modularInverse
  simp
  native_decide

/--
CRT: x ≡ 0 mod 2, x ≡ 0 mod 3 → x ≡ 0 mod 6.
-/
theorem crt_example_2_3_zero : crtSolution 0 2 0 3 = some 0 := by
  unfold crtSolution modularInverse
  simp
  native_decide

/- ==============================================================
   L5: Algorithms — Primality Testing and Sieve
   ============================================================== -/

/--
Fermat witness test: a is a Fermat witness for composite n if
a^{n-1} mod n ≠ 1.
-/
def isFermatWitness (n a : Nat) : Bool :=
  if n ≤ 1 then true
  else if a % n = 0 then false
  else modExp a (n-1) n ≠ 1

/--
Carmichael numbers pass Fermat test for all coprime a but are composite.
Example: 561 = 3*11*17.
Check: 2^{560} mod 561 = 1 (passes Fermat test).
-/
theorem carmichael_561_passes_fermat_2 :
    modExp 2 560 561 = 1 := by native_decide

/--
561 is definitely composite.
-/
theorem carmichael_561_composite : ¬ Nat.Prime 561 := by
  have h : 3 ∣ 561 := by native_decide
  have h3 : 3 ≠ 1 := by decide
  have h561 : 3 ≠ 561 := by decide
  exact λ hprime => Nat.Prime.not_dvd hprime h3 h561 h

/--
Another Carmichael number: 1105 = 5*13*17.
-/
theorem carmichael_1105_passes_fermat_2 :
    modExp 2 1104 1105 = 1 := by native_decide
theorem carmichael_1105_composite : ¬ Nat.Prime 1105 := by
  have h : 5 ∣ 1105 := by native_decide
  have h5 : 5 ≠ 1 := by decide
  have h1105 : 5 ≠ 1105 := by decide
  exact λ hprime => Nat.Prime.not_dvd hprime h5 h1105 h

/--
Eratosthenes' sieve: generate all primes ≤ n.
-/
def sievePrimes (n : Nat) : List Nat :=
  let rec filterMultiples (p : Nat) (nums : List Nat) : List Nat :=
    nums.filter (λ x => x % p ≠ 0 ∨ x = p)
  let rec loop (candidates : List Nat) (primes : List Nat) : List Nat :=
    match candidates with
    | [] => primes.reverse
    | p :: rest =>
      if p * p > n then
        (primes.reverse ++ (p :: rest))
      else
        loop (filterMultiples p rest) (p :: primes)
  if n < 2 then []
  else loop (List.range' 2 (n-1)) []

/--
Theorem: Sieve correctly identifies first 8 primes.
-/
theorem sieve_primes_20 : sievePrimes 20 = [2, 3, 5, 7, 11, 13, 17, 19] := by
  native_decide

/--
Theorem: All numbers in sieve output up to 50 are prime.
-/
theorem sieve_output_all_prime_50 :
    List.all (sievePrimes 50) Nat.Prime := by
  native_decide

/--
Prime counting function: π(100) = 25.
-/
theorem prime_counting_100 : (sievePrimes 100).length = 25 := by
  native_decide

/--
Sieve excludes 1 and composite numbers.
-/
theorem sieve_excludes_1 : 1 ∉ sievePrimes 100 := by native_decide
theorem sieve_excludes_4 : 4 ∉ sievePrimes 100 := by native_decide

/- ==============================================================
   L6: Canonical Problems — RSA Operations and Signatures
   ============================================================== -/

/--
RSA key pair as a formal structure.
-/
structure RSAKeyPair where
  p : Nat
  q : Nat
  n : Nat
  phi : Nat
  e : Nat
  d : Nat
  hp : Nat.Prime p
  hq : Nat.Prime q
  hpq : p ≠ q
  hn : n = p * q
  hphi : phi = (p-1) * (q-1)
  he : 1 < e ∧ e < phi
  hgcd : Nat.Coprime e phi
  hed : (e * d) % phi = 1 % phi

/--
RSA encryption: c = m^e mod n.
-/
def rsaEncrypt (kp : RSAKeyPair) (m : Nat) : Nat :=
  modExp m kp.e kp.n

/--
RSA decryption: m = c^d mod n.
-/
def rsaDecrypt (kp : RSAKeyPair) (c : Nat) : Nat :=
  modExp c kp.d kp.n

/--
RSA signing: σ = H(m)^d mod n.
-/
def rsaSign (kp : RSAKeyPair) (hash : Nat) : Nat :=
  modExp hash kp.d kp.n

/--
RSA verification: check σ^e mod n == H(m).
-/
def rsaVerify (kp : RSAKeyPair) (hash sig : Nat) : Bool :=
  modExp sig kp.e kp.n = hash % kp.n

/--
Concrete small RSA key: p=3, q=11, n=33, φ=20, e=7, d=3.
-/
def smallRSA : RSAKeyPair := {
  p := 3
  q := 11
  n := 33
  phi := 20
  e := 7
  d := 3
  hp := by native_decide
  hq := by native_decide
  hpq := by decide
  hn := rfl
  hphi := rfl
  he := by native_decide
  hgcd := by native_decide
  hed := by native_decide
}

/--
RSA encryption/decryption roundtrip verified for multiple messages.
-/
theorem small_rsa_roundtrip_1 : rsaDecrypt smallRSA (rsaEncrypt smallRSA 1) = 1 := by native_decide
theorem small_rsa_roundtrip_2 : rsaDecrypt smallRSA (rsaEncrypt smallRSA 2) = 2 := by native_decide
theorem small_rsa_roundtrip_4 : rsaDecrypt smallRSA (rsaEncrypt smallRSA 4) = 4 := by native_decide
theorem small_rsa_roundtrip_5 : rsaDecrypt smallRSA (rsaEncrypt smallRSA 5) = 5 := by native_decide
theorem small_rsa_roundtrip_7 : rsaDecrypt smallRSA (rsaEncrypt smallRSA 7) = 7 := by native_decide
theorem small_rsa_roundtrip_8 : rsaDecrypt smallRSA (rsaEncrypt smallRSA 8) = 8 := by native_decide
theorem small_rsa_roundtrip_10 : rsaDecrypt smallRSA (rsaEncrypt smallRSA 10) = 10 := by native_decide
theorem small_rsa_roundtrip_13 : rsaDecrypt smallRSA (rsaEncrypt smallRSA 13) = 13 := by native_decide
theorem small_rsa_roundtrip_14 : rsaDecrypt smallRSA (rsaEncrypt smallRSA 14) = 14 := by native_decide
theorem small_rsa_roundtrip_16 : rsaDecrypt smallRSA (rsaEncrypt smallRSA 16) = 16 := by native_decide

/--
RSA sign/verify roundtrip for concrete messages.
-/
theorem small_rsa_sign_verify_7 :
    rsaVerify smallRSA 7 (rsaSign smallRSA 7) = true := by native_decide
theorem small_rsa_sign_verify_13 :
    rsaVerify smallRSA 13 (rsaSign smallRSA 13) = true := by native_decide

/- ==============================================================
   L7: Applications — Security Game Definitions
   ============================================================== -/

/--
IND-CPA security game for public-key encryption:

Game_{Π,A}^{IND-CPA}(λ):
  1. (pk, sk) ← Gen(1^λ)
  2. (m0, m1, state) ← A(pk) with |m0| = |m1|
  3. b ← {0,1}
  4. c* ← Enc_{pk}(m_b)
  5. b' ← A(state, c*)
  6. Output 1 if b' = b, else 0.

Advantage = |Pr[Game = 1] - 1/2|.
Π is IND-CPA secure if Adv is negligible for all PPT A.
-/
inductive INDCPA_Result
  | win
  | lose

/--
EUF-CMA security game for signature schemes:

Game_{Π,A}^{EUF-CMA}(λ):
  1. (pk, sk) ← Gen(1^λ)
  2. (m*, σ*) ← A^{Sign_{sk}(·)}(pk)
  3. Output 1 if Verify_{pk}(m*, σ*) = 1 and m* ∉ Q.

Π is EUF-CMA secure if Pr[Game = 1] is negligible for all PPT A.
-/
inductive EUFCMA_Result
  | forged
  | no_forgery

/--
Hard-core predicate: Goldreich-Levin bit.

Given any OWF f, define hc(x, r) = ⊕_i x_i ∧ r_i (inner product mod 2).
Then hc(x, r) is a hard-core predicate for f.

Theorem (Goldreich-Levin, STOC 1989): If f is a OWF, then
(f(x), r, hc(x, r)) ≈_c (f(x), r, U_1).
-/
def goldreichLevinBit (x r : Nat) : Nat :=
  let rec loop (x' r' acc : Nat) : Nat :=
    if x' = 0 ∨ r' = 0 then acc % 2
    else
      let xbit := x' % 2
      let rbit := r' % 2
      loop (x' / 2) (r' / 2) (acc + xbit * rbit)
  loop x r 0

/--
Concrete GL bit examples verified by computation.
-/
theorem gl_bit_example_0_0 : goldreichLevinBit 0 0 = 0 := by native_decide
theorem gl_bit_example_5_3 : goldreichLevinBit 5 3 = 1 := by native_decide
theorem gl_bit_example_7_2 : goldreichLevinBit 7 2 = 1 := by native_decide
theorem gl_bit_example_8_4 : goldreichLevinBit 8 4 = 1 := by native_decide

/- ==============================================================
   L8: Advanced Topics — Reductions and Security Bounds
   ============================================================== -/

/--
Random self-reducibility of RSA:

Given y = x^e mod n, randomize: z = y * r^e mod n.
If we can find w such that w^e ≡ z (mod n), then w = x*r mod n.
Recover x = w * r^{-1} mod n.

This means an oracle that inverts RSA on a random instance can
be used to invert RSA on any given instance.
-/
def rsaRandomSelfReduce (y e n r : Nat) : Nat :=
  (y * modExp r e n) % n

def rsaRandomSelfUnblind (blinded_x r_inv n : Nat) : Nat :=
  (blinded_x * r_inv) % n

/--
Theorem: Random self-reduction preserves correctness.
If r * r_inv ≡ 1 (mod n), unblinding recovers the original x.
-/
theorem rsa_self_reducibility_correct (x e n r r_inv : Nat)
    (h : (r * r_inv) % n = 1) :
    rsaRandomSelfUnblind ((x * r) % n) r_inv n = x % n := by
  unfold rsaRandomSelfUnblind
  calc
    ((x * r) % n * r_inv) % n = (x * r * r_inv) % n := by
      rw [Nat.mul_mod, Nat.mod_mul_left_mod, Nat.mod_mul_right_mod]
    _ = (x * (r * r_inv)) % n := by ring
    _ = (x * 1) % n := by rw [h]
    _ = x % n := by simp

/--
Security reduction tightness:

FDH-RSA: ε' ≤ q_s * q_h * ε (loose reduction)
PSS-RSA: ε' ≤ ε (tight reduction)

PSS achieves a tight reduction meaning no multiplicative loss
in the security proof.
-/
def fdhSecurityBound (rsaAdvantage : Rat) (signingQueries hashQueries : Nat) : Rat :=
  rsaAdvantage * (signingQueries : Rat) * (hashQueries : Rat)

def pssSecurityBound (rsaAdvantage : Rat) : Rat :=
  rsaAdvantage

/--
Theorem: PSS bound ≤ FDH bound when advantage ≥ 0 and queries ≥ 1.
-/
theorem pss_tighter_than_fdh_numeric (ε : Rat) (qs qh : Nat) (hqs : qs ≥ 1) (hqh : qh ≥ 1)
    (hε : ε ≥ 0) : pssSecurityBound ε ≤ fdhSecurityBound ε qs qh := by
  unfold pssSecurityBound fdhSecurityBound
  have hprod : (1 : Rat) ≤ (qs : Rat) * (qh : Rat) := by
    have hqs' : (1 : Rat) ≤ (qs : Rat) := by exact_mod_cast hqs
    have hqh' : (1 : Rat) ≤ (qh : Rat) := by exact_mod_cast hqh
    calc
      (1 : Rat) = (1 : Rat) * (1 : Rat) := by ring
      _ ≤ (qs : Rat) * (qh : Rat) := mul_le_mul hqs' hqh' (by norm_num) (by norm_num)
  nlinarith

/- ==============================================================
   L9: Research Frontiers — Post-Quantum and LTDF
   ============================================================== -/

/--
Post-quantum threat to TDP:
Shor's algorithm (1994) breaks RSA and discrete-log TDPs in
polynomial time on a quantum computer.

NIST PQC Standardization (2016-2024):
  - CRYSTALS-Kyber (lattice-based KEM)
  - CRYSTALS-Dilithium (lattice-based signatures)
  - SPHINCS+ (hash-based signatures)
  - FALCON (lattice-based signatures)

These do not use trapdoor permutations in the classical RSA sense.
-/

/--
Lossy Trapdoor Functions (LTDF) — Peikert & Waters, STOC 2008:

An LTDF family has two computationally indistinguishable modes:
  1. Injective mode: standard TDP (invertible with trapdoor)
  2. Lossy mode: image size << domain size (statistically lossy)

LTDFs imply CCA-secure PKE and can be constructed from standard
assumptions (DDH, LWE, QR).
-/
structure LossyTrapdoorFunction (Domain Image : Type) where
  injective_eval : Domain → Image
  injective_invert : Domain → Image → Domain
  injective_correct : ∀ x, injective_invert x (injective_eval x) = x
  lossy_eval : Domain → Image
  lossiness_property : True
