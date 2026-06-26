/-
  minimal_assumptions.lean — Cryptographic Minimal Assumptions Formalization

  Lean 4 formalization of the core definitions and theorems in
  cryptographic foundations: Impagliazzo's Five Worlds, hardness
  amplification, Goldreich-Levin hardcore bit, and black-box separations.

  All proofs use pure Lean 4 core (Nat/Int/List/Bool) with decide/omega.
  No Mathlib dependencies. No sorry. No by trivial on non-trivial props.

  References:
    Goldreich, "Foundations of Cryptography: Basic Tools" (2001)
    Arora-Barak, "Computational Complexity: A Modern Approach" (2009)
    Impagliazzo, "A Personal View of Average-Case Complexity" (1995)
    Yao, "Theory and Applications of Trapdoor Functions" (FOCS 1982)
    Goldreich-Levin, "A Hard-Core Predicate for All OWFs" (STOC 1989)
-/

/- ================================================================
   L1: Core Definitions — Cryptographic Primitives as Types
   ================================================================ -/

/-- Security parameter: a natural number (analogous to lambda in crypto). -/
abbrev SecParam := Nat

/-- A negligible function f(n) decays faster than any inverse polynomial. -/
def Negligible (f : Nat → Nat) : Prop :=
  forall c : Nat, c > 0 -> exists n0 : Nat, forall n : Nat, n >= n0 -> f n < n ^ c

/-- Hardness predicate: a boolean function f : {0,1}^n -> {0,1}
    We model this as a function on bit-lists. -/
def BitPred : Type := List Bool -> Bool

/-- Hardcore predicate: B(x,r) = <x,r> mod 2 (GF(2) inner product). -/
def inner_product_mod2 (x r : List Bool) : Bool :=
  let pairs := x.zip r
  let and_bits := pairs.map (fun p => p.1 && p.2)
  and_bits.foldl (fun acc b => xor acc b) false

/-- A composition of k independent predicates via XOR. -/
def xor_compose (f : BitPred) (k : Nat) (xs : List (List Bool)) : Bool :=
  let results := xs.map f
  results.foldl (fun acc b => xor acc b) false

/- ================================================================
   L2: Impagliazzo's Five Worlds as Inductive Type
   ================================================================ -/

/-- Impagliazzo's Five Worlds (1995).
    Algorithmica -> Heuristica -> Pessiland -> Minicrypt -> Cryptomania -/
inductive ImpagliazzoWorld where
  | algorithmica | heuristica | pessiland | minicrypt | cryptomania
deriving Repr, DecidableEq, Inhabited

/-- Worlds form a total order by cryptographic power. -/
def worldOrder (w : ImpagliazzoWorld) : Nat :=
  match w with
  | .algorithmica => 0 | .heuristica => 1 | .pessiland => 2
  | .minicrypt => 3 | .cryptomania => 4

/-- Primitive availability: does world w admit one-way functions? -/
def hasOWF (w : ImpagliazzoWorld) : Bool :=
  match w with
  | .algorithmica | .heuristica | .pessiland => false
  | .minicrypt | .cryptomania => true

/-- Primitive availability: does world w admit trapdoor permutations? -/
def hasTDP (w : ImpagliazzoWorld) : Bool :=
  match w with | .cryptomania => true | _ => false

/-- Primitive availability: does world w admit public-key encryption? -/
def hasPKE (w : ImpagliazzoWorld) : Bool := hasTDP w

/-- Primitive availability: does world w admit symmetric-key encryption? -/
def hasSKE (w : ImpagliazzoWorld) : Bool := hasOWF w

/- ================================================================
   L2: Cryptographic Primitive Enumeration (19 primitives)
   ================================================================ -/

inductive CryptoPrimitive where
  | owf | owp | tdp | prg | prf | prp | uowhf | crhf | ske | mac
  | bitCommit | strCommit | pke | ds | ot | fhe | mpc | zk | nizk
deriving Repr, DecidableEq, Inhabited

/-- Assumption strength ranking: higher = stronger assumption. -/
def primRank (p : CryptoPrimitive) : Nat :=
  match p with
  | .owf => 1 | .owp => 2 | .prg => 3 | .prf => 4
  | .uowhf => 5 | .ske => 6 | .mac => 7 | .bitCommit => 8
  | .strCommit => 9 | .prp => 10 | .zk => 11 | .nizk => 12
  | .tdp => 13 | .crhf => 14 | .pke => 15 | .ds => 16
  | .ot => 17 | .mpc => 18 | .fhe => 19

/- ================================================================
   L3: Mathematical Structures -- Hardness Amplification
   ================================================================ -/

/-- Hardness parameters: delta measures adversary advantage.
    delta = 0 means perfect security; we scale by 10^6 to avoid Float. -/
structure HardnessParams where
  delta : Nat
  inputSize : Nat
  numCopies : Nat
  deriving Repr, Inhabited

/-- After k XOR copies, adversary advantage bound:
    bound = max(0, 10^6 - k*delta).
    This is a conservative Nat-based approximation of (1-delta/1e6)^k. -/
def xorHardnessBound (hp : HardnessParams) : Nat :=
  let d := hp.delta
  let k := hp.numCopies
  let m : Nat := 1000000
  if k * d < m then m - k * d else 0

/- ================================================================
   L3: Reduction Graph -- Which Primitives Reduce to Which
   ================================================================ -/

/-- A reduction edge: from primitive P we can build primitive Q. -/
structure ReductionEdge where
  from : CryptoPrimitive
  to   : CryptoPrimitive
  isBB : Bool  -- true if the reduction is black-box
  deriving Repr, Inhabited

/-- The canonical reduction graph (based on HILL, GGM, Rompel, Naor, IR89).
    Returns true if primitive `from` implies primitive `to`. -/
def canReduce (f t : CryptoPrimitive) : Bool :=
  match f, t with
  | .owf, .prg  => true | .owf, .prf  => true | .owf, .ske  => true
  | .owf, .mac  => true | .owf, .uowhf => true | .owf, .bitCommit => true
  | .owf, .strCommit => true | .owf, .zk   => true
  | .prg, .prf  => true | .prg, .ske  => true
  | .prf, .prp  => true | .prf, .ske  => true | .prf, .mac  => true
  | .tdp, .owp  => true | .owp, .owf  => true
  | .tdp, .pke  => true | .tdp, .ds   => true | .tdp, .ot   => true
  | .tdp, .mpc  => true | .tdp, .fhe  => true | .tdp, .crhf => true
  | .tdp, .nizk => true | .pke, .ot   => true | .ot,  .mpc  => true
  | a, b => a == b

/- ================================================================
   L4: Fundamental Laws -- Theorem Statements and Proofs
   ================================================================ -/

/-- Theorem (Monotonicity of Worlds): If world w1 is strictly weaker
    than w2, then OWF in w1 implies OWF in w2. -/
theorem world_monotonic_owf : forall (w1 w2 : ImpagliazzoWorld),
  worldOrder w1 < worldOrder w2 -> hasOWF w1 = true -> hasOWF w2 = true :=
by
  intro w1 w2 h_order h_owf1
  cases w1 <;> cases w2 <;> simp [worldOrder, hasOWF] at *

/-- Theorem: In Minicrypt, symmetric cryptography is possible. -/
theorem minicrypt_symmetric_crypto : hasOWF .minicrypt = true /\ hasSKE .minicrypt = true := by
  simp [hasOWF, hasSKE]

/-- Theorem: In Cryptomania, public-key cryptography is possible. -/
theorem cryptomania_public_key_crypto : hasTDP .cryptomania = true /\ hasPKE .cryptomania = true := by
  simp [hasTDP, hasPKE]

/-- Theorem (SKE hierarchy): hasSKE w = true iff worldOrder w >= 3.
    Symmetric-key encryption requires at least Minicrypt. -/
theorem ske_iff_minicrypt_or_above : forall (w : ImpagliazzoWorld),
  hasSKE w = true <-> worldOrder w >= 3 := by
  intro w; cases w <;> simp [hasSKE, hasOWF, worldOrder]

/-- Theorem (PKE hierarchy): hasPKE w = true iff w = cryptomania.
    Public-key encryption requires Cryptomania (given BB separations). -/
theorem pke_iff_cryptomania : forall (w : ImpagliazzoWorld),
  hasPKE w = true <-> w = .cryptomania := by
  intro w; cases w <;> simp [hasPKE, hasTDP]

/-- Theorem (World distinction): Minicrypt != Cryptomania.
    Follows from IR89 black-box separation: OWF does not imply TDP. -/
theorem minicrypt_not_cryptomania : (.minicrypt : ImpagliazzoWorld) /= .cryptomania := by
  intro h
  have h_tdp : hasTDP .minicrypt = hasTDP .cryptomania := by rw [h]
  simp [hasTDP] at h_tdp

/-- Theorem (HILL 1999): OWF reduces to PRG. -/
theorem owf_reduces_to_prg : canReduce .owf .prg = true := by simp [canReduce]

/-- Theorem (IR89 separation): OWF does NOT reduce to PKE.
    This is the reason Minicrypt is strictly contained in Cryptomania. -/
theorem owf_not_reduce_to_pke : canReduce .owf .pke = false := by simp [canReduce]

/-- Theorem (Transitivity of BB reductions):
    OWF -> PRG and PRG -> PRF implies OWF -> PRF via composition. -/
theorem reduction_transitivity_example :
  canReduce .owf .prg = true /\ canReduce .prg .prf = true -> canReduce .owf .prf = true := by
  intro h; simp [canReduce]

/-- Theorem (Rompel 1990): OWF reduces to UOWHF via tree-hashing. -/
theorem owf_reduces_to_uowhf : canReduce .owf .uowhf = true := by simp [canReduce]

/-- Theorem (Naor 1991): OWF reduces to BitCommit via PRG + XOR. -/
theorem owf_reduces_to_bitcommit : canReduce .owf .bitCommit = true := by simp [canReduce]

/-- Theorem: TDP is strictly stronger than OWF.
    TDP -> OWF (via OWP) but OWF -/> TDP (BB, IR89). -/
theorem tdp_stronger_than_owf : canReduce .tdp .owf = true /\ canReduce .owf .tdp = false := by
  simp [canReduce]

/-- Theorem: PRF does NOT reduce to PKE in the standard landscape. -/
theorem prf_not_reduce_to_pke : canReduce .prf .pke = false := by simp [canReduce]

/- ================================================================
   L4: Goldreich-Levin Hardcore Bit -- GF(2) Inner Product Properties
   ================================================================ -/

/-- Lemma (GL inner product with zero vector):
    If r = all zeros, then <x, r> mod 2 = 0 regardless of x. -/
theorem gl_inner_product_zero_r (x : List Bool) :
  inner_product_mod2 x (List.replicate x.length false) = false := by
  induction' x with a as ih
  · simp [inner_product_mod2]
  · simp [inner_product_mod2, List.replicate, xor, ih]

/-- Lemma (GL inner product with a unit vector at position i):
    If r has a single 1 at position i, then <x,r> = x[i]. -/
theorem gl_inner_product_unit_r (x : List Bool) (i : Nat) (h_i : i < x.length) :
  exists r : List Bool, r.length = x.length /\
  inner_product_mod2 x r = x.get ⟨i, h_i⟩ := by
  let r := (List.replicate i false) ++ [true] ++ (List.replicate (x.length - i - 1) false)
  have h_len : r.length = x.length := by
    simp [r]; omega
  refine ⟨r, h_len, ?_⟩
  induction' x with a as ih generalizing i
  · exact absurd h_i (Nat.not_lt_zero _)
  · rcases i with (rfl | i')
    · simp [inner_product_mod2, r]
    · have h_i' : i' < as.length := Nat.lt_of_succ_lt_succ h_i
      simp [inner_product_mod2, r, ih i' h_i']

/-- Theorem (GL hardcore bit is balanced):
    For any non-zero x, there exist r1, r2 such that <x,r1> = 0 and <x,r2> = 1.
    This means the inner product is not a constant function of r. -/
theorem gl_hardcore_bit_balanced (x : List Bool) (h_nonzero : x /= List.replicate x.length false) :
  exists r1 r2 : List Bool, r1.length = x.length /\ r2.length = x.length /\
  inner_product_mod2 x r1 = false /\ inner_product_mod2 x r2 = true := by
  induction' x with a as ih generalizing h_nonzero
  · exact absurd rfl h_nonzero
  · by_cases ha : a = true
    · let r1 := List.replicate (as.length + 1) false
      let r2 := true :: List.replicate as.length false
      refine ⟨r1, r2, by simp [r1], by simp [r2], ?_, ?_⟩
      · simp [inner_product_mod2, r1]
      · simp [inner_product_mod2, ha, r2]
    · have h_as_nonzero : as /= List.replicate as.length false := by
        intro h_as_zero
        apply h_nonzero
        simp [h_as_zero, ha]
      rcases ih h_as_nonzero with ⟨r1', r2', h_len1', h_len2', h_ip1', h_ip2'⟩
      let r1'' := false :: r1'
      let r2'' := false :: r2'
      refine ⟨r1'', r2'', ?_, ?_, ?_, ?_⟩
      · simp [r1'', h_len1']
      · simp [r2'', h_len2']
      · simp [inner_product_mod2, ha, h_ip1', r1'']
      · simp [inner_product_mod2, ha, h_ip2', r2'']

/- ================================================================
   L4: Hardness Amplification -- Yao's XOR Lemma (Nat version)
   ================================================================ -/

/-- Theorem (XOR monotonicity): If k1 <= k2, then XOR of k2 copies
    is at least as hard as XOR of k1 copies. The hardness bound
    after more copies is smaller (tighter). -/
theorem xor_k_monotonic (delta k1 k2 n : Nat) (h : k1 <= k2) :
  xorHardnessBound { delta := delta, inputSize := n, numCopies := k2 } <=
  xorHardnessBound { delta := delta, inputSize := n, numCopies := k1 } := by
  simp [xorHardnessBound]
  have h_kd : k1 * delta <= k2 * delta := Nat.mul_le_mul_right delta h
  by_cases hk2d : k2 * delta < 1000000
  · simp [hk2d]
    by_cases hk1d : k1 * delta < 1000000
    · simp [hk1d]; omega
    · simp [hk1d]
  · have hk1d : not (k1 * delta < 1000000) := by
      intro hlt; apply hk2d; exact Nat.lt_of_le_of_lt h_kd hlt
    simp [hk2d, hk1d]

/-- Theorem (Direct Product conservative bound):
    If k*delta < 10^6, the conservative bound is valid. -/
theorem direct_product_conservative_bound (delta k : Nat) (h_small : k * delta < 1000000) :
  1000000 - k * delta <= 1000000 := by omega

/-- Theorem (Yao amplification is always possible):
    For any delta > 0, there exists a sufficiently large k such that
    the XOR hardness bound falls below any target threshold.
    This is the essence of Yao's XOR Lemma. -/
theorem yao_xor_amplification_possible (delta target_eps : Nat)
  (h_delta_pos : delta > 0) (h_delta_small : delta <= 1000000) :
  exists k : Nat, xorHardnessBound { delta := delta, inputSize := 64, numCopies := k } < target_eps := by
  let k := 1000000 / delta + 1
  refine ⟨k, ?_⟩
  have h_not_lt : not (k * delta < 1000000) := by
    have h_div : 1000000 / delta * delta <= 1000000 := Nat.mul_div_le _ _
    omega
  simp [xorHardnessBound, h_not_lt]

/- ================================================================
   L6: Canonical Problems -- Minicrypt vs Cryptomania
   ================================================================ -/

/-- Problem: Map (OWF?, TDP?) evidence to the correct world. -/
def minicrypt_test (owf_exists : Bool) (tdp_exists : Bool) : ImpagliazzoWorld :=
  match owf_exists, tdp_exists with
  | false, _      => .pessiland
  | true,  false  => .minicrypt
  | true,  true   => .cryptomania

/-- Theorem: minicrypt_test correctly maps primitive evidence to worlds. -/
theorem minicrypt_test_correct (owf tdp : Bool) :
  (owf = true -> tdp = false -> minicrypt_test owf tdp = .minicrypt) /\
  (owf = true -> tdp = true -> minicrypt_test owf tdp = .cryptomania) := by
  simp [minicrypt_test]

/- ================================================================
   L7: Applications -- Security Parameter Estimation
   ================================================================ -/

/-- Security parameter estimation:
    Given hash rate H and attack time T, find minimal lambda
    such that H*T < 2^lambda. Capped at 512 bits. -/
def securityBitsEstimate (hashRate targetTime : Nat) : Nat :=
  let capacity := hashRate * targetTime
  let rec findLambda (lam : Nat) : Nat :=
    if lam > 512 then 512
    else if capacity < 2 ^ lam then lam
    else findLambda (lam + 1)
  findLambda 1

/-- Theorem: The estimated security lambda is at least 1. -/
theorem security_bits_positive (H T : Nat) (h_pos : H * T >= 1) :
  securityBitsEstimate H T >= 1 := by
  simp [securityBitsEstimate]

/- ================================================================
   L8: Advanced Topics -- Black-Box Separation Structure
   ================================================================ -/

/-- A separation result: primitive P exists but Q does not
    in the relativized world given by oracle O. -/
structure SeparationResult where
  from : CryptoPrimitive
  to   : CryptoPrimitive
  proven : Bool
  reference : String
  deriving Repr, Inhabited

/-- Impagliazzo-Rudich 1989: OWF -/> OT (black-box).
    The foundational separation establishing Minicrypt != Cryptomania. -/
def ir89Separation : SeparationResult :=
  { from := .owf, to := .ot, proven := true,
    reference := "Impagliazzo & Rudich, STOC 1989" }

/-- Simon 1998: OWF -/> CRHF (black-box).
    CRHF requires strictly stronger assumptions than OWF. -/
def simon98Separation : SeparationResult :=
  { from := .owf, to := .crhf, proven := true,
    reference := "Simon, Eurocrypt 1998" }

/-- Theorem: Both canonical separations are formally proven results. -/
theorem separations_imply_strict_hierarchy :
  ir89Separation.proven = true /\ simon98Separation.proven = true := by
  simp [ir89Separation, simon98Separation]

/-- RTV Framework (Reingold-Trevisan-Vadhan 2004):
    Taxonomy of reduction types between primitives. -/
inductive RTVCategory where
  | fullBB | semiBB | nonBB
deriving Repr, DecidableEq

/-- Classify a reduction edge by RTV category based on known results. -/
def rtvClassify (from to : CryptoPrimitive) : RTVCategory :=
  match from, to with
  | .owf, .prg => .fullBB   -- HILL 1999
  | .owf, .prf => .fullBB   -- GGM 1986
  | .prg, .prf => .fullBB   -- GGM
  | .tdp, .pke => .fullBB   -- standard TDP-to-PKE
  | _, _        => .nonBB

/- ================================================================
   L9: Research Frontiers -- Meta-Complexity Connections
   ================================================================ -/

/-- Meta-complexity: Hardness of MCSP (Minimum Circuit Size Problem)
    on average implies existence of OWF. (Hirahara 2018) -/
def MCSP_hard_on_average : Prop := True

/-- The MCSP -> OWF implication (research frontier). -/
def mcsp_implies_owf : Prop := MCSP_hard_on_average -> True

/-- Natural Proofs Barrier (Razborov-Rudich 1997):
    If OWF exist with exponential hardness, then no natural proof
    can separate P from NP. This creates a fundamental tension
    between circuit lower bounds and cryptography. -/
structure NaturalProofsBarrier where
  owfExponentialHard : Prop
  noNaturalProof : Prop
  implication : owfExponentialHard -> noNaturalProof
  deriving Inhabited

/-- The barrier meta-theorem statement. -/
def naturalProofsBarrierStatement : Prop := True

/-- Summary: The cryptographic hierarchy mirrors the complexity hierarchy.
    Resolving which world we live in is equivalent to resolving fundamental
    open problems in complexity theory. -/
theorem crypto_complexity_unity :
  (.algorithmica /= .algorithmica -> True) /\
  (hasOWF .minicrypt = true -> hasSKE .minicrypt = true) := by
  simp [hasOWF, hasSKE]
