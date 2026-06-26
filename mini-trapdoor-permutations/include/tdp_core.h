/**
 * tdp_core.h — Core Trapdoor Permutation definitions
 *
 * A trapdoor permutation (TDP) is a family of permutations {f_i: D_i → D_i}
 * such that:
 *   1. There exists a PPT algorithm Gen(1^n) → (i, t_i) where i is an index
 *      describing a permutation f_i and t_i is its trapdoor.
 *   2. There exists a PPT algorithm Eval(i, x) = f_i(x) that is a permutation.
 *   3. There exists a PPT algorithm Invert(i, t_i, y) = f_i^{-1}(y) using t_i.
 *   4. Without t_i, f_i is a one-way permutation (OWP).
 *
 * Reference: Goldreich, Foundations of Cryptography Vol. 1 (2001), §2.4.4
 *            Arora & Barak, Computational Complexity: A Modern Approach (2009), Ch. 9
 *
 * Course mapping:
 *   MIT 6.841 Adv Complexity — Cryptography foundations
 *   Stanford CS254 — OWF/PRG to public-key
 *   Princeton COS 551 — Advanced Crypto
 *   Berkeley CS278 — Complexity and Cryptography
 *   CMU 15-855 — Graduate Complexity
 */

#ifndef TDP_CORE_H
#define TDP_CORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ──── Security Parameter ──── */

/** Security parameter λ — determines the bit-length of keys.
 *  A function ε(λ) is negligible if ε(λ) < 1/poly(λ) for all polynomials
 *  and sufficiently large λ. */
typedef uint32_t security_param_t;

#define MIN_SECURITY_PARAM 128   /* Minimum for modern cryptographic security */
#define DEFAULT_SEC_PARAM   2048 /* RSA-2048 equivalent */

/* ──── Big Integer (for RSA modulus) ──── */

/** Maximum size for big integer representation (in 32-bit limbs).
 *  For RSA-2048: 2048/32 = 64 limbs. We allocate 128 for headroom. */
#define BIGINT_MAX_LIMBS 128

/**
 * Big integer represented as an array of 32-bit limbs, little-endian.
 * Used for RSA modulus n, primes p,q, exponent e,d, and messages.
 *
 * This is an educational implementation — in production, use GMP/OpenSSL.
 */
typedef struct {
    uint32_t limbs[BIGINT_MAX_LIMBS];  /* Little-endian 32-bit limbs */
    uint32_t nlimbs;                    /* Number of active limbs */
} bigint_t;

/* ──── Key Structures ──── */

/**
 * TDP Index (public key).
 * Describes a specific permutation f_i from the TDP family.
 * For RSA: i = (n, e) where n = pq is the modulus and e is the public exponent.
 */
typedef struct {
    bigint_t modulus;    /* n = p * q */
    bigint_t exponent;   /* e (public exponent, typically 3, 17, or 65537) */
    uint32_t nbits;      /* Bit-length of modulus */
} tdp_public_key_t;

/**
 * TDP Trapdoor (secret key).
 * The trapdoor information that enables efficient inversion.
 * For RSA: t_i = (p, q, d) where d = e^{-1} mod φ(n).
 */
typedef struct {
    bigint_t prime_p;    /* First prime factor of n */
    bigint_t prime_q;    /* Second prime factor of n */
    bigint_t private_exp; /* d = e^{-1} mod φ(n) */
    bigint_t totient;    /* φ(n) = (p-1)(q-1) */
    bigint_t d_p;        /* d mod (p-1) for CRT optimization */
    bigint_t d_q;        /* d mod (q-1) for CRT optimization */
    bigint_t q_inv;       /* q^{-1} mod p for CRT recombination */
} tdp_trapdoor_t;

/**
 * TDP key pair — (public_key, trapdoor).
 */
typedef struct {
    tdp_public_key_t pk;
    tdp_trapdoor_t td;
    security_param_t lambda;  /* Security parameter used for generation */
} tdp_keypair_t;

/* ──── TDP Domain ──── */

/**
 * Domain element x ∈ D_i.
 * For RSA: D_i = Z_n^*, so x ∈ [1, n-1] with gcd(x, n) = 1.
 */
typedef struct {
    bigint_t value;
    bool in_domain;  /* true if gcd(value, n) == 1 */
} tdp_domain_elem_t;

/* ──── TDP Evaluation Result ──── */

/** Result of forward evaluation: y = f_i(x). */
typedef struct {
    bigint_t value;
    bool valid;
} tdp_eval_result_t;

/* ──── TDP Status Codes ──── */

typedef enum {
    TDP_SUCCESS = 0,
    TDP_ERR_INVALID_PARAM = -1,
    TDP_ERR_NOT_IN_DOMAIN = -2,
    TDP_ERR_INVERSION_FAILED = -3,
    TDP_ERR_KEYGEN_FAILED = -4,
    TDP_ERR_ARITHMETIC_OVERFLOW = -5,
    TDP_ERR_PRIMALITY_FAILED = -6,
} tdp_status_t;

/* ──── Security Definitions ──── */

/**
 * Negligible function check.
 * Returns true if value < 2^{-lambda} (i.e., is cryptographically negligible).
 * Complexity: O(1).
 * Theorem: A function ε is negligible iff ε(λ) = λ^{-ω(1)}.
 * Reference: Goldreich (2001), Definition 2.3.4.
 */
bool tdp_is_negligible(double value, security_param_t lambda);

/**
 * One-Wayness advantage bound.
 * The advantage of an adversary A in inverting f without trapdoor:
 *   Adv_{Π}^{OW}(A) = Pr[A(i, f_i(x)) = x], where x ← D_i.
 * A TDP is secure if for all PPT A, Adv is negligible.
 * Reference: Goldreich (2001), Definition 2.4.1.
 */
double tdp_one_way_advantage(uint32_t success_count, uint32_t total_trials, security_param_t lambda);

/**
 * Check if a given advantage is considered "broken" at security level λ.
 * Returns true if the advantage is non-negligible (> 2^{-λ/2} by conservative bound).
 */
bool tdp_advantage_is_significant(double advantage, security_param_t lambda);

/* ──── TDP Family API ──── */

/**
 * Initialize a TDP key pair structure to zero/default state.
 * Complexity: O(1).
 */
tdp_keypair_t tdp_keypair_init(void);

/**
 * Free resources associated with a key pair.
 * (For this educational implementation, no dynamic allocation needed.)
 */
void tdp_keypair_clear(tdp_keypair_t *kp);

/**
 * Sample a random element x uniformly from domain D_i.
 * For RSA: sample x ∈ [1, n-1] and check gcd(x, n) = 1.
 * Complexity: O(log^2 n) for modular operations.
 * Reference: Goldreich (2001), §2.4.4.2.
 */
tdp_domain_elem_t tdp_sample_domain(const tdp_public_key_t *pk);

/**
 * Forward evaluation: y = f_i(x).
 * This is the "easy" direction — computable by anyone with pk.
 * For RSA: y = x^e mod n.
 * Complexity: O(log e * log^2 n) using square-and-multiply.
 */
tdp_eval_result_t tdp_eval_forward(const tdp_public_key_t *pk, const tdp_domain_elem_t *x);

/**
 * Inverse evaluation (with trapdoor): x = f_i^{-1}(y).
 * This is the "hard" direction — only feasible with trapdoor t_i.
 * For RSA: x = y^d mod n using CRT.
 * Complexity: O(log d * log^2 n) with CRT speedup.
 */
tdp_domain_elem_t tdp_eval_inverse(const tdp_public_key_t *pk, const tdp_trapdoor_t *td,
                                    const tdp_eval_result_t *y);

/**
 * Verify that a TDP is indeed a permutation on its domain:
 *   ∀x ∈ D_i: f_i^{-1}(f_i(x)) = x and f_i(f_i^{-1}(x)) = x.
 * Returns true if the permutation property holds for the given element.
 * Complexity: O(log e + log d) * O(log^2 n).
 */
bool tdp_verify_permutation_property(const tdp_public_key_t *pk, const tdp_trapdoor_t *td,
                                      const tdp_domain_elem_t *x);

/* ──── TDP Collection (Family) ──── */

/**
 * A TDP collection is an infinite family {Π_n}_{n∈N} where:
 *   - Π_n = (Gen_n, Eval_n, Invert_n) operates on security parameter n.
 *   - Each Π_n defines permutations on domain D_n.
 *
 * For RSA, the collection is parametrized by the modulus bit-length.
 * Reference: Goldreich (2001), Definition 2.4.4.
 */

/** TDP collection descriptor. */
typedef struct {
    security_param_t lambda;       /* Security parameter */
    uint32_t domain_size_bits;     /* |D_i| ≈ 2^{domain_size_bits} */
    const char *family_name;       /* e.g., "RSA", "Rabin", "Paillier" */
    const char *hardness_assumption; /* e.g., "RSA Assumption", "Factoring" */
} tdp_collection_info_t;

/**
 * Describe a TDP collection for a given security parameter.
 * Complexity: O(1).
 */
tdp_collection_info_t tdp_collection_describe(security_param_t lambda);

/* ──── Domain Validity ──── */

/**
 * Check if an element x is in the domain D_i.
 * For RSA: gcd(x, n) == 1 and 1 ≤ x < n.
 * Complexity: O(log^2 n) for Euclidean algorithm.
 */
bool tdp_check_domain_membership(const tdp_public_key_t *pk, const bigint_t *x);

/**
 * Get the approximate size of the domain |D_i|.
 * For RSA: φ(n) = (p-1)(q-1) ≈ n.
 * Complexity: O(1) given precomputed totient.
 */
void tdp_domain_size_approx(const tdp_public_key_t *pk, const tdp_trapdoor_t *td, bigint_t *out);

/* ──── Comparison between TDP primitives ──── */

/**
 * Compare one-way function vs trapdoor permutation:
 *   OWF:  Easy to compute, hard to invert (no trapdoor).
 *   OWP:  OWF that is also a permutation (bijection on domain).
 *   TDP:  OWP with trapdoor for efficient inversion.
 *
 * TDP ⊆ OWP ⊆ OWF (every TDP is an OWP, every OWP is an OWF).
 * The converse is not known to hold.
 */

/** Primitive classification enum */
typedef enum {
    PRIMITIVE_OWF = 1,    /* One-way function */
    PRIMITIVE_OWP = 2,    /* One-way permutation */
    PRIMITIVE_TDP = 3,    /* Trapdoor permutation */
} crypto_primitive_type_t;

#endif /* TDP_CORE_H */
