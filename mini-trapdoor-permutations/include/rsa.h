/**
 * rsa.h — RSA Trapdoor Permutation
 *
 * RSA is the canonical example of a trapdoor permutation:
 *   - Public key:  (n, e) where n = pq for distinct primes p, q
 *   - Secret key:  (p, q, d) where d = e^{-1} mod φ(n)
 *   - Forward:     f(x) = x^e mod n      (encryption / verification)
 *   - Inverse:     f^{-1}(y) = y^d mod n (decryption / signing)
 *
 * The RSA Assumption: Given (n, e) and y = x^e mod n for random x ∈ Z_n^*,
 * it is computationally infeasible to recover x without knowing d.
 *
 * The Factoring Assumption is stronger: factoring n = pq is hard.
 * RSA is at most as hard as factoring; the converse is not known.
 *
 * Historical note: RSA was first described publicly by Rivest, Shamir, and
 * Adleman (1978), but equivalent constructions were developed earlier at
 * GCHQ by Cocks (1973, declassified 1997).
 *
 * Reference: Rivest, Shamir, Adleman, "A Method for Obtaining Digital
 *            Signatures and Public-Key Cryptosystems," CACM 21(2), 1978.
 *            Goldreich, Foundations of Cryptography Vol. 2, Ch. 10.
 *
 * Course mapping:
 *   Stanford CS255 — RSA cryptosystem
 *   Princeton COS 551 — Number-theoretic cryptography
 *   Berkeley CS276 — Graduate Cryptography
 *   MIT 6.875 — Public-key encryption
 *   Cambridge Part III — Advanced cryptography
 *   ETH 263-4660 — RSA in practice
 */

#ifndef RSA_H
#define RSA_H

#include "tdp_core.h"
#include "modular_math.h"

/* ──── RSA Parameters ──── */

/** Standard RSA public exponents (must be coprime to φ(n)).
 *  e = 3:    Fastest encryption, but requires careful padding (Coppersmith attacks).
 *  e = 17:   Moderate speed.
 *  e = 65537: Industry standard (Fermat prime F4 = 2^16+1), Hamming weight 2. */
#define RSA_E_3      3
#define RSA_E_17     17
#define RSA_E_65537  65537

/** Recommended public exponent for production use. */
#define RSA_DEFAULT_E RSA_E_65537

/* ──── RSA-specific Structures ──── */

/**
 * RSA parameters: p, q (primes), n = p*q (modulus).
 * φ(n) = (p-1)(q-1) for p, q distinct primes.
 * λ(n) = lcm(p-1, q-1) is the Carmichael function (also valid; smaller).
 */
typedef struct {
    bigint_t p;        /* First prime factor, e.g., 512-bit for RSA-1024 */
    bigint_t q;        /* Second prime factor */
    bigint_t n;        /* Modulus: n = p * q */
    bigint_t phi_n;    /* Euler's totient: φ(n) = (p-1)(q-1) */
    bigint_t lambda_n; /* Carmichael λ(n) = lcm(p-1, q-1) */
    bigint_t e;        /* Public exponent */
    bigint_t d;        /* Private exponent: d = e^{-1} mod φ(n) */
    uint32_t nbits;    /* Bit-length of n */
} rsa_params_t;

/**
 * RSA key pair — compatible with tdp_keypair_t.
 * This is the concrete instantiation of the TDP abstraction.
 */
typedef struct {
    rsa_params_t params;
    /* CRT precomputed values for efficient decryption */
    bigint_t d_p;      /* d mod (p-1) */
    bigint_t d_q;      /* d mod (q-1) */
    bigint_t q_inv;    /* q^{-1} mod p */
} rsa_keypair_t;

/* ──── RSA Core Operations ──── */

/**
 * RSA forward permutation (encryption in PKE context):
 *   y = RSA_Encrypt_{n,e}(x) = x^e mod n
 *
 * This is the "easy" direction, computable with only the public key.
 * Complexity: O(log e * log^2 n) ≈ O(log^3 n) for typical e.
 */
tdp_eval_result_t rsa_encrypt(const rsa_params_t *params, const bigint_t *x);

/**
 * RSA inverse permutation (decryption in PKE context):
 *   x = RSA_Decrypt_{n,d}(y) = y^d mod n
 *
 * Uses Garner's CRT algorithm for ~4× speedup:
 *   x_p = y^{d_p} mod p
 *   x_q = y^{d_q} mod q
 *   x = CRT(x_p, x_q)
 *
 * Complexity: O(log d * log^2 n) naive; O(log d_p * log^2 p) with CRT.
 */
tdp_domain_elem_t rsa_decrypt_crt(const rsa_keypair_t *key, const bigint_t *y);

/**
 * RSA naive decrypt (without CRT, for comparison).
 * Complexity: O(log d * log^2 n).
 */
tdp_domain_elem_t rsa_decrypt_naive(const rsa_params_t *params, const bigint_t *y);

/**
 * RSA signing (inverse permutation):
 *   σ = RSA_Sign_{n,d}(m) = H(m)^d mod n
 * (Note: actual signing requires hashing; this is the "textbook RSA" core.)
 *
 * Complexity: O(log d * log^2 n).
 */
tdp_domain_elem_t rsa_sign(const rsa_keypair_t *key, const bigint_t *message_hash);

/**
 * RSA verification (forward permutation):
 *   m' = RSA_Verify_{n,e}(σ) = σ^e mod n; check m' == H(m).
 *
 * Complexity: O(log e * log^2 n).
 */
tdp_eval_result_t rsa_verify(const rsa_params_t *params, const bigint_t *signature);

/**
 * RSA multiplicative homomorphism:
 *   RSA(x1 × x2) = RSA(x1) × RSA(x2) mod n
 * This property is both useful (homomorphic encryption) and dangerous
 * (malleability — requires padding in PKE and signatures).
 *
 * Reference: Rivest, Shamir, Adleman (1978), §IV.
 */
bool rsa_verify_homomorphism(const rsa_params_t *params,
                              const bigint_t *x1, const bigint_t *x2);

/* ──── RSA Security Properties ──── */

/**
 * Check if a public exponent e is valid for modulus n:
 *   gcd(e, φ(n)) = 1 (ensures d exists).
 * Complexity: O(log^2 n).
 */
bool rsa_check_public_exponent(const bigint_t *e, const bigint_t *phi_n);

/**
 * Self-reducibility of RSA:
 * Given y = x^e mod n, choose random r, compute z = y * r^e mod n.
 * If we can invert z (get x*r), we can recover x = (x*r) * r^{-1} mod n.
 *
 * This is used in security reductions: the RSA problem is random self-reducible,
 * meaning an average-case solver implies a worst-case solver.
 *
 * Complexity: O(log^2 n).
 *
 * Reference: Goldreich (2001), §2.4.4.
 */
void rsa_random_self_reduce(const rsa_params_t *params, const bigint_t *y,
                             bigint_t *blinded_y, bigint_t *r, bigint_t *r_inv);

/**
 * Recover original RSA plaintext from blinded version:
 *   x = blinded_x * r_inv mod n.
 * Complexity: O(log^2 n).
 */
void rsa_random_self_unblind(const rsa_params_t *params, const bigint_t *blinded_x,
                              const bigint_t *r_inv, bigint_t *x);

/**
 * The RSA Assumption formalization:
 * Define advantage Adv_A^{RSA}(λ) = Pr[A(n, e, x^e mod n) = x]
 * where (n,e,d) ← Gen(1^λ), x ← Z_n^*.
 * The RSA Assumption states that for all PPT A, Adv_A^{RSA} is negligible.
 */
double rsa_assumption_advantage(uint32_t success_count, uint32_t trials, security_param_t lambda);

/* ──── Relationship to Factoring ──── */

/**
 * Factoring → RSA: If factoring n = pq is easy, then RSA is broken
 * (compute d = e^{-1} mod φ(n)).
 *
 * RSA → Factoring: Not known! Breaking RSA might be easier than factoring.
 * The equivalence is known only for restricted cases (e.g., small e).
 *
 * Complexity: O(1) — informational.
 */
typedef enum {
    RSA_ASSUMPTION_HOLDS = 0,
    FACTORING_FEASIBLE = 1,      /* Factoring breaks RSA deterministically */
    RSA_BROKEN_BUT_NOT_FACTORED = 2, /* Hypothetical: RSA broken without factoring */
} rsa_security_status_t;

#endif /* RSA_H */
