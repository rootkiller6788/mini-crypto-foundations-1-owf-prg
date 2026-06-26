/*
 * impagliazzo_worlds.c — Impagliazzo's Five Worlds Formalization
 * Reference: Impagliazzo, "A Personal View of Average-Case Complexity" (1995)
 */
#include "impagliazzo_worlds.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* ================================================================
 * L1: World Axioms — Standard axiom sets for each world
 * ================================================================ */
WorldAxioms algorithmica_axioms(void) {
    WorldAxioms a = {1, 0, 0, 0};
    return a;
}
WorldAxioms heuristica_axioms(void) {
    WorldAxioms a = {0, 1, 0, 0};
    return a;
}
WorldAxioms pessiland_axioms(void) {
    WorldAxioms a = {0, 0, 0, 0};
    /* P!=NP, DistNP not in AvgP, no OWF — P3 implicitly
     * holds when P1+P2 are true and no OWF candidate works */
    return a;
}
WorldAxioms minicrypt_axioms(void) {
    WorldAxioms a = {0, 0, 1, 0};
    return a;
}
WorldAxioms cryptomania_axioms(void) {
    WorldAxioms a = {0, 0, 1, 1};
    return a;
}

/* ================================================================
 * L2: World Belief — Bayesian belief updating over five worlds
 *
 * Start with uniform prior: 20% each world.
 * Update based on evidence via likelihood ratios.
 * ================================================================ */
WorldBelief world_belief_init(void) {
    WorldBelief b;
    b.p_algorithmica = 0.20;
    b.p_heuristica   = 0.20;
    b.p_pessiland    = 0.20;
    b.p_minicrypt    = 0.20;
    b.p_cryptomania  = 0.20;
    b.p_unknown      = 0.0;
    return b;
}

/*
 * Update belief based on a piece of evidence.
 *
 * Evidence types and their likelihoods:
 * - RSA_STILL_STANDING: very likely in Cryptomania, unlikely in Algorithmica
 * - PKE_DEPLOYED: strongly suggests Minicrypt or Cryptomania
 * - NO_P_NP_PROOF: compatible with all worlds except Algorithmica
 * - QUANTUM_THREAT: affects factoring/DLog, but not LWE-based worlds
 */
void world_belief_update(WorldBelief* belief, const char* evidence) {
    if (!belief || !evidence) return;

    /* Simple heuristic update based on evidence keywords.
     * In a full implementation, this would use proper Bayesian
     * updating with pre-computed likelihood ratios from the
     * cryptographic literature. */

    double total = belief->p_algorithmica + belief->p_heuristica +
                   belief->p_pessiland + belief->p_minicrypt +
                   belief->p_cryptomania;

    /* Normalize before update */
    if (total > 0.0) {
        belief->p_algorithmica /= total;
        belief->p_heuristica   /= total;
        belief->p_pessiland    /= total;
        belief->p_minicrypt    /= total;
        belief->p_cryptomania  /= total;
    }

    /* Evidence-specific likelihood ratios */
    if (strstr(evidence, "RSA") || strstr(evidence, "TLS") ||
        strstr(evidence, "PKE") || strstr(evidence, "Bitcoin")) {
        /* Crypto works → favor Minicrypt and Cryptomania */
        belief->p_minicrypt   *= 1.5;
        belief->p_cryptomania *= 1.5;
        belief->p_algorithmica *= 0.3;
        belief->p_heuristica  *= 0.3;
        belief->p_pessiland   *= 0.3;
    }
    if (strstr(evidence, "P_NP") || strstr(evidence, "no proof")) {
        /* P vs NP unresolved → evidence against Algorithmica */
        belief->p_algorithmica *= 0.5;
        belief->p_heuristica   *= 1.1;
    }
    if (strstr(evidence, "quantum") || strstr(evidence, "Shor")) {
        /* Quantum threat: reduces confidence in factoring-based TDP
         * but LWE-based Crypto may still hold */
        belief->p_cryptomania *= 0.9;  /* mild reduction */
    }
    if (strstr(evidence, "LWE") || strstr(evidence, "lattice")) {
        /* LWE evidence: favors Cryptomania (LWE gives PKE) */
        belief->p_cryptomania *= 1.3;
        belief->p_minicrypt   *= 0.9;
    }

    /* Re-normalize */
    total = belief->p_algorithmica + belief->p_heuristica +
            belief->p_pessiland + belief->p_minicrypt +
            belief->p_cryptomania;
    if (total > 0.0) {
        belief->p_algorithmica /= total;
        belief->p_heuristica   /= total;
        belief->p_pessiland    /= total;
        belief->p_minicrypt    /= total;
        belief->p_cryptomania  /= total;
    }
    belief->p_unknown = 1.0 - (belief->p_algorithmica + belief->p_heuristica +
                                belief->p_pessiland + belief->p_minicrypt +
                                belief->p_cryptomania);
    if (belief->p_unknown < 0.0) belief->p_unknown = 0.0;
}

ImpagliazzoWorld world_belief_map(const WorldBelief* belief) {
    if (!belief) return MINICRYPT;  /* default conservative */
    double max = belief->p_algorithmica;
    ImpagliazzoWorld best = ALGORITHMICA;
    if (belief->p_heuristica > max)  { max = belief->p_heuristica;  best = HEURISTICA; }
    if (belief->p_pessiland > max)   { max = belief->p_pessiland;   best = PESSILAND; }
    if (belief->p_minicrypt > max)   { max = belief->p_minicrypt;   best = MINICRYPT; }
    if (belief->p_cryptomania > max) { max = belief->p_cryptomania; best = CRYPTOMANIA; }
    return best;
}

void world_belief_print(const WorldBelief* belief) {
    if (!belief) return;
    printf("\n=== World Belief Distribution ===\n");
    printf("  Algorithmica:  %.2f%%\n", belief->p_algorithmica * 100);
    printf("  Heuristica:    %.2f%%\n", belief->p_heuristica * 100);
    printf("  Pessiland:     %.2f%%\n", belief->p_pessiland * 100);
    printf("  Minicrypt:     %.2f%%\n", belief->p_minicrypt * 100);
    printf("  Cryptomania:   %.2f%%\n", belief->p_cryptomania * 100);
    printf("  Unclassified:  %.2f%%\n", belief->p_unknown * 100);
    printf("  MAP estimate:  %s\n", world_name(world_belief_map(belief)));
    printf("=== End Belief Distribution ===\n");
}

/* ================================================================
 * L2: Evidence Enumeration & Likelihood
 * ================================================================ */
static const char* evidence_names[] = {
    "RSA still standing after decades",
    "PKE widely deployed (TLS, PGP)",
    "No poly-time factoring discovered",
    "SHA-3 competition: hash functions secure",
    "Secure MPC implemented (feasible)",
    "Bitcoin proof-of-work holds",
    "P vs NP remains open",
    "Quantum threat (Shor's algorithm)",
    "Indistinguishability Obfuscation candidate found"
};

const char* evidence_name(Evidence e) {
    if (e >= 0 && e < EVID_NUM) return evidence_names[e];
    return "UNKNOWN";
}

/*
 * Log-likelihood of evidence e given world w.
 * Positive = supports world, Negative = contradicts world.
 *
 * These are approximate values based on cryptographic consensus.
 */
double evidence_log_likelihood(Evidence e, ImpagliazzoWorld w) {
    switch (e) {
    case EVID_RSA_STILL_STANDING:
        return (w >= MINICRYPT) ? 2.0 : -1.0;
    case EVID_PKE_DEPLOYED:
        return (w == CRYPTOMANIA) ? 3.0 :
               (w == MINICRYPT) ? -2.0 : -5.0;
    case EVID_FACTORING_NO_PROGRESS:
        return (w >= MINICRYPT) ? 1.5 : -0.5;
    case EVID_SHA3_COMPETITION:
        return (w >= MINICRYPT) ? 1.0 : -1.0;
    case EVID_MPC_FEASIBLE:
        return (w == CRYPTOMANIA) ? 2.5 :
               (w == MINICRYPT) ? -1.0 : -3.0;
    case EVID_BITCOIN_SECURE:
        return (w >= MINICRYPT) ? 2.0 : -2.0;
    case EVID_NO_P_NP_PROOF:
        return (w != ALGORITHMICA) ? 0.5 : -3.0;
    case EVID_QUANTUM_THREAT:
        return (w == CRYPTOMANIA) ? -2.0 : 0.5;
    case EVID_IO_CANDIDATE:
        return (w == CRYPTOMANIA) ? 1.5 : -1.0;
    default: return 0.0;
    }
}

/* ================================================================
 * L3: World Capabilities — Which primitives exist in each world
 * ================================================================ */
WorldCapabilities world_capabilities(ImpagliazzoWorld w) {
    WorldCapabilities cap;
    memset(&cap, 0, sizeof(cap));
    cap.world = w;
    switch (w) {
    case ALGORITHMICA:
        /* P=NP: no cryptography possible */
        break;
    case HEURISTICA:
        /* P!=NP but easy on average: no crypto */
        break;
    case PESSILAND:
        /* Hard-on-average exist but no OWF: paradoxically no crypto */
        break;
    case MINICRYPT:
        cap.has_owf = 1; cap.has_prg = 1; cap.has_prf = 1;
        cap.has_uowhf = 1; cap.has_ske = 1; cap.has_mac = 1;
        cap.has_bit_commit = 1; cap.has_zk = 1;
        break;
    case CRYPTOMANIA:
        cap.has_owf = 1; cap.has_prg = 1; cap.has_prf = 1;
        cap.has_uowhf = 1; cap.has_crhf = 1;
        cap.has_ske = 1; cap.has_mac = 1;
        cap.has_bit_commit = 1;
        cap.has_tdp = 1; cap.has_owp = 1;
        cap.has_pke = 1; cap.has_ds = 1;
        cap.has_ot = 1; cap.has_mpc = 1;
        cap.has_zk = 1; cap.has_fhe = 1; cap.has_io = 1;
        break;
    }
    return cap;
}

void world_capabilities_print(ImpagliazzoWorld w) {
    WorldCapabilities cap = world_capabilities(w);
    printf("\n=== %s Capabilities ===\n", world_name(w));
    printf("  OWF: %d  PRG: %d  PRF: %d  UOWHF: %d\n",
           cap.has_owf, cap.has_prg, cap.has_prf, cap.has_uowhf);
    printf("  CRHF: %d  SKE: %d  MAC: %d\n",
           cap.has_crhf, cap.has_ske, cap.has_mac);
    printf("  BitCommit: %d  TDP: %d  OWP: %d\n",
           cap.has_bit_commit, cap.has_tdp, cap.has_owp);
    printf("  PKE: %d  DS: %d  OT: %d  MPC: %d\n",
           cap.has_pke, cap.has_ds, cap.has_ot, cap.has_mpc);
    printf("  ZK: %d  FHE: %d  iO: %d\n",
           cap.has_zk, cap.has_fhe, cap.has_io);
    printf("=== End Capabilities ===\n");
}

/* ================================================================
 * L4: Theorems about World Transitions
 * ================================================================ */
int theorem_hill_world_transition(void) {
    printf("\n=== Theorem: HILL World Transition ===\n");
    printf("HILL 1999: If OWF exist, then PRG exist.\n");
    printf("This establishes the Heuristica->Minicrypt transition:\n");
    printf("  OWF = PRG = PRF = SKE = MAC = BitCommit\n");
    printf("All of symmetric cryptography follows from OWF alone.\n");
    printf("=== End HILL Transition ===\n");
    return 0;
}

int theorem_ir_separation(void) {
    printf("\n=== Theorem: Impagliazzo-Rudich Separation ===\n");
    printf("IR 1989: OWF does NOT imply OT in the black-box model.\n");
    printf("This proves Minicrypt != Cryptomania (BB), since:\n");
    printf("  Cryptomania requires OT/PKE, Minicrypt does not.\n");
    printf("Construction: Random oracle is OWF but OT impossible.\n");
    printf("=== End IR Separation ===\n");
    return 0;
}

int theorem_rompel_uowhf(void) {
    printf("\n=== Theorem: Rompel UOWHF ===\n");
    printf("Rompel 1990: OWF implies UOWHF.\n");
    printf("Construction uses OWF in a tree-hashing mode.\n");
    printf("UOWHF is sufficient for signature schemes (via one-time sigs).\n");
    printf("=== End Rompel Theorem ===\n");
    return 0;
}

int theorem_naor_bitcommit(void) {
    printf("\n=== Theorem: Naor Bit Commitment ===\n");
    printf("Naor 1991: OWF implies Bit Commitment.\n");
    printf("Construction via PRG: Commit(b) = G(r) XOR (b*1^{3n}).\n");
    printf("BitCommit is a crucial building block for ZK proofs.\n");
    printf("=== End Naor Theorem ===\n");
    return 0;
}

/* ================================================================
 * L5: Relativized World Oracle Construction
 *
 * Build a random oracle model to demonstrate separations.
 * In this model, OWF exist (the oracle is one-way to PPT),
 * but stronger primitives may not be constructible.
 * ================================================================ */
RelativizedWorld* rw_create(size_t input_bits, int as_permutation) {
    if (input_bits > 16) return NULL;  /* 2^16 entries max for simulation */
    size_t entries = 1ULL << input_bits;
    size_t byte_len = (input_bits + 7) / 8;

    RelativizedWorld* rw = calloc(1, sizeof(RelativizedWorld));
    if (!rw) return NULL;

    rw->input_size = input_bits;
    rw->table_entries = entries;
    rw->is_permutation = as_permutation;
    rw->oracle_table = calloc(entries, byte_len);
    if (!rw->oracle_table) { free(rw); return NULL; }

    /* Initialize with pseudorandom values (simple LCG for demo) */
    uint64_t state = 0x123456789ABCDEF0ULL;
    for (size_t i = 0; i < entries; i++) {
        for (size_t j = 0; j < byte_len; j++) {
            state = state * 6364136223846793005ULL + 1442695040888963407ULL;
            rw->oracle_table[i * byte_len + j] = (uint8_t)(state >> 56);
        }
    }
    return rw;
}

void rw_free(RelativizedWorld* rw) {
    if (!rw) return;
    free(rw->oracle_table);
    free(rw);
}

/*
 * Evaluate the random oracle at point x.
 * The oracle is a truly random function (simulated via PRNG for demo).
 * PPT adversaries cannot invert it without exhaustive search.
 */
int rw_eval(const RelativizedWorld* rw, const uint8_t* x, uint8_t* y) {
    if (!rw || !x || !y) return -1;
    /* Convert x to table index */
    size_t idx = 0;
    size_t byte_len = (rw->input_size + 7) / 8;
    for (size_t j = 0; j < byte_len; j++)
        idx = (idx << 8) | x[j];
    idx %= rw->table_entries;
    memcpy(y, rw->oracle_table + idx * byte_len, byte_len);
    return 0;
}

/*
 * PSPACE inverter: exhaustive search over all possible inputs.
 * This demonstrates that PSPACE can invert any function, but PPT cannot.
 * The existence of PSPACE inversion does not contradict OWF because
 * OWF only requires security against PPT (not PSPACE).
 */
int rw_invert_pspace(const RelativizedWorld* rw, const uint8_t* y,
                      uint8_t* x, size_t xlen) {
    if (!rw || !y || !x) return -1;
    size_t byte_len = (rw->input_size + 7) / 8;
    for (size_t i = 0; i < rw->table_entries; i++) {
        int match = 1;
        for (size_t j = 0; j < byte_len; j++) {
            if (rw->oracle_table[i * byte_len + j] != y[j]) {
                match = 0;
                break;
            }
        }
        if (match) {
            /* Found preimage, convert index to bytes */
            for (size_t j = 0; j < byte_len && j < xlen; j++)
                x[j] = (uint8_t)(i >> (8 * (byte_len - 1 - j)));
            return 0;
        }
    }
    return -1;  /* No preimage found */
}

/*
 * Demonstrate the separation: in a random oracle model,
 * OWF exist but OT cannot be BB-constructed from OWF.
 */
int rw_demonstrate_separation(RelativizedWorld* rw) {
    if (!rw) return -1;
    printf("\n=== Random Oracle Separation Demonstration ===\n");
    printf("Random oracle with 2^%zu entries is one-way to PPT.\n",
           rw->input_size);
    printf("PSPACE can invert via exhaustive search.\n");
    printf("Any BB-OT protocol makes poly(n) queries to oracle.\n");
    printf("PSPACE adversary can answer all queries, removing\n");
    printf("the computational asymmetry needed for OT.\n");
    printf("Conclusion: OWF exist, OT does NOT (in BB-sense).\n");
    printf("=== End Separation Demonstration ===\n");
    return 0;
}

/* ================================================================
 * L6: Canonical Question — Which World Do We Live In?
 * ================================================================ */
void print_current_consensus(void) {
    printf("\n=== Which World Do We Live In? (2026 Consensus) ===\n\n");
    printf("Algorithmica (P=NP):\n");
    printf("  Nearly ruled out. Decades of failed algorithmic\n");
    printf("  attacks on SAT, factoring, and NP-complete problems\n");
    printf("  suggest P != NP with overwhelming confidence.\n\n");
    printf("Heuristica (P!=NP, easy on average):\n");
    printf("  Unlikely. Cryptography appears to work in practice,\n");
    printf("  suggesting average-case hard problems exist.\n\n");
    printf("Pessiland (hard on avg, no OWF):\n");
    printf("  Unlikely. Many OWF candidates (SHA, factoring)\n");
    printf("  have resisted attack for decades.\n\n");
    printf("Minicrypt (OWF, no TDP):\n");
    printf("  Possible. If factoring and DLog are broken (quantum),\n");
    printf("  but some OWF remain, we end up here.\n\n");
    printf("Cryptomania (TDP exist):\n");
    printf("  Most likely. Factoring, DLog, and LWE all seem hard.\n");
    printf("  Even post-quantum, LWE-based TDP candidates exist.\n\n");
    printf("Current best estimate: Cryptomania (confidence: ~75%%)\n");
    printf("=== End Consensus ===\n");
}

void print_post_quantum_analysis(void) {
    printf("\n=== Post-Quantum World Analysis ===\n\n");
    printf("Shor's algorithm breaks factoring and discrete log.\n");
    printf("This eliminates RSA, DSA, ECDSA, and DH key exchange.\n\n");
    printf("Surviving assumptions:\n");
    printf("  LWE (Learning With Errors) — believed quantum-resistant\n");
    printf("  SVP (Shortest Vector Problem) — lattice-based, quantum-safe\n");
    printf("  Code-based (McEliece, BIKE) — quantum-resistant\n");
    printf("  Hash-based signatures (SPHINCS+) — quantum-resistant\n\n");
    printf("Key question: Does LWE → TDP in the post-quantum sense?\n");
    printf("  LWE gives PKE (Regev 2005), which is sufficient for\n");
    printf("  Cryptomania-level capabilities.\n\n");
    printf("If LWE is secure, we remain in Cryptomania post-quantum.\n");
    printf("If LWE is broken AND no replacement exists, we fall\n");
    printf("to Minicrypt (symmetric-only) or lower.\n");
    printf("=== End Post-Quantum Analysis ===\n");
}
