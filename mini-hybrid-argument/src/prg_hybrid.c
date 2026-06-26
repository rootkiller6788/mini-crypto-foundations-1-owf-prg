/*
 * prg_hybrid.c - PRG Security via the Hybrid Argument
 *
 * A Pseudorandom Generator (PRG) G: {0,1}^n -> {0,1}^{l(n)} is a deterministic
 * polynomial-time algorithm whose output is computationally indistinguishable
 * from uniform. The hybrid argument is the standard technique for proving the
 * PRG Length Extension Theorem (Blum-Micali-Yao).
 *
 * L1: PRG, stretch, PRG security game
 * L4: PRG Length Extension Theorem (BMY)
 * L5: BMY iteration algorithm
 * L7: Stream cipher, key derivation (applications)
 *
 * Reference:
 *   Blum & Micali (1984) SIAM J. Comput.
 *   Yao (1982) FOCS
 *   Goldreich (2001) Foundations of Cryptography Vol 1, Sec 3.3
 *
 * Courses: MIT 6.875, Stanford CS355, Berkeley CS276, Princeton COS 522
 */

#include "prg_hybrid.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* ================================================================
 * PRG Core
 * ================================================================ */

PRG* prg_create(const char* name,
                 size_t (*stretch_fn)(size_t seed_bits),
                 prg_eval_fn eval_fn,
                 void* state) {
    PRG* g = (PRG*)malloc(sizeof(PRG));
    if (!g) return NULL;
    g->name = name ? _strdup(name) : NULL;
    g->stretch = stretch_fn;
    g->evaluate = eval_fn;
    g->state = state;
    return g;
}

void prg_free(PRG* g) {
    if (g) { free(g->name); free(g); }
}

void prg_evaluate(const PRG* g,
                   const uint8_t* seed, size_t seed_bits,
                   uint8_t* output, size_t* output_bits) {
    if (g && g->evaluate && seed && output && output_bits)
        g->evaluate(g, seed, seed_bits, output, output_bits);
}

/* ================================================================
 * PRG Security Game (PrivK^{prg}_{A,G})
 *
 * 1. Challenger chooses b <- {0,1} uniformly.
 * 2. If b=0: send r <- U_{l(n)}; If b=1: send y = G(s), s <- U_n.
 * 3. Adversary outputs b', succeeds if b' = b.
 *
 * Advantage = |Pr[A(G(s))=1] - Pr[A(r)=1]|
 * ================================================================ */

PRGSecurityGame prg_security_game_run(const PRG* g,
                                       const Distinguisher* adv,
                                       security_param_t n,
                                       int num_trials) {
    PRGSecurityGame game;
    memset(&game, 0, sizeof(game));
    if (!g || !adv || num_trials <= 0) return game;

    size_t out_bits = n + (g->stretch ? g->stretch(n) : 16);
    size_t out_bytes = (out_bits + 7) / 8;
    size_t seed_bytes = (n + 7) / 8;

    uint8_t* prg_out = (uint8_t*)malloc(out_bytes);
    uint8_t* uniform_out = (uint8_t*)malloc(out_bytes);
    uint8_t* seed = (uint8_t*)malloc(seed_bytes);
    if (!prg_out || !uniform_out || !seed) {
        free(prg_out); free(uniform_out); free(seed);
        return game;
    }

    double cnt_adv1_b1 = 0.0;  /* Pr[adv=1 | b=1] */
    double cnt_adv1_b0 = 0.0;  /* Pr[adv=1 | b=0] */
    int num_b1 = 0, num_b0 = 0;

    for (int t = 0; t < num_trials; t++) {
        rand_bytes(seed, seed_bytes);
        size_t produced = 0;
        prg_evaluate(g, seed, n, prg_out, &produced);
        rand_bytes(uniform_out, out_bytes);

        int b = rand_bit();
        DistributionSample* challenge = dsample_create(out_bits);
        if (!challenge) continue;

        if (b == 0) {
            memcpy(challenge->data, uniform_out, out_bytes);
            num_b0++;
        } else {
            memcpy(challenge->data, prg_out, out_bytes);
            num_b1++;
        }
        if (out_bits % 8 != 0) {
            uint8_t mask = (uint8_t)((1 << (out_bits % 8)) - 1);
            challenge->data[out_bytes - 1] &= mask;
        }

        int guess = dist_evaluate(adv, challenge);
        if (b == 1 && guess == 1) cnt_adv1_b1 += 1.0;
        if (b == 0 && guess == 1) cnt_adv1_b0 += 1.0;
        dsample_free(challenge);
    }

    free(prg_out); free(uniform_out); free(seed);

    game.num_trials = num_trials;
    /* Advantage = |Pr[adv=1|b=1] - Pr[adv=1|b=0]| */
    double p1 = (num_b1 > 0) ? cnt_adv1_b1 / (double)num_b1 : 0.0;
    double p0 = (num_b0 > 0) ? cnt_adv1_b0 / (double)num_b0 : 0.0;
    game.advantage = fabs(p1 - p0);
    return game;
}

void prg_security_game_print(const PRGSecurityGame* game) {
    if (!game) return;
    printf("=== PRG Security Game ===\n");
    printf("Trials: %d\n", game->num_trials);
    printf("Advantage: %.6f\n", game->advantage);
    printf("Secure (adv<0.1): %s\n", game->advantage < 0.1 ? "MAYBE" : "NO");
}

/* ================================================================
 * Trivial PRG: G(s) = s || ~s (complement)
 *
 * Obviously insecure: adversary can check if second half == ~first half.
 * Pr[uniform passes] = 2^{-n}, Pr[PRG output passes] = 1.
 * Advantage ~= 1.
 *
 * Purpose: Pedagogical baseline for what a BROKEN PRG looks like.
 * ================================================================ */

static size_t trivial_stretch_fn(size_t seed_bits) {
    return seed_bits; /* stretch = n, output = 2n bits */
}

static void trivial_prg_eval_fn(const PRG* g,
                                 const uint8_t* seed, size_t seed_bits,
                                 uint8_t* output, size_t* output_bits) {
    (void)g;
    size_t sb = (seed_bits + 7) / 8;
    size_t out_bits = seed_bits * 2;
    size_t ob = (out_bits + 7) / 8;

    memset(output, 0, ob);
    memcpy(output, seed, sb);
    for (size_t i = 0; i < sb && sb + i < ob; i++)
        output[sb + i] = (uint8_t)(~seed[i]);

    if (seed_bits % 8 != 0) {
        uint8_t m1 = (uint8_t)((1 << (seed_bits % 8)) - 1);
        output[sb - 1] &= m1;
        uint8_t m2 = m1;
        if (sb < ob) output[sb] &= m2;
    }
    *output_bits = out_bits;
}

PRG* prg_create_trivial(void) {
    return prg_create("TrivialPRG", trivial_stretch_fn, trivial_prg_eval_fn, NULL);
}

/* == PRG_END_PART1 == */

/* ================================================================
 * LCG-based PRG (Insecure)
 *
 * X_{i+1} = (a * X_i + c) mod m
 * NOT cryptographically secure — state recoverable from output.
 * Demonstrates gap between statistical and cryptographic PRGs.
 * ================================================================ */

typedef struct {
    uint64_t multiplier, increment, modulus, state;
} LCGState;

static size_t lcg_stretch_fn(size_t seed_bits) {
    (void)seed_bits;
    return 256; /* produce 256 extra pseudorandom bits */
}

static void lcg_prg_eval_fn(const PRG* g,
                             const uint8_t* seed, size_t seed_bits,
                             uint8_t* output, size_t* output_bits) {
    if (!g || !g->state || !seed || !output || !output_bits) return;
    LCGState* lcg = (LCGState*)g->state;
    lcg->state = 0;
    size_t sb = (seed_bits + 7) / 8;
    memcpy(&lcg->state, seed, (sb < 8) ? sb : 8);
    if (lcg->state == 0) lcg->state = 1;

    size_t total_bits = seed_bits + 256;
    size_t total_bytes = (total_bits + 7) / 8;
    memset(output, 0, total_bytes);
    memcpy(output, seed, sb);

    size_t bits_done = seed_bits;
    size_t bo = sb;
    while (bits_done < total_bits) {
        lcg->state = (lcg->multiplier * lcg->state + lcg->increment) % lcg->modulus;
        for (int s = 0; s < 64 && bits_done < total_bits; s += 8) {
            if (bo < total_bytes) {
                output[bo++] = (uint8_t)((lcg->state >> s) & 0xFF);
                bits_done += 8;
            }
        }
    }
    *output_bits = total_bits;
}

PRG* prg_create_lcg(uint64_t a, uint64_t c, uint64_t m) {
    LCGState* st = (LCGState*)malloc(sizeof(LCGState));
    if (!st) return NULL;
    st->multiplier = a; st->increment = c; st->modulus = m; st->state = 1;
    return prg_create("LCG-PRG", lcg_stretch_fn, lcg_prg_eval_fn, st);
}

/* ================================================================
 * Hash-Chain PRG (Random Oracle Model)
 *
 * G(s) = H(s||0) || H(s||1) || ... || H(s||k-1)
 * Provably secure in the random oracle model if H is a RO.
 * Basis of CTR_DRBG (NIST SP 800-90A) and HKDF (RFC 5869).
 * ================================================================ */

typedef struct { size_t num_blocks; } HCState;

static uint64_t simple_hash(const uint8_t* d, size_t n, uint64_t salt) {
    uint64_t h = 5381ULL ^ salt;
    for (size_t i = 0; i < n; i++) h = ((h << 5) + h) + (uint64_t)d[i];
    h ^= (h >> 33); h *= 0xFF51AFD7ED558CCDULL;
    h ^= (h >> 33); h *= 0xC4CEB9FE1A85EC53ULL;
    h ^= (h >> 33);
    return h;
}

static size_t hc_stretch_fn(size_t sb) { (void)sb; return 64; }

static void hc_prg_eval_fn(const PRG* g,
                            const uint8_t* seed, size_t seed_bits,
                            uint8_t* output, size_t* output_bits) {
    if (!g || !g->state || !seed || !output || !output_bits) return;
    HCState* hcs = (HCState*)g->state;
    size_t sb = (seed_bits + 7) / 8;
    size_t bb = 64, tb = seed_bits + hcs->num_blocks * bb;
    size_t tby = (tb + 7) / 8;
    memset(output, 0, tby);
    memcpy(output, seed, sb);

    uint8_t* buf = (uint8_t*)malloc(sb + 8);
    if (!buf) { *output_bits = seed_bits; return; }
    memcpy(buf, seed, sb);

    for (size_t b = 0; b < hcs->num_blocks; b++) {
        uint64_t ctr = (uint64_t)b;
        memcpy(buf + sb, &ctr, 8);
        uint64_t h = simple_hash(buf, sb + 8, 0xDEADBEEFULL);
        size_t off = sb + b * 8;
        for (int j = 0; j < 8 && off + j < tby; j++)
            output[off + j] = (uint8_t)((h >> (j * 8)) & 0xFF);
    }
    free(buf);
    *output_bits = tb;
}

PRG* prg_create_hash_chain(size_t num_blocks) {
    HCState* st = (HCState*)malloc(sizeof(HCState));
    if (!st) return NULL;
    st->num_blocks = num_blocks;
    PRG* g = (PRG*)malloc(sizeof(PRG));
    if (!g) { free(st); return NULL; }
    g->name = _strdup("HashChainPRG");
    g->stretch = hc_stretch_fn;
    g->evaluate = hc_prg_eval_fn;
    g->state = st;
    return g;
}

/* ================================================================
 * XorShift PRG (Insecure but fast)
 *
 * xorshift128+ by Vigna (2015). Period ~2^128.
 * Predictable: 2-3 consecutive outputs suffice to recover state.
 * Illustrates limitation of statistical testing for crypto security.
 * ================================================================ */

typedef struct { uint64_t s[2]; } XSState;

static size_t xs_stretch_fn(size_t sb) { (void)sb; return 256; }

static void xs_prg_eval_fn(const PRG* g,
                            const uint8_t* seed, size_t seed_bits,
                            uint8_t* output, size_t* output_bits) {
    if (!g || !g->state || !seed || !output || !output_bits) return;
    XSState* xs = (XSState*)g->state;
    size_t sb = (seed_bits + 7) / 8;
    xs->s[0] = 0; xs->s[1] = 0;
    memcpy(&xs->s[0], seed, (sb < 8) ? sb : 8);
    if (sb > 8) memcpy(&xs->s[1], seed+8, (sb-8 < 8) ? (sb-8) : 8);
    if (xs->s[0]==0 && xs->s[1]==0) xs->s[0]=1;

    size_t tb = seed_bits + 256, tby = (tb + 7) / 8;
    memset(output, 0, tby);
    memcpy(output, seed, sb);
    size_t bd = seed_bits, bo = sb;

    while (bd < tb) {
        uint64_t s1 = xs->s[0], s0 = xs->s[1];
        xs->s[0] = s0;
        s1 ^= s1 << 23;
        xs->s[1] = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5);
        uint64_t v = xs->s[1] + s0;
        for (int j = 0; j < 8 && bd < tb; j++) {
            if (bo < tby) { output[bo++] = (uint8_t)(v & 0xFF); v >>= 8; bd += 8; }
        }
    }
    *output_bits = tb;
}

PRG* prg_create_xorshift(uint64_t init) {
    XSState* st = (XSState*)malloc(sizeof(XSState));
    if (!st) return NULL;
    st->s[0] = init; st->s[1] = init ^ 0x9E3779B97F4A7C15ULL;
    return prg_create("XorShiftPRG", xs_stretch_fn, xs_prg_eval_fn, st);
}

/* ================================================================
 * BMY Construction: PRG Length Extension
 * ================================================================ */

typedef struct { PRG* base_prg; size_t k; } BMYState;

static size_t bmy_stretch_fn(size_t sb) { (void)sb; return 0; }

static void bmy_prg_eval_fn(const PRG* g,
                             const uint8_t* seed, size_t seed_bits,
                             uint8_t* output, size_t* output_bits) {
    if (!g || !g->state || !seed || !output || !output_bits) return;
    BMYState* bmy = (BMYState*)g->state;
    PRG* base = bmy->base_prg;
    size_t k = bmy->k, n = seed_bits;
    size_t obits = n + k, obytes = (obits + 7) / 8;
    size_t sbytes = (n + 7) / 8;
    uint8_t* st = (uint8_t*)calloc(sbytes + 16, 1);
    uint8_t* bo = (uint8_t*)calloc(sbytes * 2 + 16, 1);
    if (!st || !bo) { free(st); free(bo); return; }
    memcpy(st, seed, sbytes);
    memset(output, 0, obytes);
    size_t col = 0;
    for (size_t i = 0; i < k; i++) {
        size_t bob = 0;
        prg_evaluate(base, st, n, bo, &bob);
        memcpy(st, bo, sbytes);
        size_t extra = bob - n;
        for (size_t j = 0; j < extra && col < k; j++) {
            size_t bp = n + j, bi = bp/8, bj = 7-(bp%8);
            int bit = (bi < (bob+7)/8) ? ((bo[bi]>>bj)&1) : 0;
            size_t obi = col/8, obj = 7-(col%8);
            if (obi < obytes) {
                if (bit) output[obi] |= (1U << obj);
                else output[obi] &= (uint8_t)(~(1U << obj));
            }
            col++;
        }
    }
    for (size_t j = 0; j < sbytes*8 && col < obits; j++) {
        size_t bi = j/8, bj = 7-(j%8);
        int bit = (bi < sbytes) ? ((st[bi]>>bj)&1) : 0;
        size_t obi = col/8, obj = 7-(col%8);
        if (obi < obytes) {
            if (bit) output[obi] |= (1U << obj);
            else output[obi] &= (uint8_t)(~(1U << obj));
        }
        col++;
    }
    *output_bits = obits;
    free(st); free(bo);
}

PRG* prg_bmy_extend(const PRG* base_prg, size_t k) {
    if (!base_prg || k == 0) return NULL;
    BMYState* bs = (BMYState*)malloc(sizeof(BMYState));
    if (!bs) return NULL;
    PRG* bc = (PRG*)malloc(sizeof(PRG));
    if (!bc) { free(bs); return NULL; }
    memcpy(bc, base_prg, sizeof(PRG));
    bc->name = base_prg->name ? _strdup(base_prg->name) : NULL;
    bs->base_prg = bc; bs->k = k;
    PRG* g = (PRG*)malloc(sizeof(PRG));
    if (!g) { free(bc->name); free(bc); free(bs); return NULL; }
    g->name = _strdup("BMY-Extended-PRG");
    g->stretch = bmy_stretch_fn;
    g->evaluate = bmy_prg_eval_fn;
    g->state = bs;
    return g;
}

/* ================================================================
 * BMY Hybrid Sequence
 * ================================================================ */

typedef struct { PRG* base_prg; size_t i, n, k; } HybridData;

static size_t hybrid_out_len_fn(security_param_t n) { return n + 32; }

static void hybrid_sample_fn(const DistributionEnsemble* ens,
                              security_param_t pn, DistributionSample* out) {
    if (!ens || !ens->aux_data || !out) return;
    HybridData* hd = (HybridData*)ens->aux_data;
    size_t n = hd->n, k = hd->k, i = hd->i, total = n + k;
    size_t sbytes = (n + 7) / 8;
    (void)pn;
    memset(out->data, 0, out->byte_length);
    for (size_t b = 0; b < i && b < total; b++) {
        if (rand_bit()) {
            size_t bi8 = b/8, bj8 = 7-(b%8);
            if (bi8 < out->byte_length) out->data[bi8] |= (1U << bj8);
        }
    }
    uint8_t* st = (uint8_t*)calloc(sbytes + 16, 1);
    uint8_t* bo = (uint8_t*)calloc(sbytes*2 + 16, 1);
    if (!st || !bo) { free(st); free(bo); return; }
    rand_bytes(st, sbytes);
    for (size_t step = 0; step < i; step++) {
        size_t bob = 0;
        prg_evaluate(hd->base_prg, st, n, bo, &bob);
        memcpy(st, bo, sbytes);
    }
    for (size_t b = 0; b < total - i; b++) {
        size_t sbi = b/8, sbj = 7-(b%8);
        int bit = (sbi < sbytes) ? ((st[sbi]>>sbj)&1) : rand_bit();
        size_t obi = (i+b)/8, obj = 7-((i+b)%8);
        if (obi < out->byte_length) {
            if (bit) out->data[obi] |= (1U << obj);
            else out->data[obi] &= (uint8_t)(~(1U << obj));
        }
    }
    free(st); free(bo);
}

HybridSequence* prg_bmy_hybrid_sequence(const PRG* base_prg,
                                          security_param_t n, size_t k) {
    if (!base_prg || k == 0) return NULL;
    HybridSequence* hs = hseq_create((int)k + 1);
    if (!hs) return NULL;
    PRG* bc = (PRG*)malloc(sizeof(PRG));
    if (!bc) { hseq_free(hs); return NULL; }
    memcpy(bc, base_prg, sizeof(PRG));
    for (size_t i = 0; i <= k; i++) {
        HybridData* hd = (HybridData*)malloc(sizeof(HybridData));
        if (!hd) continue;
        hd->base_prg = bc; hd->i = i; hd->n = n; hd->k = k;
        char nm[32];
        snprintf(nm, sizeof(nm), "H_%zu", i);
        DistributionEnsemble* ens =
            dens_create(nm, hybrid_out_len_fn, hybrid_sample_fn, hd);
        if (ens) hseq_add(hs, ens);
        else free(hd);
    }
    return hs;
}

HybridArgumentResult* prg_bmy_verify_hybrid(const PRG* base_prg,
                                              security_param_t n,
                                              size_t k, int num_trials) {
    HybridSequence* hs = prg_bmy_hybrid_sequence(base_prg, n, k);
    if (!hs) return NULL;
    double eps = 1.0 / (double)k;
    HybridArgumentResult* r = hybrid_arg_verify(hs, n, num_trials, eps);
    for (int i = 0; i < hseq_length(hs); i++) {
        DistributionEnsemble* e = hseq_get(hs, i);
        if (e) { if (e->aux_data) free(e->aux_data); dens_free(e); }
    }
    hseq_free(hs);
    return r;
}

/* ================================================================
 * Stream Cipher from PRG (L7 Application)
 * ================================================================ */

void prg_stream_xor(const PRG* g,
                     const uint8_t* key, size_t key_bits,
                     const uint8_t* input, size_t input_bits,
                     uint8_t* output) {
    if (!g || !key || !input || !output || input_bits == 0) return;
    size_t ib = (input_bits + 7) / 8;
    uint8_t* ks = (uint8_t*)calloc(ib, 1);
    if (!ks) return;
    size_t ksb = 0;
    prg_evaluate(g, key, key_bits, ks, &ksb);
    for (size_t i = 0; i < ib; i++) output[i] = input[i] ^ ks[i];
    if (input_bits % 8 != 0) {
        uint8_t mask = (uint8_t)((1 << (input_bits % 8)) - 1);
        output[ib - 1] &= mask;
    }
    free(ks);
}

/* ================================================================
 * Key Derivation Function (L7 Application)
 * ================================================================ */

int prg_kdf_derive(const PRG* g,
                    const uint8_t* mk, size_t mk_bits,
                    const uint8_t* salt, size_t salt_bits,
                    uint8_t* sub_key, size_t sub_key_bits) {
    if (!g || !mk || !sub_key || sub_key_bits == 0) return -1;
    size_t sb = (salt_bits + 7) / 8, mb = (mk_bits + 7) / 8;
    size_t tb = salt_bits + mk_bits, tby = (tb + 7) / 8;
    uint8_t* seed = (uint8_t*)calloc(tby, 1);
    if (!seed) return -1;
    if (salt && salt_bits > 0) memcpy(seed, salt, sb);
    memcpy(seed + sb, mk, mb);
    size_t ob = (sub_key_bits + 7) / 8;
    uint8_t* out = (uint8_t*)calloc(ob, 1);
    if (!out) { free(seed); return -1; }
    size_t obits = 0;
    prg_evaluate(g, seed, tb, out, &obits);
    memcpy(sub_key, out, ob);
    if (sub_key_bits % 8 != 0) {
        uint8_t mask = (uint8_t)((1 << (sub_key_bits % 8)) - 1);
        sub_key[ob - 1] &= mask;
    }
    free(seed); free(out);
    return 0;
}

/* ================================================================
 * PRG Output Statistical Analysis
 * ================================================================ */

PRGStatistics prg_analyze_output(const PRG* g,
                                  const uint8_t* seed, size_t seed_bits) {
    PRGStatistics stats;
    memset(&stats, 0, sizeof(stats));
    if (!g || !seed) return stats;
    size_t ob = 2048;
    uint8_t* out = (uint8_t*)calloc((ob+7)/8, 1);
    if (!out) return stats;
    size_t out_bits = 0;
    prg_evaluate(g, seed, seed_bits, out, &out_bits);
    if (out_bits > ob) out_bits = ob;
    size_t ones = 0;
    for (size_t i = 0; i < out_bits; i++)
        if ((out[i/8] >> (7-(i%8))) & 1) ones++;
    stats.mean_bit_fraction = (double)ones / (double)out_bits;
    stats.num_runs = 1;
    for (size_t i = 1; i < out_bits; i++) {
        int cur = (out[i/8] >> (7-(i%8))) & 1;
        int prev = (out[(i-1)/8] >> (7-((i-1)%8))) & 1;
        if (cur != prev) stats.num_runs++;
    }
    size_t bins[256] = {0};
    size_t ns = out_bits / 8;
    for (size_t i = 0; i < ns && i < 256; i++) bins[out[i]]++;
    if (ns > 0) {
        double H = 0.0;
        for (int b = 0; b < 256; b++) {
            if (bins[b] > 0) {
                double p = (double)bins[b] / (double)ns;
                H -= p * log2(p);
            }
        }
        stats.entropy_estimate = H;
    }
    stats.output_bits = out_bits;
    free(out);
    return stats;
}
