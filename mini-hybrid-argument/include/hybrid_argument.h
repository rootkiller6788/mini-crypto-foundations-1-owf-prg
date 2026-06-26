/*
 * hybrid_argument.h - Hybrid Argument: Core Framework and Types
 *
 * The hybrid argument is the fundamental proof technique in modern
 * cryptography for establishing computational indistinguishability.
 * Introduced by Goldwasser and Micali (1982/84) and systematized by
 * Goldreich (1993), it reduces proving that two "far apart" distributions
 * are indistinguishable to proving that adjacent "hybrid" distributions
 * are indistinguishable.
 *
 * L1 Definitions: Hybrid Sequence, Hybrid Argument, Advantage
 * L2 Core Concepts: Computational indist., statistical indist.
 * L3 Math Structures: Distribution ensemble, PPT distinguisher
 * L4 Fundamental Laws: Hybrid Argument Lemma, Triangle Inequality
 *
 * Reference:
 *   Goldwasser & Micali (1984) "Probabilistic Encryption"
 *   Goldreich (2001) "Foundations of Cryptography" Vol 1
 *   Arora & Barak (2009) Section 9.2-9.3
 *   Katz & Lindell (2014) "Introduction to Modern Cryptography" Ch 3
 *
 * Courses: MIT 6.875, Stanford CS355, Princeton COS 522, Berkeley CS276
 */

#ifndef HYBRID_ARGUMENT_H
#define HYBRID_ARGUMENT_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <stdio.h>

/* ================================================================
 * Security Parameter
 * ================================================================ */

typedef uint32_t security_param_t;

/* ================================================================
 * Negligible Functions
 *
 * mu: N -> R is negligible if for every polynomial p, there exists N
 * such that for all n > N: mu(n) < 1/p(n).
 * ================================================================ */

typedef enum {
    NEGL_TYPE_EXP,          /* 2^{-n} */
    NEGL_TYPE_SUPERPOLY,    /* n^{-log n} */
    NEGL_TYPE_EXP_SQRT,     /* 2^{-sqrt(n)} */
    NEGL_TYPE_NEAR_EXP,     /* n * 2^{-n} */
    NEGL_TYPE_EXP_NEGL,     /* 2^{-n/2} */
    NEGL_TYPE_CUSTOM
} NegligibleType;

typedef double (*negligible_fn)(security_param_t n);

typedef struct {
    NegligibleType type;
    double         coefficient;
    negligible_fn  custom_fn;
} NegligibleFunction;

double negl_eval(const NegligibleFunction* negl, security_param_t n);
NegligibleFunction negl_exp(void);
NegligibleFunction negl_superpoly(void);
NegligibleFunction negl_exp_sqrt(void);
NegligibleFunction negl_near_exp(void);
int negl_is_negligible(const NegligibleFunction* negl, security_param_t n,
                        double threshold);
const char* negl_type_name(NegligibleType t);

/* ================================================================
 * Distribution Ensembles
 *
 * {X_n}_{n in N} where X_n is a distribution over {0,1}^{l(n)}.
 * ================================================================ */

typedef struct {
    uint8_t* data;
    size_t   length;
    size_t   byte_length;
} DistributionSample;

DistributionSample* dsample_create(size_t bit_length);
DistributionSample* dsample_clone(const DistributionSample* src);
void                dsample_free(DistributionSample* s);
int                 dsample_cmp(const DistributionSample* a,
                                const DistributionSample* b);
void                dsample_randomize(DistributionSample* s);
void                dsample_fprint(FILE* f, const DistributionSample* s);

typedef struct DistributionEnsemble DistributionEnsemble;

typedef void (*ensemble_sampler_fn)(const DistributionEnsemble* ens,
                                     security_param_t n,
                                     DistributionSample* out);

struct DistributionEnsemble {
    char*              name;
    size_t             (*output_length)(security_param_t n);
    ensemble_sampler_fn sample;
    void*              aux_data;
};

DistributionEnsemble* dens_create(const char* name,
                                   size_t (*output_len)(security_param_t n),
                                   ensemble_sampler_fn sample_fn,
                                   void* aux_data);
void dens_free(DistributionEnsemble* ens);
void dens_sample(const DistributionEnsemble* ens,
                 security_param_t n,
                 DistributionSample* out);

/* ================================================================
 * PPT Distinguisher
 *
 * D: {0,1}* -> {0,1} is a PPT algorithm.
 * Adv_D(X,Y) = |Pr_{x<-X}[D(x)=1] - Pr_{y<-Y}[D(y)=1]|
 * ================================================================ */

typedef struct Distinguisher Distinguisher;

typedef int (*distinguisher_fn)(const Distinguisher* D,
                                 const DistributionSample* x);

struct Distinguisher {
    char*             name;
    distinguisher_fn  evaluate;
    void*             state;
    size_t            time_complexity;
};

Distinguisher* dist_create(const char* name,
                            distinguisher_fn eval_fn,
                            void* state,
                            size_t time_complexity);
void dist_free(Distinguisher* D);
int  dist_evaluate(const Distinguisher* D, const DistributionSample* x);
double dist_estimate_advantage(const Distinguisher* D,
                                const DistributionEnsemble* X,
                                const DistributionEnsemble* Y,
                                security_param_t n,
                                int num_trials,
                                double* confidence_half_width);

/* ================================================================
 * Hybrid Sequence
 *
 * H_0, H_1, ..., H_m a sequence of distribution ensembles.
 * ================================================================ */

typedef struct HybridSequence HybridSequence;

struct HybridSequence {
    DistributionEnsemble** hybrids;
    int                    num_hybrids;
    int                    capacity;
};

HybridSequence* hseq_create(int capacity);
void            hseq_free(HybridSequence* hs);
int             hseq_add(HybridSequence* hs, DistributionEnsemble* hybrid);
int             hseq_length(const HybridSequence* hs);
DistributionEnsemble* hseq_get(const HybridSequence* hs, int index);

/* ================================================================
 * Hybrid Argument Lemma
 *
 * If Adv_D(H_i, H_{i+1}) <= epsilon(n) for all i, then
 * Adv_D(H_0, H_m) <= m * epsilon(n).
 * ================================================================ */

typedef struct {
    int     num_hybrids;
    double  pairwise_epsilon;
    double  overall_bound;
    int     passes_bound;
    double* pairwise_advantages;
    double  measured_total;
} HybridArgumentResult;

HybridArgumentResult* hybrid_arg_verify(const HybridSequence* hs,
                                          security_param_t n,
                                          int num_trials,
                                          double epsilon);
void hybrid_arg_result_free(HybridArgumentResult* r);
void hybrid_arg_result_print(const HybridArgumentResult* r);

/* ================================================================
 * Statistical Distance
 *
 * Delta(X,Y) = (1/2) * sum |Pr[X=w] - Pr[Y=w]|
 * ================================================================ */

double stat_dist_estimate(const DistributionEnsemble* X,
                           const DistributionEnsemble* Y,
                           security_param_t n,
                           int num_trials);
double stat_dist_uniform_vs_biased(double bias);
int stat_dist_triangle_inequality(double d_xy, double d_yz, double d_xz);

/* ================================================================
 * Utility RNG (not cryptographically secure - for demo only)
 * ================================================================ */

void rand_seed(uint64_t seed);
uint64_t rand_next(void);
uint8_t rand_bit(void);
void rand_bytes(uint8_t* buf, size_t nbytes);

/* ================================================================
 * Entropy Estimation (L3: Mathematical Structures)
 * ================================================================ */

double shannon_entropy_estimate(const DistributionSample** samples,
                                 int num_samples);
double min_entropy_estimate(const DistributionSample** samples,
                             int num_samples);
double collision_entropy_estimate(const DistributionSample** samples,
                                   int num_samples);

/* ================================================================
 * Statistical Tests for Distribution Comparison (L5: Algorithms)
 * ================================================================ */

double ks_statistic(const DistributionSample** samples_a, int num_a,
                     const DistributionSample** samples_b, int num_b);
double chi_squared_two_sample(const DistributionSample** samples_a, int num_a,
                               const DistributionSample** samples_b, int num_b,
                               size_t num_bins);
double kullback_leibler_divergence(const DistributionSample** sam_p, int np,
                                    const DistributionSample** sam_q, int nq,
                                    size_t num_bins);
double correlation_coefficient(const DistributionSample** sx,
                                const DistributionSample** sy, int n);

#endif /* HYBRID_ARGUMENT_H */