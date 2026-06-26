#ifndef ASSUMPTION_HIERARCHY_H
#define ASSUMPTION_HIERARCHY_H
#include "minimal_assumptions.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    CryptoPrimitive prim;
    int is_minimal;
    CryptoPrimitive* weaker_than;
    int n_weaker;
    CryptoPrimitive* stronger_than;
    int n_stronger;
    const char* standard_construction;
} PrimitiveNode;

typedef struct {
    PrimitiveNode* nodes;
    int n_nodes;
    ReductionEdge* reductions;
    int n_reductions;
    ReductionEdge* separations;
    int n_separations;
} CryptoLandscape;

CryptoLandscape* cl_create(void);
void cl_free(CryptoLandscape* cl);
int cl_is_minimal(const CryptoLandscape* cl, CryptoPrimitive p);
int cl_find_minimal_for(const CryptoLandscape* cl, CryptoPrimitive target,
                        CryptoPrimitive** result, int* n_result);
void cl_print_hierarchy(const CryptoLandscape* cl);
void cl_print_minimality_proof(const CryptoLandscape* cl, CryptoPrimitive p);
double cl_hierarchy_depth(const CryptoLandscape* cl);
int cl_primitive_rank(const CryptoLandscape* cl, CryptoPrimitive p);
void cl_check_consistency(const CryptoLandscape* cl);

#ifdef __cplusplus
}
#endif
#endif
