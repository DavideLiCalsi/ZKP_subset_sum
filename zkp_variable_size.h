#ifndef ZKP_VAR_H
#define ZKP_VAR_H

#include <openssl/bn.h>
#include "pedersen.h"
#include "zkp_fixed_size.h"

#define N_VAR 256

BIGNUM** pad_with_zeros(BIGNUM** a, int n){

    BIGNUM** new_a = (BIGNUM**) malloc(sizeof(BIGNUM*)*(2*n));

    for(int i=0; i<2*n;++i){
        new_a[i]=BN_new();

        if (i<n)
            BN_copy(new_a[i],a[i]);
    }

    return new_a;
}

char* pad_with_zeros_solution(char* a, int n){

    char* new_a = (char*) malloc(sizeof(char)*(2*n));

    for(int i=0; i<2*n;++i){
        new_a[i]= i<n? a[i] : 0;

        if ( i >= n && i < n + (n-K) )
            new_a[i]=1;
    }
    

    return new_a;
}

PED_commitment** PROVER_commits_variable(BIGNUM** a, PED_params* params, BN_CTX* ctx){

    PED_commitment** commitments = (PED_commitment**) malloc(sizeof(PED_commitment*) * N_VAR*2);


    for (int i=0; i<N_VAR*2; ++i){
        commitments[i] = pedersen_commit(a[i],params->p,params->g,params->h,ctx);
    }

    return commitments;
}

/**
 * The prover opens one his two initial commitments
 * @param c: array of commitments
 * @param a: array of values the prover committed to
 * @param s: array of randomnesses used by the prover
 * @param p: the prime used to implement Pedersen commitments
 * @param g: first generator
 * @param h: second generator
 */
bool PROVER_opens_variable(BIGNUM** c, BIGNUM** a, BIGNUM** s, BIGNUM* p, BIGNUM* g, BIGNUM* h, BN_CTX* ctx){

    bool is_success;

    for(int i=0; i<N_VAR*2; ++i){
        is_success = pederesen_unveil(c[i],s[i],a[i],p,g,h,ctx);

        if (!is_success){
            printf("Failed opening %d-th commitment.\n",i);
            return false;
        }
    }

    return true;
}

/**
 * Computes the homomorphic sum of elements included in the solution
 * @param c: Array of commitments
 * @param solution: Permuted solutions
 * @param mod: Modulus
 * @param ctx: OpenSSL context 
 */
BIGNUM* VERIFIER_homomorphic_sum_variable(BIGNUM** c, char* solution, BIGNUM* prime, BN_CTX* ctx){

    BN_CTX_start(ctx);

    BIGNUM* prod = BN_new();
    
    BN_add(prod,prod,BN_value_one());
    
    for( int i=0; i<N_VAR*2;++i){
        if (solution[i]==1){
            BN_mod_mul(prod,prod,c[i],prime,ctx);
        }
    }

    BN_CTX_end(ctx);

    return prod;
}

#endif