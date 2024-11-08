#include <stdio.h>
#include <stdbool.h>
#include <openssl/bn.h>

#include "utils.h"

#define GL_BITS 2048

struct gl_commitment
{
    BN_pair* f;
    char masked_b;
    BN_pair* inputs;
};

typedef struct gl_commitment GL_COMMIT;


// Useful constants
BIGNUM* safeprime = NULL;
BIGNUM* gen = NULL;

/*
Implementation of bit-commitment using Goldreich-Levin theorem.
*/

/**
 * Implementation of the injective one-way function used for Goldreich-Levin
 * bit commitments.
*/
BIGNUM* one_way_permutation(BIGNUM* x){
    // Parameters for modular exponentiation

    if (gen == NULL)
        BN_dec2bn(&gen,"2");


    BN_CTX* ctx = BN_CTX_new();

    if (safeprime==NULL){
        DEBUG_PRINT("Searching for safe prime...\n");
        safeprime=BN_new();
        BN_generate_prime_ex(safeprime,GL_BITS,1,NULL,NULL,NULL);
    } 

    BIGNUM* r=BN_new();

    BN_mod_exp(r,gen,x,safeprime,ctx);

    return r;
}

/**
 * Implements the g function
*/
BN_pair* g(BN_pair* input){

    BIGNUM* x = input->x;
    BIGNUM* r = input->y;

    BN_pair* result = (BN_pair*) malloc(sizeof(BN_pair));

    result->x = one_way_permutation(x);
    result->y = r;

    return result;
}

/**
 * Computation of the hard-core predicate H
*/
int H_predicate(BIGNUM* x, BIGNUM* r){

    int res = 0;

    for(int i=0; i<GL_BITS;++i){
        res ^= BN_is_bit_set(x,i) & BN_is_bit_set(r,i);
    }

    return res;
}

/**
 * Implements commitment to binary value b
*/
GL_COMMIT* gl_commit(char b){

    int res;
    GL_COMMIT* commitment = (GL_COMMIT*) malloc(sizeof(GL_COMMIT));

    BIGNUM* x = BN_new();
    BIGNUM* r = BN_new();

    DEBUG_PRINT("Generating random inputs\n");
    BN_rand(x,GL_BITS,0,0);
    BN_rand(r,GL_BITS,0,0);

    // Compute g(x,r)
    DEBUG_PRINT("Computing one-way function\n");
    BN_pair* inputs = (BN_pair*) malloc(sizeof(BN_pair));
    inputs->x=x;
    inputs->y=r;
    BN_pair* f = g(inputs);
    
    // Compute predicate H
    DEBUG_PRINT("Computing hardcore predicate\n");
    res = H_predicate(x,r);

    // Mask the commitment value
    DEBUG_PRINT("Masking commitment value\n");
    char masked = b ^ (char) res;

    // Prepare result
    commitment->f=f;
    commitment->masked_b = masked;
    commitment->inputs = inputs;

    return commitment;
}

/**
 * Verifies that the unveiled commitment is true
*/
bool gl_verify( char b, GL_COMMIT comm){

    BN_pair* computed_f = g(comm.inputs);
    int computed_h = H_predicate(comm.inputs->x,comm.inputs->y);

    if (b ^ ((char) computed_h) != comm.masked_b){
        int c1,c2;
        c1 = (int) (b ^ ((char) computed_h));
        c2 = (int) comm.masked_b;
        DEBUG_PRINT("Masked commitment values do not match! %d vs %d\n",c1,c2);
        return false;
    }

    if (BN_cmp(computed_f->x,comm.f->x) != 0 || BN_cmp(computed_f->y,comm.f->y) != 0)
    {
        DEBUG_PRINT("One-way permutation does not match!\n");

        if (BN_cmp(computed_f->x,comm.f->x) != 0){
            DEBUG_PRINT("Failed x comparison\n");
        }

        if (BN_cmp(computed_f->y,comm.f->y) != 0){
            DEBUG_PRINT("Failed y comparison\n");
        }
        return false;
    }
    
    return true;
}






