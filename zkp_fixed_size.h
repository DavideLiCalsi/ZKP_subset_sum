#ifndef ZKP_FIXED_H
#define ZKP_FIXED_H

#include <openssl/bn.h>
#include "pedersen.h"

#define N_FIXED 256
#define K 16

typedef struct instance
{
    /* data */
    BIGNUM** a;
    BIGNUM* S;
    BIGNUM* M;
    char* solution;
} KSS_instance;

typedef unsigned short * permutation;

typedef struct PROVER_data
{
    /* data */
    char* p1;
    char* p2;
    PED_commitment** commitment_1;
    PED_commitment** commitment_2;
    KSS_instance* instance;
} PROVER_data;

typedef struct VERIFIER_data
{
    /* data */
    PED_commitment** commitment_1;
    PED_commitment** commitment_2;
    KSS_instance* instance;
} VERIFIER_data;


/**
 * Creates an identity permutation on size elements
 */
permutation permutation_init(int size){

    permutation permutation = (unsigned short*) malloc(sizeof(unsigned short)*size);

    for(unsigned short i=0; i<size;++i){
        permutation[i]=i;
    }

    return permutation;
}

/**
 * Destroys an existing permutation
 */
void permutation_free(permutation p){
    free(p);
}

/**
 * Generates a random permutation on size elements.
 */
permutation permutation_get_random(int size){
    permutation p = permutation_init(size);
    Fisher_Yates_shuffle_perm(&p,size);
    return p;
}

/**
 * Prints a given permutation
 */
void permutation_print(permutation p, int size){

    for(int i=0; i<size;++i){
        printf("%hu, ", p[i]);
    }
    printf("\n");
}

/**
 * Applies a given permutation on an array of BIGNUM
 * @param array: The array to permute
 * @param p: The permutation to apply
 * @param size: Size of array and p
 */
BIGNUM** permutation_apply(BIGNUM** array, permutation p, int size){
    
    unsigned short i,new_index;
    BIGNUM** new = (BIGNUM**) malloc(sizeof(BIGNUM*)*size);

    for(i=0;i<size;++i){
        new_index=p[i];
        new[i]= BN_new();
        BN_copy(new[i],array[new_index]);
    }

    for(i=0;i<size;++i){
        if ( BN_cmp(new[i],array[ p[i]]) != 0)
            printf("Error in position %d\n",i);
    }

    return new;
}

/**
 * Applies a given permutation on an array representing a solution
 * @param array: The array to permute
 * @param p: The permutation to apply
 * @param size: Size of array and p
 */
char* permutation_apply_sol(char* array, permutation p, int size){
    
    unsigned int i,new_index;
    char* new = (char*) malloc(sizeof(char)*size);

    for(i=0;i<size;++i){
        new_index= p[i];
        new[i]=array[new_index];
    }

    return new;
}

/**
 * Applies the Fisher-Yates shuffle to an array of n elements
 * @param a: pointer to the array to shuffle
 * @param n: size of the array to shuffle
 */
void Fisher_Yates_shuffle(char** a, int n){

    char temp;
    int i;

    for(i=0;i<=n-2;i++){
        int j = i + ( rand() % (n - i) );
        temp = (*a)[i];
        (*a)[i]=(*a)[j];
        (*a)[j]=temp;
    }
}

/**
 * Applies the Fisher-Yates shuffle to an array of n elements
 * @param a: pointer to the array to shuffle
 * @param n: size of the array to shuffle
 */
void Fisher_Yates_shuffle_perm(permutation* a, int n){

    unsigned short temp;
    int i;

    for(i=0;i<=n-2;i++){
        int j = i + ( rand() % (n - i) );
        temp = (*a)[i];
        (*a)[i]=(*a)[j];
        (*a)[j]=temp;
    }
}

/**
 * Prints in binary form the solution to a yes-instance of the subset sum problem
 */
void print_solution(char* a, int n){

    fputs("Solution: ",stdout);
    for(int i=0;i<n;++i){

        if (a[i]==0)
            putchar('0');
        else if (a[i]==1)
        {
           putchar('1');
        }
    }
    putchar('\n');
}

/**
 * Generates a random yes-instance of the Size Modular Subset-Sum problem
 * @param M: The chosen modulo
 * @param ctx: OpenSSL context to use
 */
KSS_instance* gen_instance(BIGNUM* M, BN_CTX* ctx, int n){

    KSS_instance* inst = (KSS_instance*) malloc(sizeof(KSS_instance));

    BN_CTX_start(ctx);

    puts("Generating yes instance of modular size subset sum...");

    BIGNUM** a = (BIGNUM**) malloc(sizeof(BIGNUM*)*n);
    BIGNUM** solution = (BIGNUM**) malloc(sizeof(BIGNUM*)*K);
    char* select_solution = (char*) malloc(sizeof(char)*n);

    int i;

    for(i=0;i<n;++i){
        a[i]=BN_new();
        BN_rand_range(a[i],M);
    }

    for(i=0;i<K;i++){
        select_solution[i]=1;
    }

    for(i=K;i<n;i++){
        select_solution[i]=0;
    }

    Fisher_Yates_shuffle(&select_solution,n);

    BIGNUM* S=BN_new();

    for(i=0;i<n;++i){
        if (select_solution[i]==1){
            BN_mod_add(S,S,a[i],M,ctx);
        }
    }

    inst->a=a;
    inst->M=M;
    inst->S=S;
    inst->solution=select_solution;

    BN_CTX_end(ctx);

    puts("Done");
    print_solution(inst->solution, n);
    printf("Target: 0x%s\n",BN_bn2hex(S));

    return inst;
}

bool verify_solution(KSS_instance* inst, BN_CTX* ctx){

    int i;
    BN_CTX_start(ctx);
    BIGNUM* sum=BN_new();

    for(i=0;i<N_FIXED;++i){

        if (inst->solution[i]==1)
            BN_mod_add(sum,sum,inst->a[i],inst->M,ctx);
    }

    bool res = BN_cmp(sum,inst->S) == 0;

    BN_free(sum);
    BN_CTX_end(ctx);

    return res;
}

PED_commitment** PROVER_commits(BIGNUM** a, PED_params* params, BN_CTX* ctx){

    PED_commitment** commitments = (PED_commitment**) malloc(sizeof(PED_commitment*) * N_FIXED);


    for (int i=0; i<N_FIXED; ++i){
        commitments[i] = pedersen_commit(a[i],params->p,params->g,params->h,ctx);
    }

    return commitments;
}

int VERIFIER_selects_index(){
    srand(time(NULL));
    return rand()%2;
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
bool PROVER_opens(BIGNUM** c, BIGNUM** a, BIGNUM** s, BIGNUM* p, BIGNUM* g, BIGNUM* h, BN_CTX* ctx){

    bool is_success;

    for(int i=0; i<N_FIXED; ++i){
        is_success = pederesen_unveil(c[i],s[i],a[i],p,g,h,ctx);

        if (!is_success){
            printf("Failed opening %d-th commitment.\n",i);
            return false;
        }
    }

    return true;
}

bool VERIFIER_check_permutation(BIGNUM** received, BIGNUM** claimed, permutation p, int len){

    for(int i=0; i<len;++i){

        if ( BN_cmp(received[i], claimed[p[i]]) != 0)
            return false;
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
BIGNUM* VERIFIER_homomorphic_sum(BIGNUM** c, char* solution, BIGNUM* prime, BN_CTX* ctx){

    BN_CTX_start(ctx);

    BIGNUM* prod = BN_new();
    
    BN_add(prod,prod,BN_value_one());
    
    for( int i=0; i<N_FIXED;++i){
        if (solution[i]==1){
            BN_mod_mul(prod,prod,c[i],prime,ctx);
        }
    }

    BN_CTX_end(ctx);

    return prod;
}

#endif