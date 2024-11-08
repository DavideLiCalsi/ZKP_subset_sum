#include "pedersen.h"
#include "zkp_fixed_size.h"
#include "zkp_variable_size.h"
#include <openssl/bn.h>

#include <time.h>
#include <stdlib.h>
#include <intrin.h>

#pragma intrinsic(__rdtsc)

#define SHOTS 1000

#define CPU_FREQ 2100000000

//#define DEBUG

#ifdef DEBUG
#define PRINTF printf
#define PUTS puts
#else
#define PRINTF // macros
#define PUTS // macros
#endif

int main(){

    BN_CTX* ctx = BN_CTX_new();

    PED_params* param = pedersen_get_param(ctx); //pedersen_init(ctx);

    BIGNUM* m = BN_new();
    BIGNUM* t= BN_new();
    BN_add(t,t,BN_value_one());

    PUTS("Testing commitment parameters...");

    BN_rand_range(m,param->p);
    
    PED_commitment* comm = pedersen_commit(m,param->p,param->g,param->h,ctx);
    bool res = pederesen_unveil(comm->c,comm->s,m,param->p,param->g,param->h,ctx);
    
    if (res){
        PUTS("Test SUCCESS!\n");
    }

    pedersen_save_param(param);
    
    BIGNUM* M = BN_new();
    BN_sub(M,param->p,BN_value_one());
    KSS_instance* inst=gen_instance(M,ctx,N_VAR);

    
    if(verify_solution(inst,ctx))
        PUTS("KSS yes-instance is correct");
    else{
        PUTS("UNSUCCESSFUL KSS instance. Aborting");
        exit(0);
    }

    //fixed_length();
    variable_length(param,inst,ctx);
    variable_length(param,inst,ctx);

    return 0;
}

void fixed_length(){
    int i;

    BN_CTX* ctx = BN_CTX_new();

    PED_params* param = pedersen_init(ctx);

    BIGNUM* m = BN_new();
    BIGNUM* t= BN_new();
    BN_add(t,t,BN_value_one());

    PUTS("Testing commitment parameters...");

    BN_rand_range(m,param->p);
    
    PED_commitment* comm = pedersen_commit(m,param->p,param->g,param->h,ctx);
    bool res = pederesen_unveil(comm->c,comm->s,m,param->p,param->g,param->h,ctx);
    
    if (res){
        PUTS("Test SUCCESS!\n");
    }
    
    BIGNUM* M = BN_new();
    BN_sub(M,param->p,BN_value_one());
    KSS_instance* inst=gen_instance(M,ctx,N_FIXED);

    
    if(verify_solution(inst,ctx))
        PUTS("KSS yes-instance is correct");

    
    unsigned __int64 begin, end;

    BIGNUM** comm_array0 = (BIGNUM**) malloc(sizeof(BIGNUM*)*N_FIXED);
    BIGNUM** comm_array1 = (BIGNUM**) malloc(sizeof(BIGNUM*)*N_FIXED);
    BIGNUM** randomnesses0 = (BIGNUM**) malloc(sizeof(BIGNUM*)*N_FIXED);
    BIGNUM** randomnesses1 = (BIGNUM**) malloc(sizeof(BIGNUM*)*N_FIXED);

    begin = __rdtsc();

    puts("\n########## FIRST STEP: PROVER ##########");
    puts("Prover generates random permutations...");
    permutation p1 = permutation_get_random(N_FIXED);
    permutation p2 = permutation_get_random(N_FIXED);
    printf("p1: ");
    permutation_print(p1,N_FIXED);
    printf("p2: ");
    permutation_print(p2,N_FIXED);

    PUTS("Prover's first commitment...");
    BIGNUM** perm_a_1 = permutation_apply(inst->a,p1,N_FIXED);
    PED_commitment** comm0 = PROVER_commits(perm_a_1,param,ctx);
    PUTS("Done");

    PUTS("Prover's second commitment...");
    BIGNUM** perm_a_2 = permutation_apply(inst->a,p2,N_FIXED);
    PED_commitment** comm1 = PROVER_commits(perm_a_2,param,ctx);
    PUTS("Done");

    PUTS("\n########## SECOND STEP: VERIFIER ##########");
    PUTS("Verifier selects random index");
    int index = VERIFIER_selects_index();
    printf("Verifier selected: %d\n",index);

    PUTS("\n########## THIRD STEP: PROVER ##########");

    // Prepare commitments to be opened

    for(i=0; i<N_FIXED;++i){
        comm_array0[i]=comm0[i]->c;
        comm_array1[i]=comm1[i]->c;
        randomnesses0[i]=comm0[i]->s;
        randomnesses1[i]=comm1[i]->s;
    }

    PUTS("Prover opens chosen commitment...");

    bool are_commitments_correct, is_permutation_correct;

    if ( index ==0 ){
        are_commitments_correct= PROVER_opens(comm_array0,perm_a_1,randomnesses0,param->p,param->g,param->h,ctx);
        is_permutation_correct = VERIFIER_check_permutation(perm_a_1, inst->a,p1,N_FIXED);
    }
    else if ( index == 1 ){
        are_commitments_correct= PROVER_opens(comm_array1,perm_a_2,randomnesses1,param->p,param->g,param->h,ctx);
        is_permutation_correct = VERIFIER_check_permutation(perm_a_2, inst->a,p2,N_FIXED);
    }
    else {
        PUTS("ERROR! Verifier selected invalid index. Aborting.");
        exit(1);
    }
    PUTS("Done");

    PUTS("\n########## FOURTH STEP: VERIFIER ##########");
    PUTS("Verifier checks commitments...");

    if (are_commitments_correct && is_permutation_correct)
        PUTS("Commitments successfully opened. No cheating detected.");
    else{
        PUTS("At least one opening failed. Aborting.");
        exit(1);
    }

    if (is_permutation_correct)
        PUTS("Checked is unveiled value is a permutation of original instance. No cheating detected.");
    else{
        PUTS("The committed array is not a permutation of the original instance. Aborting.");
        exit(1);
    }

    PUTS("\n########## FIFTH STEP: PROVER ##########");
    PUTS("Prover sending permuted solution to Verifier");
    printf("Verifier receiving ");
    char* permuted_sol = (index == 0 ? permutation_apply_sol(inst->solution,p2,N_FIXED) : permutation_apply_sol(inst->solution,p1,N_FIXED) );
    print_solution(permuted_sol,N_FIXED);

    PUTS("\n########## SIXTH STEP: VERIFIER ##########");
    BIGNUM** leftover_comms = index == 0 ? comm_array1 : comm_array0;
    BIGNUM* commitment_to_sum = VERIFIER_homomorphic_sum(leftover_comms,permuted_sol,param->p,ctx);

    PUTS("\n########## SEVENTH STEP: PROVER ##########");
    PUTS("Prover opens commitment");
    BIGNUM* sum=BN_new();
    BIGNUM** leftover_rands = index == 0 ? randomnesses1 : randomnesses0;
    char* solution= permuted_sol;

    for(i=0;i<N_FIXED;++i){
        if( solution[i]==1)
            BN_mod_add(sum,sum,leftover_rands[i], inst->M,ctx);
    }

    if ( pederesen_unveil(commitment_to_sum,sum,inst->S,param->p,param->g,param->h,ctx))
        PUTS("Verifier accepted final commitment. Proof concluded. Verifier ACCEPTS");
    else
        PUTS("Verifier rejected final commitment. Proof concluded. Verifier REJECTS");
    
    end = __rdtsc();

    printf_s("%I64d ticks\n", end-begin);
}

void variable_length(PED_params* param, KSS_instance* inst, BN_CTX* ctx){
    int i;

    /*BN_CTX* ctx = BN_CTX_new();

    PED_params* param = pedersen_get_param(ctx); //pedersen_init(ctx);

    BIGNUM* m = BN_new();
    BIGNUM* t= BN_new();
    BN_add(t,t,BN_value_one());

    PUTS("Testing commitment parameters...");

    BN_rand_range(m,param->p);
    
    PED_commitment* comm = pedersen_commit(m,param->p,param->g,param->h,ctx);
    bool res = pederesen_unveil(comm->c,comm->s,m,param->p,param->g,param->h,ctx);
    
    if (res){
        PUTS("Test SUCCESS!\n");
    }

    pedersen_save_param(param);
    
    BIGNUM* M = BN_new();
    BN_sub(M,param->p,BN_value_one());
    KSS_instance* inst=gen_instance(M,ctx,N_VAR);

    
    if(verify_solution(inst,ctx))
        PUTS("KSS yes-instance is correct");
    else{
        PUTS("UNSUCCESSFUL KSS instance. Aborting");
        exit(0);
    }
    */
    
    unsigned __int64 begin, end;

    BIGNUM** comm_array0 = (BIGNUM**) malloc(sizeof(BIGNUM*)*N_VAR*2);
    BIGNUM** comm_array1 = (BIGNUM**) malloc(sizeof(BIGNUM*)*N_VAR*2);
    BIGNUM** randomnesses0 = (BIGNUM**) malloc(sizeof(BIGNUM*)*N_VAR*2);
    BIGNUM** randomnesses1 = (BIGNUM**) malloc(sizeof(BIGNUM*)*N_VAR*2);

    begin = __rdtsc();

    puts("\n########## FIRST STEP: PROVER ##########");
    puts("Prover generates random permutations...");
    permutation p1 = permutation_get_random(2*N_VAR);
    permutation p2 = permutation_get_random(2*N_VAR);
    printf("p1: ");
    permutation_print(p1,2*N_VAR);
    printf("p2: ");
    permutation_print(p2,2*N_VAR);

    BIGNUM** padded_instance = pad_with_zeros(inst->a,N_VAR);
    BIGNUM** padded_solution = pad_with_zeros_solution(inst->solution,N_VAR);

    PUTS("Prover's first commitment...");
    BIGNUM** perm_a_1 = permutation_apply(padded_instance,p1,2*N_VAR);

    PED_commitment** comm0 = PROVER_commits_variable(perm_a_1,param,ctx);
    PUTS("Done");

    PUTS("Prover's second commitment...");
    BIGNUM** perm_a_2 = permutation_apply(padded_instance,p2,2*N_VAR);
    PED_commitment** comm1 = PROVER_commits_variable(perm_a_2,param,ctx);
    PUTS("Done");

    PUTS("\n########## SECOND STEP: VERIFIER ##########");
    PUTS("Verifier selects random index");
    int index = VERIFIER_selects_index();
    printf("Verifier selected: %d\n",index);

    PUTS("\n########## THIRD STEP: PROVER ##########");

    // Prepare commitments to be opened

    for(i=0; i<N_VAR*2;++i){
        comm_array0[i]=comm0[i]->c;
        comm_array1[i]=comm1[i]->c;
        randomnesses0[i]=comm0[i]->s;
        randomnesses1[i]=comm1[i]->s;
    }

    PUTS("Prover opens chosen commitment...");

    bool are_commitments_correct, is_permutation_correct;

    if ( index ==0 ){
        are_commitments_correct= PROVER_opens_variable(comm_array0,perm_a_1,randomnesses0,param->p,param->g,param->h,ctx);
        is_permutation_correct = VERIFIER_check_permutation(perm_a_1,padded_instance,p1,2*N_VAR);
    }
    else if ( index == 1 ){
        are_commitments_correct= PROVER_opens_variable(comm_array1,perm_a_2,randomnesses1,param->p,param->g,param->h,ctx);
        is_permutation_correct = VERIFIER_check_permutation(perm_a_2,padded_instance,p2,2*N_VAR);
    }
    else {
        PUTS("ERROR! Verifier selected invalid index. Aborting.");
        exit(1);
    }
    PUTS("Done");

    PUTS("\n########## FOURTH STEP: VERIFIER ##########");
    PUTS("Verifier checks commitments...");

    if (are_commitments_correct)
        PUTS("Commitments successfully opened. No cheating detected.");
    else{
        PUTS("At least one opening failed. Aborting.");
        exit(1);
    }

    if (is_permutation_correct)
        PUTS("Checked is unveiled value is a permutation of original instance padded with 0. No cheating detected.");
    else{
        PUTS("The committed array is not a permutation of the original instance padded with 0. Aborting.");
        exit(1);
    }

    PUTS("\n########## FIFTH STEP: PROVER ##########");
    PUTS("Prover sending permuted solution to Verifier");
    printf("Verifier receiving ");
    char* permuted_sol = (index == 0 ? permutation_apply_sol(padded_solution,p2,2*N_VAR) : permutation_apply_sol(padded_solution,p1,2*N_VAR) );
    print_solution(permuted_sol, 2*N_VAR);

    
    PUTS("\n########## SIXTH STEP: VERIFIER ##########");
    BIGNUM** leftover_comms = index == 0 ? comm_array1 : comm_array0;
    BIGNUM* commitment_to_sum = VERIFIER_homomorphic_sum_variable(leftover_comms,permuted_sol,param->p,ctx);


    PUTS("\n########## SEVENTH STEP: PROVER ##########");
    PUTS("Prover opens commitment");
    BIGNUM* sum=BN_new();
    BIGNUM** leftover_rands = index == 0 ? randomnesses1 : randomnesses0;
    char* solution= permuted_sol;

    for(i=0;i<2*N_VAR;++i){
        if( solution[i]==1)
            BN_mod_add(sum,sum,leftover_rands[i], inst->M,ctx);
    }

    if ( pederesen_unveil(commitment_to_sum,sum,inst->S,param->p,param->g,param->h,ctx))
        PUTS("Verifier accepted final commitment. Proof concluded. Verifier ACCEPTS");
    else
        PUTS("Verifier rejected final commitment. Proof concluded. Verifier REJECTS");
    
    end = __rdtsc();

    printf_s("%I64d ticks\n", end-begin);
}