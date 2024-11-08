#include <openssl/bn.h>

#define BITS 1024

typedef struct 
{
    BIGNUM* p;
    BIGNUM* q;
} committer_data;

typedef struct 
{
    BIGNUM* N;
} receiver_data;

committer_data* gen_ref_string_committer(){

    committer_data* comm_dat = (committer_data*) (sizeof(committer_data));
    BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();

    BN_generate_prime_ex(p,BITS,0,NULL,NULL,NULL);
    BN_generate_prime_ex(q,BITS,0,NULL,NULL,NULL);

    comm_dat->p = p;
    comm_dat->q = q;

    return comm_dat;
}

receiver_data* gen_ref_string_receiver(committer_data* comm){

    receiver_data* rcv = (receiver_data*) malloc(sizeof(receiver_data));
    BIGNUM* N = BN_new();
    BN_CTX* ctx1 = BN_CTX_new(); //destroy

    BN_mul(N,comm->p,comm->q,ctx1);

    rcv->N = N;

    return rcv;
}

BIGNUM* chinese_remainder(BIGNUM* x,BIGNUM* p, BIGNUM* y, BIGNUM* q){

    BIGNUM* p_inv = BN_new();
    BIGNUM* temp = BN_new();
    BIGNUM* N = BN_new();
    BN_CTX* ctx1 = BN_CTX_new(); //destroy

    BN_mul(N,p,q,ctx1);
    BN_mod_inverse(p_inv,p,q,ctx1);
    BN_mod_sub(temp,x,y,N,ctx1);
    BN_mod_mul(temp,temp,p_inv,N, ctx1);
    BN_mod_mul(temp,temp,p,N,ctx1);
    BN_mod_add(temp,temp,x,N,ctx1);

    return temp;
}

/**
 * Computes modular sqrt of x mod N=p*q
 */
BIGNUM* mod_sqrt_semiprime(BIGNUM* x, BIGNUM* p, BIGNUM* q){

    BIGNUM* p_sqrt = BN_new();
    BIGNUM* q_sqrt = BN_new();
    BIGNUM* p_sqrt_cmpl = BN_new();
    BIGNUM* q_sqrt_cmpl = BN_new();
    BIGNUM* zero = BN_new();
    BN_zero(zero);

    BN_CTX* ctx1 = BN_CTX_new(); //destroy

    // compute modular square roots mod primes
    BN_mod_sqrt(p_sqrt,x,p,ctx1);
    BN_mod_sqrt(q_sqrt,x,q,ctx1);
    BN_mod_sub(p_sqrt_cmpl,zero,p_sqrt,p,ctx1);
    BN_mod_sub(q_sqrt_cmpl,zero,q_sqrt,q,ctx1);


    // combine via CRT
    chinese_remainder(p_sqrt,p,q_sqrt,q);
    chinese_remainder(p_sqrt_cmpl,p,q_sqrt,q);
    chinese_remainder(p_sqrt,p,q_sqrt_cmpl,q);
    chinese_remainder(p_sqrt_cmpl,p,q_sqrt_cmpl,q);

    return NULL;
}


BIGNUM* commit(committer_data* comm, BIGNUM* m){

    BIGNUM* N = BN_new();
    BIGNUM* thresh = BN_new();
    BIGNUM* two = BN_new();
    BIGNUM* square = BN_new();

    // get const 2
    BN_add(two, BN_value_one(),BN_value_one());


    BN_CTX* ctx1 = BN_CTX_new(); //destroy

    BN_mul(N,comm->p,comm->q,ctx1);

    // Reject if m is smaller than N/2
    BN_div(thresh,NULL,N,two,ctx1);

    if (BN_cmp(m,thresh) >= 0){
        printf("Error! Invalid commitment value!");
        return NULL;
    }

    BN_mod_sqr(square,m,N,ctx1);

}