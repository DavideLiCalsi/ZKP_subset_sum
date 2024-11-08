#include <openssl/bn.h>

#define BITS 1024

BIGNUM* commit(BIGNUM* m){

    BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();
    BIGNUM* r = BN_new();
    BIGNUM* s = BN_new();
    BIGNUM* N = BN_new();
    BIGNUM* M = BN_new();

    BN_CTX* ctx1 = BN_CTX_new();
    BN_CTX* ctx2 = BN_CTX_new();

    BN_generate_prime_ex(p,BITS,0,NULL,NULL,NULL);
    BN_generate_prime_ex(q,BITS,0,NULL,NULL,NULL);
    BN_generate_prime_ex(r,BITS,0,NULL,NULL,NULL);
    BN_generate_prime_ex(s,BITS,0,NULL,NULL,NULL);

    BN_mul(N,p,q,ctx1);
    BN_mul(M,p,q,ctx2);

    return N;
}