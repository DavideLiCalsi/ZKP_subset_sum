#pragma once

#include <openssl/bn.h>

#define DEBUG

#ifdef DEBUG
#define DEBUG_PRINT(...) do{ fprintf( stderr, __VA_ARGS__ ); } while( false )
#else
#define DEBUG_PRINT(...) do{ } while ( false )
#endif

struct bn_pair
{
    /* data */
    BIGNUM* x;
    BIGNUM* y;
};

typedef struct bn_pair BN_pair;

/***
 * Bitwise xor between two BIGNUM x and y
*/
BIGNUM* BN_xor( BIGNUM* x, BIGNUM* y){

    int size = BN_num_bytes(x);

    unsigned char* buf_x = (unsigned char*) malloc(size);
    unsigned char* buf_y = (unsigned char*) malloc(size);
    unsigned char* buf_res = (unsigned char*) malloc(size);

    BIGNUM* res = BN_new();

    // Convert to bits
    BN_bn2bin(x,buf_x);
    BN_bn2bin(y,buf_y);

    for (int i=0; i<size;++i){

        buf_res[i] = buf_x[i]^buf_y[i];
    }

    BN_bin2bn(buf_res,size,res);

    return res;

}