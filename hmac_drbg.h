#include <stdio.h>
#include <string.h>

#include "utils.h"

#include <openssl/hmac.h>
#include <openssl/sha.h>

#define PERIOD 100000
#define KEY_SIZE 256/8+1
#define V_SIZE 256/8+1
#define ADDIN_SIZE 256/8+1

#define CONCAT_NO_MIDDLE_VAL 0x2

#define EVP_GET_HASH() EVP_sha256()

struct prng_state{
    unsigned int d;
    unsigned char* K;
    unsigned char* V;
};

typedef struct prng_state PRNG_STATE;

PRNG_STATE* drbg_state;

/**
 * Concatenates two buffers for the Update function. It appends either 0x00 or 0x01 in between
*/
unsigned char* concatenate(unsigned char* x, unsigned char* y, unsigned int len1, unsigned int len2,unsigned char append){

    unsigned char* res = (unsigned char*) malloc(sizeof(unsigned char)*(len1+1+len2));

    if (x != NULL)
        memcpy(res,x,len1);

    if (append != CONCAT_NO_MIDDLE_VAL)
        *(res+len1) = append;

    if ( y!=NULL)
        memcpy(res+len1+1,y,len2);

    return res;

}

/**
 * Update function used in the HMAC_DRBG NIST specification
*/
int Update(PRNG_STATE* state, unsigned char* addin){

    unsigned char* K = (unsigned char*) malloc(sizeof(KEY_SIZE));
    unsigned char* V = (unsigned char*) malloc(sizeof(V_SIZE));
    unsigned char* res;
    unsigned int md_len, tot_size;

    res = (addin != NULL)? concatenate(state->V,addin,V_SIZE,ADDIN_SIZE,0x00) : concatenate(state->V,addin,V_SIZE,0,0x00);

    printf("%s\n",res);

    DEBUG_PRINT("Concatenated\n");

    tot_size = addin==NULL ? V_SIZE + 1 : V_SIZE + 1 + ADDIN_SIZE;

    DEBUG_PRINT("Computing HMAC...");

    HMAC(EVP_GET_HASH(),state->K,KEY_SIZE,res,KEY_SIZE,K,&md_len);

    if (K==NULL)
        puts("ERROR IN HMAC");

    DEBUG_PRINT("HMAC DONE\n");

    V = HMAC(EVP_GET_HASH(),state->K,KEY_SIZE,state->V,V_SIZE,V,&md_len);

    DEBUG_PRINT("HMAC DONE\n");

    if (addin == NULL){

        DEBUG_PRINT("Null addin\n");

        state->K = K;
        state->V = V;

        return 0;
    }
    else{
        res = concatenate(V,addin,V_SIZE,ADDIN_SIZE,0x01);

        K = HMAC(EVP_GET_HASH(),K,KEY_SIZE,res,V_SIZE +1+ ADDIN_SIZE,K,&md_len);
        V = HMAC(EVP_GET_HASH(),K,KEY_SIZE,V,V_SIZE,V,&md_len);

        state->K = K;
        state->V = V;

        return 0;
    }

}

/**
 * Extracts the l leftmost bits from a buffer buf.
 * For simplicity l is always assumed to be an integer multiple of 8
*/
unsigned char* leftmost(unsigned char* buf, int l){

    unsigned char* res;

    int bytesize = l;

    res = (unsigned char*) malloc(bytesize);

    memcpy(res,buf,bytesize);

    return res;

}

unsigned char* DRBG_Generate(unsigned char* addin, int requested){

    if (drbg_state->d >= PERIOD){
        return NULL;
    }
    
    // Update if addin is NOT null
    if (addin != NULL){
        Update(drbg_state,addin);
    }

    int len=0;
    unsigned int md_len;
    unsigned char* tmp=NULL;

    printf("%d %d",len,requested);
    while (len < requested)
    {
        /* code */
        puts("updating");
        HMAC(EVP_GET_HASH(),drbg_state->K,KEY_SIZE,drbg_state->V,V_SIZE,drbg_state->V,&md_len);
        tmp=concatenate(tmp,drbg_state->V,len,V_SIZE,CONCAT_NO_MIDDLE_VAL);
        len += V_SIZE;
    }

    unsigned char* s;

    //Extract leftmost bits of tmp
    s = leftmost(tmp,requested);
    Update(drbg_state,addin);

    // Update counter
    drbg_state->d=1;
    
    return s;
}

/**
 * Initializaes the DRBG
*/
void DRBG_Instantiate(unsigned char* addin){

    DEBUG_PRINT("Initializting\n");    

    drbg_state = (PRNG_STATE*) malloc(sizeof(PRNG_STATE));

    unsigned char* key = (unsigned char*) malloc(sizeof(KEY_SIZE));
    unsigned char* V = (unsigned char*) malloc(sizeof(V_SIZE));

    memset(key,0,KEY_SIZE);
    memset(V,0x01,V_SIZE);
    drbg_state->K=key;
    drbg_state->V=V;

    drbg_state->d=1;

    DEBUG_PRINT("First state update...");
    Update(drbg_state,addin);
    DEBUG_PRINT("DONE\n");

}

/**
 * Reseeds the DRBG
*/
void DRBG_Reseed(unsigned char* addin){
    Update(drbg_state,addin);
    drbg_state->d=1;
}