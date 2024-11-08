#ifndef PEDERSEN_H
#define PEDERSEN_H

#include <openssl/bn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define BITS 2048

typedef struct pedersen_commitment
{
    /* data */
    BIGNUM* c;
    BIGNUM* s;
} PED_commitment;

typedef struct pedersen_parameters
{
    /* data */
    BIGNUM* p;
    BIGNUM* g;
    BIGNUM* h;
} PED_params;

BIGNUM* get_generator(BIGNUM* p, BN_CTX* ctx){

    BIGNUM* g = BN_new();
    BIGNUM* q = BN_new();
    BIGNUM* power_2 = BN_new();
    BIGNUM* power_q = BN_new();

    BN_CTX_start(ctx);

    BN_sub(q,p,BN_value_one());
    BN_rshift(q,q,1);

    //find generators
    while (true)
    {
        BN_rand_range(g,p);
        BN_mod_mul(power_2,g,g,p,ctx);
        BN_mod_exp(power_q,g,q,p,ctx);

        if ( (BN_cmp(power_2,BN_value_one()) != 0) && (BN_cmp(power_q,BN_value_one()) != 0) ){

            BN_free(q);
            BN_free(power_2);
            BN_free(power_q);
            BN_CTX_end(ctx);
            return g;
        }
    }
}

PED_params* pedersen_init(BN_CTX* ctx){

    BIGNUM* p = BN_new();
    BIGNUM* g;
    BIGNUM* h;

    PED_params* param = (PED_params*) malloc(sizeof(PED_params));

    BN_CTX_start(ctx);

    puts("Generating commitment parameters...");

    BN_generate_prime(p,BITS,1,NULL,NULL,NULL,NULL);
    
    g = get_generator(p,ctx);
    do{
        h = get_generator(p,ctx);
    } while(BN_cmp(g,h)==0);
    
    param->g=g;
    param->h=h;
    param->p=p;

    BN_CTX_end(ctx);

    puts("Done.");
    printf("Prime p: 0x%s\n",BN_bn2hex(p));
    printf("Generator g: 0x%s\n",BN_bn2hex(g));
    printf("Generator h: 0x%s\n",BN_bn2hex(g));

    return param;
}

/**
 * Saves parameters for pedersen commitment to a path
 * @param p: Pointer to pedersen parameters
 */
int pedersen_save_param(PED_params* p){

    char size[5];
    itoa(BITS,size,10);

    char prefix[20]="PED_";

    char* fullpath =strcat(prefix,size);
    fullpath=strcat(fullpath,".dat");

    FILE* f = fopen(fullpath,"wb");
    char* buf;

    // Convert bignums to bits, then store
    int num_bytes_g= BN_num_bytes(p->g);
    int num_bytes_h = BN_num_bytes(p->h);
    int num_bytes_p = BN_num_bytes(p->p);

    fwrite(&num_bytes_g,sizeof(int),1,f);
    fwrite(&num_bytes_h,sizeof(int),1,f);
    fwrite(&num_bytes_p,sizeof(int),1,f);

    buf = (unsigned char*) malloc(num_bytes_g);
    BN_bn2bin(p->g,buf);
    fwrite(buf,num_bytes_g,1,f);
    free(buf);

    buf = (unsigned char*) malloc(num_bytes_h);
    BN_bn2bin(p->h,buf);
    fwrite(buf,num_bytes_h,1,f);
    free(buf);

    buf = (unsigned char*) malloc(num_bytes_p);
    BN_bn2bin(p->p,buf);
    fwrite(buf,num_bytes_p,1,f);
    free(buf);

    fclose(f);

    return 0;
}

PED_params* pedersen_get_param(BN_CTX* ctx){
    char size[5];
    itoa(BITS,size,10);

    char prefix[20]="PED_";

    char* fullpath =strcat(prefix,size);
    fullpath=strcat(fullpath,".dat");

    PED_params* param;
    char* buf;
    int sg, sh,sp;

    FILE * file= fopen(fullpath, "rb");
    if (file != NULL) {
        puts("Successfully opened file. Skipping generation");
        param = (PED_params*) malloc(sizeof(PED_params));
        fread(&sg, sizeof(int), 1, file);
        fread(&sh, sizeof(int), 1, file);
        fread(&sp, sizeof(int), 1, file);

        buf = (unsigned char*) malloc(sg);
        fread(buf,sg,1,file);
        param->g = BN_bin2bn(buf,sg,NULL);
        free(buf);

        buf = (unsigned char*) malloc(sh);
        fread(buf,sh,1,file);
        param->h = BN_bin2bn(buf,sh,NULL);
        free(buf);

        buf = (unsigned char*) malloc(sp);
        fread(buf,sp,1,file);
        param->p = BN_bin2bn(buf,sp,NULL);
        free(buf);

        fclose(file);
    }
    else{
        param =pedersen_init(ctx);
        pedersen_save_param(param);
    }

    return param;
}

PED_commitment* pedersen_commit(BIGNUM* m, BIGNUM* p, BIGNUM* g, BIGNUM* h,BN_CTX* ctx){

    BN_CTX_start(ctx);

    BIGNUM* s = BN_new();
    BIGNUM* x1 = BN_new();
    BIGNUM* x2 = BN_new();
    BIGNUM* commitment = BN_new();

    PED_commitment* result;
    result=(PED_commitment*) malloc(sizeof(PED_commitment));

    BN_rand_range(s,p);
    BN_mod_exp(x1,g,m,p,ctx);
    BN_mod_exp(x2,h,s,p,ctx);
    BN_mod_mul(commitment,x1,x2,p,ctx);

    result->c=commitment;
    result->s=s;

    //cleaning
    BN_free(x1);
    BN_free(x2);
    
    BN_CTX_end(ctx);

    return result;
}

bool pederesen_unveil(BIGNUM* c, BIGNUM* s, BIGNUM* m, BIGNUM* p, BIGNUM* g, BIGNUM* h, BN_CTX* ctx){

    BN_CTX_start(ctx);
    
    BIGNUM* x1 = BN_new();
    BIGNUM* x2 = BN_new();
    BIGNUM* local_c = BN_new();
    bool res;

    BN_mod_exp(x1,g,m,p,ctx);
    BN_mod_exp(x2,h,s,p,ctx);
    BN_mod_mul(local_c,x1,x2,p,ctx);

    res = BN_cmp(local_c,c) == 0;
    
    //cleaning
    BN_free(x1);
    BN_free(x2);
    BN_free(local_c);
    
    BN_CTX_end(ctx);

    return res;
}

#endif