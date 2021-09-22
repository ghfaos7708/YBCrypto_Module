#ifndef HEADER_YBCRYPTO_H
#define HEADER_YBCRYPTO_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <memory.h>

//! utill
#define TRUE 0x94FFFFFF
#define FALSE 0x94FF0001

//! YBCrypto
#define SUCCESS 0x94000001
#define FAIL_CORE 0x94000000

//! block cipher ////////////////////////////////////////////////////////////////
#define AES 0x94000001
#define ARIA 0x94000002
#define ENCRYPT 0x94000001
#define DECRYPT 0x94000000
#define AES_MAXNR 14
#define BC_MAX_BLOCK_SIZE 16 //AES, ARIA, LEA, SEED have 16 bytes inner state

typedef struct aes_key_st {
    uint32_t rd_key[4 * (AES_MAXNR + 1)];
    int rounds;
} AES_KEY;

typedef struct aria_key_st {
    uint8_t aria_key[BC_MAX_BLOCK_SIZE*17];
    int rounds;
} ARIA_KEY;

typedef struct YBCrypto_cipher_manager_st{
    uint64_t encrypted_len;
    uint32_t block_cipher; 
    uint32_t key_bitsize;
	uint32_t block_size;

    uint32_t last_block_flag;
    uint32_t remained_len;
	uint32_t pad_len;
	uint32_t direct;
	
	uint8_t iv[BC_MAX_BLOCK_SIZE];
	uint8_t buf[BC_MAX_BLOCK_SIZE];
    uint8_t lastblock[BC_MAX_BLOCK_SIZE];

    ARIA_KEY aria_key;
    AES_KEY aes_key;
	
} CipherManager; // provides AES, ARIA, LEA, SEED

//! Hash Function ////////////////////////////////////////////////////////////////
#define SHA256 0x94000001
#define SHA3 0x94000002
#define LSH 0x94000003

#define SHA256_SHORT uint8_t
#define SHA256_LONG uint64_t
#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_LENGTH 32

#define SHA3_256_SHORT uint8_t
#define SHA3_256_LONG uint32_t
#define KECCAK_STATE_SIZE 200

typedef struct YBCrypto_Hash_manager_st{
    uint32_t hash_function;
    SHA256_LONG l1;
    SHA256_LONG l2;
    SHA256_LONG data[8];
    SHA256_SHORT buf[SHA256_BLOCK_SIZE];
    SHA3_256_LONG keccakRate;
    SHA3_256_LONG keccakCapacity;
    SHA3_256_LONG keccakSuffix;
    SHA3_256_LONG end_offset;
    SHA3_256_SHORT keccak_state[KECCAK_STATE_SIZE];
} HashManager;// provides SHA256, SHA3(keccack 1600), LEA


//! Hash Function ////////////////////////////////////////////////////////////////
#define MAX_HMAC_KEYSIZE 64
typedef struct YBCrypto_Hmac_manager_st{
   HashManager hash_manger;
   int32_t hash_function;
   int32_t keyset;
   uint8_t key[MAX_HMAC_KEYSIZE];
   uint8_t keyLen;
} HMACManager;


//! YBCrypto common API
void YBCrypto_memset(void* p, int value, int size);

#endif
//EOF