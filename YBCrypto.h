#ifndef HEADER_YBCRYPTO_H
#define HEADER_YBCRYPTO_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <memory.h>


//! YBCrypto
#define SUCCESS 0x94000001
#define FAIL_CORE 0x94000000

//! block cipher ////////////////////////////////////////////////////////////////
#define AES 0x94000001
#define ARIA 0x94000002
#define LEA 0x94000003
#define SEED 0x94000004
#define ENCRYPT 0x94000001
#define DECRYPT 0x94000000
#define BC_MAX_BLOCK_SIZE 16 //AES, ARIA, LEA, SEED have 16 bytes inner state

typedef struct YBCrypto_cipher_manager_st{
    uint32_t block_cipher; 
    uint32_t key_size;
	uint32_t block_size;
	uint32_t encrypt;
	void   *key_st;
	
	unsigned char iv[BC_MAX_BLOCK_SIZE];
	unsigned char buf[BC_MAX_BLOCK_SIZE];
	uint32_t buflen;
	
	unsigned char last_block[BC_MAX_BLOCK_SIZE];
	int last_block_flag;

	uint32_t (*set_enc_key)(unsigned char *, int, void *);
	uint32_t (*set_dec_key)(unsigned char *, int, void *);
	void (*encrypt_block)(unsigned char*, unsigned char*, void *);
	void (*decrypt_block)(unsigned char*, unsigned char*, void *);
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
    SHA256_SHORT keccak_state[KECCAK_STATE_SIZE];
} HashManager;// provides SHA256, SHA3(keccack 1600), LEA

//! YBCrypto common API
void YBCrypto_memset(void* p, int value, int size);

#endif
//EOF