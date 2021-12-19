#ifndef HEADER_YBCRYPTO_H
#define HEADER_YBCRYPTO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <memory.h>
#include <malloc.h>
#include <stdint.h>
#include <windows.h>
#include <wincrypt.h>

//! utill
#define PRINT_MODE

//! YBCrypto ////////////////////////////////////////////////////////////////////
#define YBCrtypto_RESULT_BASE 0x94100000
#define YBCrtypto_MODULE_BASE 0x94200000
#define TRUE 0x940001
#define FALSE 0x940002

enum YBCrtypto_FUNCTION_RESULT
{
    SUCCESS = YBCrtypto_RESULT_BASE, //0x94100000
    FAIL_CORE,
    FAIL_INVALID_INPUT_DATA,
    FAIL_INVALID_MODULE_STATE,
    FAIL_KATSELF_TEST,
    FAIL_INTEGIRTY_TEST,
    FAIL_COND_TEST,
    FAIL_NOT_PERFORM_KATSELFTEST,
    FAIL_DRBG_INNER_FUNCTION,
    FAIL_DRBG_ENTROPY_LEN_SMALL,
    FAIL_DRBG_NONCE_LEN_SMALL,
    FAIL_ENTROPY_TEST,
    FAIL_DRBG_NOT_INITIALIZE,
};

enum YBCrtypto_MODULE_STATE
{
    YBCrtypto_CM_LOAD = YBCrtypto_MODULE_BASE, //0x94200000
    YBCrtypto_CM_NOMAL_VM,                     //verification mode
    YBCrtypto_CM_NOMAL_NVM,                    //non_verification mode
    YBCrtypto_CM_PRE_SELFTEST,
    YBCrtypto_CM_COND_SELFTEST,
    YBCrtypto_CM_NORMAL_ERROR,
    YBCrtypto_CM_CRITICAL_ERROR,
    YBCrtypto_CM_EXIT
};

typedef struct YBCrtypto_ALG_TESTED_
{
    int32_t isBlockCipherTested;
    int32_t isHashTested;
    int32_t isHMACTested;
    int32_t isDRBGTested;
} IS_ALG_TESTED;

//! block cipher ////////////////////////////////////////////////////////////////
#define AES 0x94300001
#define ARIA 0x94300002
#define ENCRYPT 0x94300010
#define DECRYPT 0x94300011
#define ECB_MODE 0x94300011
#define CBC_MODE 0x94300012
#define CTR_MODE 0x94300013
#define BC_MAX_ENCRYPTED_LEN 0x100000 //2^20 (byte)
#define BC_MAX_BLOCK_SIZE 16          //AES, ARIA, SEED have 16 bytes inner state
#define BC_MAX_KEY_SIZE 32

typedef struct aes_key_st
{
    uint32_t rd_key[4 * (BC_MAX_BLOCK_SIZE - 1)]; //AES_MAXNR + 1 = 15
    int32_t rounds;
} AES_KEY;

typedef struct aria_key_st
{
    uint8_t aria_key[BC_MAX_BLOCK_SIZE * 17];
    int32_t rounds;
} ARIA_KEY;

typedef struct YBCrypto_cipher_manager_st
{
    uint32_t algo;
    uint32_t mode;
    uint32_t direct;
    uint32_t key_bitsize;
    uint32_t block_size;

    uint32_t last_block_flag;
    uint32_t remained_len;
    uint32_t pad_len;

    uint8_t iv[BC_MAX_BLOCK_SIZE];
    uint8_t buf[BC_MAX_BLOCK_SIZE];
    uint8_t lastblock[BC_MAX_BLOCK_SIZE];
    uint64_t encrypted_len;

    ARIA_KEY aria_key;
    AES_KEY aes_key;

} CipherManager; // provides AES, ARIA

//! Hash Function ////////////////////////////////////////////////////////////////
#define SHA256 0x94400001
#define SHA3 0x94400002
#define HASH_DIGEST 32
#define HF_MAX_HASING_LEN 0x1000000000000000UL //2^60 = 2^63 / 8
#define SHA256_SHORT uint8_t
#define SHA256_LONG uint64_t
#define SHA256_BLOCK_SIZE 64

#define SHA3_256_SHORT uint8_t
#define SHA3_256_LONG uint32_t
#define KECCAK_STATE_SIZE 200

typedef struct YBCrypto_Hash_manager_st
{
    uint32_t algo;
    SHA256_LONG l1;
    SHA256_LONG l2;
    SHA256_LONG data[8];
    SHA256_SHORT buf[SHA256_BLOCK_SIZE];
    SHA3_256_LONG keccakRate;
    SHA3_256_LONG keccakCapacity;
    SHA3_256_LONG keccakSuffix;
    SHA3_256_LONG end_offset;
    SHA3_256_SHORT keccak_state[KECCAK_STATE_SIZE];
} HashManager; // provides SHA256, SHA3(keccack 1600), LEA

//! Hash Function ////////////////////////////////////////////////////////////////
#define HMAC_SHA256_KEYSIZE 64
#define HMAC_SHA3_KEYSIZE 136
#define HMAC_DIGEST 32
#define HM_MAX_HMAC_LEN 0x1000000000000000UL //2^60 = 2^63 / 8
typedef struct YBCrypto_Hmac_manager_st
{
    HashManager hash_manger;
    int32_t algo;
    int32_t keyset;
    uint8_t key[HMAC_SHA3_KEYSIZE];
    uint8_t keyLen;
    uint8_t fix_keysize;
} HMACManager;

//! CTR_DRBG ////////////////////////////////////////////////////////////////////
#define USE_DF 0x94500001
#define USE_PR 0x94500002
#define NO_DF 0x94500003
#define NO_PR 0x94500004
typedef struct YBCrypto_CTR_DRBG_manager_st
{
    uint32_t algo; // algo is default which is ARIA-128
    uint8_t V[BC_MAX_BLOCK_SIZE];
    int32_t Vlen;
    uint8_t Key[32];
    uint32_t Key_bytelen;
    uint32_t seedlen;
    uint64_t reseed_counter;
    uint32_t security_strength;
    uint32_t initialized_flag; // If initialized_flag = STATE_INITIALIZED_FLAG, state is already initialized.
    uint32_t derivation_function_flag;
    uint32_t prediction_resistance_flag;
} DRBGManager;

//! Initializaition and Destroy
__declspec(dllexport) void YBCrypto_Initialization(void);
__declspec(dllexport) void Destroy_YBCrypto(void);

//! YBCrypto Common API /////////////////////////////////////////////////////////////
__declspec(dllexport) void  YBCrypto_memset(void *pointer, int32_t value, int32_t size);
__declspec(dllexport) void YBCrypto_ModuleInfo(void);                                   //*done
__declspec(dllexport) int32_t YBCrypto_GetState(void);                                  //*done
__declspec(dllexport) int32_t YBCrypto_PreSelfTest(void);                               //todo integrity Test

//! YBCrypto BlockCipher API ////////////////////////////////////////////////////////
__declspec(dllexport) int32_t  YBCrypto_BlockCipher(CipherManager *CM, uint32_t ALG, int32_t MODE, int32_t direct, const uint8_t *user_key, uint32_t key_bitlen, const uint8_t *in, uint64_t in_byteLen, const uint8_t *iv, uint8_t *out);
__declspec(dllexport) int32_t  YBCrypto_BlockCipher_Init(CipherManager *CM, uint32_t ALG, int32_t MODE, int32_t direct, const uint8_t *user_key, uint32_t key_bitlen, const uint8_t *iv);
__declspec(dllexport) int32_t  YBCrypto_BlockCipher_Update(CipherManager *CM, const uint8_t *in, uint64_t in_byteLen, uint8_t *out, uint64_t *out_byteLen);
__declspec(dllexport) int32_t  YBCrypto_BlockCipher_Final(CipherManager *CM, uint8_t *out, uint32_t *pad_bytelen);
__declspec(dllexport) int32_t  YBCrypto_BlockCipher_Clear(CipherManager *CM);

//! YBCrypto HashFunction API ///////////////////////////////////////////////////////
__declspec(dllexport) int32_t  YBCrypto_Hash(HashManager *HM, uint32_t ALG, const uint8_t *msg, uint64_t msg_byteLen, uint8_t *md);
__declspec(dllexport) int32_t  YBCrypto_Hash_Init(HashManager *HM, uint32_t ALG);
__declspec(dllexport) int32_t  YBCrypto_Hash_Update(HashManager *HM, const uint8_t *msg, uint64_t msg_byteLen);
__declspec(dllexport) int32_t  YBCrypto_Hash_Final(HashManager *HM, uint8_t *md);
__declspec(dllexport) int32_t  YBCrypto_Hash_Clear(HashManager *HM);

//! YBCrypto HMAC API ///////////////////////////////////////////////////////////////
__declspec(dllexport) int32_t  YBCrypto_HMAC(HMACManager *MM, uint32_t ALG, const uint8_t *key, uint32_t key_bytelen, const uint8_t *msg, uint64_t msg_byteLen, uint8_t *mac);
__declspec(dllexport) int32_t  YBCrypto_HMAC_Init(HMACManager *MM, uint32_t ALG, const uint8_t *key, uint32_t key_bytelen);
__declspec(dllexport) int32_t  YBCrypto_HMAC_Update(HMACManager *MM, const uint8_t *msg, uint64_t msg_byteLen);
__declspec(dllexport) int32_t  YBCrypto_HMAC_Final(HMACManager *MM, uint8_t *mac);
__declspec(dllexport) int32_t  YBCrypto_HMAC_Clear(HMACManager *MM);

//! YBCrypto CTR_DRBG API ///////////////////////////////////////////////////////////////
__declspec(dllexport) int32_t YBCrypto_CTR_DRBG_Instantiate(
    DRBGManager *DM,
    uint32_t ALG, uint32_t key_bitlen,
    uint8_t *entropy_input, uint32_t entropy_bytelen,
    uint8_t *nonce, uint32_t nonce_bytelen,
    uint8_t *personalization_string, uint32_t string_bytelen,
    uint32_t derivation_function_flag);

__declspec(dllexport) int32_t YBCrypto_CTR_DRBG_Reseed(
    DRBGManager *DM,
    uint8_t *entropy_input, uint32_t entropy_bytelen,
    uint8_t *additional_input, uint32_t add_bytelen);

__declspec(dllexport) int32_t YBCrypto_CTR_DRBG_Generate(
    DRBGManager *DM,
    uint8_t *output, uint64_t requested_num_of_bits,
    uint8_t *entropy_input, uint32_t entropy_bytelen,
    uint8_t *addtional_input, uint32_t add_bytelen,
    uint32_t prediction_resistance_flag);

__declspec(dllexport) int32_t YBCrypto_CTR_DRBG_Uninstantiate(DRBGManager *DM);
#endif
//EOF