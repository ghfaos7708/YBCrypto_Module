#ifndef HEADER_CTR_DRBG_H
#define HEADER_CTR_DRBG_H

#include "YBCrypto.h"

#define SEEDLEN_128 BC_MAX_BLOCK_SIZE + 16
#define SEEDLEN_192 BC_MAX_BLOCK_SIZE + 24
#define SEEDLEN_256 BC_MAX_BLOCK_SIZE + 32

#define MAX_V_LEN_IN BC_MAX_BLOCK_SIZE
#define MAX_Key_LEN BC_MAX_KEY_SIZE
#define MAX_SEEDLEN SEEDLEN_256

#define DM_INITIALIZED_FLAG 0x94500099
#define MAX_RESEED_COUNTER 0x1000000000000UL // 2^48
#define MAX_PERSONALIZED_STRING_LEN	0x100000000	// 2^35 bits
#define MAX_ADDITIONAL_INPUT_LEN 0x100000000		// 2^35 bits
#define MAX_RAND_BYTE_LEN 2048	

int32_t CTR_DRBG_Instantiate(DRBGManager *DM,
                             uint32_t algo, uint32_t key_bitlen,
                             uint8_t *entropy_input, uint32_t entropy_bytelen,
                             uint8_t *nonce, uint32_t nonce_bytelen,
                             uint8_t *personalization_string, uint32_t string_bytelen,
                             uint32_t derivation_function_flag);

int32_t CTR_DRBG_Reseed(DRBGManager *DM,
                        uint8_t *entropy_input, uint32_t entropy_bytelen,
                        uint8_t *additional_input, uint32_t add_bytelen);

int32_t CTR_DRBG_Generate(DRBGManager *DM,
                          uint8_t *output, uint64_t requested_num_of_bits,
                          uint8_t *entropy_input, uint32_t entropy_bytelen,
                          uint8_t *addtional_input, uint32_t add_bytelen,
                          uint32_t prediction_resistance_flag);

#endif
//EOF