#ifndef HEADER_MODE_H
#define HEADER_MODE_H

#include "YBCrypto.h"

int ECB_Init(CipherManager *c, int32_t ALG, int32_t direct, const uint8_t *userkey, uint64_t key_bitlen);
int ECB_Update(CipherManager *c, const uint8_t *in, uint64_t in_byteLen, uint8_t *out, uint64_t *out_byteLen);
int ECB_Final(CipherManager *c, uint8_t *out, uint32_t *pad_bytelen);

int CBC_Init(CipherManager *c, int32_t ALG, int32_t direct, const uint8_t *userkey, int32_t key_bitlen, const uint8_t *iv);
int CBC_Update(CipherManager *c, const uint8_t *in, uint64_t in_byteLen, uint8_t *out, uint64_t *out_byteLen);
int CBC_Final(CipherManager *c, uint8_t *out, uint32_t *pad_bytelen);

int CTR_Init(CipherManager *c, int32_t ALG, int32_t direct, const uint8_t *userkey, int32_t key_bitlen, const uint8_t *iv);
int CTR_Update(CipherManager *c, const uint8_t *in, uint64_t in_byteLen, uint8_t *out, uint64_t *out_byteLen);
int CTR_Final(CipherManager *c, uint8_t *out, uint32_t *pad_bytelen);
#endif
//EOF