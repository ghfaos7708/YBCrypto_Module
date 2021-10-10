#ifndef HEADER_MODE_H
#define HEADER_MODE_H

#include "YBCrypto.h"

int32_t ECB_Init(CipherManager *c, int32_t ALG, int32_t direct, const uint8_t *userkey, uint32_t key_bitlen);
int32_t ECB_Update(CipherManager *c, const uint8_t *in, uint64_t in_byteLen, uint8_t *out, uint64_t *out_byteLen);
int32_t ECB_Final(CipherManager *c, uint8_t *out, uint32_t *pad_bytelen);

int32_t CBC_Init(CipherManager *c, int32_t ALG, int32_t direct, const uint8_t *userkey, int32_t key_bitlen, const uint8_t *iv);
int32_t CBC_Update(CipherManager *c, const uint8_t *in, uint64_t in_byteLen, uint8_t *out, uint64_t *out_byteLen);
int32_t CBC_Final(CipherManager *c, uint8_t *out, uint32_t *pad_bytelen);

int32_t CTR_Init(CipherManager *c, int32_t ALG, int32_t direct, const uint8_t *userkey, int32_t key_bitlen, const uint8_t *iv);
int32_t CTR_Update(CipherManager *c, const uint8_t *in, uint64_t in_byteLen, uint8_t *out, uint64_t *out_byteLen);
int32_t CTR_Final(CipherManager *c, uint8_t *out, uint32_t *pad_bytelen);
#endif
//EOF