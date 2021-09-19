#ifndef HEADER_MODE_H
#define HEADER_MODE_H

#include "YBCrypto.h"

int ECB_Init(CipherManager *c, int32_t ALG, int32_t direct, uint8_t *userkey, uint64_t key_bitlen);
int ECB_Update(CipherManager *c, uint8_t *in, uint64_t in_byteLen, uint8_t *out, uint64_t out_byteLen);
#endif
//EOF