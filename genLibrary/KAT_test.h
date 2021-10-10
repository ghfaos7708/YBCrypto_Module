#ifndef KAT_TESET_H
#define KAT_TESET_H

#include "YBCrypto.h"

int32_t Inner_API_BlockCipher_SelfTest();
int32_t Inner_API_HashFunction_SelfTest();
int32_t Inner_API_HMAC_SelfTest();
int32_t Inner_API_CTR_DRBG_SelfTest();

#endif
//EOF