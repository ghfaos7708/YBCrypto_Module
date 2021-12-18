#ifndef HEADER_HMAC_H
#define HEADER_HMAC_H

#include "YBCrypto.h"

#define OPAD 0x5C
#define IPAD 0x36

int HMAC_init(HMACManager *c, uint32_t ALG, const uint8_t *key, uint32_t key_bytelen);
int HMAC_update(HMACManager *c, const uint8_t *msg, uint64_t msg_bytelen);
int HMAC_final(HMACManager *c, uint8_t *mac);

#endif
//EOF