#ifndef HEADER_HASH_H
#define HEADER_HASH_H

#include "YBCrypto.h"

//! SHA256 inner function
int SHA256_init(HashManager *c);
int SHA256_update(HashManager *c, const uint8_t *msg, uint64_t msg_bytelen);
int SHA256_final(HashManager *c, uint8_t *md);

//! SHA3 inner function
int SHA3_init(HashManager *c);
int SHA3_update(HashManager *c, const uint8_t *msg, uint64_t msg_bytelen);
int SHA3_final(HashManager *c, uint8_t *md);

//TODO
int SHA256_MD(unsigned char *in, int len, unsigned char *out);
int SHA3_MD(unsigned char *in, int len, unsigned char *out);

#endif
//EOF
