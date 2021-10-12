#ifndef HEADER_BLOCKCIPHER_H
#define HEADER_BLOCKCIPHER_H
#include "YBCrypto.h"

#define AES_BLOCK_SIZE 16
#define ARIA_BLOCK_SIZE 16
#define GETU32(pt) (((uint32_t)(pt)[0] << 24) ^ ((uint32_t)(pt)[1] << 16) ^ ((uint32_t)(pt)[2] << 8) ^ ((uint32_t)(pt)[3]))
#define PUTU32(ct, st)                   \
    {                                    \
        (ct)[0] = (uint8_t)((st) >> 24); \
        (ct)[1] = (uint8_t)((st) >> 16); \
        (ct)[2] = (uint8_t)((st) >> 8);  \
        (ct)[3] = (uint8_t)(st);         \
    }
#define FULL_UNROLL

int32_t AES_set_encrypt_key(const uint8_t *userKey, int bits, AES_KEY *key);
int32_t AES_set_decrypt_key(const uint8_t *userKey, int bits, AES_KEY *key);
void AES_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
void AES_decrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);

int32_t ARIA_EncKeySetup(const uint8_t *userKey, int bits, ARIA_KEY *key);
int32_t ARIA_DecKeySetup(const uint8_t *userKey, int bits, ARIA_KEY *key);
void ARIA_Crypt(const uint8_t *in, int rounds, const ARIA_KEY *key, uint8_t *out);

#endif
//EOF