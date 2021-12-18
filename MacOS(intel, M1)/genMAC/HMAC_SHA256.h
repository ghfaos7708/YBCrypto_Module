#ifndef HMAC_SHA256_H
#define HMAC_SHA256_H

#include "SHA256.h"

# define HMAC_MAX_MD_CBLOCK      128

typedef struct {
	SHA256_INFO sha256_ctx;
} HMAC_SHA256_INFO;

void HMAC_SHA256_Encrpyt(IN const BYTE* pszMessage,
	IN UINT uPlainTextLen,
	IN const BYTE* key,
	IN UINT keyLen,
	OUT BYTE* mac);

void HMAC_KAT();

void genIntegrityData(char* fileName);

#endif
// EOFi

