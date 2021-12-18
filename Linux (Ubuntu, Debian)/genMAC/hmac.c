
#include <memory.h>
#include "HMAC_SHA256.h"

#define I_PAD 0x36
#define O_PAD 0x5C


void HMAC_SHA256_Encrpyt(IN const BYTE* pszMessage,
	IN UINT uPlainTextLen,
	IN const BYTE* key,
	IN UINT keyLen,
	OUT BYTE* mac)
{
	int cnt_i;
	int updatedKeyLen;

	SHA256_INFO info;
	BYTE K0[32] = { 0x00, };
	BYTE K1[SHA256_DIGEST_BLOCKLEN] = { 0x00, };		
	BYTE K2[SHA256_DIGEST_BLOCKLEN] = { 0x00, };		
	BYTE firsOut[SHA256_DIGEST_VALUELEN] = { 0x00, };

	if (keyLen > SHA256_DIGEST_BLOCKLEN)
	{
		SHA256_Init(&info);
		SHA256_Process(&info, key, keyLen);
		SHA256_Close(&info, K0);
		updatedKeyLen = SHA256_DIGEST_VALUELEN;
	}
	else
	{
		memcpy(K0, key, keyLen);
		updatedKeyLen = keyLen;
	}

	memset(K1, I_PAD, 64);
	memset(K2, O_PAD, 64);

	for (cnt_i = 0; cnt_i < updatedKeyLen; cnt_i++)
	{
		K1[cnt_i] = I_PAD ^ K0[cnt_i];
		K2[cnt_i] = O_PAD ^ K0[cnt_i];
	}

	SHA256_Init(&info);
	SHA256_Process(&info, K1, sizeof(K1));
	SHA256_Process(&info, pszMessage, uPlainTextLen);
	SHA256_Close(&info, firsOut);

	SHA256_Init(&info);
	SHA256_Process(&info, K2, sizeof(K2));
	SHA256_Process(&info, firsOut, sizeof(firsOut));
	SHA256_Close(&info, mac);
}

// EOF
