#include "YBCrypto.h"
#include "mode.h"

CipherManager CM;

int32_t YBCrypto_BlockCipher(int32_t ALG, int32_t MODE, int32_t direct, const uint8_t *user_key, uint32_t key_bitlen, const uint8_t *in, uint64_t in_byteLen, const uint8_t *iv, uint8_t *out)
{
    int32_t ret = SUCCESS;
    uint64_t out_byteLen = 0;
    uint32_t pad_bytelen = 0;

    //TODO Module 상태

    //! check [ALG]
    if((ALG != ARIA) && (ALG != AES))
    {

    }
    switch (MODE)
    {
    case ECB_MODE:
        ret = ECB_Init(&CM, ALG, direct, user_key, key_bitlen);
        if(ret != SUCCESS) goto EXIT;
        ret = ECB_Update(&CM, in, in_byteLen, out, &out_byteLen);
        if(ret != SUCCESS) goto EXIT;
        ret = ECB_Final(&CM, out, &pad_bytelen);
        if(ret != SUCCESS) goto EXIT;
        break;

    case CBC_MODE:
        ret = CBC_Init(&CM, ALG, direct, user_key, key_bitlen,iv);
        if(ret != SUCCESS) goto EXIT;
        ret = CBC_Update(&CM, in, in_byteLen, out, &out_byteLen);
        if(ret != SUCCESS) goto EXIT;
        ret = CBC_Final(&CM, out, &pad_bytelen);
        if(ret != SUCCESS) goto EXIT;
        break;

    case CTR_MODE:
        ret = CTR_Init(&CM, ALG, direct, user_key, key_bitlen,iv);
        if(ret != SUCCESS) goto EXIT;
        ret = CTR_Update(&CM, in, in_byteLen, out, &out_byteLen);
        if(ret != SUCCESS) goto EXIT;
        ret = CTR_Final(&CM, out, &pad_bytelen);
        if(ret != SUCCESS) goto EXIT;
        break;

    default:
        return FAIL_CORE;
        break;
    }

EXIT: 
    out_byteLen = 0, pad_bytelen = 0;
    return ret;
}