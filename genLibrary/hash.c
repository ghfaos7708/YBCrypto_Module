#include "YBCrypto.h"
#include "hash.h"

extern int32_t YBCRYPTO_STATE;
extern IS_ALG_TESTED algTestedFlag;
extern int32_t Inner_API_GetState(void);
HashManager HM;

int32_t YBCrypto_Hash(uint32_t ALG, const uint8_t *msg, uint64_t in_byteLen, uint8_t *md)
{
    int32_t ret = SUCCESS;

    //TODO Module 상태

    switch (ALG)
    {
    case SHA256:
        ret = SHA256_init(&HM);
        if(ret != SUCCESS) goto EXIT;

        ret = SHA256_update(&HM, msg, in_byteLen);
        if(ret != SUCCESS) goto EXIT;

        ret = SHA256_final(&HM, md);
        if(ret != SUCCESS) goto EXIT;
        break;

    case SHA3:
        ret = SHA3_init(&HM);
        if(ret != SUCCESS) goto EXIT;

        ret = SHA3_update(&HM, msg, in_byteLen);
        if(ret != SUCCESS) goto EXIT;

        ret = SHA3_final(&HM, md);
        if(ret != SUCCESS) goto EXIT;
        break;

    default:
        ret = FAIL_INVALID_INPUT_DATA;
        break;
    }

EXIT: 
    if(ret != SUCCESS)  fprintf(stdout, "=*Location : YBCrypto_Hash              =\n");
    return ret;
}

//EOF