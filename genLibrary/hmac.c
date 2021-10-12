#include "YBCrypto.h"
#include "hmac.h"

HMACManager MM;

int32_t YBCrypto_HMAC(uint32_t ALG, const uint8_t *key, uint32_t key_bytelen, const uint8_t *msg, uint64_t msg_byteLen, uint8_t *mac)
{
    int32_t ret = SUCCESS;

    //TODO Module 상태

    if(ALG != SHA256 && ALG != SHA3)
    {
        YBCrypto_ChangeState(YBCrtypto_CM_NORMAL_ERROR);
        ret = FAIL_INVALID_INPUT_DATA;
        goto EXIT;
    }

    ret = HMAC_init(&MM, ALG, key, key_bytelen);
    if (ret != SUCCESS) goto EXIT;

    ret = HMAC_update(&MM, msg, msg_byteLen);
    if (ret != SUCCESS) goto EXIT;

    ret = HMAC_final(&MM, mac);
    if (ret != SUCCESS) goto EXIT;


EXIT:
    if (ret != SUCCESS) fprintf(stdout, "=*Location : YBCrypto_HMAC              =\n");
    
    return ret;
}
