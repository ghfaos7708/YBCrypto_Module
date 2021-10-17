#include "YBCrypto.h"
#include "mode.h"

extern int32_t YBCRYPTO_STATE;
extern IS_ALG_TESTED algTestedFlag;
extern int32_t Inner_API_GetState(void);
extern void YBCrypto_ChangeState(int32_t newState);
CipherManager CM;

int32_t YBCrypto_BlockCipher(uint32_t ALG, int32_t MODE, int32_t direct, const uint8_t *user_key, uint32_t key_bitlen, const uint8_t *in, uint64_t in_byteLen, const uint8_t *iv, uint8_t *out)
{
    int32_t ret = SUCCESS;
    int32_t parameter_flag = TRUE;
    int32_t state = Inner_API_GetState();
    uint64_t out_byteLen = 0;
    uint32_t pad_bytelen = 0;

    //! check Module sate and Conditional Test
    if ((state != YBCrtypto_CM_NOMAL_VM) && (state != YBCrtypto_CM_PRE_SELFTEST))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "=     [YBCrypto V1.0 Not Nomal Mode]    =\n");
        fprintf(stdout, "=*Location : YBCrypto_BlockCipher       =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_INVALID_MODULE_STATE;
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        Destroy_YBCrypto();
        return ret;
    }

    if ((state != YBCrtypto_CM_PRE_SELFTEST) && (algTestedFlag.isBlockCipherTested != SUCCESS))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "= [YBCrypto V1.0 Not Performed KATtest] =\n");
        fprintf(stdout, "=*Location : YBCrypto_BlockCipher       =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_NOT_PERFORM_KATSELFTEST;
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        Destroy_YBCrypto();
        return ret;
    }

    //! check parameter type
    if (((ALG != ARIA) && (ALG != AES)) || ((MODE != ECB_MODE) && (MODE != CBC_MODE) && (MODE != CTR_MODE)) || ((direct != ENCRYPT) && (direct != DECRYPT)))
    {
        parameter_flag = FALSE;
        goto INIT;
    }
    if (user_key == NULL || in == NULL || out == NULL)
    {
        parameter_flag = FALSE;
        goto INIT;
    }
    if (((key_bitlen != 128) && (key_bitlen != 192) && (key_bitlen != 256)) || (in_byteLen == 0) || (in_byteLen > BC_MAX_ENCRYPTED_LEN))
    {
        parameter_flag = FALSE;
        goto INIT;
    }

    if ((MODE != ECB_MODE) && (iv == NULL))
    {
        parameter_flag = FALSE;
        goto INIT;
    }

INIT:
    if (parameter_flag != TRUE)
    {
        YBCrypto_ChangeState(YBCrtypto_CM_NORMAL_ERROR);

        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "=    [YBCrypto V1.0 Parameter ERROR]    =\n");
        fprintf(stdout, "=*Location : YBCrypto_BlockCipher       =\n");
        fprintf(stdout, "=*Please revise parameters...           =\n");
        fprintf(stdout, "=*CM-> YBCrypto_CM_NOMAL_ERROR          =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_NOMAL_VM            =\n");
        fprintf(stdout, "=========================================\n\n");

        YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);
        ret = FAIL_INVALID_INPUT_DATA;
        return ret;
    }

    //! Encrypting oR Decrypting
    if ((state != YBCrtypto_CM_PRE_SELFTEST) && (ALG == AES))
    {
        YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_NVM);
    }
    switch (MODE)
    {
    case ECB_MODE:
        ret = ECB_Init(&CM, ALG, direct, user_key, key_bitlen);
        if (ret != SUCCESS)
            goto EXIT;
        ret = ECB_Update(&CM, in, in_byteLen, out, &out_byteLen);
        if (ret != SUCCESS)
            goto EXIT;
        ret = ECB_Final(&CM, out, &pad_bytelen);
        if (ret != SUCCESS)
            goto EXIT;
        break;

    case CBC_MODE:
        ret = CBC_Init(&CM, ALG, direct, user_key, key_bitlen, iv);
        if (ret != SUCCESS)
            goto EXIT;
        ret = CBC_Update(&CM, in, in_byteLen, out, &out_byteLen);
        if (ret != SUCCESS)
            goto EXIT;
        ret = CBC_Final(&CM, out, &pad_bytelen);
        if (ret != SUCCESS)
            goto EXIT;
        break;

    case CTR_MODE:
        ret = CTR_Init(&CM, ALG, direct, user_key, key_bitlen, iv);
        if (ret != SUCCESS)
            goto EXIT;
        ret = CTR_Update(&CM, in, in_byteLen, out, &out_byteLen);
        if (ret != SUCCESS)
            goto EXIT;
        ret = CTR_Final(&CM, out, &pad_bytelen);
        if (ret != SUCCESS)
            goto EXIT;
        break;

    default:
        //Do not occur.
        return FAIL_INVALID_INPUT_DATA;
        break;
    }

    if ((state != YBCrtypto_CM_PRE_SELFTEST) && (ALG == AES))
    {
        YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);
    }

EXIT:
    if (ret != SUCCESS)
        fprintf(stdout, "=*Location : YBCrypto_BlockCipher       =\n");
    parameter_flag = 0x00;
    state = 0x00;
    out_byteLen = 0x00;
    pad_bytelen = 0x00;
    YBCrypto_memset(&CM, 0x00, sizeof(CipherManager));
    return ret;
}

int32_t YBCrypto_BlockCipher_Init(uint32_t ALG, int32_t MODE, int32_t direct, const uint8_t *user_key, uint32_t key_bitlen, const uint8_t *iv)
{
    int32_t ret = SUCCESS;
    int32_t parameter_flag = TRUE;
    int32_t state = Inner_API_GetState();

    //! check Module sate and Conditional Test
    if ((state != YBCrtypto_CM_NOMAL_VM) && (state != YBCrtypto_CM_PRE_SELFTEST))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "=     [YBCrypto V1.0 Not Nomal Mode]    =\n");
        fprintf(stdout, "=*Location : YBCrypto_BlockCipher_Init  =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_INVALID_MODULE_STATE;
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        Destroy_YBCrypto();
        return ret;
    }

    if ((state != YBCrtypto_CM_PRE_SELFTEST) && (algTestedFlag.isBlockCipherTested != SUCCESS))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "= [YBCrypto V1.0 Not Performed KATtest] =\n");
        fprintf(stdout, "=*Location : YBCrypto_BlockCipher_Init  =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_NOT_PERFORM_KATSELFTEST;
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        Destroy_YBCrypto();
        return ret;
    }

    //! check parameter type
    if (((ALG != ARIA) && (ALG != AES)) || ((MODE != ECB_MODE) && (MODE != CBC_MODE) && (MODE != CTR_MODE)) || ((direct != ENCRYPT) && (direct != DECRYPT)))
    {
        parameter_flag = FALSE;
        goto INIT;
    }

    if (((key_bitlen != 128) && (key_bitlen != 192) && (key_bitlen != 256)) || (user_key == NULL))
    {
        parameter_flag = FALSE;
        goto INIT;
    }

    if ((MODE != ECB_MODE) && (iv == NULL))
    {
        parameter_flag = FALSE;
        goto INIT;
    }

INIT:
    if (parameter_flag != TRUE)
    {
        YBCrypto_ChangeState(YBCrtypto_CM_NORMAL_ERROR);

        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "=    [YBCrypto V1.0 Parameter ERROR]    =\n");
        fprintf(stdout, "=*Location : YBCrypto_BlockCipher_Init  =\n");
        fprintf(stdout, "=*Please revise parameters...           =\n");
        fprintf(stdout, "=*CM-> YBCrypto_CM_NOMAL_ERROR          =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_NOMAL_VM            =\n");
        fprintf(stdout, "=========================================\n\n");

        YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);
        ret = FAIL_INVALID_INPUT_DATA;
        return ret;
    }

    //! Encrypting oR Decrypting
    if ((state != YBCrtypto_CM_PRE_SELFTEST) && (ALG == AES))
    {
        YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_NVM);
    }
    switch (MODE)
    {
    case ECB_MODE:
        ret = ECB_Init(&CM, ALG, direct, user_key, key_bitlen);
        if (ret != SUCCESS)
            goto EXIT;
        break;

    case CBC_MODE:
        ret = CBC_Init(&CM, ALG, direct, user_key, key_bitlen, iv);
        if (ret != SUCCESS)
            goto EXIT;
        break;

    case CTR_MODE:
        ret = CTR_Init(&CM, ALG, direct, user_key, key_bitlen, iv);
        if (ret != SUCCESS)
            goto EXIT;
        break;

    default:
        //Do not occur.
        return FAIL_INVALID_INPUT_DATA;
        break;
    }

    if ((state != YBCrtypto_CM_PRE_SELFTEST) && (ALG == AES))
    {
        YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);
    }

EXIT:
    if (ret != SUCCESS)
        fprintf(stdout, "=*Location : YBCrypto_BlockCipher_Init  =\n");
    parameter_flag = 0x00;
    state = 0x00;
    return ret;
}

int32_t YBCrypto_BlockCipher_Update(const uint8_t *in, uint64_t in_byteLen, uint8_t *out, uint64_t *out_byteLen)
{
    int32_t ret = SUCCESS;
    int32_t parameter_flag = TRUE;
    int32_t state = Inner_API_GetState();

    //! check Module sate and Conditional Test
    if ((state != YBCrtypto_CM_NOMAL_VM) && (state != YBCrtypto_CM_PRE_SELFTEST))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "=     [YBCrypto V1.0 Not Nomal Mode]    =\n");
        fprintf(stdout, "=*Location : YBCrypto_BlockCipher_Update=\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_INVALID_MODULE_STATE;
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        Destroy_YBCrypto();
        return ret;
    }

    if ((state != YBCrtypto_CM_PRE_SELFTEST) && (algTestedFlag.isBlockCipherTested != SUCCESS))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "= [YBCrypto V1.0 Not Performed KATtest] =\n");
        fprintf(stdout, "=*Location : YBCrypto_BlockCipher_Update=\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_NOT_PERFORM_KATSELFTEST;
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        Destroy_YBCrypto();
        return ret;
    }

    //! check parameter type

    if (in == NULL || out == NULL || out_byteLen == NULL)
    {
        parameter_flag = FALSE;
        goto INIT;
    }
    if ((in_byteLen == 0) || (in_byteLen > BC_MAX_ENCRYPTED_LEN))
    {
        parameter_flag = FALSE;
        goto INIT;
    }

INIT:
    if (parameter_flag != TRUE)
    {
        YBCrypto_ChangeState(YBCrtypto_CM_NORMAL_ERROR);

        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "=    [YBCrypto V1.0 Parameter ERROR]    =\n");
        fprintf(stdout, "=*Location : YBCrypto_BlockCipher_Update=\n");
        fprintf(stdout, "=*Please revise parameters...           =\n");
        fprintf(stdout, "=*CM-> YBCrypto_CM_NOMAL_ERROR          =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_NOMAL_VM            =\n");
        fprintf(stdout, "=========================================\n\n");

        YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);
        ret = FAIL_INVALID_INPUT_DATA;
        return ret;
    }

    //! Encrypting oR Decrypting
    if ((state != YBCrtypto_CM_PRE_SELFTEST) && (CM.algo == AES))
    {
        YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_NVM);
    }
    switch (CM.mode)
    {
    case ECB_MODE:
        ret = ECB_Update(&CM, in, in_byteLen, out, out_byteLen);
        if (ret != SUCCESS)
            goto EXIT;
        break;

    case CBC_MODE:
        ret = CBC_Update(&CM, in, in_byteLen, out, out_byteLen);
        if (ret != SUCCESS)
            goto EXIT;
        break;

    case CTR_MODE:
        ret = CTR_Update(&CM, in, in_byteLen, out, out_byteLen);
        if (ret != SUCCESS)
            goto EXIT;
        break;

    default:
        //Do not occur.
        return FAIL_INVALID_INPUT_DATA;
        break;
    }

    if ((state != YBCrtypto_CM_PRE_SELFTEST) && (CM.algo == AES))
    {
        YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);
    }

EXIT:
    if (ret != SUCCESS)
        fprintf(stdout, "=*Location : YBCrypto_BlockCipher_Update=\n");
    parameter_flag = 0x00;
    state = 0x00;
    return ret;
}

int32_t YBCrypto_BlockCipher_Final(uint8_t *out, uint32_t *pad_bytelen)
{
    int32_t ret = SUCCESS;
    int32_t parameter_flag = TRUE;
    int32_t state = Inner_API_GetState();

    //! check Module sate and Conditional Test
    if ((state != YBCrtypto_CM_NOMAL_VM) && (state != YBCrtypto_CM_PRE_SELFTEST))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "=     [YBCrypto V1.0 Not Nomal Mode]    =\n");
        fprintf(stdout, "=*Location : YBCrypto_BlockCipher_Final =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_INVALID_MODULE_STATE;
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        Destroy_YBCrypto();
        return ret;
    }

    if ((state != YBCrtypto_CM_PRE_SELFTEST) && (algTestedFlag.isBlockCipherTested != SUCCESS))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "= [YBCrypto V1.0 Not Performed KATtest] =\n");
        fprintf(stdout, "=*Location : YBCrypto_BlockCipher_Final =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_NOT_PERFORM_KATSELFTEST;
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        Destroy_YBCrypto();
        return ret;
    }

    //! check parameter type
    if ((out == NULL) || (pad_bytelen == NULL))
    {
        parameter_flag = FALSE;
        goto INIT;
    }

INIT:
    if (parameter_flag != TRUE)
    {
        YBCrypto_ChangeState(YBCrtypto_CM_NORMAL_ERROR);

        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "=    [YBCrypto V1.0 Parameter ERROR]    =\n");
        fprintf(stdout, "=*Location : YBCrypto_BlockCipher_Final =\n");
        fprintf(stdout, "=*Please revise parameters...           =\n");
        fprintf(stdout, "=*CM-> YBCrypto_CM_NOMAL_ERROR          =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_NOMAL_VM            =\n");
        fprintf(stdout, "=========================================\n\n");

        YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);
        ret = FAIL_INVALID_INPUT_DATA;
        return ret;
    }

    //! Encrypting oR Decrypting
    if ((state != YBCrtypto_CM_PRE_SELFTEST) && (CM.algo == AES))
    {
        YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_NVM);
    }
    switch (CM.mode)
    {
    case ECB_MODE:
        ret = ECB_Final(&CM, out, pad_bytelen);
        if (ret != SUCCESS)
            goto EXIT;
        break;

    case CBC_MODE:
        ret = CBC_Final(&CM, out, pad_bytelen);
        if (ret != SUCCESS)
            goto EXIT;
        break;

    case CTR_MODE:
        ret = CTR_Final(&CM, out, pad_bytelen);
        if (ret != SUCCESS)
            goto EXIT;
        break;

    default:
        //Do not occur.
        return FAIL_INVALID_INPUT_DATA;
        break;
    }

    if ((state != YBCrtypto_CM_PRE_SELFTEST) && (CM.algo == AES))
    {
        YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);
    }

EXIT:
    if (ret != SUCCESS)
        fprintf(stdout, "=*Location : YBCrypto_BlockCipher_Final =\n");
    parameter_flag = 0x00;
    state = 0x00;
    YBCrypto_memset(&CM, 0x00, sizeof(CipherManager));
    return ret;
}

int32_t YBCrypto_BlockCipher_Clear(void)
{
    int32_t ret = SUCCESS;
    int32_t state = Inner_API_GetState();

    //! check Module sate and Conditional Test
    if ((state != YBCrtypto_CM_NOMAL_VM) && (state != YBCrtypto_CM_PRE_SELFTEST))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "=     [YBCrypto V1.0 Not Nomal Mode]    =\n");
        fprintf(stdout, "=*Location : YBCrypto_BlockCipher_Clear =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_INVALID_MODULE_STATE;
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        Destroy_YBCrypto();
        return ret;
    }

    if ((state != YBCrtypto_CM_PRE_SELFTEST) && (algTestedFlag.isBlockCipherTested != SUCCESS))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "= [YBCrypto V1.0 Not Performed KATtest] =\n");
        fprintf(stdout, "=*Location : YBCrypto_BlockCipher_Clear =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_NOT_PERFORM_KATSELFTEST;
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        Destroy_YBCrypto();
        return ret;
    }

    //! Zero Manager
    YBCrypto_memset(&CM, 0x00, sizeof(CipherManager));
    return ret;
}