#include "YBCrypto.h"
#include "hash.h"

extern int32_t YBCRYPTO_STATE;
extern IS_ALG_TESTED algTestedFlag;
extern int32_t Inner_API_GetState(void);
extern void YBCrypto_ChangeState(int32_t newState);
// HashManager HM;

int32_t __attribute__ ((visibility("default"))) YBCrypto_Hash(HashManager* HM, uint32_t ALG, const uint8_t *msg, uint64_t msg_byteLen, uint8_t *md)
{
    int32_t ret = SUCCESS;
    int32_t parameter_flag = TRUE;
    int32_t state = Inner_API_GetState();

    //! check Module sate and Conditional Test
    if ((state != YBCrtypto_CM_NOMAL_VM) && (state != YBCrtypto_CM_PRE_SELFTEST))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "=     [YBCrypto V1.0 Not Nomal Mode]    =\n");
        fprintf(stdout, "=*Location : YBCrypto_Hash              =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_INVALID_MODULE_STATE;
        YBCrypto_memset(HM, 0x00, sizeof(HashManager));
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        Destroy_YBCrypto();
        return ret;
    }

    if ((state != YBCrtypto_CM_PRE_SELFTEST) && (algTestedFlag.isHashTested != SUCCESS))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "= [YBCrypto V1.0 Not Performed KATtest] =\n");
        fprintf(stdout, "=*Location : YBCrypto_Hash              =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_NOT_PERFORM_KATSELFTEST;
        YBCrypto_memset(HM, 0x00, sizeof(HashManager));
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        Destroy_YBCrypto();
        return ret;
    }

    //! check parameter type
    if ((ALG != SHA256) && (ALG != SHA3))
    {
        parameter_flag = FALSE;
        goto INIT;
    }
    if (msg == NULL || md == NULL)
    {
        parameter_flag = FALSE;
        goto INIT;
    }
    if ((msg_byteLen == 0) || (msg_byteLen > HF_MAX_HASING_LEN))
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
        fprintf(stdout, "=*Location : YBCrypto_Hash              =\n");
        fprintf(stdout, "=*Please revise parameters...           =\n");
        fprintf(stdout, "=*CM-> YBCrypto_CM_NOMAL_ERROR          =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_NOMAL_VM            =\n");
        fprintf(stdout, "=========================================\n\n");

        YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);
        ret = FAIL_INVALID_INPUT_DATA;
        return ret;
    }

    //! Hashing
    switch (ALG)
    {
    case SHA256:
        ret = SHA256_init(HM);
        if (ret != SUCCESS)
            goto EXIT;
        ret = SHA256_update(HM, msg, msg_byteLen);
        if (ret != SUCCESS)
            goto EXIT;
        ret = SHA256_final(HM, md);
        if (ret != SUCCESS)
            goto EXIT;
        break;

    case SHA3:
        ret = SHA3_init(HM);
        if (ret != SUCCESS)
            goto EXIT;
        ret = SHA3_update(HM, msg, msg_byteLen);
        if (ret != SUCCESS)
            goto EXIT;
        ret = SHA3_final(HM, md);
        if (ret != SUCCESS)
            goto EXIT;
        break;

    default:
        //Do not occur.
        ret = FAIL_INVALID_INPUT_DATA;
        break;
    }

EXIT:
    if (ret != SUCCESS)
        fprintf(stdout, "=*Location : YBCrypto_Hash              =\n");
    parameter_flag = 0x00;
    state = 0x00;
    YBCrypto_memset(HM, 0x00, sizeof(HashManager));
    return ret;
}

int32_t __attribute__ ((visibility("default"))) YBCrypto_Hash_Init(HashManager* HM, uint32_t ALG)
{
    int32_t ret = SUCCESS;
    int32_t parameter_flag = TRUE;
    int32_t state = Inner_API_GetState();

    //! check Module sate and Conditional Test
    if ((state != YBCrtypto_CM_NOMAL_VM) && (state != YBCrtypto_CM_PRE_SELFTEST))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "=     [YBCrypto V1.0 Not Nomal Mode]    =\n");
        fprintf(stdout, "=*Location : YBCrypto_Hash_Init         =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_INVALID_MODULE_STATE;
        YBCrypto_memset(HM, 0x00, sizeof(HashManager));
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        Destroy_YBCrypto();
        return ret;
    }

    if ((state != YBCrtypto_CM_PRE_SELFTEST) && (algTestedFlag.isHashTested != SUCCESS))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "= [YBCrypto V1.0 Not Performed KATtest] =\n");
        fprintf(stdout, "=*Location : YBCrypto_Hash_Init         =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_NOT_PERFORM_KATSELFTEST;
        YBCrypto_memset(HM, 0x00, sizeof(HashManager));
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        Destroy_YBCrypto();
        return ret;
    }

    //! check parameter type
    if ((ALG != SHA256) && (ALG != SHA3))
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
        fprintf(stdout, "=*Location : YBCrypto_Hash_Init         =\n");
        fprintf(stdout, "=*Please revise parameters...           =\n");
        fprintf(stdout, "=*CM-> YBCrypto_CM_NOMAL_ERROR          =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_NOMAL_VM            =\n");
        fprintf(stdout, "=========================================\n\n");

        YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);
        YBCrypto_memset(HM, 0x00, sizeof(HashManager));
        ret = FAIL_INVALID_INPUT_DATA;
        return ret;
    }

    //! Hashing
    switch (ALG)
    {
    case SHA256:
        ret = SHA256_init(HM);
        if (ret != SUCCESS)
            goto EXIT;
        break;

    case SHA3:
        ret = SHA3_init(HM);
        if (ret != SUCCESS)
            goto EXIT;
        break;

    default:
        //Do not occur.
        ret = FAIL_INVALID_INPUT_DATA;
        break;
    }

EXIT:
    if (ret != SUCCESS)
    {
        fprintf(stdout, "=*Location : YBCrypto_Hash_Init         =\n");
        YBCrypto_memset(HM, 0x00, sizeof(HashManager));
    }
    parameter_flag = 0x00;
    state = 0x00;
    return ret;
}

int32_t __attribute__ ((visibility("default"))) YBCrypto_Hash_Update(HashManager* HM, const uint8_t *msg, uint64_t msg_byteLen)
{
    int32_t ret = SUCCESS;
    int32_t parameter_flag = TRUE;
    int32_t state = Inner_API_GetState();

    //! check Module sate and Conditional Test
    if ((state != YBCrtypto_CM_NOMAL_VM) && (state != YBCrtypto_CM_PRE_SELFTEST))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "=     [YBCrypto V1.0 Not Nomal Mode]    =\n");
        fprintf(stdout, "=*Location : YBCrypto_Hash_Update       =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_INVALID_MODULE_STATE;
        YBCrypto_memset(HM, 0x00, sizeof(HashManager));
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        Destroy_YBCrypto();
        return ret;
    }

    if ((state != YBCrtypto_CM_PRE_SELFTEST) && (algTestedFlag.isHashTested != SUCCESS))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "= [YBCrypto V1.0 Not Performed KATtest] =\n");
        fprintf(stdout, "=*Location : YBCrypto_Hash_Update       =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_NOT_PERFORM_KATSELFTEST;
        YBCrypto_memset(HM, 0x00, sizeof(HashManager));
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        Destroy_YBCrypto();
        return ret;
    }

    //! check parameter type
    if ((msg == NULL) || (msg_byteLen == 0) || (msg_byteLen > HF_MAX_HASING_LEN))
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
        fprintf(stdout, "=*Location : YBCrypto_Hash_Update       =\n");
        fprintf(stdout, "=*Please revise parameters...           =\n");
        fprintf(stdout, "=*CM-> YBCrypto_CM_NOMAL_ERROR          =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_NOMAL_VM            =\n");
        fprintf(stdout, "=========================================\n\n");

        YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);
        ret = FAIL_INVALID_INPUT_DATA;
        return ret;
    }

    //! Hashing
    switch (HM->algo)
    {
    case SHA256:
        ret = SHA256_update(HM, msg, msg_byteLen);
        if (ret != SUCCESS)
            goto EXIT;
        break;

    case SHA3:
        ret = SHA3_update(HM, msg, msg_byteLen);
        if (ret != SUCCESS)
            goto EXIT;
        break;

    default:
        //Do not occur.
        ret = FAIL_INVALID_INPUT_DATA;
        break;
    }

EXIT:
    if (ret != SUCCESS)
    {
        fprintf(stdout, "=*Location : YBCrypto_Hash_Update       =\n");
        YBCrypto_memset(HM, 0x00, sizeof(HashManager));
    }
    parameter_flag = 0x00;
    state = 0x00;
    return ret;
}

int32_t __attribute__ ((visibility("default"))) YBCrypto_Hash_Final(HashManager* HM, uint8_t *md)
{
    int32_t ret = SUCCESS;
    int32_t parameter_flag = TRUE;
    int32_t state = Inner_API_GetState();

    //! check Module sate and Conditional Test
    if ((state != YBCrtypto_CM_NOMAL_VM) && (state != YBCrtypto_CM_PRE_SELFTEST))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "=     [YBCrypto V1.0 Not Nomal Mode]    =\n");
        fprintf(stdout, "=*Location : YBCrypto_Hash_Final        =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_INVALID_MODULE_STATE;
        YBCrypto_memset(HM, 0x00, sizeof(HashManager));
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        Destroy_YBCrypto();
        return ret;
    }

    if ((state != YBCrtypto_CM_PRE_SELFTEST) && (algTestedFlag.isHashTested != SUCCESS))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "= [YBCrypto V1.0 Not Performed KATtest] =\n");
        fprintf(stdout, "=*Location : YBCrypto_Hash_Final        =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_NOT_PERFORM_KATSELFTEST;
        YBCrypto_memset(HM, 0x00, sizeof(HashManager));
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        Destroy_YBCrypto();
        return ret;
    }

    //! check parameter type
    if (md == NULL)
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
        fprintf(stdout, "=*Location : YBCrypto_Hash_Final        =\n");
        fprintf(stdout, "=*Please revise parameters...           =\n");
        fprintf(stdout, "=*CM-> YBCrypto_CM_NOMAL_ERROR          =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_NOMAL_VM            =\n");
        fprintf(stdout, "=========================================\n\n");

        YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);
        ret = FAIL_INVALID_INPUT_DATA;
        return ret;
    }

    //! Hashing
    switch (HM->algo)
    {
    case SHA256:
        ret = SHA256_final(HM, md);
        if (ret != SUCCESS)
            goto EXIT;
        break;

    case SHA3:
        ret = SHA3_final(HM, md);
        if (ret != SUCCESS)
            goto EXIT;
        break;

    default:
        //Do not occur.
        ret = FAIL_INVALID_INPUT_DATA;
        break;
    }

EXIT:
    if (ret != SUCCESS)
        fprintf(stdout, "=*Location : YBCrypto_Hash_Final        =\n");
    parameter_flag = 0x00;
    state = 0x00;
    YBCrypto_memset(HM, 0x00, sizeof(HashManager));
    return ret;
}

int32_t __attribute__ ((visibility("default"))) YBCrypto_Hash_Clear(HashManager* HM)
{
    int32_t ret = SUCCESS;
    int32_t state = Inner_API_GetState();

    //! check Module sate and Conditional Test
    if ((state != YBCrtypto_CM_NOMAL_VM) && (state != YBCrtypto_CM_PRE_SELFTEST))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "=     [YBCrypto V1.0 Not Nomal Mode]    =\n");
        fprintf(stdout, "=*Location : YBCrypto_Hash_Clear        =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_INVALID_MODULE_STATE;
        YBCrypto_memset(HM, 0x00, sizeof(HashManager));
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        Destroy_YBCrypto();
        return ret;
    }

    if ((state != YBCrtypto_CM_PRE_SELFTEST) && (algTestedFlag.isHashTested != SUCCESS))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "= [YBCrypto V1.0 Not Performed KATtest] =\n");
        fprintf(stdout, "=*Location : YBCrypto_Hash_Clear        =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_NOT_PERFORM_KATSELFTEST;
        YBCrypto_memset(HM, 0x00, sizeof(HashManager));
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        Destroy_YBCrypto();
        return ret;
    }

    //! Zero Manager
    YBCrypto_memset(HM, 0x00, sizeof(HashManager));
    return ret;
}
//EOF