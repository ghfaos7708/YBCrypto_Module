#include "YBCrypto.h"
#include "ctr_drbg.h"
#include "entropy.h"
#define ENTROPY_LEN_SMALL_MAX 0x9400
#define NONCE_LEN_SMALL 0x9401
#define PARAMETER_ERROR 0x9402
#define PERSONALIZED_STRING_LEN_MAX 0x9403
#define ADD_INPUT_LEN 0x9404
#define NOT_INITALIZED 0x9405


extern int32_t YBCRYPTO_STATE;
extern IS_ALG_TESTED algTestedFlag;
extern int32_t Inner_API_GetState(void);
extern void YBCrypto_ChangeState(int32_t newState);

static inline void print_parameterErroR(uint32_t error_flag)
{
    switch (error_flag)
    {
    case ENTROPY_LEN_SMALL_MAX:
        fprintf(stdout, "=*Please revise entropy len...          =\n");
        break;

    case NONCE_LEN_SMALL:
        fprintf(stdout, "=*Please revise nonce len...            =\n");
        break;

    case PARAMETER_ERROR:
        fprintf(stdout, "=*Please revise parameter(ALG, keybit)  =\n");
        break;

    case PERSONALIZED_STRING_LEN_MAX:
        fprintf(stdout, "=*Please revise per-stringlen(too long) =\n");
        break;

    case ADD_INPUT_LEN:
        fprintf(stdout, "=*Please revise add_in(signed or long)  =\n");
        break;

    case NOT_INITALIZED:
        fprintf(stdout, "=*Please call CTRDRBG_Instantiate       =\n");
        break;

    default:
        break;
    }
}

int32_t __attribute__ ((visibility("default"))) YBCrypto_CTR_DRBG_Instantiate(
    DRBGManager *DM,
    uint32_t ALG, uint32_t key_bitlen,
    uint8_t *entropy_input, uint32_t entropy_bytelen,
    uint8_t *nonce, uint32_t nonce_bytelen,
    uint8_t *personalization_string, uint32_t string_bytelen,
    uint32_t derivation_function_flag)
{
    uint32_t ret = SUCCESS;
    uint32_t parameter_flag = TRUE;
    uint32_t error_flag = TRUE;
    int32_t state = Inner_API_GetState();

    //! check Module sate and Conditional Test
    if ((state != YBCrtypto_CM_NOMAL_VM) && (state != YBCrtypto_CM_PRE_SELFTEST))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "=     [YBCrypto V1.0 Not Nomal Mode]    =\n");
        fprintf(stdout, "=*Location : CTR_DRBG_Instantiate       =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_INVALID_MODULE_STATE;
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        YBCrypto_memset(DM, 0x00, sizeof(DRBGManager));
        Destroy_YBCrypto();
        return ret;
    }

    if ((state != YBCrtypto_CM_PRE_SELFTEST) && (algTestedFlag.isDRBGTested != SUCCESS))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "= [YBCrypto V1.0 Not Performed KATtest] =\n");
        fprintf(stdout, "=*Location : CTR_DRBG_Instantiate       =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_NOT_PERFORM_KATSELFTEST;
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        YBCrypto_memset(DM, 0x00, sizeof(DRBGManager));
        Destroy_YBCrypto();
        return ret;
    }

    YBCrypto_memset(DM, 0x00, sizeof(DRBGManager));

    //! check parameter type
    if (((ALG != ARIA) && (ALG != AES)) || ((derivation_function_flag != USE_DF) && (derivation_function_flag != NO_DF)))
    {
        parameter_flag = FALSE;
        error_flag = PARAMETER_ERROR;
        goto INIT;
    }

    if (((key_bitlen != 128) && (key_bitlen != 192) && (key_bitlen != 256)))
    {
        parameter_flag = FALSE;
        error_flag = PARAMETER_ERROR;
        goto INIT;
    }

    if (nonce == NULL || (nonce_bytelen < (key_bitlen / 16)))
    {
        parameter_flag = FALSE;
        error_flag = NONCE_LEN_SMALL;
        goto INIT;
    }

    if ((personalization_string != NULL) && ((string_bytelen > (MAX_PERSONALIZED_STRING_LEN / 8)) || string_bytelen < 0))
    {
        parameter_flag = FALSE;
        error_flag = PERSONALIZED_STRING_LEN_MAX;
        goto INIT;
    }

    if (derivation_function_flag == USE_DF)
    {
        if ((entropy_input != NULL) && ((entropy_bytelen < (key_bitlen / 8)) || (entropy_bytelen > MAX_ENTROPY_LEN)))
        {
            parameter_flag = FALSE;
            error_flag = ENTROPY_LEN_SMALL_MAX;
            goto INIT;
        }
    }
    else // derivation_function_flag == NO_DF
    {
        if ((entropy_input != NULL) && ((entropy_bytelen < (BC_MAX_BLOCK_SIZE + (key_bitlen / 8))) || (entropy_bytelen > MAX_ENTROPY_LEN)))
        {
            parameter_flag = FALSE;
            error_flag = ENTROPY_LEN_SMALL_MAX;
            goto INIT;
        }
    }

INIT:

    if (parameter_flag != TRUE)
    {
        YBCrypto_ChangeState(YBCrtypto_CM_NORMAL_ERROR);

        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "=    [YBCrypto V1.0 Parameter ERROR]    =\n");
        fprintf(stdout, "=*Location : CTR_DRBG_Instantiate       =\n");
        print_parameterErroR(error_flag);
        fprintf(stdout, "=*CM-> YBCrypto_CM_NOMAL_ERROR          =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_NOMAL_VM            =\n");
        fprintf(stdout, "=========================================\n\n");

        YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);
        ret = FAIL_INVALID_INPUT_DATA;
        return ret;
    }

    //! Entropy Check and CTR_DRBG_Instantiate
    if (entropy_input == NULL)
    {
        uint8_t *ret_entropy = NULL;
        uint32_t ret_entropylen = MAX_ENTROPY_LEN;
        ret_entropy = (uint8_t *)calloc(ret_entropylen, sizeof(uint8_t));

        YBCrypto_ChangeState(YBCrtypto_CM_COND_SELFTEST);
        ret = Inner_API_DRBG_CENT(ret_entropy, ret_entropylen, FALSE);
        if (ret != SUCCESS)
        {
            goto EXIT;
            YBCrypto_memset(ret_entropy, 0x00, ret_entropylen);
            free(ret_entropy);
        }

        YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);
        ret = CTR_DRBG_Instantiate(DM, ALG, key_bitlen, ret_entropy, MAX_ENTROPY_LEN, nonce, nonce_bytelen, personalization_string, string_bytelen, derivation_function_flag);
        YBCrypto_memset(ret_entropy, 0x00, ret_entropylen);
        free(ret_entropy);
    }
    else // there is a entropy_input
    {
        ret = CTR_DRBG_Instantiate(DM, ALG, key_bitlen, entropy_input, entropy_bytelen, nonce, nonce_bytelen, personalization_string, string_bytelen, derivation_function_flag);
    }

EXIT:

    if (ret != SUCCESS)
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "= [YBCrypto V1.0 Entropy oR InFun ERROR]=\n");
        fprintf(stdout, "=*Location : CTR_DRBG_Instantiate       =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        YBCrypto_memset(DM, 0x00, sizeof(DRBGManager));
        Destroy_YBCrypto();
    }

    return ret;
}

int32_t __attribute__ ((visibility("default"))) YBCrypto_CTR_DRBG_Reseed(
    DRBGManager *DM,
    uint8_t *entropy_input, uint32_t entropy_bytelen,
    uint8_t *additional_input, uint32_t add_bytelen)

{
    uint32_t ret = SUCCESS;
    uint32_t parameter_flag = TRUE;
    uint32_t error_flag = TRUE;
    int32_t state = Inner_API_GetState();

    //! check Module sate and Conditional Test
    if ((state != YBCrtypto_CM_NOMAL_VM) && (state != YBCrtypto_CM_PRE_SELFTEST))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "=     [YBCrypto V1.0 Not Nomal Mode]    =\n");
        fprintf(stdout, "=*Location : CTR_DRBG_Reseed            =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_INVALID_MODULE_STATE;
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        YBCrypto_memset(DM, 0x00, sizeof(DRBGManager));
        Destroy_YBCrypto();
        return ret;
    }

    if ((state != YBCrtypto_CM_PRE_SELFTEST) && (algTestedFlag.isDRBGTested != SUCCESS))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "= [YBCrypto V1.0 Not Performed KATtest] =\n");
        fprintf(stdout, "=*Location : CTR_DRBG_Reseed            =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_NOT_PERFORM_KATSELFTEST;
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        YBCrypto_memset(DM, 0x00, sizeof(DRBGManager));
        Destroy_YBCrypto();
        return ret;
    }

    //! check parameter type
    if ((additional_input != NULL) && ((add_bytelen > (MAX_ADDITIONAL_INPUT_LEN / 8)) || add_bytelen < 0))
    {
        parameter_flag = FALSE;
        error_flag = ADD_INPUT_LEN;
        goto INIT;
    }

    if ((entropy_input != NULL) && (((entropy_bytelen < DM->Key_bytelen)) || (entropy_bytelen > MAX_ENTROPY_LEN)))
    {
        parameter_flag = FALSE;
        error_flag = ENTROPY_LEN_SMALL_MAX;
        goto INIT;
    }

    if(DM->initialized_flag != DM_INITIALIZED_FLAG)
    {
        parameter_flag = FALSE;
        error_flag = NOT_INITALIZED;
        goto INIT;
    }

INIT:

    if (parameter_flag != TRUE)
    {
        YBCrypto_ChangeState(YBCrtypto_CM_NORMAL_ERROR);

        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "=    [YBCrypto V1.0 Parameter ERROR]    =\n");
        fprintf(stdout, "=*Location : CTR_DRBG_Reseed            =\n");
        print_parameterErroR(error_flag);
        fprintf(stdout, "=*CM-> YBCrypto_CM_NOMAL_ERROR          =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_NOMAL_VM            =\n");
        fprintf(stdout, "=========================================\n\n");

        YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);
        ret = FAIL_INVALID_INPUT_DATA;
        return ret;
    }

    //! Entropy Check and CTR_DRBG_Reseed
    if (entropy_input == NULL)
    {
        uint8_t *ret_entropy = NULL;
        uint32_t ret_entropylen = MAX_ENTROPY_LEN;
        ret_entropy = (uint8_t *)calloc(ret_entropylen, sizeof(uint8_t));

        YBCrypto_ChangeState(YBCrtypto_CM_COND_SELFTEST);
        ret = Inner_API_DRBG_CENT(ret_entropy, ret_entropylen, FALSE);
        if (ret != SUCCESS)
        {
            goto EXIT;
            YBCrypto_memset(ret_entropy, 0x00, ret_entropylen);
            free(ret_entropy);
        }

        YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);
        ret = CTR_DRBG_Reseed(DM, ret_entropy, MAX_ENTROPY_LEN, additional_input, add_bytelen);
        YBCrypto_memset(ret_entropy, 0x00, ret_entropylen);
        free(ret_entropy);
    }
    else // there is a entropy_input
    {
        ret = CTR_DRBG_Reseed(DM, entropy_input, entropy_bytelen, additional_input, add_bytelen);
    }

EXIT:

    if (ret != SUCCESS)
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "= [YBCrypto V1.0 Entropy oR InFun ERROR]=\n");
        fprintf(stdout, "=*Location : CTR_DRBG_Reseed            =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        YBCrypto_memset(DM, 0x00, sizeof(DRBGManager));
        Destroy_YBCrypto();
    }

    return ret;
}

int32_t __attribute__ ((visibility("default")))  YBCrypto_CTR_DRBG_Generate(
    DRBGManager *DM,
    uint8_t *output, uint64_t requested_num_of_bits,
    uint8_t *entropy_input, uint32_t entropy_bytelen,
    uint8_t *addtional_input, uint32_t add_bytelen,
    uint32_t prediction_resistance_flag)
{
    uint32_t ret = SUCCESS;
    uint32_t parameter_flag = TRUE;
    uint32_t error_flag = TRUE;
    int32_t state = Inner_API_GetState();

    //! check Module sate and Conditional Test
    if ((state != YBCrtypto_CM_NOMAL_VM) && (state != YBCrtypto_CM_PRE_SELFTEST))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "=     [YBCrypto V1.0 Not Nomal Mode]    =\n");
        fprintf(stdout, "=*Location : CTR_DRBG_Generate          =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_INVALID_MODULE_STATE;
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        YBCrypto_memset(DM, 0x00, sizeof(DRBGManager));
        Destroy_YBCrypto();
        return ret;
    }

    if ((state != YBCrtypto_CM_PRE_SELFTEST) && (algTestedFlag.isDRBGTested != SUCCESS))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "= [YBCrypto V1.0 Not Performed KATtest] =\n");
        fprintf(stdout, "=*Location : CTR_DRBG_Generate          =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_NOT_PERFORM_KATSELFTEST;
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        YBCrypto_memset(DM, 0x00, sizeof(DRBGManager));
        Destroy_YBCrypto();
        return ret;
    }

    //! check parameter type
    if ((output == NULL) || (requested_num_of_bits < 0) || ( requested_num_of_bits / 8 > MAX_RAND_BYTE_LEN))
    {
        parameter_flag = FALSE;
        error_flag = PARAMETER_ERROR;
        goto INIT;
    }

    if ((prediction_resistance_flag != USE_PR) && (prediction_resistance_flag != NO_PR))
    {
        parameter_flag = FALSE;
        error_flag = PARAMETER_ERROR;
        goto INIT;
    }

    if ((addtional_input != NULL) && ((add_bytelen > (MAX_ADDITIONAL_INPUT_LEN / 8)) || add_bytelen < 0))
    {
        parameter_flag = FALSE;
        error_flag = ADD_INPUT_LEN;
        goto INIT;
    }

    if ((entropy_input != NULL) && (((entropy_bytelen < DM->Key_bytelen)) || (entropy_bytelen > MAX_ENTROPY_LEN)))
    {
        parameter_flag = FALSE;
        error_flag = ENTROPY_LEN_SMALL_MAX;
        goto INIT;
    }

    if(DM->initialized_flag != DM_INITIALIZED_FLAG)
    {
        parameter_flag = FALSE;
        error_flag = NOT_INITALIZED;
        goto INIT;
    }

INIT:

    if (parameter_flag != TRUE)
    {
        YBCrypto_ChangeState(YBCrtypto_CM_NORMAL_ERROR);

        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "=    [YBCrypto V1.0 Parameter ERROR]    =\n");
        fprintf(stdout, "=*Location : CTR_DRBG_Generate          =\n");
        print_parameterErroR(error_flag);
        fprintf(stdout, "=*CM-> YBCrypto_CM_NOMAL_ERROR          =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_NOMAL_VM            =\n");
        fprintf(stdout, "=========================================\n\n");

        YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);
        ret = FAIL_INVALID_INPUT_DATA;
        return ret;
    }

    //! Entropy Check and CTR_DRBG_Reseed
    if ((entropy_input == NULL) && (prediction_resistance_flag == USE_PR))
    {
        uint8_t *ret_entropy = NULL;
        uint32_t ret_entropylen = MAX_ENTROPY_LEN;
        ret_entropy = (uint8_t *)calloc(ret_entropylen, sizeof(uint8_t));

        YBCrypto_ChangeState(YBCrtypto_CM_COND_SELFTEST);
        ret = Inner_API_DRBG_CENT(ret_entropy, ret_entropylen, FALSE);
        if (ret != SUCCESS)
        {
            goto EXIT;
            YBCrypto_memset(ret_entropy, 0x00, ret_entropylen);
            free(ret_entropy);
        }

        YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);
        ret = CTR_DRBG_Generate(DM, output, requested_num_of_bits, ret_entropy, MAX_ENTROPY_LEN, addtional_input, add_bytelen, prediction_resistance_flag);
        YBCrypto_memset(ret_entropy, 0x00, ret_entropylen);
        free(ret_entropy);
    }
    else // there is a entropy_input
    {
        ret = CTR_DRBG_Generate(DM, output, requested_num_of_bits, entropy_input, entropy_bytelen, addtional_input, add_bytelen, prediction_resistance_flag);
    }
    

EXIT:

    if (ret != SUCCESS)
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "= [YBCrypto V1.0 Entropy oR InFun ERROR]=\n");
        fprintf(stdout, "=*Location : CTR_DRBG_Generate          =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        YBCrypto_memset(DM, 0x00, sizeof(DRBGManager));
        Destroy_YBCrypto();
    }

    return ret;
}

int32_t __attribute__ ((visibility("default"))) YBCrypto_CTR_DRBG_Uninstantiate(DRBGManager *DM)
{
    uint32_t ret = SUCCESS;
    uint32_t parameter_flag = TRUE;
    uint32_t error_flag = TRUE;
    int32_t state = Inner_API_GetState();

    //! check Module sate and Conditional Test
    if ((state != YBCrtypto_CM_NOMAL_VM) && (state != YBCrtypto_CM_PRE_SELFTEST))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "=     [YBCrypto V1.0 Not Nomal Mode]    =\n");
        fprintf(stdout, "=*Location : CTR_DRBG_Generate          =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_INVALID_MODULE_STATE;
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        YBCrypto_memset(DM, 0x00, sizeof(DRBGManager));
        Destroy_YBCrypto();
        return ret;
    }

    if ((state != YBCrtypto_CM_PRE_SELFTEST) && (algTestedFlag.isDRBGTested != SUCCESS))
    {
        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "= [YBCrypto V1.0 Not Performed KATtest] =\n");
        fprintf(stdout, "=*Location : CTR_DRBG_Generate          =\n");
        fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
        fprintf(stdout, "=========================================\n\n");

        ret = FAIL_NOT_PERFORM_KATSELFTEST;
        YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
        YBCrypto_memset(DM, 0x00, sizeof(DRBGManager));
        Destroy_YBCrypto();
        return ret;
    }

     if (DM == NULL)
    {
        parameter_flag = FALSE;
        error_flag = PARAMETER_ERROR;
        goto INIT;
    }

INIT:

    if (parameter_flag != TRUE)
    {
        YBCrypto_ChangeState(YBCrtypto_CM_NORMAL_ERROR);

        fprintf(stdout, "=========================================\n");
        fprintf(stdout, "=    [YBCrypto V1.0 Parameter ERROR]    =\n");
        fprintf(stdout, "=*Location : CTR_DRBG_Uninstantiate     =\n");
        print_parameterErroR(error_flag);
        fprintf(stdout, "=*CM-> YBCrypto_CM_NOMAL_ERROR          =\n");
        fprintf(stdout, "=*CM-> YBCrtypto_CM_NOMAL_VM            =\n");
        fprintf(stdout, "=========================================\n\n");

        YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);
        YBCrypto_memset(DM, 0x00, sizeof(DRBGManager));
        ret = FAIL_INVALID_INPUT_DATA;
        return ret;
    }

    YBCrypto_memset(DM, 0x00, sizeof(DRBGManager));
    return ret;
}
// EOF