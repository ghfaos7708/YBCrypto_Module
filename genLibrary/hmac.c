#include "YBCrypto.h"
#include "hmac.h"

extern int32_t YBCRYPTO_STATE;
extern IS_ALG_TESTED algTestedFlag;
extern int32_t Inner_API_GetState(void);
extern void YBCrypto_ChangeState(int32_t newState);

int32_t YBCrypto_HMAC(HMACManager* MM, uint32_t ALG, const uint8_t *key, uint32_t key_bytelen, const uint8_t *msg, uint64_t msg_byteLen, uint8_t *mac)
{
	int32_t ret = SUCCESS;
	int32_t parameter_flag = TRUE;
	int32_t state = Inner_API_GetState();

	//! check Module sate and Conditional Test
	if ((state != YBCrtypto_CM_NOMAL_VM) && (state != YBCrtypto_CM_PRE_SELFTEST))
	{
		fprintf(stdout, "=========================================\n");
		fprintf(stdout, "=     [YBCrypto V1.0 Not Nomal Mode]    =\n");
		fprintf(stdout, "=*Location : YBCrypto_HMAC              =\n");
		fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
		fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
		fprintf(stdout, "=========================================\n\n");

		ret = FAIL_INVALID_MODULE_STATE;
		YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
		Destroy_YBCrypto();
		return ret;
	}

	if ((state != YBCrtypto_CM_PRE_SELFTEST) && (algTestedFlag.isHMACTested != SUCCESS))
	{
		fprintf(stdout, "=========================================\n");
		fprintf(stdout, "= [YBCrypto V1.0 Not Performed KATtest] =\n");
		fprintf(stdout, "=*Location : YBCrypto_HMAC              =\n");
		fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
		fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
		fprintf(stdout, "=========================================\n\n");

		ret = FAIL_NOT_PERFORM_KATSELFTEST;
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
	if ((msg == NULL) || (key == NULL) || (mac == NULL))
	{
		parameter_flag = FALSE;
		goto INIT;
	}
	if ((key_bytelen == 0) || (msg_byteLen == 0) || (msg_byteLen > HM_MAX_HMAC_LEN))
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
		fprintf(stdout, "=*Location : YBCrypto_HMAC              =\n");
		fprintf(stdout, "=*Please revise parameters...           =\n");
		fprintf(stdout, "=*CM-> YBCrypto_CM_NOMAL_ERROR          =\n");
		fprintf(stdout, "=*CM-> YBCrtypto_CM_NOMAL_VM            =\n");
		fprintf(stdout, "=========================================\n\n");

		YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);
		ret = FAIL_INVALID_INPUT_DATA;
		return ret;
	}

	//! Generating MAC
	ret = HMAC_init(MM, ALG, key, key_bytelen);
	if (ret != SUCCESS)
		goto EXIT;
	ret = HMAC_update(MM, msg, msg_byteLen);
	if (ret != SUCCESS)
		goto EXIT;
	ret = HMAC_final(MM, mac);
	if (ret != SUCCESS)
		goto EXIT;

EXIT:
	if (ret != SUCCESS)
	{
		fprintf(stdout, "=*Location : YBCrypto_HMAC              =\n");
	}
	parameter_flag = 0x00;
	state = 0x00;
	YBCrypto_memset(MM, 0x00, sizeof(HashManager));
	return ret;
}

int32_t YBCrypto_HMAC_Init(HMACManager* MM, uint32_t ALG, const uint8_t *key, uint32_t key_bytelen)
{
	int32_t ret = SUCCESS;
	int32_t parameter_flag = TRUE;
	int32_t state = Inner_API_GetState();

	//! check Module sate and Conditional Test
	if ((state != YBCrtypto_CM_NOMAL_VM) && (state != YBCrtypto_CM_PRE_SELFTEST))
	{
		fprintf(stdout, "=========================================\n");
		fprintf(stdout, "=     [YBCrypto V1.0 Not Nomal Mode]    =\n");
		fprintf(stdout, "=*Location : YBCrypto_HMAC_Init         =\n");
		fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
		fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
		fprintf(stdout, "=========================================\n\n");

		ret = FAIL_INVALID_MODULE_STATE;
		YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
		Destroy_YBCrypto();
		return ret;
	}

	if ((state != YBCrtypto_CM_PRE_SELFTEST) && (algTestedFlag.isHMACTested != SUCCESS))
	{
		fprintf(stdout, "=========================================\n");
		fprintf(stdout, "= [YBCrypto V1.0 Not Performed KATtest] =\n");
		fprintf(stdout, "=*Location : YBCrypto_HMAC_Init         =\n");
		fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
		fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
		fprintf(stdout, "=========================================\n\n");

		ret = FAIL_NOT_PERFORM_KATSELFTEST;
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
	if ((key == NULL) || (key_bytelen == 0))
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
		fprintf(stdout, "=*Location : YBCrypto_HMAC_Init         =\n");
		fprintf(stdout, "=*Please revise parameters...           =\n");
		fprintf(stdout, "=*CM-> YBCrypto_CM_NOMAL_ERROR          =\n");
		fprintf(stdout, "=*CM-> YBCrtypto_CM_NOMAL_VM            =\n");
		fprintf(stdout, "=========================================\n\n");

		YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);
		ret = FAIL_INVALID_INPUT_DATA;
		return ret;
	}

	//! Generating MAC
	ret = HMAC_init(MM, ALG, key, key_bytelen);
	if (ret != SUCCESS)
		goto EXIT;

EXIT:
	if (ret != SUCCESS)
	{
		fprintf(stdout, "=*Location : YBCrypto_HMAC_Init         =\n");
		YBCrypto_memset(MM, 0x00, sizeof(HMACManager));
	}
	parameter_flag = 0x00;
	state = 0x00;
	return ret;
}

int32_t YBCrypto_HMAC_Update(HMACManager* MM, const uint8_t *msg, uint64_t msg_byteLen)
{
	int32_t ret = SUCCESS;
	int32_t parameter_flag = TRUE;
	int32_t state = Inner_API_GetState();

	//! check Module sate and Conditional Test
	if ((state != YBCrtypto_CM_NOMAL_VM) && (state != YBCrtypto_CM_PRE_SELFTEST))
	{
		fprintf(stdout, "=========================================\n");
		fprintf(stdout, "=     [YBCrypto V1.0 Not Nomal Mode]    =\n");
		fprintf(stdout, "=*Location : YBCrypto_HMAC_Update       =\n");
		fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
		fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
		fprintf(stdout, "=========================================\n\n");

		ret = FAIL_INVALID_MODULE_STATE;
		YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
		Destroy_YBCrypto();
		return ret;
	}

	if ((state != YBCrtypto_CM_PRE_SELFTEST) && (algTestedFlag.isHMACTested != SUCCESS))
	{
		fprintf(stdout, "=========================================\n");
		fprintf(stdout, "= [YBCrypto V1.0 Not Performed KATtest] =\n");
		fprintf(stdout, "=*Location : YBCrypto_HMAC_Update       =\n");
		fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
		fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
		fprintf(stdout, "=========================================\n\n");

		ret = FAIL_NOT_PERFORM_KATSELFTEST;
		YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
		Destroy_YBCrypto();
		return ret;
	}

	//! check parameter type
	if ((msg == NULL) || (msg_byteLen == 0) || (msg_byteLen > HM_MAX_HMAC_LEN))
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
		fprintf(stdout, "=*Location : YBCrypto_HMAC_Update       =\n");
		fprintf(stdout, "=*Please revise parameters...           =\n");
		fprintf(stdout, "=*CM-> YBCrypto_CM_NOMAL_ERROR          =\n");
		fprintf(stdout, "=*CM-> YBCrtypto_CM_NOMAL_VM            =\n");
		fprintf(stdout, "=========================================\n\n");

		YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);
		ret = FAIL_INVALID_INPUT_DATA;
		return ret;
	}

	//! Generating MAC
	ret = HMAC_update(MM, msg, msg_byteLen);
	if (ret != SUCCESS)
		goto EXIT;

EXIT:
	if (ret != SUCCESS)
	{
		fprintf(stdout, "=*Location : YBCrypto_HMAC_Update       =\n");
		YBCrypto_memset(MM, 0x00, sizeof(HMACManager));
	}
	parameter_flag = 0x00;
	state = 0x00;
	return ret;
}

int32_t YBCrypto_HMAC_Final(HMACManager* MM, uint8_t *mac)
{
	int32_t ret = SUCCESS;
	int32_t parameter_flag = TRUE;
	int32_t state = Inner_API_GetState();

	//! check Module sate and Conditional Test
	if ((state != YBCrtypto_CM_NOMAL_VM) && (state != YBCrtypto_CM_PRE_SELFTEST))
	{
		fprintf(stdout, "=========================================\n");
		fprintf(stdout, "=     [YBCrypto V1.0 Not Nomal Mode]    =\n");
		fprintf(stdout, "=*Location : YBCrypto_HMAC_Final        =\n");
		fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
		fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
		fprintf(stdout, "=========================================\n\n");

		ret = FAIL_INVALID_MODULE_STATE;
		YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
		Destroy_YBCrypto();
		return ret;
	}

	if ((state != YBCrtypto_CM_PRE_SELFTEST) && (algTestedFlag.isHMACTested != SUCCESS))
	{
		fprintf(stdout, "=========================================\n");
		fprintf(stdout, "= [YBCrypto V1.0 Not Performed KATtest] =\n");
		fprintf(stdout, "=*Location : YBCrypto_HMAC_Final        =\n");
		fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
		fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
		fprintf(stdout, "=========================================\n\n");

		ret = FAIL_NOT_PERFORM_KATSELFTEST;
		YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
		Destroy_YBCrypto();
		return ret;
	}

	//! check parameter type
	if (mac == NULL)
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
		fprintf(stdout, "=*Location : YBCrypto_HMAC_Final        =\n");
		fprintf(stdout, "=*Please revise parameters...           =\n");
		fprintf(stdout, "=*CM-> YBCrypto_CM_NOMAL_ERROR          =\n");
		fprintf(stdout, "=*CM-> YBCrtypto_CM_NOMAL_VM            =\n");
		fprintf(stdout, "=========================================\n\n");

		YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);
		ret = FAIL_INVALID_INPUT_DATA;
		return ret;
	}

	//! Generating MAC
	ret = HMAC_final(MM, mac);
	if (ret != SUCCESS)
		goto EXIT;

EXIT:
	if (ret != SUCCESS)
		fprintf(stdout, "=*Location : YBCrypto_HMAC_Final        =\n");
	parameter_flag = 0x00;
	state = 0x00;
	YBCrypto_memset(MM, 0x00, sizeof(HashManager));
	return ret;
}

int32_t YBCrypto_HMAC_Clear(HMACManager* MM)
{
	int32_t ret = SUCCESS;
	int32_t state = Inner_API_GetState();

	//! check Module sate and Conditional Test
	if ((state != YBCrtypto_CM_NOMAL_VM) && (state != YBCrtypto_CM_PRE_SELFTEST))
	{
		fprintf(stdout, "=========================================\n");
		fprintf(stdout, "=     [YBCrypto V1.0 Not Nomal Mode]    =\n");
		fprintf(stdout, "=*Location : YBCrypto_HMAC_Clear        =\n");
		fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
		fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
		fprintf(stdout, "=========================================\n\n");

		ret = FAIL_INVALID_MODULE_STATE;
		YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
		Destroy_YBCrypto();
		return ret;
	}

	if ((state != YBCrtypto_CM_PRE_SELFTEST) && (algTestedFlag.isHMACTested != SUCCESS))
	{
		fprintf(stdout, "=========================================\n");
		fprintf(stdout, "= [YBCrypto V1.0 Not Performed KATtest] =\n");
		fprintf(stdout, "=*Location : YBCrypto_HMAC_Clear        =\n");
		fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
		fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
		fprintf(stdout, "=========================================\n\n");

		ret = FAIL_NOT_PERFORM_KATSELFTEST;
		YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
		Destroy_YBCrypto();
		return ret;
	}

	//! Zero Manager
	YBCrypto_memset(MM, 0x00, sizeof(HMACManager));
	return ret;
}
