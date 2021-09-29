#include "YBCrypto.h"

int32_t YBCRYPTO_STATE = YBCrtypto_CM_LOAD;

static void unner_API_ALG_Init()
{
	algTestedFlag.isBlockCipherTested = FAIL_KATSELF_TEST;
	algTestedFlag.isHashTested = FAIL_KATSELF_TEST;
	algTestedFlag.isHMACTested = FAIL_KATSELF_TEST;
	algTestedFlag.isDRBGTested = FAIL_KATSELF_TEST;
}

static int32_t Inner_API_GetState()
{
	return YBCRYPTO_STATE;
}

static int32_t Inner_API_AlgSelfTest()
{
	int32_t ret = SUCCESS;

	//! BlockCipher KAT Test
	if (algTestedFlag.isBlockCipherTested != SUCCESS)
	{
		// ret = _ARIA_KAT_SelfTest();
		if (ret != SUCCESS)
		{
			algTestedFlag.isBlockCipherTested = FAIL_KATSELF_TEST;
#ifdef PRINT_MODE
			fprintf(stdout,"[Inner_API_AlgSelfTest] BlockCipher Error\n");
#endif
			goto EXIT;
		}
		else
		{
			algTestedFlag.isBlockCipherTested = SUCCESS;
		}
	}

	//! Hash KAT Test
	if (algTestedFlag.isHashTested != SUCCESS)
	{
		// ret = _Hash_KAT_SelfTest();
		if (ret != SUCCESS)
		{
			algTestedFlag.isHashTested = FAIL_KATSELF_TEST;
#ifdef PRINT_MODE
			fprintf(stdout,"[Inner_API_AlgSelfTest] Hash Error\n");
#endif
			goto EXIT;
		}
		else
		{
			algTestedFlag.isHashTested = SUCCESS;
		}
	}

	//! Hmac KAT Test
	if (algTestedFlag.isHMACTested != SUCCESS)
	{
		// ret = _Hmac_KAT_SelfTest();
		if (ret != SUCCESS)
		{
			algTestedFlag.isHMACTested = FAIL_KATSELF_TEST;
#ifdef PRINT_MODE
			fprintf(stdout,"[Inner_API_AlgSelfTest] Hmac Error\n");
#endif
			goto EXIT;
		}
		else
		{
			algTestedFlag.isHMACTested = SUCCESS;
		}
	}

	//! DRBG KAT Test
	if (algTestedFlag.isDRBGTested != SUCCESS)
	{
		// ret = _Hmac_KAT_SelfTest();
		if (ret != SUCCESS)
		{
			algTestedFlag.isDRBGTested = FAIL_KATSELF_TEST;
#ifdef PRINT_MODE
			fprintf(stdout,"[Inner_API_AlgSelfTest] CTR_DRBG Error\n");
#endif
			goto EXIT;
		}
		else
		{
			algTestedFlag.isDRBGTested = SUCCESS;
		}
	}

EXIT:

	return ret;
}

static int32_t Inner_API_integrityTest()
{
	int32_t ret = SUCCESS;

	//! SHA-256 KAT Test
	// ret = _SHA256_KAT_SelfTest();
	if (ret != SUCCESS) 
	{
		goto EXIT;
	}
	//! HMAC KAT Test
	// ret = _HMAC_SHA256_KAT_SelfTest();
	if (ret != SUCCESS) 
	{
		goto EXIT;
	}

	//! Integrity Test
	//ret = integrityTest();

EXIT:

	return ret;
}

void YBCrypto_ChangeState(int32_t newState)
{

	switch (newState)
	{
	case YBCrtypto_CM_LOAD:
		YBCRYPTO_STATE = YBCrtypto_CM_LOAD;
		break;
	case YBCrtypto_CM_NOMAL_VM:
		YBCRYPTO_STATE = YBCrtypto_CM_NOMAL_VM;
		break;
	case YBCrtypto_CM_NOMAL_NVM:
		YBCRYPTO_STATE = YBCrtypto_CM_NOMAL_NVM;
		break;
	case YBCrtypto_CM_PRE_SELFTEST:
		YBCRYPTO_STATE = YBCrtypto_CM_PRE_SELFTEST;
		break;
	case YBCrtypto_CM_COND_SELFTEST:
		YBCRYPTO_STATE = YBCrtypto_CM_COND_SELFTEST;
		break;
	case YBCrtypto_CM_NORMAL_ERROR:
		YBCRYPTO_STATE = YBCrtypto_CM_NORMAL_ERROR;
		break;
	case YBCrtypto_CM_CRITICAL_ERROR:
		YBCRYPTO_STATE = YBCrtypto_CM_CRITICAL_ERROR;
		break;
	case YBCrtypto_CM_EXIT:
		YBCRYPTO_STATE = YBCrtypto_CM_EXIT;
		break;
	default:
#ifdef PRINT_MODE
		fprintf(stdout,"[YBCrypto_ChangeState] Error\n");
#endif
		break;
	}
}

void YBCrypto_memset(void *pointer, int32_t value, int32_t size)
{
	if (pointer == NULL)
	{
		return;
	}

	volatile int8_t *vp = (volatile int8_t *)pointer;
	while (size)
	{
		*vp = value;
		vp++;
		size--;
	}
}

void YBCrypto_ModuleInfo()
{
	fprintf(stdout, "YBCrypto V1.0\n");
	fprintf(stdout, "This library is made by YoungBeom Kim of Kookmin_University\n");
}

int32_t YBCrypto_GetState() 
{ 
	return Inner_API_GetState();
}
//EOF