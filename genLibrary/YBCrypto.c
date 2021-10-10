#include "YBCrypto.h"

int32_t YBCRYPTO_STATE = YBCrtypto_CM_LOAD;
IS_ALG_TESTED algTestedFlag;

static int32_t Inner_API_GetState()
{
	return YBCRYPTO_STATE;
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
	fprintf(stdout, "This library is made by YoungBeom Kim of Kookmin_University[COALAB]\n");
}

int32_t YBCrypto_GetState() 
{ 
	return Inner_API_GetState();
}
//EOF