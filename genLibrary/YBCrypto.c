#include "YBCrypto.h"
#include "KAT_test.h"

int32_t YBCRYPTO_STATE = YBCrtypto_CM_LOAD;
IS_ALG_TESTED algTestedFlag;
extern CipherManager CM;
extern HashManager HM;
extern HMACManager MM;
extern DRBGManager DM;

static int32_t Inner_API_GetState(void)
{
	return YBCRYPTO_STATE;
}
static int32_t Inner_API_PreSelfTest(void)
{
	int32_t ret = SUCCESS;

	return ret;
}

static int32_t Inner_API_Initialize(void)
{
	int32_t ret = SUCCESS;

	YBCrypto_memset(&algTestedFlag, 0x00, sizeof(IS_ALG_TESTED));
	YBCrypto_memset(&CM, 0x00, sizeof(CipherManager));
	YBCrypto_memset(&HM, 0x00, sizeof(HashManager));
	YBCrypto_memset(&MM, 0x00, sizeof(HMACManager));
	YBCrypto_memset(&DM, 0x00, sizeof(DRBGManager));

	//TODO Integrity Test
	//TODO Entropy Test

	//! KAT Test
	ret = Inner_API_KatSelfTest();



EXIT:
	return ret;
}

int32_t YBCrypto_GetState(void)
{
	return Inner_API_GetState();
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
		fprintf(stdout, "[YBCrypto_ChangeState] Error\n");
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

void YBCrypto_ModuleInfo(void)
{
	fprintf(stdout, "YBCrypto V1.0\n");
	fprintf(stdout, "This library is made by YoungBeom Kim of Kookmin_University[COALAB]\n");
}

//! constructor model
void Load_YBCrypto(void)
{
	int32_t ret = SUCCESS;

	YBCrypto_ChangeState(YBCrtypto_CM_LOAD);
	ret = Inner_API_Initialize();

	if (ret != SUCCESS)
	{
		fprintf(stdout, "=[CRITICAL ERROR DETECTED]==============\n");
		fprintf(stdout, "=[Location : Load_YBCrypto]=============\n");
		YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
		goto EXIT;
	}
	else
	{

#ifdef _WIN64
		system("cls");
#else
		system("clear");
#endif
		fprintf(stdout, "=========================================\n");
		fprintf(stdout, "=       [YBCrypto V1.0 Initialize]      =\n");
		fprintf(stdout, "=*[Support Crypto]                      =\n");
		fprintf(stdout, "=*--> BlockCipher : ARIA, AES           =\n");
		fprintf(stdout, "=*--> Hash        : SHA_256, SHA3       =\n");
		fprintf(stdout, "=*--> HMAC        : SHA_256, SHA3       =\n");
		fprintf(stdout, "=*--> CTR_DRBG    : ARIA, AES           =\n");
		fprintf(stdout, "=*[Ready to Start YBCrypto V1.0]        =\n");
		fprintf(stdout, "=====================[made by YoungBeom]=\n\n\n");
		YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);
	}

	return;

EXIT:
	Destroy_YBCrypto();
}

//! destructor model
void Destroy_YBCrypto(void)
{
	YBCrypto_memset(&algTestedFlag, 0x00, sizeof(IS_ALG_TESTED));
	YBCrypto_memset(&CM, 0x00, sizeof(CipherManager));
	YBCrypto_memset(&HM, 0x00, sizeof(HashManager));
	YBCrypto_memset(&MM, 0x00, sizeof(HMACManager));
	YBCrypto_memset(&DM, 0x00, sizeof(DRBGManager));

#ifdef _WIN64
	system("cls");
#else
	system("clear");
#endif

	if (YBCrypto_GetState() == YBCrtypto_CM_CRITICAL_ERROR)
	{
		fprintf(stdout, "=========================================\n");
		fprintf(stdout, "=     [Destroy YBCryptoV1.0........]    =\n");
		fprintf(stdout, "=*        [Critical ERROR ISSUE]       *=\n");
		fprintf(stdout, "=*-->Entropy Test Fail          [OR]    =\n");
		fprintf(stdout, "=*-->KAT Test Fail              [OR]    =\n");
		fprintf(stdout, "=*-->Integrity Test Fail        [OR]    =\n");
		fprintf(stdout, "==============[Please Contact YoungBeom]=\n\n\n");
	}
	else
	{
		fprintf(stdout, "=========================================\n");
		fprintf(stdout, "=     [Destroy YBCryptoV1.0........]    =\n");
		fprintf(stdout, "=*              Good Bye~!!            *=\n");
		fprintf(stdout, "=====================[made by YoungBeom]=\n\n\n");
	}
	YBCrypto_ChangeState(YBCrtypto_CM_EXIT);

	return; //! Really Good Bye.....
}
//EOF