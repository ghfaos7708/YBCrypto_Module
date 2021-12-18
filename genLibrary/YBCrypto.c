#include "YBCrypto.h"
#include "KAT_test.h"
#include "entropy.h"

int32_t YBCRYPTO_STATE = YBCrtypto_CM_LOAD;
IS_ALG_TESTED algTestedFlag;
extern CipherManager CM;
extern HashManager HM;
extern HMACManager MM;
extern DRBGManager DM;

int32_t Inner_API_GetState(void)
{
	return YBCRYPTO_STATE;
}
static int32_t Inner_API_PreSelfTest(void)
{
	int32_t ret = SUCCESS;

	YBCrypto_memset(&algTestedFlag, 0x00, sizeof(IS_ALG_TESTED));
	YBCrypto_memset(&CM, 0x00, sizeof(CipherManager));
	YBCrypto_memset(&HM, 0x00, sizeof(HashManager));
	YBCrypto_memset(&MM, 0x00, sizeof(HMACManager));
	YBCrypto_memset(&DM, 0x00, sizeof(DRBGManager));

	algTestedFlag.isBlockCipherTested = FAIL_NOT_PERFORM_KATSELFTEST;
	algTestedFlag.isHashTested = FAIL_NOT_PERFORM_KATSELFTEST;
	algTestedFlag.isHMACTested = FAIL_NOT_PERFORM_KATSELFTEST;
	algTestedFlag.isDRBGTested = FAIL_NOT_PERFORM_KATSELFTEST;

	//! KAT Test
	ret = Inner_API_KatSelfTest();

	if (ret != SUCCESS)
	{
		fprintf(stdout, "=*Location : Inner_API_PreSelfTest(KAT) =\n");
		goto EXIT;
	}
	//! Entropy Test
	ret = Inner_API_DRBG_CENT(NULL, 0, TRUE);
	if (ret != SUCCESS)
	{
		fprintf(stdout, "=*Location : Inner_API_PreSelfTest(Ent) =\n");
		goto EXIT;
	}
	//TODO Integrity Test
	if (ret != SUCCESS)
	{
		fprintf(stdout, "=*Location : Inner_API_PreSelfTest(MAC) =\n");
		goto EXIT;
	}

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
		//Do not occur.
		fprintf(stdout, "[YBCrypto_ChangeState] Error\n");
#endif
		break;
	}
}


int32_t YBCrypto_PreSelfTest(void)
{
	int32_t ret = SUCCESS;
	int32_t state = Inner_API_GetState();

	if (state != YBCrtypto_CM_NOMAL_VM)
	{
		fprintf(stdout, "=========================================\n");
		fprintf(stdout, "=     [YBCrypto V1.0 Not Nomal Mode]    =\n");
		fprintf(stdout, "=*Location : YBCrypto_PreSelfTest       =\n");
		fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
		fprintf(stdout, "=========================================\n\n");

		ret = FAIL_INVALID_MODULE_STATE;
		YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
		Destroy_YBCrypto();
		return FAIL_INVALID_MODULE_STATE;
	}

	fprintf(stdout, "=========================================\n");
	fprintf(stdout, "=    [YBCrypto V1.0 PreSelf Testing]    =\n");
	fprintf(stdout, "=*CM-> YBCrtypto_CM_PRE_SELFTEST        =\n");
	fprintf(stdout, "=*PreSelf_Testing.......................=\n");

	YBCrypto_ChangeState(YBCrtypto_CM_PRE_SELFTEST);
	ret = Inner_API_PreSelfTest();

	if (ret != SUCCESS)
	{
		fprintf(stdout, "=*Location : YBCrypto_PreSelfTest       =\n");
		fprintf(stdout, "=*FAIL : PreSelfTest                    =\n");
		fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
		fprintf(stdout, "=========================================\n");
		YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
		Destroy_YBCrypto();
		return ret;
	}

	fprintf(stdout, "=*--> SUCESS!!!!!!                      =\n");
	fprintf(stdout, "=*CM-> YBCrtypto_CM_NOMAL_VM            =\n");
	fprintf(stdout, "=========================================\n");
	YBCrypto_ChangeState(YBCrtypto_CM_NOMAL_VM);

	return ret;
}

int32_t YBCrypto_GetState(void)
{
	int32_t state = Inner_API_GetState();

	if (state == YBCrtypto_CM_CRITICAL_ERROR)
	{
		fprintf(stdout, "=========================================\n");
		fprintf(stdout, "= [YBCrypto V1.0 Detact Critical ERROR] =\n");
		fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
		fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
		fprintf(stdout, "=========================================\n\n");
	}

	return state;
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
	if (Inner_API_GetState() != YBCrtypto_CM_NOMAL_VM)
	{
		fprintf(stdout, "=========================================\n");
		fprintf(stdout, "=     [YBCrypto V1.0 Not Nomal Mode]    =\n");
		fprintf(stdout, "=*Location : Inner_API_GetState         =\n");
		fprintf(stdout, "=*Please reset Module(ReLoad)           =\n");
		fprintf(stdout, "=========================================\n\n");
		return;
	}

	fprintf(stdout, "=========================================\n");
	fprintf(stdout, "=*Module name = YBCrypto V1.0           =\n");
	fprintf(stdout, "=*Developer   = YoungBeom Kim           =\n");
	fprintf(stdout, "=*Date        = 2021. 10. 10.           =\n");
	fprintf(stdout, "=*Location    = Kookmin_Universiy       =\n");
	fprintf(stdout, "=*git         = github.com/Youngbeom94  =\n");
	fprintf(stdout, "=========================================\n\n");
}

//! constructor model
void Load_YBCrypto(void)
{
	int32_t ret = SUCCESS;

#ifdef _WIN64
	system("cls");
#else //* MAC OS and Linux
	system("clear");
#endif
	YBCrypto_ChangeState(YBCrtypto_CM_LOAD);
	YBCrypto_ChangeState(YBCrtypto_CM_PRE_SELFTEST);
	fprintf(stdout, "=========================================\n");
	fprintf(stdout, "=       [YBCrypto V1.0 Load Success]    =\n");
	fprintf(stdout, "=*CM-> YBCrtypto_CM_PRE_SELFTEST        =\n");
	fprintf(stdout, "=*PreSelf Module Testing......          =\n");
	ret = Inner_API_PreSelfTest();

	if (ret != SUCCESS)
	{
		fprintf(stdout, "=*Location : Load_YBCrypto              =\n");
		fprintf(stdout, "=*CM-> YBCrtypto_CM_CRITICAL_ERROR      =\n");
		fprintf(stdout, "=[CRITICAL ERROR DETECTED]===============\n");
		YBCrypto_ChangeState(YBCrtypto_CM_CRITICAL_ERROR);
		goto EXIT;
	}
	else
	{
		fprintf(stdout, "=*--> SUCESS!!!!!!                      =\n");
		fprintf(stdout, "=========================================\n");
		fprintf(stdout, "=       [YBCrypto V1.0 Initialize]      =\n");
		fprintf(stdout, "=*[Support Crypto]                      =\n");
		fprintf(stdout, "=*--> BlockCipher : ARIA, AES           =\n");
		fprintf(stdout, "=*--> Hash        : SHA_256, SHA3       =\n");
		fprintf(stdout, "=*--> HMAC        : SHA_256, SHA3       =\n");
		fprintf(stdout, "=*--> CTR_DRBG    : ARIA, AES           =\n");
		fprintf(stdout, "=*[Ready to Start YBCrypto V1.0]        =\n");
		fprintf(stdout, "=*CM-> YBCrtypto_CM_NOMAL_VM            =\n");
		fprintf(stdout, "=====================[made by YoungBeom]=\n\n");
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

	if (Inner_API_GetState() == YBCrtypto_CM_CRITICAL_ERROR)
	{
		fprintf(stdout, "=========================================\n");
		fprintf(stdout, "=     [Destroy YBCryptoV1.0........]    =\n");
		fprintf(stdout, "=*        [Critical ERROR ISSUE]       *=\n");
		fprintf(stdout, "=*-->Not Nomal Module State     [OR]    =\n");
		fprintf(stdout, "=*-->Entropy Test Fail          [OR]    =\n");
		fprintf(stdout, "=*-->KAT Test Fail              [OR]    =\n");
		fprintf(stdout, "=*-->Integrity Test Fail        [OR]    =\n");
		fprintf(stdout, "==============[Please Contact YoungBeom]=\n\n");
	}
	else
	{

#ifdef _WIN64
		//system("cls");
#else //* MAC OS and Linux
		//system("clear");
#endif
		fprintf(stdout, "=========================================\n");
		fprintf(stdout, "=     [Destroy YBCryptoV1.0........]    =\n");
		fprintf(stdout, "=*              Good Bye~!!            *=\n");
		fprintf(stdout, "=====================[made by YoungBeom]=\n\n");
	}
	YBCrypto_ChangeState(YBCrtypto_CM_EXIT);

	return; //! Really Good Bye.....
}
//EOF