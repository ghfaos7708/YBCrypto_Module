#include "YBCrypto.h"
#include "ctr_drbg.h"

extern int32_t YBCRYPTO_STATE;
extern IS_ALG_TESTED algTestedFlag;
extern int32_t Inner_API_GetState(void);
extern void YBCrypto_ChangeState(int32_t newState);
CipherManager CM;

DRBGManager DM;

//EOF