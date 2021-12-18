#ifndef ENTROPY_H
#define ENTROPY_H

#include "YBCrypto.h"

#define MAX_ENTROPY_LEN 256 // 256 bytes  = 2048-bit >= 112-bit
#define REPEAT_TEST_CUTOFF 5 //(RCT CutOff)
#define ADAPTIVE_TEST_CUTOFF 6 //(APT CutOff)
#define ENTROPY_WINDOW 16

int32_t Inner_API_DRBG_CENT(uint8_t *entropy, uint32_t bytelen, uint32_t test_flag);

#endif
//EOF
