#ifndef ENTROPY_H
#define ENTROPY_H

#include "YBCrypto.h"

void Inner_API_EntropyAdd(uint8_t *entrophy, uint32_t collectedlen, uint32_t cur_pos, uint8_t *src, uint32_t srclen, const int8_t *title);
int32_t Inner_API_GetEntropy(uint8_t entropy[], uint32_t size);

#endif
//EOF
