#include "YBCrypto.h"

void YBCrypto_memset(void* p, int value, int size)
{
	if (p == NULL){
		return;
	}

	volatile char* vp = (volatile char*)p; 
	while (size){
		*vp = value;
		vp++;
		size--;
	}
}
//EOF