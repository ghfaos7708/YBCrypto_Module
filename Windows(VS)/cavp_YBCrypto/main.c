#include <stdio.h>
#include "YBCrypto.h"
#include "api.h"

int main()
{
	//! Initialization of YBCrypto
	YBCrypto_Initialization();

	//! BlockCIpher CAVP
	ARIA_ECB_KAT();
	ARIA_CBC_KAT();
	ARIA_CTR_KAT();

	ARIA_ECB_MMT();
	ARIA_CBC_MMT();
	ARIA_CTR_MMT();

	ARIA_ECB_MCT();
	ARIA_CBC_MCT();
	ARIA_CTR_MCT();

	//! HashFunction CAVP
	SHA256_SHORT_LONG();
	SHA256_MCT();

	//! HMAC CAVP
	HMAC_SHA256_KAT();

	//! CTR_DRBG CAVP
	ARIA_CTR_DRBG_UDF_UPR();
	ARIA_CTR_DRBG_NDF_UPR();
	ARIA_CTR_DRBG_UDF_NPR();
	ARIA_CTR_DRBG_NDF_NPR();

	// End Moudle
	Destroy_YBCrypto();

	return 0;
}

int asc2hex(uint8_t* dst, char* src)
{
	uint8_t temp = 0x00;
	int i = 0;

	while (src[i] != 0x00)
	{
		temp = 0x00;

		if ((src[i] >= 0x30) && (src[i] <= 0x39))
			temp = src[i] - '0';
		else if ((src[i] >= 0x41) && (src[i] <= 0x5A))
			temp = src[i] - 'A' + 10;
		else if ((src[i] >= 0x61) && (src[i] <= 0x7A))
			temp = src[i] - 'a' + 10;
		else
			temp = 0x00;

		(i & 1) ? (dst[i >> 1] ^= temp & 0x0F) : (dst[i >> 1] = 0, dst[i >> 1] = temp << 4);

		i++;
	}

	return ((i + 1) / 2);
}

void print_hex( char* valName,  uint8_t* data,  int dataByteLen)
{
	int i = 0;

	printf("%s [%dbyte] :", valName, dataByteLen);
	for (i = 0; i < dataByteLen; i++)
	{
		if (!(i & 0x0F))
			printf("\n");
		printf(" %02X", data[i]);
	}
	printf("\n\n");
}

void Count_Addition(unsigned char *count) //Count 배열에서 값을 1증가시키는 함수
{
    int cnt_i, carry = 0;           //맨처음 Carry 값은 0
    unsigned char out[16] = {0x00}; // 최종배열
    unsigned char one[16] = {0x00}; // 0x01을 의미하는 배열
    one[15] = 0x01;

    for (cnt_i = 15; cnt_i >= 0; cnt_i--)
    {
        out[cnt_i] = count[cnt_i] + one[cnt_i] + carry;
        if (out[cnt_i] < count[cnt_i])
            carry = 1;
        else
        {
            carry = 0;
        }
    }
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        count[cnt_i] = out[cnt_i];
    }
}
// EOF
