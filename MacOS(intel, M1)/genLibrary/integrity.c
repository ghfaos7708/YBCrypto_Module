#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <memory.h>
#include "hmac.h"
#include "integrity.h"

#define	MODULE_NAME	"YBCrypto.dylib"
#define HMAC_LEN 32

// key : 0x82, 0xB8, 0x4B, 0xA0, 0x64, 0xFE, 0xED, 0x9E, 0x02, 0xA2, 0xCF, 0xCF, 0x25, 0x4F, 0xBC, 0x67, 0x8d, 0x14, 0x70, 0x62, 0x5f, 0x59, 0xeb, 0xac, 0xb0, 0xe5, 0x5b, 0x53, 0x4b, 0x3e, 0x46, 0x2b
// masking_data :0x4D,0x62,0xC3,0xF1,0xE6,0x36,0xAC,0x4F, 0xC8,0xE6,0xE0,0x27,0x22,0x6F,0xB7,0x81,	0xAE,0x3A,0x4C,0x22,0xEE,0x4D,0xDB,0x5F, 0xB6,0xBF,0x6E,0x30,0xEA,0x6E,0xB9,0x85
// masked key: 0XCF, 0XDA, 0X88, 0X51, 0X82, 0XC8, 0X41, 0XD1, 0XCA, 0X44, 0X2F, 0XE8, 0X07, 0X20, 0X0B, 0XE6, 0X23, 0X2E, 0X3C, 0X40, 0XB1, 0X14, 0X30, 0XF3, 0X06, 0X5A, 0X35, 0X63, 0XA1, 0X50, 0XFF, 0XAE 

//! Global variable
uint8_t Hmac_key1[16] = { 0XCF, 0XDA, 0X88, 0X51, 0X82, 0XC8, 0X41, 0XD1, 0XCA, 0X44, 0X2F, 0XE8, 0X07, 0X20, 0X0B, 0XE6};
uint8_t masking_data1[16] = {0x4D, 0x62, 0xC3, 0xF1, 0xE6, 0x36, 0xAC, 0x4F, 0xC8, 0xE6, 0xE0, 0x27, 0x22, 0x6F, 0xB7, 0x81};

int32_t Inner_API_integrityTest() 
{
	int32_t cnt_i = 0;
	int32_t ret = SUCCESS;
	int32_t read = 0;
	FILE* fp = NULL;
	uint8_t * buf = NULL;
	int32_t fileSize = 0;
    HMACManager MM;

	//!local variable
	uint8_t Hmac_key_recovered[32] = {0x00};
	uint8_t Hmac_key2[16] = {0X23, 0X2E, 0X3C, 0X40, 0XB1, 0X14, 0X30, 0XF3, 0X06, 0X5A, 0X35, 0X63, 0XA1, 0X50, 0XFF, 0XAE};
	uint8_t masking_data2[16] = {0xAE,0x3A,0x4C,0x22,0xEE,0x4D,0xDB,0x5F, 0xB6,0xBF,0x6E,0x30,0xEA,0x6E,0xB9,0x85};
	uint8_t precomutedMAC[HMAC_LEN] = { 0x00, };
	uint8_t mac[HMAC_LEN] = { 0x00, };

	//! find Real Key using XOR (Hmackey and masking data)
	for(cnt_i = 0; cnt_i < 16 ; cnt_i ++)
	{
		Hmac_key_recovered[cnt_i] = Hmac_key1[cnt_i]^masking_data1[cnt_i];
		Hmac_key_recovered[cnt_i+16] = Hmac_key2[cnt_i]^masking_data2[cnt_i];
	}

	fp = fopen(MODULE_NAME, "rb");
	assert(fp != NULL);
	
	fseek(fp, 0, SEEK_END);
	fileSize = ftell(fp);
	buf = (uint8_t *)calloc(fileSize, sizeof(uint8_t));
	assert(buf != NULL);

	fseek(fp, 0, SEEK_SET);
	read = fread(buf, sizeof(uint8_t), fileSize, fp);
	memcpy(precomutedMAC, &buf[fileSize - HMAC_LEN], sizeof(mac));

    YBCrypto_HMAC(&MM, SHA256, Hmac_key_recovered,sizeof(Hmac_key_recovered), buf, fileSize - HMAC_LEN, mac);
    
	if (memcmp(precomutedMAC, mac, HMAC_LEN)) 
    {
		ret = FAIL_INTEGIRTY_TEST;
		goto END;
	}

END:
	if (fp != NULL)
		fclose(fp);
	if (buf != NULL)
		free(buf);

	YBCrypto_memset(Hmac_key2,0x00,sizeof(Hmac_key2));
	YBCrypto_memset(masking_data2,0x00,sizeof(masking_data2));
	YBCrypto_memset(precomutedMAC,0x00,sizeof(precomutedMAC));
	YBCrypto_memset(Hmac_key_recovered,0x00,sizeof(Hmac_key_recovered));
	YBCrypto_memset(mac,0x00,sizeof(mac));

	return ret;
}

// EOF

