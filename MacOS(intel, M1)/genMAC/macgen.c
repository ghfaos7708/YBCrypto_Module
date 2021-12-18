
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <memory.h>

#include "SHA256.h"
#include "HMAC_SHA256.h"

/*
 * 암호모듈에 대한 무결성 데이터 생성
 * 생성된 무결성 데이터를 암호모듈에 패딩
 */
void genIntegrityData(char* fileName) {
	FILE* fp = NULL;
	unsigned char* buf = NULL;
	int fileSize;
	BYTE key[32] = { 0x82, 0xB8, 0x4B, 0xA0, 0x64, 0xFE, 0xED, 0x9E, 0x02, 0xA2, 0xCF, 0xCF, 0x25, 0x4F, 0xBC, 0x67, 
				   0x8d, 0x14, 0x70, 0x62, 0x5f, 0x59, 0xeb, 0xac, 0xb0, 0xe5, 0x5b, 0x53, 0x4b, 0x3e, 0x46, 0x2b };
				   
	BYTE mac[32] = { 0x00, };
	int cnt_i;

	fp = fopen(fileName, "rb");
	assert(fp != NULL);

	fseek(fp, 0, SEEK_END);
	fileSize = ftell(fp);
	buf = (unsigned char*)calloc(fileSize + 32, sizeof(unsigned char));
	assert(buf != NULL);

	fseek(fp, 0, SEEK_SET);
	fread(buf, sizeof(unsigned char), fileSize, fp);

	HMAC_SHA256_Encrpyt(buf, fileSize, key, sizeof(key), mac);

	printf("\n[Computed MAC value]\n");
	for (cnt_i = 0; cnt_i < 32; cnt_i++)
	{
		if ((cnt_i != 0) && !(cnt_i % 16))
		{
			printf("\n");
		}
		printf("0x%02X, ", mac[cnt_i]);
	}
	printf("\n");

	if (fp != NULL) {
		fclose(fp);
	}

	// 생성된 MAC값을 파일의 마지막에 패딩
	memcpy(buf + fileSize, mac, sizeof(mac));

	// 파일을 쓰기 모드로 다시 열기
	fp = fopen(fileName, "wb");
	assert(fp != NULL);

	fwrite(buf, sizeof(unsigned char), fileSize + 32, fp);

	if (fp != NULL) {
		fclose(fp);
	}

	if (buf != NULL) {
		free(buf);
	}
}

// EOF