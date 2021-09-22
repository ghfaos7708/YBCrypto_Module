#include "YBCrypto.h"

#include <stdio.h>
#include <stdint.h>

//!TODO 지울것
#include "hash.h"
#include "mode.h"
#include "blockcipher.h"
#include "hmac.h"

typedef unsigned char u8;

int asc2hex(u8* dst, char* src);
int string2hex(u8* dst, char* src);
void print_hex( char* valName,  u8* data,  int dataLen);

int main()
{
    // u8 entropyInput[256] = { 0 };
	// u8 entropyReseed[256] = { 0 };
	// u8 nonce1[128] = { 0 };
	// u8 pString[256] = { 0 };
	// u8 addInputReseed[256] = { 0 };
	// u8 addInput1[256] = { 0 };
	// u8 addInput2[256] = { 0 };
	// u8 rand1[256] = { 0 };
	// u8 rand2[256] = { 0 };
	// u8 KAT[512] = { 0 };
	u8 key[1000] = {0};
	u8 iv[128] = {0};
	u8 plaintext[1000] = {0};
	u8 plaintext2[1000] = {0};
	u8 ciphertext[1000] = {0};
	// u8 answer[128] = {0};
	u8 msg[1000] = {0x00,};
	u8 msg2[1000] = {0x00,};
	u8 digest[32] = {0x00,};
	CipherManager CM = {0x00,};
	HMACManager HmacCM = {0x00,};

	// int entropyInputLen = 0;
	// int entropyReseedLen = 0;
	// int addInputReseedLen = 0;
	// int addInput1Len = 0;
	// int addInput2Len = 0;
	// int pStringLen = 0;
	// int nonce1Len = 0;
	//int KATLen = 0;
	// int ret = 0;
	int keyLen = 0;
	int ptLen = 0;
	int ptLen2 = 0;
	uint64_t ctLen1 = 0;
	uint64_t ctLen2 = 0;
	uint32_t padlen = 0;
	int msglen = 0;
	int msg2len = 0;
	int ivlen = 0;
	// int digestlen;

	//! AES Test
	// keyLen = asc2hex(key, "00000000000000000000000000000000");
	// ptLen = asc2hex(plaintext, "80000000000000000000000000000000");
	// ptLen2 = asc2hex(plaintext2, "80000000000000000000000000000000");
	// ECB_Init(&CM, AES, ENCRYPT, key, keyLen*8);
	// ECB_Update(&CM, plaintext, ptLen, ciphertext, &ctLen1);
	// ECB_Update(&CM, plaintext2, ptLen2, ciphertext, &ctLen2);
	// ECB_Final(&CM, ciphertext, &padlen);
	//print_hex("AES_RET", ciphertext, ctLen1 + ctLen2 + padlen);

	//! ARIA  ECB Test
	keyLen = asc2hex(key, "3AAFC1EB3C0CC5CC106E45A1D689F1E5");
	ptLen = asc2hex(plaintext, "74B690D38145006662157884B2631176E8E0859C3306365FA9AB7266A1D7F50D5DD3AF13ED82C8924FF4");
	//cipher text : 360B9B96F79F52FA3F9F43B0144A6992BA8257F2C130FE04BE17BE56F3EA055CB4F476673AB3056E023E2D0C26F42950
	ptLen2 = asc2hex(plaintext2, "E235DB399EA5");
	ECB_Init(&CM, ARIA, ENCRYPT, key, keyLen*8);
	ECB_Update(&CM, plaintext, ptLen, ciphertext, &ctLen1);
	ECB_Update(&CM, plaintext2, ptLen2, ciphertext, &ctLen2);
	ECB_Final(&CM, ciphertext, &padlen);
	//print_hex("ARIA_RET", ciphertext, ctLen1 + ctLen2 + padlen);

	ECB_Init(&CM, ARIA, DECRYPT, key, keyLen*8);
	ECB_Update(&CM, ciphertext, ptLen + ptLen2, plaintext, &ctLen1);
	ECB_Final(&CM, plaintext, &padlen);
	//print_hex("ARIA_reRET", plaintext, ctLen1 + padlen);

	//! ARIA  CBC Test
	keyLen = asc2hex(key, "E8E0859C3306365FA9AB7266A1D7F50D");
	ivlen = asc2hex(iv, "5DD3AF13ED82C8924FF4E235DB399EA5");
	ptLen = asc2hex(plaintext, "DF736144862F581EFEF6B91DD91E4C7CB4E62B7D17C3C65F9DF4298A555C820E6791DD4BFB3133F1");
	ptLen2 = asc2hex(plaintext2, "5675A32C4608FF18");
	CBC_Init(&CM, ARIA, ENCRYPT, key, keyLen*8, iv);
	CBC_Update(&CM, plaintext, ptLen, ciphertext, &ctLen1);
	CBC_Update(&CM, plaintext2, ptLen2, ciphertext, &ctLen2);
	CBC_Final(&CM, ciphertext, &padlen);
	// print_hex("ARIA_CBC_RET", ciphertext, ctLen1 + ctLen2 + padlen);

	CBC_Init(&CM, ARIA, DECRYPT, key, keyLen*8, iv);
	CBC_Update(&CM, ciphertext, ptLen + ptLen2, plaintext, &ctLen1);
	CBC_Final(&CM, plaintext, &padlen);
	// print_hex("ARIA_CBC_ReRET", plaintext, ctLen1 + padlen);

	//! ARIA  CTR Test
	keyLen = asc2hex(key, "26F88C260A37518FE79C74777A3EBB5D");
	ivlen = asc2hex(iv, "D733F3A95BB486EAE37D50623B73AFC4");
	ptLen = asc2hex(plaintext, "DA89D93CCCE473B0EF3E5F466288D5263BD3B58178701BD2395634632CC5511348293A58BE41C580");
	ptLen2 = asc2hex(plaintext2, "2C80A73C14B4895E");
	CTR_Init(&CM, ARIA, ENCRYPT, key, keyLen*8, iv);
	CTR_Update(&CM, plaintext, ptLen, ciphertext, &ctLen1);
	CTR_Update(&CM, plaintext2, ptLen2, ciphertext, &ctLen2);
	CTR_Final(&CM, ciphertext, &padlen);
	// print_hex("ARIA_CTR_RET", ciphertext, ctLen1 + ctLen2 + padlen);

	CTR_Init(&CM, ARIA, DECRYPT, key, keyLen*8, iv);
	CTR_Update(&CM, ciphertext, ctLen1 + ctLen2 + padlen, plaintext, &ctLen1);
	CTR_Final(&CM, plaintext, &padlen);
	// print_hex("ARIA_CTR_ReRET", plaintext, ctLen1 + padlen);

	//! Hash Test
	//! string인지 잘 확인하기
	msglen = string2hex(msg, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
	SHA256_MD(msg,msglen,digest);
	// print_hex("SHA256_RET", digest, 256/8);

    msglen = asc2hex(msg, "0AF7E1442802D371D4A729E36A62BE11538CD64583D2BCAC46E6A9A93D74E86FA35838CFD50E724E126A6B7B7F891C806E0700F6DF72BEFE47FF088D917CC30763866810A2FCAA9F38B45953156C860B7303E8B15FE97E5675D47684EBB44ECFD1EA39AE96B4C489CFECB91334F343DAEBE8541D0A1D44DD57CBBB365204D0F075EA7252BA1F07365E7C5463E4069D165E1D0DE2E8F758BA754D9E4DCE549392D7EFDDA31423BDCE6DCBF2E92E8DDAE7520CDBA9015F011657C3E86E678CDDDB8062404AAFA92C7884415B5019704374511C851A5E3E8819869361432695F7F6F7A964EE909A9E5D2C46563EAE9720E6E2B5D5DC067A35EA8927D17412552909C42E1138C1DC59A5EC42AC5CF4EAB9648E3F919801FD50B2E8E500A933B5BA3D70570ECF4959A6774D9D2551F3525517DB2282F558AD21982C37B689929DF4B9828E255D30F7CCFBD6BF89C5B3B5");
	SHA3_MD(msg,msglen,digest);
    // print_hex("SHA-3_256_RET", digest, 256/8);



	//! HMAC SHA2 Test
	msglen = asc2hex(msg, "213703E423B25103F00B3E8AAA311473F38BADFBA4DBCDA6C268B583AE5CF4B19B6B812245B5079FE1EE800C4FBC05EE9760E42A9399F40FE9C525973D4A5BEAA4347D245B20C858B9586AD5623F4CA8BEF02F62A922FA1B6C4F52B6EC156C6722DC1F73CBB93E376192246C498390A94E81B4294E3D88CF334B6467");
	msg2len = asc2hex(msg2, "2584CE2F");
	keyLen = asc2hex(key, "A5A3DFF7F808CC172130AFA03720866156D767F14F30CDAC9E0930F89DA5D8CDF74FF2745E40E48E81C3DE593897B12F0295E54FB29205E065873E33B7F029493771E49518BF670229BE153807E7921B90EDD5959CA07E96E811695953F783E84D51DCE28C4DFE7C00697EC60AD8D030E9275F4C7520DDD50FEFD8F1D8838FB3");
	//88B75698C4513297D72B4CF089F2296ED9CD42B04EBCA59A9B607254621F9390
	HMAC_init(&HmacCM,SHA256,key,keyLen);
	HMAC_update(&HmacCM,msg, msglen);
	HMAC_update(&HmacCM,msg2, msg2len);
	HMAC_final(&HmacCM,digest);
	//print_hex("HMAC_SHA256RET", digest, 256/8);

	//! HMAC SHA3 Test
	//! string인지 잘 확인하기
	msglen = asc2hex(msg, "A78ADC61161AD1D6F5FDE98D1806BB8EED3A4AA2B032D9CEE2C1011AF7D700964FA5549F6702895F510E4F936115CF912AB63F89A844B40BBF6C38C9E4181D9F1B9491D021EF7293EAA563CE4E7A1F21FFA90D26BE3E15F7CEC1B3F1A91449B8F39EBA7BACAA347AA9094DC545FF5246545DDB0158EAA39BF807");
	msg2len = asc2hex(msg2, "9719AD932DEB");
	keyLen = asc2hex(key, "FB88F4E90A9657516030F76C617A7230BABD01BF97C44FEA17868BF4FC05BB99A875544F45A108CC438BE0C807528A04E159F48B3FA61A3821881C78CD7D9351C45225A4F48C57AF2F07A3D5DCDDCBA2ED896C0A114DD6F12AD11BF1010C665738678E6E8120EB010EED691B49E3DA11C49591C273802C1E19A7B1E5007ADDB1EDFCB83753256DCAC7855921B42B625950C58A3DCE09C3C6D65306DE328F9F69CA59CB86D263841242179C6F867E0983776180038BAE45F1481C4163FF125587B6C6EEE466A2D9E267EB598D28A4779623B09A9A103857A7594C8AFDCFCDA6119B8A49D877A914411E49B9040065559A3BFB018CC76EA3F1F02A0B320A863B1160EE05EA6D41DC384F78E45A78894B98");
	//6348F6D659055F2FBB404D42E026215F042FC63BA9A359689C34006AEB512663
	HMAC_init(&HmacCM,SHA3,key,keyLen);
	HMAC_update(&HmacCM,msg, msglen);
	HMAC_update(&HmacCM,msg2, msg2len);
	HMAC_final(&HmacCM,digest);
	print_hex("HMAC_SHA3RET", digest, 256/8);

	//! CTR_DRBG Test
	// entropyInputLen = asc2hex(entropyInput, "CECD2F5C8AD5A29E35C15850E4A0339B");
	// nonce1Len = asc2hex(nonce1, "AD8505D91430A655C6EA44518AB1FB4E");
	// entropyReseedLen = asc2hex(entropyReseed, "7495A5875B62F4BF8E7FBE3CC3169714");
	// ret = GTCrypto_CTR_DRBG_Instantiate(NULL, 0, nonce1, nonce1Len, NULL, 0, USE_DERIVATION_FUNCTION);
	// GTCrypto_CTR_DRBG_Generate(rand1, 1024, entropyReseed, entropyReseedLen, NULL, 0, USE_PREDICTION_RESISTANCE);	
	// print_hex("ReturnedBits", rand1, 1024/8);

	//! PreSelf Test
	//ret = GTCrypto_PreSelfTest();

    return 0;
}

int asc2hex(u8* dst, char* src)
{
	u8 temp = 0x00;
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

int string2hex(u8* dst, char* src)
{
	int i = 0;

	while (src[i] != '\0')
	{
		dst[i] = src[i];

		i++;
	}

	return (i);
}



void print_hex( char* valName,  u8* data,  int dataByteLen)
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