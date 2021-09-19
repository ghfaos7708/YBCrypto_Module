#include "YBCrypto.h"

#include <stdio.h>
#include <stdint.h>

//!TODO 지울것
#include "hash.h"
#include "mode.h"
#include "blockcipher.h"

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
	u8 key[128] = {0};
	u8 plaintext[1000] = {0};
	u8 plaintext2[1000] = {0};
	u8 ciphertext[1000] = {0};
	// u8 answer[128] = {0};
	u8 msg[500] = {0x00,};
	u8 digest[32] = {0};
	CipherManager CM = {0x00,};

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
	int ctLen = 0;
	int msglen = 0;
	// int digestlen;


	//! ARIA Test
	// keyLen = asc2hex(key, "00000000000000000000000000000000");
	// ptLen = asc2hex(plaintext, "80000000000000000000000000000000");
	// GTCrypto_ARIA_Crypt(ARIA_ENCRYPT, ARIA_ECB_MODE, NULL, plaintext, ptLen, key, keyLen * 8, ciphertext);
	// print_hex("ARIA_RET", ciphertext, ptLen);

	//! AES Test
	keyLen = asc2hex(key, "00000000000000000000000000000000");
	ptLen = asc2hex(plaintext, "80000000000000000000000000000000");
	ptLen2 = asc2hex(plaintext2, "80000000000000000000000000000000");
	ECB_Init(&CM, AES, ENCRYPT, key, keyLen*8);
	ECB_Update(&CM, plaintext, ptLen, ciphertext, ctLen);
	ECB_Update(&CM, plaintext2, ptLen2, ciphertext, ctLen);
	ECB_Final(&CM, ciphertext, ctLen);
	//print_hex("AES_RET", ciphertext, CM.encrypted_len);

	//! ARIA Test
	keyLen = asc2hex(key, "3AAFC1EB3C0CC5CC106E45A1D689F1E5");
	ptLen = asc2hex(plaintext, "74B690D38145006662157884B2631176E8E0859C3306365FA9AB7266A1D7F50D5DD3AF13ED82C8924FF4");
	ptLen2 = asc2hex(plaintext2, "E235DB399EA5");
	ECB_Init(&CM, ARIA, ENCRYPT, key, keyLen*8);
	ECB_Update(&CM, plaintext, ptLen, ciphertext, ctLen);
	ECB_Update(&CM, plaintext2, ptLen2, ciphertext, ctLen);
	ECB_Final(&CM, ciphertext, ctLen);
	//print_hex("ARIA_RET", ciphertext, CM.encrypted_len);

	//! Hash Test
	msglen = string2hex(msg, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
	SHA256_MD(msg,msglen,digest);
	//print_hex("SHA256_RET", digest, 256/8);

    msglen = string2hex(msg, "asdjkfqkjwefnkjcnjkqwbjkecbjkqwejkfhqwkefh");
	SHA3_MD(msg,msglen,digest);
    //print_hex("SHA-3_256_RET", digest, 256/8);



	//! HMAC Test
	// msglen = asc2hex(msg, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb0000112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb0280");
	// keyLen = asc2hex(key, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
	// GTCrypto_HMAC(msg,msglen,key,keyLen,digest);
	// print_hex("HMAC_RET", digest, 256/8);

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