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
	u8 key[128] = {0};
	u8 iv[128] = {0};
	u8 plaintext[1000] = {0};
	u8 plaintext2[1000] = {0};
	u8 ciphertext[1000] = {0};
	// u8 answer[128] = {0};
	u8 msg[500] = {0x00,};
	u8 msg2[500] = {0x00,};
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
	msglen = string2hex(msg, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
	SHA256_MD(msg,msglen,digest);
	//print_hex("SHA256_RET", digest, 256/8);

    msglen = string2hex(msg, "asdjkfqkjwefnkjcnjkqwbjkecbjkqwejkfhqwkefh");
	SHA3_MD(msg,msglen,digest);
    //print_hex("SHA-3_256_RET", digest, 256/8);



	//! HMAC SHA2 Test
	msglen = asc2hex(msg, "A9F0EA015D547B53917A0111A59203757C409CFD2F8AD06B03F4200F99E95C48655DB94961B1241903D7D5DD6CB6265AE2D0A6B68022697E2C4BA3EECAF1756CAF6107555975D7FC5DBB51F0A0D39F7ECA19C277F885E234B2CFE2D61CD638D27042FCAEAB683E05876F9DD1AAB115EA1D6419C9FF7A");
	msg2len = asc2hex(msg2, "E2927BC50652F75F4C84");
	keyLen = asc2hex(key, "24737DEBAA422FBFB9B729FFAA18AEBCD7A40FCB537709C8D8AD535C00CA78BCB85AE372F2D438609BC4EB02CD290BF3451C5EB317B3B3A7A0257461BD2F7B223AB6269D8EADAEFEC539B42BBD131D4A952F2083639B9D0725A9B151FB5087AC93D071F5E49537A21F5EAF03E29E8DC8AF227DC49EF56FF04E8132B321F64560");
	//F01625E80217AA840F9122434B7770F4572DC386405EE90226ACAFC7BA451288
	HMAC_init(&HmacCM,SHA256,key,keyLen);
	HMAC_update(&HmacCM,msg, msglen);
	HMAC_update(&HmacCM,msg2, msg2len);
	HMAC_final(&HmacCM,digest);
	// print_hex("HMAC_SHA256RET", digest, 256/8);

	//! HMAC SHA2 Test
	msglen = asc2hex(msg, "548A457280851ECA0F5476AFDAC102CF6C7DBE09B3083D74FBD03DA31E9D7F27F42CD656111A7D4BB005AD2EEAED6FB62CE0B0EBE7D6933189DA0B82AD6AA8FB8E21B19AC29374462579DA0F130E3EB8DAB87F726EEB54EB5F4AE087091087ED0BAFFFC6FAB7AAC156F823DBBCEB17DD5E4E5626B10F29AA656BE73B9A57C308");
	//msg2len = asc2hex(msg2, "A39BF8079719AD932DEB");
	keyLen = asc2hex(key, "C6F1D667A50AAEBA5A200A0A7CC24FFBB24984426AB8ABACCEE75162F3E1646B");
	//F01625E80217AA840F9122434B7770F4572DC386405EE90226ACAFC7BA451288
	HMAC_init(&HmacCM,SHA3,key,keyLen);
	HMAC_update(&HmacCM,msg, msglen);
	//HMAC_update(&HmacCM,msg2, msg2len);
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