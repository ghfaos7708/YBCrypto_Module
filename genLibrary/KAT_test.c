#include "YBCrypto.h"
#include "KAT_test.h"

//TODO header fix
#include "ctr_drbg.h"

extern IS_ALG_TESTED algTestedFlag;
extern CipherManager CM;
extern HashManager HM;
extern HMACManager MM;
extern DRBGManager DM;

static void print_hex( char* valName,  uint8_t* data,  uint32_t dataByteLen)
{
	int32_t i = 0;

	printf("%s [%dbyte] :", valName, dataByteLen);
	for (i = 0; i < dataByteLen; i++)
	{
		if (!(i & 0x0F))
			printf("\n");
		printf(" %02X", data[i]);
	}
	printf("\n\n");
}

static int32_t string2hex(uint8_t* dst, char* src)
{
	int32_t cnt_i = 0;

	while (src[cnt_i] != '\0')
	{
		dst[cnt_i] = src[cnt_i];

		cnt_i++;
	}
	return (cnt_i);
}

static int32_t asc2hex(uint8_t* dst, char* src)
{
	uint8_t temp = 0x00;
	int32_t cnt_i = 0;

	while (src[cnt_i] != 0x00)
	{
		temp = 0x00;

		if ((src[cnt_i] >= 0x30) && (src[cnt_i] <= 0x39))
			temp = src[cnt_i] - '0';
		else if ((src[cnt_i] >= 0x41) && (src[cnt_i] <= 0x5A))
			temp = src[cnt_i] - 'A' + 10;
		else if ((src[cnt_i] >= 0x61) && (src[cnt_i] <= 0x7A))
			temp = src[cnt_i] - 'a' + 10;
		else
			temp = 0x00;

		(cnt_i & 1) ? (dst[cnt_i >> 1] ^= temp & 0x0F) : (dst[cnt_i >> 1] = 0, dst[cnt_i >> 1] = temp << 4);

		cnt_i++;
	}

	return ((cnt_i + 1) / 2);
}

int32_t Inner_API_KatSelfTest()
{
    int32_t ret = SUCCESS;

    ret = Inner_API_BlockCipher_SelfTest();
    if (ret != SUCCESS) goto EXIT;
    algTestedFlag.isBlockCipherTested = SUCCESS;

    ret = Inner_API_HashFunction_SelfTest();
    if (ret != SUCCESS) goto EXIT;
    algTestedFlag.isHashTested = SUCCESS;

    ret = Inner_API_HMAC_SelfTest();
    if (ret != SUCCESS) goto EXIT;
    algTestedFlag.isHashTested = SUCCESS;

    ret = Inner_API_CTR_DRBG_SelfTest();
    if (ret != SUCCESS) goto EXIT;
    algTestedFlag.isDRBGTested = SUCCESS;

EXIT:
    if (ret != SUCCESS)
        fprintf(stdout, "=*Location : Inner_API_KatSelfTest      =\n");
        
    return ret;
}

//! BlockCiper TestVecotr
typedef struct _BlockCIipher_TV_ {
	uint32_t algo;
	uint32_t mode;
	uint8_t masterkey[32];
	int key_bitlen;
	uint8_t plaintext[128];
	int pt_bytelen;
	uint8_t ciphertext_ct[144];
	int ct_bytelen;
	uint8_t IV[16];
}BlockCIipher_TV;


//! we use TTAK.KO-12.0271-part3's aria testvector 
const BlockCIipher_TV bcTestVectors[] = { 
									{ ARIA, ECB_MODE,
									{ 0x7A, 0xEC, 0x77, 0x5F, 0x7D, 0x4F, 0x49, 0x3F, 
									  0x1E, 0xF0, 0x20, 0xCD, 0x7B, 0xFE, 0xBF, 0xD0 }, 128,
									{ 0x15, 0x8B, 0x43, 0x00, 0x8F, 0x3F, 0x06, 0x5F, 
									  0xB3, 0x49, 0xC4, 0xCD, 0xB6, 0x9B, 0xFC, 0xD7,
									  0xBD, 0x57, 0x99, 0xD1, 0x9F, 0x84, 0xD2, 0x24, 
									  0xED, 0x06, 0x4F, 0xE8, 0x30, 0xCD, 0x8D, 0xB6}, 32,
									{ 0xDB, 0x20, 0x1B, 0x87, 0xBD, 0xC1, 0x0D, 0x61, 
									  0x5D, 0xFC, 0x33, 0xBE, 0x4C, 0x0E, 0x75, 0xF5,
									  0xD0, 0x84, 0x2C, 0x33, 0x98, 0x76, 0x9D, 0x49, 
									  0xD1, 0x8B, 0x7D, 0x65, 0x98, 0xBA, 0x03, 0x68 }, 32,
									  { 0x00, } }, //!done : ARIA-128 ECB Mode

									{ ARIA, ECB_MODE,
									{ 0x1E, 0xF0, 0x20, 0xCD, 0x7B, 0xFE, 0xBF, 0xD0,
									  0x15, 0x8B, 0x43, 0x00, 0x8F, 0x3F, 0x06, 0x5F, 
									  0xB3, 0x49, 0xC4, 0xCD, 0xB6, 0x9B, 0xFC, 0xD7 }, 192,
									{ 0xBD, 0x57, 0x99, 0xD1, 0x9F, 0x84, 0xD2, 0x24, 
									  0xED, 0x06, 0x4F, 0xE8, 0x30, 0xCD, 0x8D, 0xB6,
									  0x71, 0x4C, 0x83, 0xB7, 0xFF, 0x2D, 0x86, 0x01, 
									  0x6C, 0x43, 0x6A, 0x24, 0xD9, 0xC0, 0xEA, 0xFF}, 32,
									{ 0xDC, 0xFE, 0xD2, 0xA9, 0x85, 0x96, 0x93, 0x40, 
									  0x67, 0x1D, 0x76, 0xC0, 0xDF, 0x76, 0x9F, 0x30, 
									  0x91, 0x24, 0x88, 0x51, 0x80, 0xC4, 0x45, 0xA3, 
									  0x8F, 0x1B, 0x2B, 0xF8, 0xF6, 0x29, 0xE4, 0xFB }, 32,
									  { 0x00, } }, //!done : ARIA-192 ECB Mode

									{ ARIA, ECB_MODE,
									{ 0x15, 0x8B, 0x43, 0x00, 0x8F, 0x3F, 0x06, 0x5F, 
									  0xB3, 0x49, 0xC4, 0xCD, 0xB6, 0x9B, 0xFC, 0xD7, 
									  0xBD, 0x57, 0x99, 0xD1, 0x9F, 0x84, 0xD2, 0x24, 
									  0xED, 0x06, 0x4F, 0xE8, 0x30, 0xCD, 0x8D, 0xB6 }, 256,
									{ 0x71, 0x4C, 0x83, 0xB7, 0xFF, 0x2D, 0x86, 0x01,
									  0x6C, 0x43, 0x6A, 0x24, 0xD9, 0xC0, 0xEA, 0xFF, 
									  0x73, 0xA8, 0x49, 0xD9, 0x3E, 0x85, 0x3A, 0xAD, 
									  0x12, 0x5D, 0xFE, 0xC4, 0xE3, 0xE1, 0xCC, 0x89}, 32,
									{ 0x9E, 0x43, 0x5B, 0xAA, 0x06, 0xD1, 0x31, 0xA9, 
									  0xB6, 0x02, 0x5A, 0xA4, 0x76, 0x56, 0x0D, 0xAA, 
									  0x16, 0x9C, 0x69, 0xA1, 0xFB, 0xDD, 0xC2, 0x3E, 
									  0xF4, 0xE6, 0x84, 0x0A, 0xD2, 0xBD, 0x66, 0x87 }, 32,
									  { 0x00, } }, //!done : ARIA-256 ECB Mode

									{ ARIA, CBC_MODE,
									{ 0x45, 0xE7, 0x75, 0x9A, 0x2E, 0x1A, 0x48, 0x1B, 
									  0xFE, 0xF0, 0x33, 0x4F, 0xBE, 0xDD, 0x2C, 0x69 }, 128,
									{ 0x97, 0x44, 0x61, 0xCE, 0xA6, 0x6F, 0x15, 0x54, 
									  0x72, 0x3A, 0x69, 0x77, 0xED, 0x5C, 0x8B, 0xBC, 
									  0x5B, 0x9B, 0x73, 0x4C, 0x10, 0x88, 0xC6, 0x49, 
									  0x7B, 0x6A, 0xFB, 0x5E, 0x63, 0x78, 0xBC, 0x9A, 
									  0x71, 0x4B, 0x8F, 0x7E, 0xEF, 0x92, 0xB5, 0x54, 
									  0xCF, 0x08, 0x52, 0xC3, 0xEF, 0xA3, 0xCF, 0xA1}, 48,
									{ 0xED, 0x12, 0x4C, 0x67, 0x68, 0xFB, 0xAE, 0xDC, 
									  0x29, 0xC6, 0x74, 0x44, 0xFE, 0x18, 0xEB, 0x5D, 
									  0xFF, 0x44, 0x9D, 0xBB, 0xFD, 0x25, 0xFC, 0xB3, 
									  0x9F, 0x5A, 0x1B, 0x7C, 0x8C, 0xE5, 0x61, 0x69, 
									  0x67, 0xDD, 0x38, 0xF3, 0x0F, 0x97, 0x28, 0x11, 
									  0xF6, 0xB7, 0xFD, 0xE1, 0xA1, 0x30, 0xA0, 0x4B}, 48,
									{ 0xA5, 0xC7, 0xCF, 0x9F, 0xE1, 0xB9, 0x49, 0x81, 
									  0x94, 0xDB, 0x74, 0x89, 0x1C, 0xA2, 0x43, 0xF3} }, 
									//   //!done : ARIA-128 CBC Mode

									{ ARIA, CTR_MODE,
									{ 0x45, 0xE7, 0x75, 0x9A, 0x2E, 0x1A, 0x48, 0x1B, 
									  0xFE, 0xF0, 0x33, 0x4F, 0xBE, 0xDD, 0x2C, 0x69 }, 128,
									{ 0x97, 0x44, 0x61, 0xCE, 0xA6, 0x6F, 0x15, 0x54, 
									  0x72, 0x3A, 0x69, 0x77, 0xED, 0x5C, 0x8B, 0xBC, 
									  0x5B, 0x9B, 0x73, 0x4C, 0x10, 0x88, 0xC6, 0x49, 
									  0x7B, 0x6A, 0xFB, 0x5E, 0x63, 0x78, 0xBC, 0x9A, 
									  0x71, 0x4B, 0x8F, 0x7E, 0xEF, 0x92, 0xB5, 0x54, 
									  0xCF, 0x08, 0x52, 0xC3, 0xEF, 0xA3, 0xCF, 0xA1}, 48,
									{ 0xF0, 0x4F, 0x84, 0xFB, 0x31, 0x61, 0xC1, 0xD3, 
									  0xF0, 0xA0, 0x33, 0xA5, 0xE1, 0x15, 0x57, 0x27, 
									  0x23, 0xE5, 0x57, 0x35, 0x5D, 0xD0, 0x09, 0x0F, 
									  0xC3, 0xB8, 0xB8, 0xB6, 0xC4, 0x00, 0x28, 0x85,
									  0x10, 0x5F, 0x54, 0x4B, 0x2A, 0x69, 0x63, 0x37, 
									  0x33, 0x3A, 0x4B, 0xA0, 0x9E, 0xCC, 0x4B, 0x1D}, 48,
									{ 0xA5, 0xC7, 0xCF, 0x9F, 0xE1, 0xB9, 0x49, 0x81, 
									  0x94, 0xDB, 0x74, 0x89, 0x1C, 0xA2, 0x43, 0xF3} },
									//   //!done : ARIA-128 CTR Mode
									  };

int32_t Inner_API_BlockCipher_SelfTest()
{
    int32_t ret = SUCCESS;
	uint8_t ciphertext[500];
	uint8_t recovered[128];
	uint64_t out_bytelen = 0x00;
	uint32_t pad_bytelen = 0x00;

    for (int32_t cnt_i = 0; cnt_i < sizeof(bcTestVectors) / sizeof(BlockCIipher_TV); cnt_i++)
	{
        YBCrypto_memset(ciphertext, 0x00, sizeof(ciphertext));
        YBCrypto_memset(recovered, 0x00, sizeof(recovered));
		
		//! Encrypt and Decrypt Test
        YBCrypto_BlockCipher(bcTestVectors[cnt_i].algo, bcTestVectors[cnt_i].mode,ENCRYPT,bcTestVectors[cnt_i].masterkey,bcTestVectors[cnt_i].key_bitlen,bcTestVectors[cnt_i].plaintext,bcTestVectors[cnt_i].pt_bytelen,bcTestVectors[cnt_i].IV,ciphertext);
		if (memcmp(bcTestVectors[cnt_i].ciphertext_ct, ciphertext, bcTestVectors[cnt_i].pt_bytelen))
        {
            ret = FAIL_KATSELF_TEST;
			goto EXIT;
        }
		YBCrypto_BlockCipher_Init(bcTestVectors[cnt_i].algo, bcTestVectors[cnt_i].mode, DECRYPT, bcTestVectors[cnt_i].masterkey, bcTestVectors[cnt_i].key_bitlen,bcTestVectors[cnt_i].IV);
		YBCrypto_BlockCipher_Update(ciphertext, bcTestVectors[cnt_i].pt_bytelen,recovered, &out_bytelen);
		YBCrypto_BlockCipher_Final(recovered, &pad_bytelen);
		if (memcmp(bcTestVectors[cnt_i].plaintext, recovered, bcTestVectors[cnt_i].pt_bytelen))
        {
            ret = FAIL_KATSELF_TEST;
			goto EXIT;
        }
	}

EXIT:
    if(ret != SUCCESS)
        fprintf(stdout, "=*Location : Inner_API_BlockCipher_Sel..=\n");

    YBCrypto_memset(ciphertext, 0x00, sizeof(ciphertext));
    YBCrypto_memset(recovered, 0x00, sizeof(recovered));

    return ret;
}

//! HashFunction TestVecotr
typedef struct _HashFunction_TV_{
    uint32_t algo;
	uint8_t msg[512];
	uint8_t hash[HASH_DIGEST * 4];
} HashFunction_TV;

//! we use NIST FIPS 180-4 (Secure Hash Standard)'s SHA256 testvector 
static const
HashFunction_TV	HashTestVectors[] = 
{
	{
        SHA256,
        "abc",
        "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
    },
    { 
        SHA256,
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1"
    },
    { 
        SHA3,
        "abc",
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    },
    { 
        SHA3,
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "60b43211e04797536da8f618eb1ab90e8b23f69aa74b71c2a14d275d064b9cfe"
    },
};

int32_t Inner_API_HashFunction_SelfTest()
{
    int32_t ret = SUCCESS;
    
    uint8_t hased_digest[HASH_DIGEST];
	uint8_t msg[400];
	uint8_t tv_hash[HASH_DIGEST];
	int32_t msg_bytelen = 0x00;
	int32_t hash_bytelen = 0x00;

	for (int32_t cnt_i = 0; cnt_i < sizeof(HashTestVectors) / sizeof(HashFunction_TV); cnt_i++)
	{
        YBCrypto_memset(hased_digest, 0x00, sizeof(hased_digest));
        YBCrypto_memset(msg, 0x00, sizeof(msg));
        YBCrypto_memset(tv_hash, 0x00, sizeof(tv_hash));

		//! be Careful! we use string2hex
        msg_bytelen = string2hex(msg,(char *)HashTestVectors[cnt_i].msg);
        hash_bytelen = asc2hex(tv_hash,(char *)HashTestVectors[cnt_i].hash);
        YBCrypto_Hash(HashTestVectors[cnt_i].algo, msg, msg_bytelen, hased_digest);

		if (memcmp(hased_digest, tv_hash, HASH_DIGEST)) 
        {
			printf("alg = %08x",HashTestVectors[cnt_i].algo);
        	print_hex("msg", msg, msg_bytelen);
        	print_hex("tv_hash", tv_hash, hash_bytelen);
        	print_hex("our", hased_digest, hash_bytelen);
			ret = FAIL_KATSELF_TEST;
			goto EXIT;
		}
		
		YBCrypto_Hash_Init(HashTestVectors[cnt_i].algo);
        YBCrypto_Hash_Update(msg, msg_bytelen);
        YBCrypto_Hash_Final(hased_digest);

		if (memcmp(hased_digest, tv_hash, HASH_DIGEST)) 
        {
			printf("alg = %08x",HashTestVectors[cnt_i].algo);
        	print_hex("msg", msg, msg_bytelen);
        	print_hex("tv_hash", tv_hash, hash_bytelen);
        	print_hex("our", hased_digest, hash_bytelen);
			ret = FAIL_KATSELF_TEST;
			goto EXIT;
		}
	}

EXIT:
    if(ret != SUCCESS)	fprintf(stdout, "=*Location : Inner_API_HashFunction_Se..=\n");

	YBCrypto_memset(hased_digest, 0x00, sizeof(hased_digest));
    YBCrypto_memset(msg, 0x00, sizeof(msg));
    YBCrypto_memset(tv_hash, 0x00, sizeof(tv_hash));
    msg_bytelen = 0x00;
    hash_bytelen = 0x00;
    return ret;
}

//! HMAC TestVecotr
typedef struct _HMAC_TV_{
	uint32_t algo;
	uint8_t key[1000];
	uint8_t msg[1000];
	uint8_t mac[256];
	int32_t	macLength;
} HMAC_TV;

//! we use TTAE.IF-RFC6234 and TTAK.KO-12.0333-Part2's HMAC testvector 
static const
HMAC_TV	hmactestvector[] = {

	{
	SHA256,
	"E4D47A95CF75B4CFAA85DF7D4FC9BC3099FF1E3E19C440C20AB55BE487D5785BFC2F8330DBBCA2C49086C514B60E7D3C8BEB113AA1B5CFF5D721A07E886DDF9502FF6B6F3A49FBB6BEEFB2D2EA2CF4675F72771EB1509DA9609901010AC34FF2DE8D5ADA54E468AE1B08D03D53EBC8B9FDDA7873B05E53E68D65A6F7759D717B",
	"792177FA915791B2911847DF5A12A13A4D6B3BC006A798B446CCB8E730C4ED37B902EA565A691DCD07693F40656B29F3386FE98D1AF3151C73175F5AA5006A2F877ADC7615E1B5046641DFE6DEBC05EBA42CA963560A7125FC8FC2D73B189069CCCF75E32C88006194E94F5B2BCEE02A7BEBA4C821B455D8C9790AE65AD609EF",
	"08201FC6662D612BA034903F15494CFC9F2ACC8BD2E7D8D07929FAB886F934F5",32	//!done
	},

	{
	SHA3,
	"714F22D8D7654B5B9690D1EDAC26C72CD34BC90FB15DD46E4F8F5AC5CCD3963553FE1ECB4A26B705CC4F6C925A47E25ACDCFE6BE8FFB48210BDCECA7625C1E3C606826D9AE551C02497CFE94322800BD68B3234C13EB092B02BA082957077DFD81D763886BB8245BF35FAE799E90CA5E8A3EA940A4F4C0941A73D7D4149D5C809F91FC63E9187517B440A5CB0546E7441CB9A022A9DD15653D4E802FFFE562CBA0DF1AEF913CB73E73660B11CF130077076C307B8C6FAFA552922BC381A938E86E09E5B6C9EE93D9181A07D463BFBD00319F7FD1B472375C4188021603AF85DFEF57843FFAF4B0EF8AA4C19B2B12C5E6849AB8AF89AE5492F2782AB2EBC0F2B60D1120128D17B888B34C62EE8ED4C131",
	"E7A4019A73EAAF504CA9CE1FA2A42777AE7EE0B8E81F50AC7A5A1255F4CC58EA4107821CDAF0F09D396514E39123CB2ABCE7EDB875D42264C715F859C5C333187C0965BC2686BE82A1F224881F0586D51E946E9A9BFED6B782C63D816A81FAC37FF3CF03BF75C1066A992796B3110282BCCD8CE7C16414AE94B5085649CE54F3",
	"0E6753BD2A770D8B29F08C646C97BDB2825ADEF660774456EC931382C689BFB3",32	//!done
	},

};



int32_t Inner_API_HMAC_SelfTest()
{
    int32_t ret = SUCCESS;
    
	uint8_t key[1000];
	uint8_t msg[1000];
	uint8_t tv_mac[HMAC_DIGEST];
    uint8_t mac_digest[HMAC_DIGEST];
	int32_t key_bytelen = 0x00;
	int32_t msg_bytelen = 0x00;
	int32_t mac_bytelen = 0x00;

	for (int32_t cnt_i = 0; cnt_i < sizeof(hmactestvector) / sizeof(HMAC_TV); cnt_i++)
	{
        YBCrypto_memset(key, 0x00, sizeof(key));
        YBCrypto_memset(msg, 0x00, sizeof(msg));
        YBCrypto_memset(tv_mac, 0x00, sizeof(tv_mac));
        YBCrypto_memset(mac_digest, 0x00, sizeof(mac_digest));

		//! be Careful! we use asc2hex
        key_bytelen = asc2hex(key,(char *)hmactestvector[cnt_i].key);
        msg_bytelen = asc2hex(msg,(char *)hmactestvector[cnt_i].msg);
        mac_bytelen = asc2hex(tv_mac,(char *)hmactestvector[cnt_i].mac);

        YBCrypto_HMAC(hmactestvector[cnt_i].algo, key, key_bytelen, msg, msg_bytelen, mac_digest);

		if (memcmp(mac_digest, tv_mac, HMAC_DIGEST)) 
        {
			ret = FAIL_KATSELF_TEST;
			goto EXIT;
		}
	}

EXIT:
    if(ret != SUCCESS)	fprintf(stdout, "=*Location : Inner_API_HMAC_SelfTest    =\n");

	YBCrypto_memset(key, 0x00, sizeof(key));
    YBCrypto_memset(msg, 0x00, sizeof(msg));
    YBCrypto_memset(tv_mac, 0x00, sizeof(tv_mac));
    YBCrypto_memset(mac_digest, 0x00, sizeof(mac_digest));
    key_bytelen = 0x00;
    msg_bytelen = 0x00;
    mac_bytelen = 0x00;

    return ret;
}

//! CTR_DRBG testvector 
typedef struct _CTRDRBG_TV_ {
	uint32_t algo;
	uint32_t keybitlen;
	uint8_t EntropyInputStr[256];
	uint8_t NonceStr[256];
	uint8_t PStringStr[256];
	uint8_t EntropyInputReseedStr[256]; //if pre-resi on, then EntropyInputPR1
	uint8_t AdditionalInputReseedStr[256];  //if pre-resi on, then EntropyInputPR2
	uint8_t AdditionalInput1Str[256];   //if pre-resi on, then AdditionalInput1
	uint8_t AdditionalInput2Str[256];   //if pre-resi on, then  AdditionalInput1
	uint8_t KAT[512];
	uint32_t returnedBitSize;
	uint32_t prediction_resistance_flag;
}CTRDRBG_TV;

//! we use TTAK.KO-12.0189_R1's CTR_DRBG testvector 
const CTRDRBG_TV CTR_DRBG_TestVectors[] = { 

	{ARIA, 128, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", //EntropyInputStr
	"2021222324252627",  //NonceStr
	"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",	 //PStringStr
	"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F",  //Entorphy Resseed
	"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF",  //Entrophy input reseed
	"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",	 //AdditionalInput 1
	"",                                                                  //AdditionalInput 2
	"353599DF86461BD7BA6D785E07331782DD7AEB105BF8A2A85BE10E8199536393", //!done : use derivation and not use prediction resistance
	256,NO_PR },
	
	{ARIA, 128, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", //EntropyInputStr
	"2021222324252627",  //NonceStr
	"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",	 //PStringStr
	"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F",  //EntropyInputPR 1
	"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF",	 //EntropyInputPR 2
	"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",	 //AdditionalInput 1
	"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF",	 //AdditionalInput 2
	"547F7EBD69020F99BBEAE8EC883157E61EC6BAB974AE9B2888EC311AF302F0A0", //!done : use derivation and prediction resistance
	256,USE_PR },

	{ARIA, 192, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627", //EntropyInputStr
	"202122232425262728292A2B",  //NonceStr
	"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F6061626364656667",	 //PStringStr
	"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7",  //Entorphy Resseed
	"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",  //Entrophy input reseed
	"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F8081828384858687",	 //AdditionalInput 1
	"",                                                                  //AdditionalInput 2
	"302D01B7CF2A703DAC8EE832FA132E20C84197334F0919F66D001FC2C11A29ED", //!done : use derivation and not use prediction resistance
	256,NO_PR },
	
	{ARIA, 192, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627", //EntropyInputStr
	"202122232425262728292A2B",  //NonceStr
	"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F6061626364656667",	 //PStringStr
	"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7",  //EntropyInputPR 1
	"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7",	 //EntropyInputPR 2
	"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F8081828384858687",	 //AdditionalInput 1
	"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",	 //AdditionalInput 2
	"B66D15E13F5038FACA3BAED301C421033826572E3DEB5FF3E33CC75DBD43280C", //!done : use derivation and prediction resistance
	256,USE_PR },

	{ARIA, 256, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F", //EntropyInputStr
	"202122232425262728292A2B2C2D2E2F",  //NonceStr
	"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F",	 //PStringStr
	"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAF",  //Entorphy Resseed
	"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",  //Entrophy input reseed
	"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F",	 //AdditionalInput 1
	"",                                                                  //AdditionalInput 2
	"728C4D5B3BEDCA3BF67B70F5447EA2A92BA45A43E6B470D8FC95B7F5746CA957", //!done : use derivation and not use prediction resistance
	256,NO_PR },
	
	{ARIA, 256, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F", //EntropyInputStr
	"202122232425262728292A2B2C2D2E2F",  //NonceStr
	"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F",	 //PStringStr
	"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAF",  //EntropyInputPR 1
	"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF",	 //EntropyInputPR 2
	"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F",	 //AdditionalInput 1
	"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",	 //AdditionalInput 2
	"6EC12E5E6B8938C27D169FDA5D37366286F5EBC2D9AC7FC5F2A244054614C23F", //!done : use derivation and prediction resistance
	256,USE_PR },
};


int32_t Inner_API_CTR_DRBG_SelfTest()
{
    int32_t ret = SUCCESS;

    uint8_t entropyInput[256];
	uint8_t entropyReseed[256];
	uint8_t entropyinputPR1[256];
	uint8_t entropyinputPR2[256];
	uint8_t nonce1[128];
	uint8_t pString[256];
	uint8_t addInputReseed[256];
	uint8_t addInput1[256];
	uint8_t addInput2[256];
	uint8_t rand1[256];
	uint8_t rand2[256];
	uint8_t KAT[512];

	uint32_t entropyInputLen = 0x00;
	uint32_t entropyReseedLen = 0x00;
	uint32_t entropyinputPR1Len = 0x00;
	uint32_t entropyinputPR2Len = 0x00;
	uint32_t addInputReseedLen = 0x00;
	uint32_t addInput1Len = 0x00;
	uint32_t addInput2Len = 0x00;
	uint32_t pStringLen = 0x00;
	uint32_t nonce1Len = 0x00;
	uint32_t KATLen = 0x00;
	uint32_t returnedBitSize = 0x00;

    //TODO it will be deleted
	DRBGManager DRBG_DM = {0x00,};

	for (int32_t cnt_i = 0; cnt_i < sizeof(CTR_DRBG_TestVectors) / sizeof(CTRDRBG_TV); cnt_i++)
	{
		entropyInputLen = asc2hex(entropyInput, (char *)CTR_DRBG_TestVectors[cnt_i].EntropyInputStr);
		nonce1Len = asc2hex(nonce1, (char *)CTR_DRBG_TestVectors[cnt_i].NonceStr);
		pStringLen = asc2hex(pString, (char *)CTR_DRBG_TestVectors[cnt_i].PStringStr);
		KATLen = asc2hex(KAT, (char *)CTR_DRBG_TestVectors[cnt_i].KAT);

		returnedBitSize = CTR_DRBG_TestVectors[cnt_i].returnedBitSize;

		if (CTR_DRBG_TestVectors[cnt_i].prediction_resistance_flag == NO_PR)
		{
			entropyReseedLen = asc2hex(entropyReseed, (char *)CTR_DRBG_TestVectors[cnt_i].EntropyInputReseedStr);
			addInputReseedLen = asc2hex(addInputReseed, (char *)CTR_DRBG_TestVectors[cnt_i].AdditionalInputReseedStr);
			addInput1Len = asc2hex(addInput1, (char *)CTR_DRBG_TestVectors[cnt_i].AdditionalInput1Str);
			addInput2Len = asc2hex(addInput2, (char *)CTR_DRBG_TestVectors[cnt_i].AdditionalInput2Str);

			CTR_DRBG_Instantiate(&DRBG_DM, CTR_DRBG_TestVectors[cnt_i].algo, CTR_DRBG_TestVectors[cnt_i].keybitlen, entropyInput, entropyInputLen, nonce1, nonce1Len, pString, pStringLen, USE_DF);
			CTR_DRBG_Generate(&DRBG_DM, rand1, CTR_DRBG_TestVectors[cnt_i].returnedBitSize, NULL, 0, addInput1, addInput1Len, NO_PR);
			CTR_DRBG_Reseed(&DRBG_DM, entropyReseed, entropyReseedLen, addInputReseed, addInputReseedLen);
			CTR_DRBG_Generate(&DRBG_DM,rand2, CTR_DRBG_TestVectors[cnt_i].returnedBitSize, NULL, 0, NULL, 0, NO_PR);
		}
		else
		{
			entropyinputPR1Len = asc2hex(entropyinputPR1, (char *)CTR_DRBG_TestVectors[cnt_i].EntropyInputReseedStr);
			entropyinputPR2Len = asc2hex(entropyinputPR2, (char *)CTR_DRBG_TestVectors[cnt_i].AdditionalInputReseedStr);
			addInput1Len = asc2hex(addInput1, (char *)CTR_DRBG_TestVectors[cnt_i].AdditionalInput1Str);
			addInput2Len = asc2hex(addInput2, (char *)CTR_DRBG_TestVectors[cnt_i].AdditionalInput2Str);

			CTR_DRBG_Instantiate(&DRBG_DM, CTR_DRBG_TestVectors[cnt_i].algo, CTR_DRBG_TestVectors[cnt_i].keybitlen, entropyInput, entropyInputLen, nonce1, nonce1Len, pString, pStringLen, USE_DF);
			CTR_DRBG_Generate(&DRBG_DM, rand1, CTR_DRBG_TestVectors[cnt_i].returnedBitSize, entropyinputPR1, entropyinputPR1Len, addInput1, addInput1Len, USE_PR);
			CTR_DRBG_Generate(&DRBG_DM, rand2, CTR_DRBG_TestVectors[cnt_i].returnedBitSize, entropyinputPR2, entropyinputPR2Len, addInput2, addInput2Len, USE_PR);
		}
					
		if (memcmp(KAT, rand2, returnedBitSize / 8)) 
		{
            ret = FAIL_KATSELF_TEST;
			goto END;
		}
	
	}
END:
    if(ret != SUCCESS)
        fprintf(stdout, "=*Location : Inner_API_CTR_DRBG_SelfTe..=\n");
	
    YBCrypto_memset(entropyInput, 0x00, sizeof(entropyInput));
    YBCrypto_memset(entropyReseed, 0x00, sizeof(entropyReseed));
    YBCrypto_memset(entropyinputPR1, 0x00, sizeof(entropyinputPR1));
    YBCrypto_memset(entropyinputPR2, 0x00, sizeof(entropyinputPR2));
    YBCrypto_memset(nonce1, 0x00, sizeof(nonce1));
    YBCrypto_memset(pString, 0x00, sizeof(pString));
    YBCrypto_memset(addInputReseed, 0x00, sizeof(addInputReseed));
    YBCrypto_memset(addInput1, 0x00, sizeof(addInput1));
    YBCrypto_memset(addInput1, 0x00, sizeof(addInput1));
    YBCrypto_memset(rand1, 0x00, sizeof(rand1));
    YBCrypto_memset(rand2, 0x00, sizeof(rand2));
    YBCrypto_memset(KAT, 0x00, sizeof(KAT));

    entropyInputLen = 0x00;
    entropyReseedLen = 0x00;
    entropyinputPR1Len = 0x00;
    entropyinputPR2Len = 0x00;
    addInputReseedLen = 0x00;
    addInput1Len = 0x00;
    addInput2Len = 0x00;
    pStringLen = 0x00;
    nonce1Len = 0x00;
    KATLen = 0x00;
    returnedBitSize = 0x00;
    return ret;
}
