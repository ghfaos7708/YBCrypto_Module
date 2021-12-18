#include "YBCrypto.h"
#include "api.h"
#include "assert.h"

void ARIA_CTR_MCT()
{
	int cnt_i = 0, cnt_j = 0, cnt_k = 0, num_count = 0;
	FILE *fp_src = NULL, *fp_dst = NULL;
	uint8_t temp[200] = {0x00};
	uint8_t temp_count[200] = {0x00};
	uint8_t buf_msg[300] = {0x00};
	uint8_t buf_key[60] = {0x00};
	uint8_t buf_IV[16] = {0x00};
	uint8_t buf_mctpt[16] = {
		0x00,
	};
	uint8_t buf_mctct[16] = {
		0x00,
	};
	uint8_t buf_mctkey[16] = {
		0x00,
	};
	uint8_t buf_mctIV[16] = {
		0x00,
	};
	uint8_t buf_ciphertext[400] = {
		0x00,
	};
	uint8_t enc_ciphertext[400] = {
		0x00,
	};
	uint32_t msglen = 0;
	uint32_t count = 0;
	char *PT = NULL;
    CipherManager CM;

	int key_size = 0; //! max = 3 : 128 0, 192 1, 256 2

	for (key_size = 0; key_size < 3; key_size++)
	{
		if (key_size == 0)
		{
			fp_src = fopen("testvector_req/ARIA128(CTR)MCT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA128(CTR)MCT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 276;
		}
		else if (key_size == 1)
		{
			fp_src = fopen("testvector_req/ARIA192(CTR)MCT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA192(CTR)MCT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 338;
		}
		else
		{
			fp_src = fopen("testvector_req/ARIA256(CTR)MCT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA256(CTR)MCT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 400;
		}

		//! Reading
		//fscanf(fp_src, "%s = 0", temp_count); //Reading "COUNT = "
		fprintf(fp_dst, "%s", "COUNT = 0\n"); //writing "COUNT = "

		fscanf(fp_src, "%s =", temp);	//Reading "KEY = "
		fprintf(fp_dst, "%s = ", temp); //writing "KEY = "

		for (cnt_j = 0; cnt_j < 16 + key_size * 8; cnt_j++)
		{
			fscanf(fp_src, "%02hhX", &temp[cnt_j]);
			fprintf(fp_dst, "%02X", temp[cnt_j]);
			buf_key[cnt_j] = temp[cnt_j];
		}
		fputs("\n", fp_dst); // Writing "/n"
		memset(temp, 0x00, sizeof(temp));

		fscanf(fp_src, "%s =", temp);	//Reading "CTR = "
		fprintf(fp_dst, "%s = ", temp); //writing "CTR = "

		for (cnt_j = 0; cnt_j < 16; cnt_j++)
		{
			fscanf(fp_src, "%02hhX", &temp[cnt_j]);
			fprintf(fp_dst, "%02X", temp[cnt_j]);
			buf_IV[cnt_j] = temp[cnt_j];
		}
		fputs("\n", fp_dst); // Writing "/n"
		memset(temp, 0x00, sizeof(temp));

		fscanf(fp_src, "%s = ", temp);	//Reading "PT = "
		fprintf(fp_dst, "%s = ", temp); //Writing "PT = "
		for (cnt_j = 0; cnt_j < 16; cnt_j++)
		{
			fscanf(fp_src, "%02hhX", &temp[cnt_j]);
			fprintf(fp_dst, "%02X", temp[cnt_j]);
			buf_msg[cnt_j] = temp[cnt_j];
		}
		fputs("\n", fp_dst); // Writing "/n"

		memcpy(buf_mctpt, buf_msg, 16);
		memcpy(buf_mctIV, buf_IV, 16);

		//! MCT Test
		for (cnt_i = 0; cnt_i < 100; cnt_i++)
		{
			if (cnt_i != 0)
			{
				fprintf(fp_dst, "%s = %d\n", "COUNT", cnt_i); //writing "COUNT = "
				fprintf(fp_dst, "KEY = ");					  //writing "KEY = "

				for (cnt_j = 0; cnt_j < 16 + key_size * 8; cnt_j++)
				{
					fprintf(fp_dst, "%02X", buf_key[cnt_j]);
				}
				fputs("\n", fp_dst); // Writing "/n"

				fprintf(fp_dst, "CTR = "); //writing "CTR = "

				for (cnt_j = 0; cnt_j < 16; cnt_j++)
				{
					fprintf(fp_dst, "%02X", buf_mctIV[cnt_j]);
				}
				fputs("\n", fp_dst); // Writing "/n"

				fprintf(fp_dst, "PT = "); //writing "PT = "

				for (cnt_j = 0; cnt_j < 16; cnt_j++)
				{
					fprintf(fp_dst, "%02X", buf_mctpt[cnt_j]);
				}
				fputs("\n", fp_dst); // Writing "/n"
			}

			for (cnt_j = 0; cnt_j < 1000; cnt_j++)
			{
				if (key_size == 0)
				{
					//! Enc 128 CTR KAT
                    YBCrypto_BlockCipher(&CM, ARIA, CTR_MODE, ENCRYPT,buf_key,128,buf_mctpt,16, buf_mctIV, enc_ciphertext);
				}
				else if (key_size == 1)
				{
					//! Enc 192 CTR KAT
					YBCrypto_BlockCipher(&CM, ARIA, CTR_MODE, ENCRYPT,buf_key,192,buf_mctpt,16, buf_mctIV, enc_ciphertext);
				}
				else
				{
					//! Enc 256 CTR KAT
					YBCrypto_BlockCipher(&CM, ARIA, CTR_MODE, ENCRYPT,buf_key,256,buf_mctpt,16, buf_mctIV, enc_ciphertext);
				}

				Count_Addition(buf_mctIV);
				if (cnt_j != 999)
				{
					memcpy(buf_mctpt, enc_ciphertext, 16);
				}
			}

			fprintf(fp_dst, "CT = "); //Writing "CT = "
			for (cnt_j = 0; cnt_j < 16; cnt_j++)
			{
				fprintf(fp_dst, "%02X", enc_ciphertext[cnt_j]);
			}
			fputs("\n\n", fp_dst); // Writing "/n"

			if (key_size == 0)
			{
				//! Enc 128 ECB MCT
				for (cnt_k = 0; cnt_k < 16 + key_size * 8; cnt_k++)
				{
					buf_key[cnt_k] = buf_key[cnt_k] ^ enc_ciphertext[cnt_k];
				}
			}
			else if (key_size == 1)
			{
				//! Enc 192 ECB MCT
				for (cnt_k = 0; cnt_k < 8; cnt_k++)
				{
					buf_key[cnt_k] = buf_key[cnt_k] ^ buf_mctpt[cnt_k + 8];
				}
				for (cnt_k = 8; cnt_k < 24; cnt_k++)
				{
					buf_key[cnt_k] = buf_key[cnt_k] ^ enc_ciphertext[cnt_k - 8];
				}
			}
			else
			{
				//! Enc 256 ECB MCT
				for (cnt_k = 0; cnt_k < 16; cnt_k++)
				{
					buf_key[cnt_k] = buf_key[cnt_k] ^ buf_mctpt[cnt_k];
				}
				for (cnt_k = 16; cnt_k < 32; cnt_k++)
				{
					buf_key[cnt_k] = buf_key[cnt_k] ^ enc_ciphertext[cnt_k - 16];
				}
			}
			memcpy(buf_mctpt, enc_ciphertext, 16);
		}

		fclose(fp_src);
		fclose(fp_dst);
	}
}

void ARIA_CBC_MCT()
{
	int cnt_i = 0, cnt_j = 0, cnt_k = 0, num_count = 0;
	FILE *fp_src = NULL, *fp_dst = NULL;
	uint8_t temp[200] = {0x00};
	uint8_t temp_count[200] = {0x00};
	uint8_t buf_msg[300] = {0x00};
	uint8_t buf_key[60] = {0x00};
	uint8_t buf_IV[16] = {0x00};
	uint8_t buf_mctpt[16] = {
		0x00,
	};
	uint8_t buf_mctct[16] = {
		0x00,
	};
	uint8_t buf_mctkey[16] = {
		0x00,
	};
	uint8_t buf_mctIV[16] = {
		0x00,
	};
	uint8_t buf_ciphertext[400] = {
		0x00,
	};
	uint8_t enc_ciphertext[400] = {
		0x00,
	};
	uint32_t msglen = 0;
	uint32_t count = 0;
	char *PT = NULL;
    CipherManager CM;

	int key_size = 0; //! max = 3 : 128 0, 192 1, 256 2

	for (key_size = 0; key_size < 3; key_size++)
	{
		if (key_size == 0)
		{
			fp_src = fopen("testvector_req/ARIA128(CBC)MCT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA128(CBC)MCT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 276;
		}
		else if (key_size == 1)
		{
			fp_src = fopen("testvector_req/ARIA192(CBC)MCT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA192(CBC)MCT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 338;
		}
		else
		{
			fp_src = fopen("testvector_req/ARIA256(CBC)MCT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA256(CBC)MCT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 400;
		}

		//! Reading
		//fscanf(fp_src, "%s = 0", temp_count);		 //Reading "COUNT = "
		fprintf(fp_dst, "%s", "COUNT = 0\n"); //writing "COUNT = "

		fscanf(fp_src, "%s =", temp);	//Reading "KEY = "
		fprintf(fp_dst, "%s = ", temp); //writing "KEY = "

		for (cnt_j = 0; cnt_j < 16 + key_size * 8; cnt_j++)
		{
			fscanf(fp_src, "%02hhX", &temp[cnt_j]);
			fprintf(fp_dst, "%02X", temp[cnt_j]);
			buf_key[cnt_j] = temp[cnt_j];
		}
		fputs("\n", fp_dst); // Writing "/n"
		memset(temp, 0x00, sizeof(temp));

		fscanf(fp_src, "%s =", temp);	//Reading "IV = "
		fprintf(fp_dst, "%s = ", temp); //writing "IV = "

		for (cnt_j = 0; cnt_j < 16; cnt_j++)
		{
			fscanf(fp_src, "%02hhX", &temp[cnt_j]);
			fprintf(fp_dst, "%02X", temp[cnt_j]);
			buf_IV[cnt_j] = temp[cnt_j];
		}
		fputs("\n", fp_dst); // Writing "/n"
		memset(temp, 0x00, sizeof(temp));

		fscanf(fp_src, "%s = ", temp);	//Reading "PT = "
		fprintf(fp_dst, "%s = ", temp); //Writing "PT = "
		for (cnt_j = 0; cnt_j < 16; cnt_j++)
		{
			fscanf(fp_src, "%02hhX", &temp[cnt_j]);
			fprintf(fp_dst, "%02X", temp[cnt_j]);
			buf_msg[cnt_j] = temp[cnt_j];
		}
		fputs("\n", fp_dst); // Writing "/n"

		memcpy(buf_mctpt, buf_msg, 16);
		memcpy(buf_mctIV, buf_IV, 16);

		//! MCT Test
		for (cnt_i = 0; cnt_i < 100; cnt_i++)
		{
			if (cnt_i != 0)
			{
				fprintf(fp_dst, "%s = %d\n", "COUNT", cnt_i); //writing "COUNT = "
				fprintf(fp_dst, "KEY = ");					  //writing "KEY = "

				for (cnt_j = 0; cnt_j < 16 + key_size * 8; cnt_j++)
				{
					fprintf(fp_dst, "%02X", buf_key[cnt_j]);
				}
				fputs("\n", fp_dst); // Writing "/n"

				fprintf(fp_dst, "IV = "); //writing "IV = "

				for (cnt_j = 0; cnt_j < 16; cnt_j++)
				{
					fprintf(fp_dst, "%02X", buf_mctIV[cnt_j]);
				}
				fputs("\n", fp_dst); // Writing "/n"

				fprintf(fp_dst, "PT = "); //writing "PT = "

				for (cnt_j = 0; cnt_j < 16; cnt_j++)
				{
					fprintf(fp_dst, "%02X", buf_mctpt[cnt_j]);
				}
				fputs("\n", fp_dst); // Writing "/n"
			}

			for (cnt_j = 0; cnt_j < 1000; cnt_j++)
			{
				if (cnt_j == 0)
				{
					if (key_size == 0)
					{
						//! Enc 128 ECB KAT
                        YBCrypto_BlockCipher(&CM, ARIA, CBC_MODE, ENCRYPT,buf_key,128, buf_mctpt, 16, buf_mctIV, enc_ciphertext);
					}
					else if (key_size == 1)
					{
						//! Enc 192 ECB KAT
						YBCrypto_BlockCipher(&CM, ARIA, CBC_MODE, ENCRYPT,buf_key,192, buf_mctpt, 16, buf_mctIV, enc_ciphertext);
					}
					else
					{
						//! Enc 256 ECB KAT
						YBCrypto_BlockCipher(&CM, ARIA, CBC_MODE, ENCRYPT,buf_key,256, buf_mctpt, 16, buf_mctIV, enc_ciphertext);
					}
					memcpy(buf_mctpt, buf_mctIV, 16);
				}
				else
				{
					memcpy(buf_msg, enc_ciphertext, 16);

					if (key_size == 0)
					{
						//! Enc 128 ECB KAT
                        YBCrypto_BlockCipher(&CM, ARIA, CBC_MODE, ENCRYPT,buf_key,128, buf_mctpt, 16, enc_ciphertext, enc_ciphertext);
					}
					else if (key_size == 1)
					{
						//! Enc 192 ECB KAT
						YBCrypto_BlockCipher(&CM, ARIA, CBC_MODE, ENCRYPT,buf_key,192, buf_mctpt, 16, enc_ciphertext, enc_ciphertext);
					}
					else
					{
						//! Enc 256 ECB KAT
						YBCrypto_BlockCipher(&CM, ARIA, CBC_MODE, ENCRYPT,buf_key,256, buf_mctpt, 16, enc_ciphertext, enc_ciphertext);
					}

					memcpy(buf_mctpt, buf_msg, 16);
				}
			}

			fprintf(fp_dst, "CT = "); //Writing "CT = "
			for (cnt_j = 0; cnt_j < 16; cnt_j++)
			{
				fprintf(fp_dst, "%02X", enc_ciphertext[cnt_j]);
			}
			fputs("\n\n", fp_dst); // Writing "/n"

			if (key_size == 0)
			{
				//! Enc 128 ECB MCT
				for (cnt_k = 0; cnt_k < 16 + key_size * 8; cnt_k++)
				{
					buf_key[cnt_k] = buf_key[cnt_k] ^ enc_ciphertext[cnt_k];
				}
			}
			else if (key_size == 1)
			{
				//! Enc 192 ECB MCT
				for (cnt_k = 0; cnt_k < 8; cnt_k++)
				{
					buf_key[cnt_k] = buf_key[cnt_k] ^ buf_mctpt[cnt_k + 8];
				}
				for (cnt_k = 8; cnt_k < 24; cnt_k++)
				{
					buf_key[cnt_k] = buf_key[cnt_k] ^ enc_ciphertext[cnt_k - 8];
				}
			}
			else
			{
				//! Enc 256 ECB MCT
				for (cnt_k = 0; cnt_k < 16; cnt_k++)
				{
					buf_key[cnt_k] = buf_key[cnt_k] ^ buf_mctpt[cnt_k];
				}
				for (cnt_k = 16; cnt_k < 32; cnt_k++)
				{
					buf_key[cnt_k] = buf_key[cnt_k] ^ enc_ciphertext[cnt_k - 16];
				}
			}
			memcpy(buf_mctIV, enc_ciphertext, 16);
		}

		fclose(fp_src);
		fclose(fp_dst);
	}
}

void ARIA_ECB_MCT()
{
	int cnt_i = 0, cnt_j = 0, cnt_k = 0, num_count = 0;
	FILE *fp_src = NULL, *fp_dst = NULL;
	uint8_t temp[200] = {0x00};
	uint8_t temp_count[200] = {0x00};
	uint8_t buf_msg[300] = {0x00};
	uint8_t buf_key[60] = {0x00};
	uint8_t buf_IV[16] = {0x00};
	uint8_t buf_mctpt[16] = {
		0x00,
	};
	uint8_t buf_mctct[16] = {
		0x00,
	};
	uint8_t buf_mctkey[16] = {
		0x00,
	};
	uint8_t buf_mctIV[16] = {
		0x00,
	};
	uint8_t buf_ciphertext[400] = {
		0x00,
	};
	uint8_t enc_ciphertext[400] = {
		0x00,
	};
	uint32_t msglen = 0;
	uint32_t count = 0;
	char *PT = NULL;
    CipherManager CM;

	int key_size = 0; //! max = 3 : 128 0, 192 1, 256 2

	for (key_size = 0; key_size < 3; key_size++)
	{
		if (key_size == 0)
		{
			fp_src = fopen("testvector_req/ARIA128(ECB)MCT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA128(ECB)MCT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 276;
		}
		else if (key_size == 1)
		{
			fp_src = fopen("testvector_req/ARIA192(ECB)MCT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA192(ECB)MCT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 338;
		}
		else
		{
			fp_src = fopen("testvector_req/ARIA256(ECB)MCT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA256(ECB)MCT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 400;
		}

		//! Reading
		//fscanf(fp_src, "%s = 0", temp_count);		 //Reading "COUNT = "
		fprintf(fp_dst, "%s", "COUNT = 0\n"); //writing "COUNT = "

		fscanf(fp_src, "%s =", temp);	//Reading "KEY = "
		fprintf(fp_dst, "%s = ", temp); //writing "KEY = "

		for (cnt_j = 0; cnt_j < 16 + key_size * 8; cnt_j++)
		{
			fscanf(fp_src, "%02hhX", &temp[cnt_j]);
			fprintf(fp_dst, "%02X", temp[cnt_j]);
			buf_key[cnt_j] = temp[cnt_j];
		}

		fputs("\n", fp_dst); // Writing "/n"
		memset(temp, 0x00, sizeof(temp));

		fscanf(fp_src, "%s = ", temp);	//Reading "PT = "
		fprintf(fp_dst, "%s = ", temp); //Writing "PT = "
		for (cnt_j = 0; cnt_j < 16; cnt_j++)
		{
			fscanf(fp_src, "%02hhX", &temp[cnt_j]);
			fprintf(fp_dst, "%02X", temp[cnt_j]);
			buf_msg[cnt_j] = temp[cnt_j];
		}
		fputs("\n", fp_dst); // Writing "/n"

		memcpy(buf_mctpt, buf_msg, 16);
		//! MCT Test
		for (cnt_i = 0; cnt_i < 100; cnt_i++) //KISA의 SEED KAT의 테스트 벡터수는 276개
		{
			if (cnt_i != 0)
			{
				fprintf(fp_dst, "%s = %d\n", "COUNT", cnt_i); //writing "COUNT = "
				fprintf(fp_dst, "KEY = ");					  //writing "KEY = "

				for (cnt_j = 0; cnt_j < 16 + key_size * 8; cnt_j++)
				{
					fprintf(fp_dst, "%02X", buf_key[cnt_j]);
				}
				fputs("\n", fp_dst); // Writing "/n"

				fprintf(fp_dst, "PT = "); //writing "PT = "

				for (cnt_j = 0; cnt_j < 16; cnt_j++)
				{
					fprintf(fp_dst, "%02X", buf_mctpt[cnt_j]);
				}
				fputs("\n", fp_dst); // Writing "/n"
			}

			for (cnt_j = 0; cnt_j < 1000; cnt_j++)
			{

				if (key_size == 0)
				{
					//! Enc 128 ECB KAT
                    YBCrypto_BlockCipher(&CM, ARIA, ECB_MODE, ENCRYPT,buf_key,128,buf_mctpt,16, NULL, enc_ciphertext);
				}
				else if (key_size == 1)
				{
					//! Enc 192 ECB KAT
					YBCrypto_BlockCipher(&CM, ARIA, ECB_MODE, ENCRYPT,buf_key,192,buf_mctpt,16, NULL, enc_ciphertext);
				}
				else
				{
					//! Enc 256 ECB KAT
					YBCrypto_BlockCipher(&CM, ARIA, ECB_MODE, ENCRYPT,buf_key,256,buf_mctpt,16, NULL, enc_ciphertext);
				}
				if (cnt_j != 999)
				{
					memcpy(buf_mctpt, enc_ciphertext, 16);
				}
			}

			fprintf(fp_dst, "CT = "); //Writing "CT = "
			for (cnt_j = 0; cnt_j < 16; cnt_j++)
			{
				fprintf(fp_dst, "%02X", enc_ciphertext[cnt_j]);
			}
			fputs("\n\n", fp_dst); // Writing "/n"

			if (key_size == 0)
			{
				//! Enc 128 ECB MCT
				for (cnt_k = 0; cnt_k < 16 + key_size * 8; cnt_k++)
				{
					buf_key[cnt_k] = buf_key[cnt_k] ^ enc_ciphertext[cnt_k];
				}
			}
			else if (key_size == 1)
			{
				//! Enc 192 ECB MCT
				for (cnt_k = 0; cnt_k < 8; cnt_k++)
				{
					buf_key[cnt_k] = buf_key[cnt_k] ^ buf_mctpt[cnt_k + 8];
				}
				for (cnt_k = 8; cnt_k < 24; cnt_k++)
				{
					buf_key[cnt_k] = buf_key[cnt_k] ^ enc_ciphertext[cnt_k - 8];
				}
			}
			else
			{
				//! Enc 256 ECB MCT
				for (cnt_k = 0; cnt_k < 16; cnt_k++)
				{
					buf_key[cnt_k] = buf_key[cnt_k] ^ buf_mctpt[cnt_k];
				}
				for (cnt_k = 16; cnt_k < 32; cnt_k++)
				{
					buf_key[cnt_k] = buf_key[cnt_k] ^ enc_ciphertext[cnt_k - 16];
				}
			}
			memcpy(buf_mctpt, enc_ciphertext, 16);
		}

		fclose(fp_src);
		fclose(fp_dst);
	}
}

void ARIA_CTR_MMT()
{
	int cnt_i = 0, cnt_j = 0, cnt_k = 0, num_count = 0;
	FILE *fp_src = NULL, *fp_dst = NULL;
	uint8_t temp[800] = {0x00};
	uint8_t buf_msg[800] = {0x00};
	uint8_t buf_key[60] = {0x00};
	uint8_t buf_IV[16] = {0x00};
	uint8_t buf_mctpt[16] = {
		0x00,
	};
	uint8_t buf_mctct[16] = {
		0x00,
	};
	uint8_t buf_mctkey[16] = {
		0x00,
	};
	uint8_t buf_mctIV[16] = {
		0x00,
	};
	uint8_t buf_ciphertext[400] = {
		0x00,
	};
	uint8_t enc_ciphertext[400] = {
		0x00,
	};
	uint32_t msglen = 0;
	uint32_t count = 0;
	char *PT = NULL;
    CipherManager CM;

	int key_size = 0; //! max = 3 : 128 0, 192 1, 256 2

	for (key_size = 0; key_size < 3; key_size++)
	{
		if (key_size == 0)
		{
			fp_src = fopen("testvector_req/ARIA128(CTR)MMT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA128(CTR)MMT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 10;
		}
		else if (key_size == 1)
		{
			fp_src = fopen("testvector_req/ARIA192(CTR)MMT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA192(CTR)MMT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 10;
		}
		else
		{
			fp_src = fopen("testvector_req/ARIA256(CTR)MMT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA256(CTR)MMT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 10;
		}

		//! Reading 10
		for (cnt_i = 0; cnt_i < num_count; cnt_i++)
		{
			memset(temp, 0x00, sizeof(temp));
			memset(buf_msg, 0x00, sizeof(buf_msg));
			memset(buf_key, 0x00, sizeof(buf_key));
			memset(buf_ciphertext, 0x00, sizeof(buf_ciphertext));
			memset(enc_ciphertext, 0x00, sizeof(enc_ciphertext));

			fscanf(fp_src, "%s = ", temp);	//Reading "KEY = "
			fprintf(fp_dst, "%s = ", temp); //writing "KEY = "

			for (cnt_j = 0; cnt_j < 16 + key_size * 8; cnt_j++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_j]);
				fprintf(fp_dst, "%02X", temp[cnt_j]);
				buf_key[cnt_j] = temp[cnt_j];
			}
			fputs("\n", fp_dst); // Writing "/n"
			memset(temp, 0x00, sizeof(temp));

			fscanf(fp_src, "%s = ", temp);	//Reading "IV = "
			fprintf(fp_dst, "%s = ", temp); //writing "IV = "

			for (cnt_j = 0; cnt_j < 16; cnt_j++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_j]);
				fprintf(fp_dst, "%02X", temp[cnt_j]);
				buf_IV[cnt_j] = temp[cnt_j];
			}
			fputs("\n", fp_dst); // Writing "/n"
			memset(temp, 0x00, sizeof(temp));

			fscanf(fp_src, "%s = ", temp);	//Reading "PT = "
			fprintf(fp_dst, "%s = ", temp); //Writing "PT = "
			for (cnt_j = 0; cnt_j < 16 + cnt_i * 16; cnt_j++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_j]);
				fprintf(fp_dst, "%02X", temp[cnt_j]);
				buf_msg[cnt_j] = temp[cnt_j];
			}
			fputs("\n", fp_dst); // Writing "/n"
			memset(temp, 0x00, sizeof(temp));

			if (key_size == 0)
			{
				//! Enc 128 CTR KAT
                YBCrypto_BlockCipher(&CM, ARIA, CTR_MODE, ENCRYPT,buf_key,128,buf_msg,16 + cnt_i * 16, buf_IV, enc_ciphertext);
			}
			else if (key_size == 1)
			{
				//! Enc 192 CTR KAT
				YBCrypto_BlockCipher(&CM, ARIA, CTR_MODE, ENCRYPT,buf_key,192,buf_msg,16 + cnt_i * 16, buf_IV, enc_ciphertext);
			}
			else
			{
				//! Enc 256 CTR KAT
				YBCrypto_BlockCipher(&CM, ARIA, CTR_MODE, ENCRYPT,buf_key,256,buf_msg,16 + cnt_i * 16, buf_IV, enc_ciphertext);
			}

			fprintf(fp_dst, "CT = "); //Writing "CT = "
			for (cnt_j = 0; cnt_j < 16 + 16 * cnt_i; cnt_j++)
			{
				fprintf(fp_dst, "%02X", enc_ciphertext[cnt_j]);
			}
			fputs("\n", fp_dst); // Writing "/n"

            fgetc(fp_src);
			// fgets(temp, sizeof(temp), fp_src); // Reading "/n"
			fputs("\n", fp_dst);			   // Writing "/n"

			memset(enc_ciphertext, 0x00, sizeof(enc_ciphertext));

			memset(buf_key, 0x00, sizeof(buf_key));
			memset(buf_msg, 0x00, sizeof(buf_msg));
		}

		fclose(fp_src);
		fclose(fp_dst);
	}
}

void ARIA_CBC_MMT()
{
	int cnt_i = 0, cnt_j = 0, cnt_k = 0, num_count = 0;
	FILE *fp_src = NULL, *fp_dst = NULL;
	uint8_t temp[800] = {0x00};
	uint8_t buf_msg[800] = {0x00};
	uint8_t buf_key[60] = {0x00};
	uint8_t buf_IV[16] = {0x00};
	uint8_t buf_mctpt[16] = {
		0x00,
	};
	uint8_t buf_mctct[16] = {
		0x00,
	};
	uint8_t buf_mctkey[16] = {
		0x00,
	};
	uint8_t buf_mctIV[16] = {
		0x00,
	};
	uint8_t buf_ciphertext[400] = {
		0x00,
	};
	uint8_t enc_ciphertext[400] = {
		0x00,
	};
	uint32_t msglen = 0;
	uint32_t count = 0;
	char *PT = NULL;
    CipherManager CM;

	int key_size = 0; //! max = 3 : 128 0, 192 1, 256 2

	for (key_size = 0; key_size < 3; key_size++)
	{
		if (key_size == 0)
		{
			fp_src = fopen("testvector_req/ARIA128(CBC)MMT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA128(CBC)MMT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 10;
		}
		else if (key_size == 1)
		{
			fp_src = fopen("testvector_req/ARIA192(CBC)MMT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA192(CBC)MMT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 10;
		}
		else
		{
			fp_src = fopen("testvector_req/ARIA256(CBC)MMT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA256(CBC)MMT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 10;
		}

		//! Reading 10
		for (cnt_i = 0; cnt_i < num_count; cnt_i++)
		{
			memset(temp, 0x00, sizeof(temp));
			memset(buf_msg, 0x00, sizeof(buf_msg));
			memset(buf_key, 0x00, sizeof(buf_key));
			memset(buf_ciphertext, 0x00, sizeof(buf_ciphertext));
			memset(enc_ciphertext, 0x00, sizeof(enc_ciphertext));

			fscanf(fp_src, "%s = ", temp);	//Reading "KEY = "
			fprintf(fp_dst, "%s = ", temp); //writing "KEY = "

			for (cnt_j = 0; cnt_j < 16 + key_size * 8; cnt_j++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_j]);
				fprintf(fp_dst, "%02X", temp[cnt_j]);
				buf_key[cnt_j] = temp[cnt_j];
			}
			fputs("\n", fp_dst); // Writing "/n"
			memset(temp, 0x00, sizeof(temp));

			fscanf(fp_src, "%s = ", temp);	//Reading "IV = "
			fprintf(fp_dst, "%s = ", temp); //writing "IV = "

			for (cnt_j = 0; cnt_j < 16; cnt_j++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_j]);
				fprintf(fp_dst, "%02X", temp[cnt_j]);
				buf_IV[cnt_j] = temp[cnt_j];
			}
			fputs("\n", fp_dst); // Writing "/n"
			memset(temp, 0x00, sizeof(temp));

			fscanf(fp_src, "%s = ", temp);	//Reading "PT = "
			fprintf(fp_dst, "%s = ", temp); //Writing "PT = "
			for (cnt_j = 0; cnt_j < 16 + cnt_i * 16; cnt_j++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_j]);
				fprintf(fp_dst, "%02X", temp[cnt_j]);
				buf_msg[cnt_j] = temp[cnt_j];
			}
			fputs("\n", fp_dst); // Writing "/n"
			memset(temp, 0x00, sizeof(temp));

			if (key_size == 0)
			{
				//! Enc 128 CBC KAT
                YBCrypto_BlockCipher(&CM, ARIA, CBC_MODE, ENCRYPT,buf_key,128,buf_msg,16 + cnt_i * 16, buf_IV, enc_ciphertext);
                
			}
			else if (key_size == 1)
			{
				//! Enc 192 CBC KAT
				YBCrypto_BlockCipher(&CM, ARIA, CBC_MODE, ENCRYPT,buf_key,192,buf_msg,16 + cnt_i * 16, buf_IV, enc_ciphertext);
			}
			else
			{
				//! Enc 256 CBC KAT
				YBCrypto_BlockCipher(&CM, ARIA, CBC_MODE, ENCRYPT,buf_key,256,buf_msg,16 + cnt_i * 16, buf_IV, enc_ciphertext);
			}

			fprintf(fp_dst, "CT = "); //Writing "CT = "
			for (cnt_j = 0; cnt_j < 16 + 16 * cnt_i; cnt_j++)
			{
				fprintf(fp_dst, "%02X", enc_ciphertext[cnt_j]);
			}
			fputs("\n", fp_dst); // Writing "/n"

			// fgets(temp, sizeof(temp), fp_src); // Reading "/n"
            fgetc(fp_src);
			fputs("\n", fp_dst);			   // Writing "/n"

			memset(enc_ciphertext, 0x00, sizeof(enc_ciphertext));

			memset(buf_key, 0x00, sizeof(buf_key));
			memset(buf_msg, 0x00, sizeof(buf_msg));
		}

		fclose(fp_src);
		fclose(fp_dst);
	}
}

void ARIA_ECB_MMT()
{
	int cnt_i = 0, cnt_j = 0, cnt_k = 0, num_count = 0;
	FILE *fp_src = NULL, *fp_dst = NULL;
	uint8_t temp[800] = {0x00};
	uint8_t buf_msg[800] = {0x00};
	uint8_t buf_key[60] = {0x00};
	uint8_t buf_IV[16] = {0x00};
	uint8_t buf_mctpt[16] = {
		0x00,
	};
	uint8_t buf_mctct[16] = {
		0x00,
	};
	uint8_t buf_mctkey[16] = {
		0x00,
	};
	uint8_t buf_mctIV[16] = {
		0x00,
	};
	uint8_t buf_ciphertext[400] = {
		0x00,
	};
	uint8_t enc_ciphertext[400] = {
		0x00,
	};
	uint32_t msglen = 0;
	uint32_t count = 0;
	char *PT = NULL;
    CipherManager CM;

	int key_size = 0; //! max = 3 : 128 0, 192 1, 256 2

	for (key_size = 0; key_size < 3; key_size++)
	{
		if (key_size == 0)
		{
			fp_src = fopen("testvector_req/ARIA128(ECB)MMT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA128(ECB)MMT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 10;
		}
		else if (key_size == 1)
		{
			fp_src = fopen("testvector_req/ARIA192(ECB)MMT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA192(ECB)MMT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 10;
		}
		else
		{
			fp_src = fopen("testvector_req/ARIA256(ECB)MMT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA256(ECB)MMT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 10;
		}

		//! Reading 10
		for (cnt_i = 0; cnt_i < num_count; cnt_i++)
		{
			memset(temp, 0x00, sizeof(temp));
			memset(buf_msg, 0x00, sizeof(buf_msg));
			memset(buf_key, 0x00, sizeof(buf_key));
			memset(buf_ciphertext, 0x00, sizeof(buf_ciphertext));
			memset(enc_ciphertext, 0x00, sizeof(enc_ciphertext));

			fscanf(fp_src, "%s = ", temp);	//Reading "KEY = "
			fprintf(fp_dst, "%s = ", temp); //writing "KEY = "

			for (cnt_j = 0; cnt_j < 16 + key_size * 8; cnt_j++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_j]);
				fprintf(fp_dst, "%02X", temp[cnt_j]);
				buf_key[cnt_j] = temp[cnt_j];
			}
			fputs("\n", fp_dst); // Writing "/n"
			memset(temp, 0x00, sizeof(temp));

			fscanf(fp_src, "%s = ", temp);	//Reading "PT = "
			fprintf(fp_dst, "%s = ", temp); //Writing "PT = "
			for (cnt_j = 0; cnt_j < 16 + cnt_i * 16; cnt_j++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_j]);
				fprintf(fp_dst, "%02X", temp[cnt_j]);
				buf_msg[cnt_j] = temp[cnt_j];
			}
			fputs("\n", fp_dst); // Writing "/n"
			memset(temp, 0x00, sizeof(temp));

			if (key_size == 0)
			{
				//! Enc 128 ECB KAT
                YBCrypto_BlockCipher(&CM, ARIA, ECB_MODE, ENCRYPT,buf_key,128, buf_msg, 16 + cnt_i * 16, NULL, enc_ciphertext);
			}
			else if (key_size == 1)
			{
				//! Enc 192 ECB KAT
				YBCrypto_BlockCipher(&CM, ARIA, ECB_MODE, ENCRYPT,buf_key,192, buf_msg, 16 + cnt_i * 16, NULL, enc_ciphertext);
			}
			else
			{
				//! Enc 256 ECB KAT
				YBCrypto_BlockCipher(&CM, ARIA, ECB_MODE, ENCRYPT,buf_key,256, buf_msg, 16 + cnt_i * 16, NULL, enc_ciphertext);
			}

			fprintf(fp_dst, "CT = "); //Writing "CT = "
			for (cnt_j = 0; cnt_j < 16 + 16 * cnt_i; cnt_j++)
			{
				fprintf(fp_dst, "%02X", enc_ciphertext[cnt_j]);
			}
			fputs("\n", fp_dst); // Writing "/n"

			// fgets(temp, sizeof(temp), fp_src); // Reading "/n"
            fgetc(fp_src);
			fputs("\n", fp_dst);			   // Writing "/n"

			memset(enc_ciphertext, 0x00, sizeof(enc_ciphertext));

			memset(buf_key, 0x00, sizeof(buf_key));
			memset(buf_msg, 0x00, sizeof(buf_msg));
		}

		fclose(fp_src);
		fclose(fp_dst);
	}
}

void ARIA_CTR_KAT()
{
	int cnt_i = 0, cnt_j = 0, cnt_k = 0, num_count = 0;
	FILE *fp_src = NULL, *fp_dst = NULL;
	uint8_t temp[200] = {0x00};
	uint8_t buf_msg[300] = {0x00};
	uint8_t buf_key[60] = {0x00};
	uint8_t buf_IV[16] = {0x00};
	uint8_t buf_mctpt[16] = {
		0x00,
	};
	uint8_t buf_mctct[16] = {
		0x00,
	};
	uint8_t buf_mctkey[16] = {
		0x00,
	};
	uint8_t buf_mctIV[16] = {
		0x00,
	};
	uint8_t buf_ciphertext[400] = {
		0x00,
	};
	uint8_t enc_ciphertext[400] = {
		0x00,
	};
	uint32_t msglen = 0;
	uint32_t count = 0;
	char *PT = NULL;
    CipherManager CM;

	int key_size = 0; //! max = 3 : 128 0, 192 1, 256 2

	for (key_size = 0; key_size < 3; key_size++)
	{
		if (key_size == 0)
		{
			fp_src = fopen("testvector_req/ARIA128(CTR)KAT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA128(CTR)KAT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 276;
		}
		else if (key_size == 1)
		{
			fp_src = fopen("testvector_req/ARIA192(CTR)KAT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA192(CTR)KAT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 338;
		}
		else
		{
			fp_src = fopen("testvector_req/ARIA256(CTR)KAT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA256(CTR)KAT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 400;
		}

		//! Reading 128 : 1104/4 = 276, 1352/4 = 338,  1600/4 = 400
		for (cnt_i = 0; cnt_i < num_count; cnt_i++)
		{
			memset(temp, 0x00, sizeof(temp));
			memset(buf_msg, 0x00, sizeof(buf_msg));
			memset(buf_key, 0x00, sizeof(buf_key));
			memset(buf_ciphertext, 0x00, sizeof(buf_ciphertext));
			memset(enc_ciphertext, 0x00, sizeof(enc_ciphertext));

			fscanf(fp_src, "%s = ", temp);	//Reading "KEY = "
			fprintf(fp_dst, "%s = ", temp); //writing "KEY = "

			for (cnt_j = 0; cnt_j < 16 + key_size * 8; cnt_j++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_j]);
				fprintf(fp_dst, "%02X", temp[cnt_j]);
				buf_key[cnt_j] = temp[cnt_j];
			}
			fputs("\n", fp_dst); // Writing "/n"
			memset(temp, 0x00, sizeof(temp));

			fscanf(fp_src, "%s = ", temp);	//Reading "IV = "
			fprintf(fp_dst, "%s = ", temp); //writing "IV = "

			for (cnt_j = 0; cnt_j < 16; cnt_j++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_j]);
				fprintf(fp_dst, "%02X", temp[cnt_j]);
				buf_IV[cnt_j] = temp[cnt_j];
			}
			fputs("\n", fp_dst); // Writing "/n"
			memset(temp, 0x00, sizeof(temp));

			fscanf(fp_src, "%s = ", temp);	//Reading "PT = "
			fprintf(fp_dst, "%s = ", temp); //Writing "PT = "
			for (cnt_j = 0; cnt_j < 16; cnt_j++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_j]);
				fprintf(fp_dst, "%02X", temp[cnt_j]);
				buf_msg[cnt_j] = temp[cnt_j];
			}
			fputs("\n", fp_dst); // Writing "/n"
			memset(temp, 0x00, sizeof(temp));

			if (key_size == 0)
			{
				//! Enc 128 CBC KAT
                YBCrypto_BlockCipher(&CM, ARIA, CTR_MODE, ENCRYPT,buf_key,128,buf_msg,16, buf_IV, enc_ciphertext);
			}
			else if (key_size == 1)
			{
				//! Enc 192 CBC KAT
				YBCrypto_BlockCipher(&CM, ARIA, CTR_MODE, ENCRYPT,buf_key,192,buf_msg,16, buf_IV, enc_ciphertext);
			}
			else
			{
				//! Enc 256 CBC KAT
				YBCrypto_BlockCipher(&CM, ARIA, CTR_MODE, ENCRYPT,buf_key,256,buf_msg,16, buf_IV, enc_ciphertext);
			}

			fprintf(fp_dst, "CT = "); //Writing "CT = "
			for (cnt_j = 0; cnt_j < 16; cnt_j++)
			{
				fprintf(fp_dst, "%02X", enc_ciphertext[cnt_j]);
			}
			fputs("\n", fp_dst); // Writing "/n"

			// fgets(temp, sizeof(temp), fp_src); // Reading "/n"
            fgetc(fp_src);
			fputs("\n", fp_dst);			   // Writing "/n"

			memset(enc_ciphertext, 0x00, sizeof(enc_ciphertext));

			memset(buf_key, 0x00, sizeof(buf_key));
			memset(buf_msg, 0x00, sizeof(buf_msg));
		}

		fclose(fp_src);
		fclose(fp_dst);
	}
}

void ARIA_CBC_KAT()
{
	int cnt_i = 0, cnt_j = 0, cnt_k = 0, num_count = 0;
	FILE *fp_src = NULL, *fp_dst = NULL;
	uint8_t temp[200] = {0x00};
	uint8_t buf_msg[300] = {0x00};
	uint8_t buf_key[60] = {0x00};
	uint8_t buf_IV[16] = {0x00};
	uint8_t buf_mctpt[16] = {
		0x00,
	};
	uint8_t buf_mctct[16] = {
		0x00,
	};
	uint8_t buf_mctkey[16] = {
		0x00,
	};
	uint8_t buf_mctIV[16] = {
		0x00,
	};
	uint8_t buf_ciphertext[400] = {
		0x00,
	};
	uint8_t enc_ciphertext[400] = {
		0x00,
	};
	uint32_t msglen = 0;
	uint32_t count = 0;
	char *PT = NULL;
    CipherManager CM;

	int key_size = 0; //! max = 3 : 128 0, 192 1, 256 2

	for (key_size = 0; key_size < 3; key_size++)
	{
		if (key_size == 0)
		{
			fp_src = fopen("testvector_req/ARIA128(CBC)KAT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA128(CBC)KAT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 276;
		}
		else if (key_size == 1)
		{
			fp_src = fopen("testvector_req/ARIA192(CBC)KAT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA192(CBC)KAT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 338;
		}
		else
		{
			fp_src = fopen("testvector_req/ARIA256(CBC)KAT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA256(CBC)KAT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 400;
		}

		//! Reading 128 : 1104/4 = 276, 1352/4 = 338,  1600/4 = 400
		for (cnt_i = 0; cnt_i < num_count; cnt_i++)
		{
			memset(temp, 0x00, sizeof(temp));
			memset(buf_msg, 0x00, sizeof(buf_msg));
			memset(buf_key, 0x00, sizeof(buf_key));
			memset(buf_ciphertext, 0x00, sizeof(buf_ciphertext));
			memset(enc_ciphertext, 0x00, sizeof(enc_ciphertext));

			fscanf(fp_src, "%s = ", temp);	//Reading "KEY = "
			fprintf(fp_dst, "%s = ", temp); //writing "KEY = "

			for (cnt_j = 0; cnt_j < 16 + key_size * 8; cnt_j++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_j]);
				fprintf(fp_dst, "%02X", temp[cnt_j]);
				buf_key[cnt_j] = temp[cnt_j];
			}
			fputs("\n", fp_dst); // Writing "/n"
			memset(temp, 0x00, sizeof(temp));

			fscanf(fp_src, "%s = ", temp);	//Reading "IV = "
			fprintf(fp_dst, "%s = ", temp); //writing "IV = "

			for (cnt_j = 0; cnt_j < 16; cnt_j++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_j]);
				fprintf(fp_dst, "%02X", temp[cnt_j]);
				buf_IV[cnt_j] = temp[cnt_j];
			}
			fputs("\n", fp_dst); // Writing "/n"
			memset(temp, 0x00, sizeof(temp));

			fscanf(fp_src, "%s = ", temp);	//Reading "PT = "
			fprintf(fp_dst, "%s = ", temp); //Writing "PT = "
			for (cnt_j = 0; cnt_j < 16; cnt_j++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_j]);
				fprintf(fp_dst, "%02X", temp[cnt_j]);
				buf_msg[cnt_j] = temp[cnt_j];
			}
			fputs("\n", fp_dst); // Writing "/n"
			memset(temp, 0x00, sizeof(temp));

			if (key_size == 0)
			{
				//! Enc 128 CBC KAT
                YBCrypto_BlockCipher(&CM, ARIA, CBC_MODE, ENCRYPT,buf_key,128,buf_msg,16, buf_IV, enc_ciphertext);
			}
			else if (key_size == 1)
			{
				//! Enc 192 CBC KAT
				YBCrypto_BlockCipher(&CM, ARIA, CBC_MODE, ENCRYPT,buf_key,192,buf_msg,16, buf_IV, enc_ciphertext);
			}
			else
			{
				//! Enc 256 CBC KAT
				YBCrypto_BlockCipher(&CM, ARIA, CBC_MODE, ENCRYPT,buf_key,256,buf_msg,16, buf_IV, enc_ciphertext);
			}

			fprintf(fp_dst, "CT = "); //Writing "CT = "
			for (cnt_j = 0; cnt_j < 16; cnt_j++)
			{
				fprintf(fp_dst, "%02X", enc_ciphertext[cnt_j]);
			}
			fputs("\n", fp_dst); // Writing "/n"

            fgetc(fp_src);
			fputs("\n", fp_dst);			   // Writing "/n"

			memset(enc_ciphertext, 0x00, sizeof(enc_ciphertext));

			memset(buf_key, 0x00, sizeof(buf_key));
			memset(buf_msg, 0x00, sizeof(buf_msg));
		}

		fclose(fp_src);
		fclose(fp_dst);
	}
}

void ARIA_ECB_KAT()
{
	int cnt_i = 0, cnt_j = 0, cnt_k = 0, num_count = 0;
	FILE *fp_src = NULL, *fp_dst = NULL;
	uint8_t temp[200] = {0x00};
	uint8_t buf_msg[300] = {0x00};
	uint8_t buf_key[60] = {0x00};
	uint8_t buf_IV[16] = {0x00};
	uint8_t buf_mctpt[16] = {
		0x00,
	};
	uint8_t buf_mctct[16] = {
		0x00,
	};
	uint8_t buf_mctkey[16] = {
		0x00,
	};
	uint8_t buf_mctIV[16] = {
		0x00,
	};
	uint8_t buf_ciphertext[400] = {
		0x00,
	};
	uint8_t enc_ciphertext[400] = {
		0x00,
	};
	uint32_t msglen = 0;
	uint32_t count = 0;
    CipherManager CM;
	char *PT = NULL;

	int key_size = 0; //! max = 3 : 128 0, 192 1, 256 2

	for (key_size = 0; key_size < 3; key_size++)
	{
		if (key_size == 0)
		{
			fp_src = fopen("testvector_req/ARIA128(ECB)KAT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA128(ECB)KAT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 276;
		}
		else if (key_size == 1)
		{
			fp_src = fopen("testvector_req/ARIA192(ECB)KAT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA192(ECB)KAT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 338;
		}
		else
		{
			fp_src = fopen("testvector_req/ARIA256(ECB)KAT.req", "r");
			fp_dst = fopen("testvector_rsp/ARIA256(ECB)KAT.rsp", "w");
			assert(fp_src != NULL);
			assert(fp_dst != NULL);
			num_count = 400;
		}

		//! Reading 128 : 828/3 = 276, 1014/3 = 338,  1200/3 = 400
		for (cnt_i = 0; cnt_i < num_count; cnt_i++)
		{
			memset(temp, 0x00, sizeof(temp));
			memset(buf_msg, 0x00, sizeof(buf_msg));
			memset(buf_key, 0x00, sizeof(buf_key));
			memset(buf_ciphertext, 0x00, sizeof(buf_ciphertext));
			memset(enc_ciphertext, 0x00, sizeof(enc_ciphertext));

			fscanf(fp_src, "%s = ", temp);	//Reading "KEY = "
			fprintf(fp_dst, "%s = ", temp); //writing "KEY = "

			for (cnt_j = 0; cnt_j < 16 + key_size * 8; cnt_j++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_j]);
				fprintf(fp_dst, "%02X", temp[cnt_j]);
				buf_key[cnt_j] = temp[cnt_j];
			}
			fputs("\n", fp_dst); // Writing "/n"
			memset(temp, 0x00, sizeof(temp));

			fscanf(fp_src, "%s = ", temp);	//Reading "PT = "
			fprintf(fp_dst, "%s = ", temp); //Writing "PT = "
			for (cnt_j = 0; cnt_j < 16; cnt_j++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_j]);
				fprintf(fp_dst, "%02X", temp[cnt_j]);
				buf_msg[cnt_j] = temp[cnt_j];
			}
			fputs("\n", fp_dst); // Writing "/n"
			memset(temp, 0x00, sizeof(temp));

			if (key_size == 0)
			{
				//! Enc 128 ECB KAT
				YBCrypto_BlockCipher(&CM, ARIA, ECB_MODE, ENCRYPT,buf_key,128,buf_msg,16, NULL, enc_ciphertext);
			}
			else if (key_size == 1)
			{
				//! Enc 192 ECB KAT
				YBCrypto_BlockCipher(&CM, ARIA, ECB_MODE, ENCRYPT,buf_key,192,buf_msg,16, NULL, enc_ciphertext);
			}
			else
			{
				//! Enc 256 ECB KAT
				YBCrypto_BlockCipher(&CM, ARIA, ECB_MODE, ENCRYPT,buf_key,256,buf_msg,16, NULL, enc_ciphertext);
			}

			fprintf(fp_dst, "CT = "); //Writing "CT = "
			for (cnt_j = 0; cnt_j < 16; cnt_j++)
			{
				fprintf(fp_dst, "%02X", enc_ciphertext[cnt_j]);
			}
			fputs("\n", fp_dst); // Writing "/n"

            fgetc(fp_src);
			// fget(temp, sizeof(temp), fp_src); // Reading "/n"
			fputs("\n", fp_dst);			   // Writing "/n"

			memset(enc_ciphertext, 0x00, sizeof(enc_ciphertext));

			memset(buf_key, 0x00, sizeof(buf_key));
			memset(buf_msg, 0x00, sizeof(buf_msg));
		}

		fclose(fp_src);
		fclose(fp_dst);
	}
}