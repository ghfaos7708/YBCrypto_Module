#include "YBCrypto.h"
#include "api.h"
#include "assert.h"

void SHA256_MCT()
{
	FILE *fp_src = NULL, *fp_dst = NULL;
	uint8_t temp[20000] = {0x00};
	uint8_t buf_msg[20000] = {0x00};
	uint8_t MI[200] = {0x00};
	uint8_t MD[1200][100] = {
		{0x00},
	};
	uint8_t **ptr = NULL;
	uint8_t read_hash_digeset256[32] = {
		0x00,
	};
	uint8_t cal_hash_digeset256[32] = {
		0x00,
	};
	uint32_t msgbit_len = 0;
	uint32_t cnt_i = 0, cnt_j = 0, cnt_k = 0;
	HashManager HM;

	fp_src = fopen("testvector_req/SHA2(256)Monte.req", "r");
	fp_dst = fopen("testvector_rsp/SHA2(256)Monte.rsp", "w");
	assert(fp_src != NULL);

	//! Reading
	fgets((char *)buf_msg, sizeof(buf_msg), fp_src); // Reading "L = 32"
	fprintf(fp_dst, "%s", "L = 32\n");		 //Writing "L = 32"

	fgets((char *)buf_msg, sizeof(buf_msg), fp_src); // Reading "/n"
	fputs("\n", fp_dst);					 // Writing "/n"

	fscanf(fp_src, "%s = ", buf_msg); //Reading "Seed = "
	fprintf(fp_dst, "Seed = ");		  //Writing "Seed = "

	for (cnt_i = 0; cnt_i < 32; cnt_i++) //Reading "Msg"
	{
		fscanf(fp_src, "%02hhX", &temp[cnt_i]);
		fprintf(fp_dst, "%02X", temp[cnt_i]);
		buf_msg[cnt_i] = temp[cnt_i];
	}
	fputs("\n\n", fp_dst); // Writing "/n"

	for (cnt_i = 0; cnt_i < 100; cnt_i++) //65
	{
		memcpy(MD[0], buf_msg, 32);
		memcpy(MD[1], buf_msg, 32);
		memcpy(MD[2], buf_msg, 32);

		for (cnt_j = 3; cnt_j < 1003; cnt_j++)
		{
			for (cnt_k = 0; cnt_k < 32; cnt_k++)
			{
				MI[cnt_k] = MD[cnt_j - 3][cnt_k];
				MI[cnt_k + 32] = MD[cnt_j - 2][cnt_k];
				MI[cnt_k + 64] = MD[cnt_j - 1][cnt_k];
			}

			//! Hashing
			YBCrypto_Hash(&HM,SHA256,MI, 96, MD[cnt_j]);
		}

		memcpy(buf_msg, MD[1002], 32);

		fprintf(fp_dst, "COUNT = %d\n", cnt_i); //Writing "Seed = "
		fprintf(fp_dst, "MD = ");				//Writing "MD = "

		for (cnt_j = 0; cnt_j < 32; cnt_j++) //Writing "MD"
		{
			fprintf(fp_dst, "%02X", buf_msg[cnt_j]);
		}
		fputs("\n\n", fp_dst); // Writing "/n"
	}

	fclose(fp_src);
	fclose(fp_dst);
}

void SHA256_SHORT_LONG()
{
	FILE *fp_src = NULL, *fp_dst = NULL;
	uint8_t temp[20000] = {0x00};
	uint8_t buf_msg[20000] = {0x00};
	uint8_t **ptr = NULL;
	uint8_t read_hash_digeset256[32] = {
		0x00,
	};
	uint8_t cal_hash_digeset256[32] = {
		0x00,
	};
	uint32_t msgbit_len = 0;
	uint32_t cnt_i = 0, cnt_j = 0;
	HashManager HM;

	//TODO SHA2(256)ShortMsg Test //////////////////////////////////////////////////////////////////////////////////////////////////////////////
	fp_src = fopen("testvector_req/SHA2(256)ShortMsg.req", "r");
	fp_dst = fopen("testvector_rsp/SHA2(256)ShortMsg.rsp", "w");
	assert(fp_src != NULL);

	//! Reading
	fgets((char *)buf_msg, sizeof(buf_msg), fp_src); // Reading "L = 32"
	fprintf(fp_dst, "%s", "L = 32\n");		 //Writing "L = 32"

	for (cnt_j = 0; cnt_j < 65; cnt_j++) //65
	{
		// fgets(buf_msg, sizeof(buf_msg), fp_src); // Reading "/n"
		fgetc(fp_src);
		fputs("\n", fp_dst);					 // Writing "/n"

		fscanf(fp_src, "%s = %d", buf_msg, &msgbit_len); //Reading "Len = %d"
		fprintf(fp_dst, "Len = %d\n", msgbit_len);		 //Writing "Len = %d"

		fscanf(fp_src, "%s = ", buf_msg); //Reading "Msg = "
		fprintf(fp_dst, "Msg = ");		  //Writing "Len = %d"
		memset(buf_msg, 0x00, sizeof(buf_msg));

		if (msgbit_len == 0)
		{
			fscanf(fp_src, "%02hhX", &temp[cnt_i]);
			fprintf(fp_dst, "%02X", temp[cnt_i]);
			buf_msg[cnt_i] = temp[cnt_i];
			fputs("\n", fp_dst); // Writing "/n"
		}
		else
		{
			for (cnt_i = 0; cnt_i < msgbit_len / 8; cnt_i++) //Reading "Msg"
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_i]);
				fprintf(fp_dst, "%02X", temp[cnt_i]);
				buf_msg[cnt_i] = temp[cnt_i];
			}
			fputs("\n", fp_dst); // Writing "/n"
		}

		fprintf(fp_dst, "MD = "); //Writing "MD = "

		//! Hashing
		YBCrypto_Hash(&HM,SHA256,buf_msg, msgbit_len / 8, cal_hash_digeset256);

		for (cnt_i = 0; cnt_i < 32; cnt_i++) //Reading "Hash Digest"
		{
			fprintf(fp_dst, "%02X", cal_hash_digeset256[cnt_i]);
		}
		fputs("\n", fp_dst); // Writing "/n"

		memset(buf_msg, 0x00, sizeof(buf_msg));
		memset(cal_hash_digeset256, 0x00, sizeof(cal_hash_digeset256));
		msgbit_len = 0;
	}
	fclose(fp_src);
	fclose(fp_dst);

	//TODO SHA2(256)LongMsg Test //////////////////////////////////////////////////////////////////////////////////////////////////////////////
	fp_src = fopen("testvector_req/SHA2(256)LongMsg.req", "r");
	fp_dst = fopen("testvector_rsp/SHA2(256)LongMsg.rsp", "w");
	assert(fp_src != NULL);

	//! Reading
	fgets((char *)buf_msg, sizeof(buf_msg), fp_src); // Reading "L = 32"
	fprintf(fp_dst, "%s", "L = 32\n");		 //Writing "L = 32"

	for (cnt_j = 0; cnt_j < 64; cnt_j++) //65
	{
		// fgets(buf_msg, sizeof(buf_msg), fp_src); // Reading "/n"
		fgetc(fp_src);
		fputs("\n", fp_dst);					 // Writing "/n"

		fscanf(fp_src, "%s = %d", buf_msg, &msgbit_len); //Reading "Len = %d"
		fprintf(fp_dst, "Len = %d\n", msgbit_len);		 //Writing "Len = %d"

		fscanf(fp_src, "%s = ", buf_msg); //Reading "Msg = "
		fprintf(fp_dst, "Msg = ");		  //Writing "Len = %d"
		memset(buf_msg, 0x00, sizeof(buf_msg));

		if (msgbit_len == 0)
		{
			fscanf(fp_src, "%02hhX", &temp[cnt_i]);
			fprintf(fp_dst, "%02X", temp[cnt_i]);
			buf_msg[cnt_i] = temp[cnt_i];
			fputs("\n", fp_dst); // Writing "/n"
		}
		else
		{
			for (cnt_i = 0; cnt_i < msgbit_len / 8; cnt_i++) //Reading "Msg"
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_i]);
				fprintf(fp_dst, "%02X", temp[cnt_i]);
				buf_msg[cnt_i] = temp[cnt_i];
			}
			fputs("\n", fp_dst); // Writing "/n"
		}

		fprintf(fp_dst, "MD = "); //Writing "MD = "

		//! Hashing
		YBCrypto_Hash(&HM,SHA256,buf_msg, msgbit_len / 8, cal_hash_digeset256);

		for (cnt_i = 0; cnt_i < 32; cnt_i++) //Reading "Hash Digest"
		{
			fprintf(fp_dst, "%02X", cal_hash_digeset256[cnt_i]);
		}
		fputs("\n", fp_dst); // Writing "/n"

		memset(buf_msg, 0x00, sizeof(buf_msg));
		memset(cal_hash_digeset256, 0x00, sizeof(cal_hash_digeset256));
		msgbit_len = 0;
	}
	fclose(fp_src);
	fclose(fp_dst);
}