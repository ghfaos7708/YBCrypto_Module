#include "YBCrypto.h"
#include "api.h"
#include "assert.h"

void ARIA_CTR_DRBG_NDF_NPR()
{
	FILE *fp_src = NULL, *fp_dst = NULL;
	uint8_t entropyInput[500] = {0};
	uint8_t entropyReseed[500] = {0};
	uint8_t entropy1[500] = {0};
	uint8_t entropy2[500] = {0};
	uint8_t nonce[500] = {0};
	uint8_t pString[500] = {0};
	uint8_t addInputReseed[500] = {0};
	uint8_t addInput1[500] = {0};
	uint8_t addInput2[500] = {0};
	uint8_t rand1[500] = {0};
	uint8_t rand2[500] = {0};
	uint8_t temp[10000] = {0};
	uint8_t temp1[10000] = {0};
	uint8_t temp2[10000] = {0};
	uint8_t buf[1000] = {0};
	char string[20];

	int cnt_i = 0, cnt_j = 0, cnt_k = 0;
	int count = 0;
	int entropyInputLen = 0;
	int entropyReseedLen = 0;
	int addInputReseedLen = 0;
	int entropy1_Len = 0;
	int entropy2_Len = 0;
	int addInput1Len = 0;
	int addInput2Len = 0;
	int pStringLen = 0;
	int nonceLen = 0;
	int KATLen = 0;
	int ret = 0;

	int lp = 0x00;
	DRBGManager DM;

	fp_src = fopen("testvector_req/CTR_DRBG(ARIA-128(no DF)(no PR))_KAT.req", "r");
	fp_dst = fopen("testvector_rsp/CTR_DRBG(ARIA-128(no DF)(no PR))_KAT.rsp", "w");
	assert(fp_src != NULL);

	for (cnt_i = 0; cnt_i < 4; cnt_i++)
	{

		//!Reading option
		memset(temp, 0x00, sizeof(temp));

		fgets((char *)temp, sizeof(temp), fp_src); // [ARIA-128 use DF]
		fprintf(fp_dst, "[ARIA-128 no DF]\n");
		fgets((char *)temp, sizeof(temp), fp_src); // [PredictionResistance = TRUE]
		fprintf(fp_dst, "[PredictionResistance = FALSE]\n");

		fgets((char *)temp, 19, fp_src); // [EntropyInputLen =
		fscanf(fp_src, "%d]\n", &entropyInputLen);
		fprintf(fp_dst, "[EntropyInputLen = %d]\n", entropyInputLen);

		fgets((char *)temp, 12, fp_src); // [nonceLen =
		fscanf(fp_src, "%d]\n", &nonceLen);
		fprintf(fp_dst, "[NonceLen = %d]\n", nonceLen);

		fgets((char *)temp, 29, fp_src); // [PersonalizationStringLe =
		fscanf(fp_src, "%d]\n", &pStringLen);
		fprintf(fp_dst, "[PersonalizationStringLen = %d]\n", pStringLen);

		fgets((char *)temp, 22, fp_src); // [AdditionalInputLen =
		fscanf(fp_src, "%d]\n", &addInputReseedLen);
		addInput1Len = addInputReseedLen;
		addInput2Len = addInputReseedLen;
		fprintf(fp_dst, "[AdditionalInputLen = %d]\n", addInput1Len);

		fgets((char *)temp, 20, fp_src); // [ReturnedBitsLen =
		fscanf(fp_src, "%d]\n\n", &lp);
		fprintf(fp_dst, "[ReturnedBitsLen = %d]\n\n", lp);

		entropyReseedLen = entropyInputLen;
		entropy2_Len = entropyInputLen;

		for (cnt_j = 0; cnt_j < 15; cnt_j++)
		{
			fgets((char *)temp, 9, fp_src); // COUNT =
			fscanf(fp_src, "%d\n", &count);
			fprintf(fp_dst, "COUNT = %d\n", count); //Writing "COUNT = "

			// EntropyInput
			fgets((char *)temp, 15, fp_src);			// EntropyInput =
			fprintf(fp_dst, "EntropyInput = "); //Writing "EntropyInput =
			for (cnt_k = 0; cnt_k < entropyInputLen / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				entropyInput[cnt_k] = temp[cnt_k];
			}
			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			// Personal
			fgets((char *)temp, 24, fp_src);					 // PersonalizationString =
			fprintf(fp_dst, "PersonalizationString = "); //Writing "PersonalizationString =
			for (cnt_k = 0; cnt_k < pStringLen / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				pString[cnt_k] = temp[cnt_k];
			}
			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			// EntropyInputReseed =
			fgets((char *)temp, 21, fp_src);				  // EntropyInputReseed =
			fprintf(fp_dst, "EntropyInputReseed = "); //Writing "EntropyInputReseed =
			for (cnt_k = 0; cnt_k < entropyReseedLen / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				entropyReseed[cnt_k] = temp[cnt_k];
			}
			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			// AdditionalInputReseed =
			fgets((char *)temp, 24, fp_src);					 // AdditionalInput =
			fprintf(fp_dst, "AdditionalInputReseed = "); //Writing "AdditionalInput =
			for (cnt_k = 0; cnt_k < addInput1Len / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				addInputReseed[cnt_k] = temp[cnt_k];
			}
			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			// AdditionalInput =
			fgets((char *)temp, 18, fp_src);			   // AdditionalInput =
			fprintf(fp_dst, "AdditionalInput = "); //Writing "AdditionalInput =
			for (cnt_k = 0; cnt_k < addInput1Len / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				addInput1[cnt_k] = temp[cnt_k];
			}
			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			// AdditionalInput =
			fgets((char *)temp, 18, fp_src);			   // AdditionalInput =
			fprintf(fp_dst, "AdditionalInput = "); //Writing "AdditionalInput =
			for (cnt_k = 0; cnt_k < addInput2Len / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				addInput2[cnt_k] = temp[cnt_k];
			}

			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			YBCrypto_CTR_DRBG_Instantiate(&DM, ARIA, 128, entropyInput, entropyInputLen / 8, NULL, 0, pString, pStringLen / 8, NO_DF);
			YBCrypto_CTR_DRBG_Reseed(&DM, entropyReseed, entropyReseedLen / 8, addInputReseed, addInputReseedLen / 8);
			YBCrypto_CTR_DRBG_Generate(&DM,rand1, 1024, NULL, 0, addInput1, addInput1Len / 8, NO_PR);
			YBCrypto_CTR_DRBG_Generate(&DM,rand2, 1024, NULL, 0, addInput2, addInput2Len / 8, NO_PR);

			fprintf(fp_dst, "ReturnedBits = "); //Writing "ReturnedBits =
			for (cnt_k = 0; cnt_k < 1024 / 8; cnt_k++)
			{
				fprintf(fp_dst, "%02X", rand2[cnt_k]);
			}

			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n\n");		   // \n
		}
	}
	fclose(fp_src);
	fclose(fp_dst);
}

void ARIA_CTR_DRBG_UDF_NPR()
{
	FILE *fp_src = NULL, *fp_dst = NULL;
	uint8_t entropyInput[500] = {0};
	uint8_t entropyReseed[500] = {0};
	uint8_t entropy1[500] = {0};
	uint8_t entropy2[500] = {0};
	uint8_t nonce[500] = {0};
	uint8_t pString[500] = {0};
	uint8_t addInputReseed[500] = {0};
	uint8_t addInput1[500] = {0};
	uint8_t addInput2[500] = {0};
	uint8_t rand1[500] = {0};
	uint8_t rand2[500] = {0};
	uint8_t temp[10000] = {0};
	uint8_t temp1[10000] = {0};
	uint8_t temp2[10000] = {0};
	uint8_t buf[1000] = {0};
	char string[20];

	int cnt_i = 0, cnt_j = 0, cnt_k = 0;
	int count = 0;
	int entropyInputLen = 0;
	int entropyReseedLen = 0;
	int addInputReseedLen = 0;
	int entropy1_Len = 0;
	int entropy2_Len = 0;
	int addInput1Len = 0;
	int addInput2Len = 0;
	int pStringLen = 0;
	int nonceLen = 0;
	int KATLen = 0;
	int ret = 0;

	int lp = 0x00;
	DRBGManager DM;

	fp_src = fopen("testvector_req/CTR_DRBG(ARIA-128(use DF)(no PR))_KAT.req", "r");
	fp_dst = fopen("testvector_rsp/CTR_DRBG(ARIA-128(use DF)(no PR))_KAT.rsp", "w");
	assert(fp_src != NULL);

	for (cnt_i = 0; cnt_i < 4; cnt_i++)
	{

		//!Reading option
		memset(temp, 0x00, sizeof(temp));

		fgets((char *)temp, sizeof(temp), fp_src); // [ARIA-128 use DF]
		fprintf(fp_dst, "[ARIA-128 use DF]\n");
		fgets((char *)temp, sizeof(temp), fp_src); // [PredictionResistance = TRUE]
		fprintf(fp_dst, "[PredictionResistance = FALSE]\n");

		fgets((char *)temp, 19, fp_src); // [EntropyInputLen =
		fscanf(fp_src, "%d]\n", &entropyInputLen);
		fprintf(fp_dst, "[EntropyInputLen = %d]\n", entropyInputLen);

		fgets((char *)temp, 12, fp_src); // [nonceLen =
		fscanf(fp_src, "%d]\n", &nonceLen);
		fprintf(fp_dst, "[NonceLen = %d]\n", nonceLen);

		fgets((char *)temp, 29, fp_src); // [PersonalizationStringLe =
		fscanf(fp_src, "%d]\n", &pStringLen);
		fprintf(fp_dst, "[PersonalizationStringLen = %d]\n", pStringLen);

		fgets((char *)temp, 22, fp_src); // [AdditionalInputLen =
		fscanf(fp_src, "%d]\n", &addInputReseedLen);
		addInput1Len = addInputReseedLen;
		addInput2Len = addInputReseedLen;
		fprintf(fp_dst, "[AdditionalInputLen = %d]\n", addInput1Len);

		fgets((char *)temp, 20, fp_src); // [ReturnedBitsLen =
		fscanf(fp_src, "%d]\n\n", &lp);
		fprintf(fp_dst, "[ReturnedBitsLen = %d]\n\n", lp);

		entropyReseedLen = entropyInputLen;
		entropy2_Len = entropyInputLen;

		for (cnt_j = 0; cnt_j < 15; cnt_j++)
		{
			fgets((char *)temp, 9, fp_src); // COUNT =
			fscanf(fp_src, "%d\n", &count);
			fprintf(fp_dst, "COUNT = %d\n", count); //Writing "COUNT = "

			// EntropyInput
			fgets((char *)temp, 15, fp_src);			// EntropyInput =
			fprintf(fp_dst, "EntropyInput = "); //Writing "EntropyInput =
			for (cnt_k = 0; cnt_k < entropyInputLen / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				entropyInput[cnt_k] = temp[cnt_k];
			}
			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			// Nonce
			fgets((char *)temp, 8, fp_src);					 // Nonce =
			fprintf(fp_dst, "Nonce = "); //Writing "Nonce =
			for (cnt_k = 0; cnt_k < nonceLen / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				nonce[cnt_k] = temp[cnt_k];
			}
			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			// Personal
			fgets((char *)temp, 24, fp_src);					 // PersonalizationString =
			fprintf(fp_dst, "PersonalizationString = "); //Writing "PersonalizationString =
			for (cnt_k = 0; cnt_k < pStringLen / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				pString[cnt_k] = temp[cnt_k];
			}
			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			// EntropyInputReseed =
			fgets((char *)temp, 21, fp_src);				  // EntropyInputReseed =
			fprintf(fp_dst, "EntropyInputReseed = "); //Writing "EntropyInputReseed =
			for (cnt_k = 0; cnt_k < entropyReseedLen / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				entropyReseed[cnt_k] = temp[cnt_k];
			}
			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			// AdditionalInputReseed =
			fgets((char *)temp, 24, fp_src);					 // AdditionalInput =
			fprintf(fp_dst, "AdditionalInputReseed = "); //Writing "AdditionalInput =
			for (cnt_k = 0; cnt_k < addInput1Len / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				addInputReseed[cnt_k] = temp[cnt_k];
			}
			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			// AdditionalInput =
			fgets((char *)temp, 18, fp_src);			   // AdditionalInput =
			fprintf(fp_dst, "AdditionalInput = "); //Writing "AdditionalInput =
			for (cnt_k = 0; cnt_k < addInput1Len / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				addInput1[cnt_k] = temp[cnt_k];
			}
			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			// AdditionalInput =
			fgets((char *)temp, 18, fp_src);			   // AdditionalInput =
			fprintf(fp_dst, "AdditionalInput = "); //Writing "AdditionalInput =
			for (cnt_k = 0; cnt_k < addInput2Len / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				addInput2[cnt_k] = temp[cnt_k];
			}

			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			YBCrypto_CTR_DRBG_Instantiate(&DM, ARIA, 128, entropyInput, entropyInputLen / 8, nonce, nonceLen/8, pString, pStringLen / 8, USE_DF);
			YBCrypto_CTR_DRBG_Reseed(&DM, entropyReseed, entropyReseedLen / 8, addInputReseed, addInputReseedLen / 8);
			YBCrypto_CTR_DRBG_Generate(&DM,rand1, 1024, NULL, 0, addInput1, addInput1Len / 8, NO_PR);
			YBCrypto_CTR_DRBG_Generate(&DM,rand2, 1024, NULL, 0, addInput2, addInput2Len / 8, NO_PR);

			fprintf(fp_dst, "ReturnedBits = "); //Writing "ReturnedBits =
			for (cnt_k = 0; cnt_k < 1024 / 8; cnt_k++)
			{
				fprintf(fp_dst, "%02X", rand2[cnt_k]);
			}

			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n\n");		   // \n
		}
	}
	fclose(fp_src);
	fclose(fp_dst);
}

void ARIA_CTR_DRBG_NDF_UPR()
{
	FILE *fp_src = NULL, *fp_dst = NULL;
	uint8_t entropyInput[500] = {0};
	uint8_t entropyReseed[500] = {0};
	uint8_t entropy1[500] = {0};
	uint8_t entropy2[500] = {0};
	uint8_t nonce[500] = {0};
	uint8_t pString[500] = {0};
	uint8_t addInputReseed[500] = {0};
	uint8_t addInput1[500] = {0};
	uint8_t addInput2[500] = {0};
	uint8_t rand1[500] = {0};
	uint8_t rand2[500] = {0};
	uint8_t temp[10000] = {0};
	uint8_t temp1[10000] = {0};
	uint8_t temp2[10000] = {0};
	uint8_t buf[1000] = {0};
	char string[20];

	int cnt_i = 0, cnt_j = 0, cnt_k = 0;
	int count = 0;
	int entropyInputLen = 0;
	int entropyReseedLen = 0;
	int addInputReseedLen = 0;
	int entropy1_Len = 0;
	int entropy2_Len = 0;
	int addInput1Len = 0;
	int addInput2Len = 0;
	int pStringLen = 0;
	int nonceLen = 0;
	int KATLen = 0;
	int ret = 0;
	DRBGManager DM;

	int lp = 0x00;

	fp_src = fopen("testvector_req/CTR_DRBG(ARIA-128(no DF)(use PR))_KAT.req", "r");
	fp_dst = fopen("testvector_rsp/CTR_DRBG(ARIA-128(no DF)(use PR))_KAT.rsp", "w");
	assert(fp_src != NULL);

	for (cnt_i = 0; cnt_i < 4; cnt_i++)
	{

		//!Reading option
		memset(temp, 0x00, sizeof(temp));

		fgets((char *)temp, sizeof(temp), fp_src); // [ARIA-128 use DF]
		fprintf(fp_dst, "[ARIA-128 no DF]\n");
		fgets((char *)temp, sizeof(temp), fp_src); // [PredictionResistance = TRUE]
		fprintf(fp_dst, "[PredictionResistance = TRUE]\n");

		fgets((char *)temp, 19, fp_src); // [EntropyInputLen =
		fscanf(fp_src, "%d]\n", &entropyInputLen);
		fprintf(fp_dst, "[EntropyInputLen = %d]\n", entropyInputLen);

		fgets((char *)temp, 12, fp_src); // [nonceLen =
		fscanf(fp_src, "%d]\n", &nonceLen);
		fprintf(fp_dst, "[NonceLen = %d]\n", nonceLen);

		fgets((char *)temp, 29, fp_src); // [NPersonalizationStringLe =
		fscanf(fp_src, "%d]\n", &pStringLen);
		fprintf(fp_dst, "[PersonalizationStringLen = %d]\n", pStringLen);

		fgets((char *)temp, 22, fp_src); // [AdditionalInputLen =
		fscanf(fp_src, "%d]\n", &addInput1Len);
		addInput2Len = addInput1Len;
		fprintf(fp_dst, "[AdditionalInputLen = %d]\n", addInput1Len);

		fgets((char *)temp, 20, fp_src); // [ReturnedBitsLen =
		fscanf(fp_src, "%d]\n\n", &lp);
		fprintf(fp_dst, "[ReturnedBitsLen = %d]\n\n", lp);

		entropy1_Len = entropyInputLen;
		entropy2_Len = entropyInputLen;

		for (cnt_j = 0; cnt_j < 15; cnt_j++)
		{
			fgets((char *)temp, 9, fp_src); // COUNT =
			fscanf(fp_src, "%d\n", &count);
			fprintf(fp_dst, "COUNT = %d\n", count); //Writing "COUNT = "

			// EntropyInput
			fgets((char *)temp, 15, fp_src);			// EntropyInput =
			fprintf(fp_dst, "EntropyInput = "); //Writing "EntropyInput =
			for (cnt_k = 0; cnt_k < entropyInputLen / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				entropyInput[cnt_k] = temp[cnt_k];
			}
			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			// Personal
			fgets((char *)temp, 24, fp_src);					 // PersonalizationString =
			fprintf(fp_dst, "PersonalizationString = "); //Writing "PersonalizationString =
			for (cnt_k = 0; cnt_k < pStringLen / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				pString[cnt_k] = temp[cnt_k];
			}
			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			// EntropyInputPR =
			fgets((char *)temp, 17, fp_src);			  // EntropyInputPR =
			fprintf(fp_dst, "EntropyInputPR = "); //Writing "EntropyInputPR =
			for (cnt_k = 0; cnt_k < entropyInputLen / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				entropy1[cnt_k] = temp[cnt_k];
			}
			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			// AdditionalInput =
			fgets((char *)temp, 18, fp_src);			   // AdditionalInput =
			fprintf(fp_dst, "AdditionalInput = "); //Writing "AdditionalInput =
			for (cnt_k = 0; cnt_k < addInput1Len / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				addInput1[cnt_k] = temp[cnt_k];
			}
			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			// EntropyInputPR =
			fgets((char *)temp, 17, fp_src);			  // EntropyInputPR =
			fprintf(fp_dst, "EntropyInputPR = "); //Writing "EntropyInputPR =
			for (cnt_k = 0; cnt_k < entropyInputLen / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				entropy2[cnt_k] = temp[cnt_k];
			}
			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			// AdditionalInput =
			fgets((char *)temp, 18, fp_src);			   // AdditionalInput =
			fprintf(fp_dst, "AdditionalInput = "); //Writing "AdditionalInput =
			for (cnt_k = 0; cnt_k < addInput1Len / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				addInput2[cnt_k] = temp[cnt_k];
			}

			YBCrypto_CTR_DRBG_Instantiate(&DM, ARIA, 128, entropyInput, entropyInputLen / 8, NULL, 0, pString, pStringLen / 8, NO_DF);
			YBCrypto_CTR_DRBG_Generate(&DM,rand1, 1024, entropy1, entropy1_Len / 8, addInput1, addInput1Len / 8, USE_PR);
			YBCrypto_CTR_DRBG_Generate(&DM,rand2, 1024, entropy2, entropy2_Len / 8, addInput2, addInput2Len / 8, USE_PR);

			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			fprintf(fp_dst, "ReturnedBits = "); //Writing "ReturnedBits =
			for (cnt_k = 0; cnt_k < 1024 / 8; cnt_k++)
			{
				fprintf(fp_dst, "%02X", rand2[cnt_k]);
			}

			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n\n");		   // \n
		}
	}
	fclose(fp_src);
	fclose(fp_dst);
}


void ARIA_CTR_DRBG_UDF_UPR()
{
	FILE *fp_src = NULL, *fp_dst = NULL;
	uint8_t entropyInput[500] = {0};
	uint8_t entropyReseed[500] = {0};
	uint8_t entropy1[500] = {0};
	uint8_t entropy2[500] = {0};
	uint8_t nonce[500] = {0};
	uint8_t pString[500] = {0};
	uint8_t addInputReseed[500] = {0};
	uint8_t addInput1[500] = {0};
	uint8_t addInput2[500] = {0};
	uint8_t rand1[500] = {0};
	uint8_t rand2[500] = {0};
	uint8_t temp[10000] = {0};
	uint8_t temp1[10000] = {0};
	uint8_t temp2[10000] = {0};
	uint8_t buf[1000] = {0};
	char string[20];

	int cnt_i = 0, cnt_j = 0, cnt_k = 0;
	int count = 0;
	int entropyInputLen = 0;
	int entropyReseedLen = 0;
	int addInputReseedLen = 0;
	int entropy1_Len = 0;
	int entropy2_Len = 0;
	int addInput1Len = 0;
	int addInput2Len = 0;
	int pStringLen = 0;
	int nonceLen = 0;
	int KATLen = 0;
	int ret = 0;

	int lp = 0x00;
	DRBGManager DM;

	fp_src = fopen("testvector_req/CTR_DRBG(ARIA-128(use DF)(use PR))_KAT.req", "r");
	fp_dst = fopen("testvector_rsp/CTR_DRBG(ARIA-128(use DF)(use PR))_KAT.rsp", "w");
	assert(fp_src != NULL);

	for (cnt_i = 0; cnt_i < 4; cnt_i++)
	{

		//!Reading option
		memset(temp, 0x00, sizeof(temp));

		fgets((char *)temp, sizeof(temp), fp_src); // [ARIA-128 use DF]
		fprintf(fp_dst, "[ARIA-128 use DF]\n");
		fgets((char *)temp, sizeof(temp), fp_src); // [PredictionResistance = TRUE]
		fprintf(fp_dst, "[PredictionResistance = TRUE]\n");

		fgets((char *)temp, 19, fp_src); // [EntropyInputLen =
		fscanf(fp_src, "%d]\n", &entropyInputLen);
		fprintf(fp_dst, "[EntropyInputLen = %d]\n", entropyInputLen);

		fgets((char *)temp, 12, fp_src); // [nonceLen =
		fscanf(fp_src, "%d]\n", &nonceLen);
		fprintf(fp_dst, "[NonceLen = %d]\n", nonceLen);

		fgets((char *)temp, 29, fp_src); // [NPersonalizationStringLe =
		fscanf(fp_src, "%d]\n", &pStringLen);
		fprintf(fp_dst, "[PersonalizationStringLen = %d]\n", pStringLen);

		fgets((char *)temp, 22, fp_src); // [AdditionalInputLen =
		fscanf(fp_src, "%d]\n", &addInput1Len);
		addInput2Len = addInput1Len;
		fprintf(fp_dst, "[AdditionalInputLen = %d]\n", addInput1Len);

		fgets((char *)temp, 20, fp_src); // [ReturnedBitsLen =
		fscanf(fp_src, "%d]\n\n", &lp);
		fprintf(fp_dst, "[ReturnedBitsLen = %d]\n\n", lp);

		entropy1_Len = entropyInputLen;
		entropy2_Len = entropyInputLen;

		for (cnt_j = 0; cnt_j < 15; cnt_j++)
		{
			fgets((char *)temp, 9, fp_src); // COUNT =
			fscanf(fp_src, "%d\n", &count);
			fprintf(fp_dst, "COUNT = %d\n", count); //Writing "COUNT = "

			// EntropyInput
			fgets((char *)temp, 15, fp_src);			// EntropyInput =
			fprintf(fp_dst, "EntropyInput = "); //Writing "EntropyInput =
			for (cnt_k = 0; cnt_k < entropyInputLen / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				entropyInput[cnt_k] = temp[cnt_k];
			}
			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			// Nonce
			fgets((char *)temp, 8, fp_src);		 // Nonce =  =
			fprintf(fp_dst, "Nonce = "); //Writing "Nonce =
			for (cnt_k = 0; cnt_k < nonceLen / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				nonce[cnt_k] = temp[cnt_k];
			}
			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			// Personal
			fgets((char *)temp, 24, fp_src);					 // PersonalizationString =
			fprintf(fp_dst, "PersonalizationString = "); //Writing "PersonalizationString =
			for (cnt_k = 0; cnt_k < pStringLen / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				pString[cnt_k] = temp[cnt_k];
			}
			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			// EntropyInputPR =
			fgets((char *)temp, 17, fp_src);			  // EntropyInputPR =
			fprintf(fp_dst, "EntropyInputPR = "); //Writing "EntropyInputPR =
			for (cnt_k = 0; cnt_k < entropyInputLen / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				entropy1[cnt_k] = temp[cnt_k];
			}
			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			// AdditionalInput =
			fgets((char *)temp, 18, fp_src);			   // AdditionalInput =
			fprintf(fp_dst, "AdditionalInput = "); //Writing "AdditionalInput =
			for (cnt_k = 0; cnt_k < addInput1Len / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				addInput1[cnt_k] = temp[cnt_k];
			}
			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			// EntropyInputPR =
			fgets((char *)temp, 17, fp_src);			  // EntropyInputPR =
			fprintf(fp_dst, "EntropyInputPR = "); //Writing "EntropyInputPR =
			for (cnt_k = 0; cnt_k < entropyInputLen / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				entropy2[cnt_k] = temp[cnt_k];
			}
			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			// AdditionalInput =
			fgets((char *)temp, 18, fp_src);			   // AdditionalInput =
			fprintf(fp_dst, "AdditionalInput = "); //Writing "AdditionalInput =
			for (cnt_k = 0; cnt_k < addInput1Len / 8; cnt_k++)
			{
				fscanf(fp_src, "%02hhX", &temp[cnt_k]);
				fprintf(fp_dst, "%02X", temp[cnt_k]);
				addInput2[cnt_k] = temp[cnt_k];
			}

			YBCrypto_CTR_DRBG_Instantiate(&DM, ARIA, 128, entropyInput, entropyInputLen / 8, nonce, nonceLen / 8, pString, pStringLen / 8, USE_DF);
			YBCrypto_CTR_DRBG_Generate(&DM,rand1, 1024, entropy1, entropy1_Len / 8, addInput1, addInput1Len / 8, USE_PR);
			YBCrypto_CTR_DRBG_Generate(&DM,rand2, 1024, entropy2, entropy2_Len / 8, addInput2, addInput2Len / 8, USE_PR);

			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n");			   // \n

			fprintf(fp_dst, "ReturnedBits = "); //Writing "ReturnedBits =
			for (cnt_k = 0; cnt_k < 1024 / 8; cnt_k++)
			{
				fprintf(fp_dst, "%02X", rand2[cnt_k]);
			}

			fgets((char *)temp, sizeof(temp), fp_src); // \n
			fprintf(fp_dst, "\n\n");		   // \n
		}
	}
	fclose(fp_src);
	fclose(fp_dst);
}