#include "YBCrypto.h"
#include "api.h"
#include "assert.h"

void HMAC_SHA256_KAT()
{
	FILE *fp_src = NULL, *fp_dst = NULL;
	uint8_t temp[20000] = {0x00};
	uint8_t buf_msg[20000] = {0x00};
	uint8_t buf_key[2000] = {0x00};
	uint8_t MAC[100] = {
		0x00,
	};
	uint8_t read_hash_digeset256[32] = {
		0x00,
	};
	uint8_t cal_hash_digeset256[32] = {
		0x00,
	};
	int keybyte_len = 0;
	int macbyte_len = 0;
	int cnt_i = 0, cnt_j = 0, cnt_k = 0;
	HMACManager MM;

	fp_src = fopen("testvector_req/HMAC-SHA256.req", "r");
	fp_dst = fopen("testvector_rsp/HMAC-SHA256.rsp", "w");
	assert(fp_src != NULL);

	//! Reading
	fgets((char *) buf_msg, sizeof(buf_msg), fp_src); // Reading "L = 32"
	fprintf(fp_dst, "%s", "L = 32\n");		 //Writing "L = 32"

	fgets((char *) buf_msg, sizeof(buf_msg), fp_src); // Reading "/n"
	fputs("\n", fp_dst);					 // Writing "/n"

	for (cnt_i = 0; cnt_i < 225; cnt_i++)
	{
		memset(buf_msg, 0x00, sizeof(buf_msg));
		memset(temp, 0x00, sizeof(temp));
		memset(buf_key, 0x00, sizeof(buf_key));
		memset(MAC, 0x00, sizeof(MAC));
		keybyte_len = 0;
		macbyte_len = 0;

		fgets((char *)buf_msg, sizeof(buf_msg), fp_src); // Reading "Count = 0"
		fprintf(fp_dst, "COUNT = %d\n", cnt_i);	 //Writing "COUNT = "

		fscanf(fp_src, "%s = %d", buf_msg, &keybyte_len); //Reading "Klen = cont_i"
		fprintf(fp_dst, "Klen = %d\n", keybyte_len);	  //Writing "Klen = "

		fscanf(fp_src, "%s = %d", buf_msg, &macbyte_len);	//Reading "Klen = cont_i"
		fprintf(fp_dst, "%s = %d\n", buf_msg, macbyte_len); //Writing "Klen = "

		fscanf(fp_src, "%s = ", buf_msg); //Reading "Key = "
		fprintf(fp_dst, "Key = ");		  //Writing "Key = "

		for (cnt_j = 0; cnt_j < keybyte_len; cnt_j++) //Reading "KEy"
		{
			fscanf(fp_src, "%02hhX", &temp[cnt_j]);
			fprintf(fp_dst, "%02X", temp[cnt_j]);
			buf_key[cnt_j] = temp[cnt_j];
		}
		fputs("\n", fp_dst); // Writing "/n"

		fscanf(fp_src, "%s = ", buf_msg); //Reading "Msg = "
		fprintf(fp_dst, "Msg = ");		  //Writing "MSg = "
		memset(buf_msg, 0x00, sizeof(buf_msg));

		for (cnt_j = 0; cnt_j < 128; cnt_j++) //Reading "Msg"
		{
			fscanf(fp_src, "%02hhX", &temp[cnt_j]);
			fprintf(fp_dst, "%02X", temp[cnt_j]);
			buf_msg[cnt_j] = temp[cnt_j];
		}
		fgets((char *)temp, sizeof(temp), fp_src); // Reading "/n"
		fputs("\n", fp_dst);			   // Writing "/n"

		//!HMAC
		YBCrypto_HMAC(&MM, SHA256, buf_key, keybyte_len, buf_msg, 128, MAC);
		fprintf(fp_dst, "Mac = "); //Writing "MAC = "

		for (cnt_j = 0; cnt_j < macbyte_len; cnt_j++) //Writing "Msg"
		{
			fprintf(fp_dst, "%02X", MAC[cnt_j]);
		}
		fputs("\n\n", fp_dst);					 // Writing "/n"
		fgets((char *)buf_msg, sizeof(buf_msg), fp_src); // Reading "/n"
	}

	fclose(fp_src);
	fclose(fp_dst);
}