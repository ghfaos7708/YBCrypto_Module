#include "YBCrypto.h"
#include "entropy.h"
#include <assert.h>

uint32_t APT_CutOff = 0;
uint32_t RCT_CutOff = 0;

static int32_t Inner_API_AdaptiveTest_EntropyAdd(uint8_t *entrophy, uint32_t *collected_bytelen, uint8_t *src, uint32_t srclen)
{
    int32_t ret = SUCCESS;
    uint8_t buffer[ENTROPY_WINDOW];

    if (*collected_bytelen == 0)
    {
        memcpy(entrophy, src, srclen);
        *collected_bytelen += srclen;
    }
    else
    {
        memcpy(buffer, entrophy, ENTROPY_WINDOW);
        if (!memcmp(buffer, src, srclen))
        {
            APT_CutOff++;
            if (APT_CutOff == ADAPTIVE_TEST_CUTOFF)
            {
                ret = FAIL_ENTROPY_TEST;
                fprintf(stdout, "=*Location : Inner_API_AdaptiveTest.... =\n");
                goto EXIT;
            }
            memcpy(entrophy + *collected_bytelen, src, srclen);
            *collected_bytelen += srclen;
        }
        else
        {
            memcpy(entrophy + *collected_bytelen, src, srclen);
            *collected_bytelen += srclen;
        }
    }

EXIT:
    YBCrypto_memset(buffer, 0x00, sizeof(buffer));
    return ret;
}

static int32_t Inner_API_RepetitionTest_getEntropy(uint8_t *entropybuffer)
{
    int32_t ret = SUCCESS;
    int32_t length = 0x00;
    uint8_t fst_buffer[ENTROPY_WINDOW];
    uint8_t snd_buffer[ENTROPY_WINDOW];
    FILE *fp = NULL;

    YBCrypto_memset(fst_buffer, 0x00, sizeof(fst_buffer));
    YBCrypto_memset(snd_buffer, 0x00, sizeof(snd_buffer));

REPEAT : 

    if ((fp = fopen("/dev/urandom", "r")) != NULL)
    {
        length = fread(fst_buffer, sizeof(uint8_t), ENTROPY_WINDOW, fp);
        fclose(fp);
        fp = NULL;
    }

    if ((fp = fopen("/dev/urandom", "r")) != NULL)
    {
        length = fread(snd_buffer, sizeof(uint8_t), ENTROPY_WINDOW, fp);
        fclose(fp);
        fp = NULL;
    }
    if (!memcmp(fst_buffer, snd_buffer, ENTROPY_WINDOW))
    {
        RCT_CutOff++;
        if (RCT_CutOff == REPEAT_TEST_CUTOFF)
        {
            ret = FAIL_ENTROPY_TEST;
            fprintf(stdout, "=*Location : Inner_API_RepetitionTest.. =\n");
            goto EXIT;
        }
        goto REPEAT;
    }
    else
    {
        memcpy(entropybuffer, snd_buffer,ENTROPY_WINDOW);
    }

EXIT:
    if(fp) free(fp);
    length = 0x00;
    YBCrypto_memset(fst_buffer, 0x00, sizeof(fst_buffer));
    YBCrypto_memset(snd_buffer, 0x00, sizeof(snd_buffer));
    return ret;
}

static int32_t Inner_API_GetEntropy(uint8_t* entropy, uint32_t size)
{
    int32_t ret = SUCCESS;

    FILE *fp = NULL;
    uint32_t collected_bytesize = 0x00;
    uint8_t entropy_buffer[MAX_ENTROPY_LEN];
    uint8_t buffer[ENTROPY_WINDOW];

    YBCrypto_memset(entropy_buffer, 0x00, sizeof(entropy_buffer));
    YBCrypto_memset(buffer, 0x00, sizeof(buffer));

    for (int cnt_i = 0; cnt_i < MAX_ENTROPY_LEN / ENTROPY_WINDOW; cnt_i++)
    {
        ret = Inner_API_RepetitionTest_getEntropy(buffer);
        if (ret != SUCCESS) goto EXIT;

        ret = Inner_API_AdaptiveTest_EntropyAdd(entropy_buffer, &collected_bytesize, buffer, ENTROPY_WINDOW);
        if (ret != SUCCESS) goto EXIT;
    }

    memcpy(entropy, entropy_buffer, size);

EXIT:
    if(ret != SUCCESS)  fprintf(stdout, "=*Location : Inner_API_GetEntropy       =\n");

    if (fp) free(fp);
    collected_bytesize = 0x00;
    YBCrypto_memset(entropy_buffer, 0x00, sizeof(entropy_buffer));
    YBCrypto_memset(buffer, 0x00, sizeof(buffer));

    return ret;
}

int32_t Inner_API_DRBG_CENT(uint8_t *entropy, uint32_t bytelen, uint32_t test_flag)
{
    int32_t ret = SUCCESS;
    uint8_t *pEnt1 = NULL;
    uint8_t *pEnt2 = NULL;

    pEnt1 = (uint8_t *)calloc(MAX_ENTROPY_LEN, sizeof(uint8_t));
	assert(pEnt1 != NULL);
	pEnt2 = (uint8_t *)calloc(MAX_ENTROPY_LEN, sizeof(uint8_t));
	assert(pEnt2 != NULL);

    //! Set Ent1
    ret = Inner_API_GetEntropy(pEnt1, MAX_ENTROPY_LEN);
    if(ret != SUCCESS) goto EXIT;

    ret = Inner_API_GetEntropy(pEnt2, MAX_ENTROPY_LEN);
    if(ret != SUCCESS) goto EXIT;

    if(!(memcmp(pEnt1, pEnt2, MAX_ENTROPY_LEN)))
    {
        ret = FAIL_ENTROPY_TEST;
        goto EXIT;
    }

    if(test_flag == FALSE)
    {
        memcpy(entropy, pEnt2, bytelen);
    }


EXIT:
    if(ret != SUCCESS)  fprintf(stdout, "=*Location : Inner_API_DRBG_CENT        =\n");
    YBCrypto_memset(pEnt1, 0x00, MAX_ENTROPY_LEN);
    YBCrypto_memset(pEnt2, 0x00, MAX_ENTROPY_LEN);
    if(pEnt1) free(pEnt1);
    if(pEnt2) free(pEnt2);

    return ret;

}
