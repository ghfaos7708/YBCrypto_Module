#include "ctr_drbg.h"

//TODO SUCCESS 함수별 바꿔야함
#define MAX_NUM_OF_BYTES_TO_RETURN 64
#define BLOCK_SIZE MAX_V_LEN_IN
#define SIZE_INT 4
#define octet_to_int(os) (((uint32_t)(os)[0] << 24) ^ ((uint32_t)(os)[1] << 16) ^ ((uint32_t)(os)[2] << 8) ^ ((uint32_t)(os)[3]))
#define int_to_octet(os, i)             \
    {                                   \
        (os)[0] = (uint8_t)((i) >> 24); \
        (os)[1] = (uint8_t)((i) >> 16); \
        (os)[2] = (uint8_t)((i) >> 8);  \
        (os)[3] = (uint8_t)(i);         \
    }
CipherManager CM;

static void ctr_increase(uint8_t *counter)
{

    uint32_t c_byte = 0;

    c_byte = octet_to_int(counter + 12);
    c_byte++;
    c_byte &= 0xFFFFFFFF;
    int_to_octet(counter + 12, c_byte);
    if (c_byte)
    {
        YBCrypto_memset(&c_byte, 0, sizeof(c_byte));
    }
    return;

    c_byte = octet_to_int(counter + 8);
    c_byte++;
    c_byte &= 0xFFFFFFFF;
    int_to_octet(counter + 8, c_byte);

    if (c_byte)
    {
        YBCrypto_memset(&c_byte, 0, sizeof(c_byte));
    }
    return;

    c_byte = octet_to_int(counter + 4);
    c_byte++;
    c_byte &= 0xFFFFFFFF;
    int_to_octet(counter + 4, c_byte);

    if (c_byte)
    {
        YBCrypto_memset(&c_byte, 0, sizeof(c_byte));
    }
    return;

    c_byte = octet_to_int(counter + 0);
    c_byte++;
    c_byte &= 0xFFFFFFFF;
    int_to_octet(counter + 0, c_byte);
}

static void BCC(int32_t algo, uint8_t *userkey, uint32_t key_bitlen, uint8_t *data, uint64_t data_bytelen, uint8_t *output_block, uint64_t out_bytelen)
{
    int32_t n = data_bytelen / out_bytelen;
    uint8_t inputblock[MAX_V_LEN_IN];

    YBCrypto_memset(inputblock, 0x00, MAX_V_LEN_IN);
    YBCrypto_memset(output_block, 0x00, out_bytelen);

    for (int cnt_i = 1; cnt_i <= n; cnt_i++)
    {
        for (int cnt_j = 0; cnt_j < out_bytelen; cnt_j++)
        {
            inputblock[cnt_j] = output_block[cnt_j] ^ data[cnt_j];
        }
        YBCrypto_BlockCipher(&CM, algo, ECB_MODE, ENCRYPT, userkey, key_bitlen, inputblock, BC_MAX_BLOCK_SIZE, NULL, output_block);
        data += BC_MAX_BLOCK_SIZE;
    }

    YBCrypto_memset(inputblock, 0x00, MAX_V_LEN_IN);
}

static int32_t Blockcipher_df(int32_t algo, uint32_t key_bitlen, uint8_t *input_string, uint64_t input_str_len, uint8_t *output, uint64_t outlen)
{

    uint8_t X[MAX_NUM_OF_BYTES_TO_RETURN];
    uint8_t K[MAX_Key_LEN];
    uint8_t IV[BLOCK_SIZE];
    uint8_t block[BLOCK_SIZE];
    uint8_t *S = NULL;
    uint8_t *temp = NULL;
    uint8_t *iv_s = NULL;
    uint8_t *ptr = NULL;

    int32_t ret = FAIL_CORE;
    int32_t L = input_str_len;
    int32_t N = outlen;
    int32_t KLen = key_bitlen / 8;
    int32_t cnt_i = 0x00;
    int32_t SLen = 0x00;
    int32_t iv_s_len = 0x00;
    int32_t templen = 0x00;

    if (outlen > MAX_NUM_OF_BYTES_TO_RETURN)
        goto EXIT;

    // form S = L||N||input_string||0x80
    SLen = 8 + input_str_len + 1;
    if ((SLen % BC_MAX_BLOCK_SIZE) != 0)
        SLen += (BC_MAX_BLOCK_SIZE - (SLen % BC_MAX_BLOCK_SIZE));

    S = (uint8_t *)malloc(SLen);
    YBCrypto_memset(S, 0x00, SLen);
    int_to_octet(S, L);
    int_to_octet(S + SIZE_INT, N);
    memcpy(S + SIZE_INT + SIZE_INT, input_string, input_str_len);

    S[SIZE_INT + SIZE_INT + input_str_len] = 0x80;

    for (cnt_i = 0; cnt_i < KLen; cnt_i++)
    {
        K[cnt_i] = cnt_i;
    }

    templen = (KLen + outlen) + (BLOCK_SIZE - ((KLen + outlen) % BLOCK_SIZE));
    temp = (uint8_t *)malloc(templen);
    ptr = temp;
    iv_s_len = SLen + BLOCK_SIZE;
    iv_s = (uint8_t *)malloc(iv_s_len);
    cnt_i = 0;
    templen = 0;
    while (templen < KLen + outlen)
    {
        int_to_octet(IV, cnt_i);
        YBCrypto_memset(IV + SIZE_INT, 0x00, BLOCK_SIZE - SIZE_INT);
        memcpy(iv_s, IV, BLOCK_SIZE);
        memcpy(iv_s + BLOCK_SIZE, S, SLen);

        BCC(algo, K, key_bitlen, iv_s, iv_s_len, block, BLOCK_SIZE);
        memcpy(ptr, block, BLOCK_SIZE);
        ptr += BLOCK_SIZE;
        templen += BLOCK_SIZE;
        cnt_i++;
    }

    memcpy(K, temp, KLen);
    memcpy(X, temp + KLen, outlen);

    YBCrypto_memset(temp, 0x00, templen);
    free(temp);

    temp = (uint8_t *)malloc((outlen) + (BLOCK_SIZE - ((outlen) % BLOCK_SIZE)));
    ptr = temp;
    templen = 0;
    while (templen < outlen)
    {
        YBCrypto_BlockCipher(&CM, algo, ECB_MODE, ENCRYPT, K, key_bitlen, X, BC_MAX_BLOCK_SIZE, NULL, X);
        memcpy(ptr, X, BLOCK_SIZE);
        ptr += BLOCK_SIZE;
        templen += BLOCK_SIZE;
    }
    memcpy(output, temp, outlen);

    ret = SUCCESS;

EXIT:

    if (S != NULL)
    {
        YBCrypto_memset(S, 0x00, SLen);
        free(S);
    }
    if (temp != NULL)
    {
        YBCrypto_memset(temp, 0x00, templen);
        free(temp);
    }
    if (iv_s != NULL)
    {
        YBCrypto_memset(iv_s, 0x00, iv_s_len);
        free(iv_s);
    }
    YBCrypto_memset(X, 0x00, sizeof(X));
    YBCrypto_memset(K, 0x00, sizeof(K));
    YBCrypto_memset(IV, 0x00, sizeof(IV));
    YBCrypto_memset(block, 0x00, sizeof(block));

    return ret;
}

static int32_t CTR_DRBG_Update(uint8_t *provided_data, DRBGManager *DM)
{
    uint8_t temp[MAX_SEEDLEN];
    uint8_t *ptr = NULL;
    int32_t templen = 0x00;
    int32_t cnt_i = 0x00;
    int32_t ret = SUCCESS;

    YBCrypto_memset(temp, 0x00, MAX_SEEDLEN);
    if (provided_data == NULL)
    {
        ret = FAIL_INVALID_INPUT_DATA;
        goto EXIT;
    }

    ptr = temp;

    while (templen < DM->seedlen)
    {
        ctr_increase(DM->V);
        YBCrypto_BlockCipher(&CM, DM->algo, ECB_MODE, ENCRYPT, DM->Key, (DM->Key_bytelen) * 8, DM->V, BC_MAX_BLOCK_SIZE, NULL, ptr);
        ptr += BC_MAX_BLOCK_SIZE;
        templen += BC_MAX_BLOCK_SIZE;
    }

    for (cnt_i = 0; cnt_i < DM->seedlen; cnt_i++)
    {
        temp[cnt_i] ^= provided_data[cnt_i];
    }

    memcpy(DM->Key, temp, DM->Key_bytelen);

    ptr = temp;
    memcpy(DM->V, ptr + (DM->seedlen) - (DM->Vlen), DM->Vlen);

EXIT:
    if (ret != SUCCESS)
    {
        YBCrypto_memset(DM, 0x00, sizeof(DRBGManager));
    }
    ptr = NULL;
    YBCrypto_memset(temp, 0x00, DM->seedlen);
    return ret;
}

int32_t CTR_DRBG_Instantiate(DRBGManager *DM,
                             uint32_t algo, uint32_t key_bitlen,
                             uint8_t *entropy_input, uint32_t entropy_bytelen,
                             uint8_t *nonce, uint32_t nonce_bytelen,
                             uint8_t *personalization_string, uint32_t string_bytelen,
                             uint32_t derivation_function_flag)
{
    uint8_t seed_material[MAX_SEEDLEN];
    uint8_t *seed_material_in = NULL;
    uint8_t *ptr = NULL;
    int32_t seed_material_len = 0;
    int32_t loop = 0x00;
    int32_t cnt_i = 0x00;
    int32_t ret = SUCCESS;

    YBCrypto_memset(DM, 0x00, sizeof(DRBGManager));

    DM->algo = algo;
    DM->Key_bytelen = key_bitlen / 8;
    DM->seedlen = BC_MAX_BLOCK_SIZE + DM->Key_bytelen;
    DM->Vlen = BC_MAX_BLOCK_SIZE;

    if (derivation_function_flag == USE_DF)
    {
        DM->derivation_function_flag = USE_DF;
    }
    else
    {
        DM->derivation_function_flag = NO_DF;
    }

    if (DM->derivation_function_flag == USE_DF)
    {
        YBCrypto_memset(seed_material, 0x00, MAX_SEEDLEN);
        seed_material_len = entropy_bytelen;
        if (nonce != NULL && nonce_bytelen > 0)
            seed_material_len += (nonce_bytelen);
        if (personalization_string != NULL && string_bytelen > 0)
            seed_material_len += (string_bytelen);

        ptr = seed_material_in = (uint8_t *)malloc(seed_material_len);

        memcpy(ptr, entropy_input, entropy_bytelen);
        if (nonce != NULL && nonce_bytelen > 0)
        {
            ptr += entropy_bytelen;
            memcpy(ptr, nonce, nonce_bytelen);
        }

        if (personalization_string != NULL && string_bytelen > 0)
        {
            ptr += nonce_bytelen;
            memcpy(ptr, personalization_string, string_bytelen);
        }

        if (Blockcipher_df(algo, key_bitlen, seed_material_in, seed_material_len, seed_material, DM->seedlen) != SUCCESS)
        {
            YBCrypto_memset(seed_material, 0x00, DM->seedlen);
            fprintf(stdout, "=*Location : Blockcipher_df             =\n");
            ret = FAIL_DRBG_INNER_FUNCTION;
            goto EXIT;
        }
    }

    else
    {
        loop = string_bytelen <= entropy_bytelen ? string_bytelen : entropy_bytelen;

        if (loop > MAX_SEEDLEN)
            loop = MAX_SEEDLEN;
        YBCrypto_memset(seed_material, 0x00, MAX_SEEDLEN);
        if (personalization_string == NULL || string_bytelen == 0)
            for (cnt_i = 0; cnt_i < entropy_bytelen; cnt_i++)
                seed_material[cnt_i] = entropy_input[cnt_i];
        else
            for (cnt_i = 0; cnt_i < loop; cnt_i++)
                seed_material[cnt_i] = entropy_input[cnt_i] ^ personalization_string[cnt_i];
    }

    YBCrypto_memset(DM->Key, 0x00, MAX_Key_LEN);
    YBCrypto_memset(DM->V, 0x00, MAX_V_LEN_IN);

    if (CTR_DRBG_Update(seed_material, DM) != SUCCESS)
    {
        YBCrypto_memset(seed_material, 0x00, DM->seedlen);
        ret = FAIL_DRBG_INNER_FUNCTION;
        fprintf(stdout, "=*Location : CTR_DRBG_Update            =\n");
        goto EXIT;
    }

    DM->reseed_counter = 1;
    DM->initialized_flag = DM_INITIALIZED_FLAG;

EXIT:
    if (ret != SUCCESS)
    {
        YBCrypto_memset(DM, 0x00, sizeof(DM));
    }
    if (seed_material_in != NULL)
    {
        YBCrypto_memset(seed_material_in, 0x00, seed_material_len);
        free(seed_material_in);
    }
    YBCrypto_memset(seed_material, 0x00, MAX_SEEDLEN);
    return ret;
}

int32_t CTR_DRBG_Reseed(DRBGManager *DM,
                        uint8_t *entropy_input, uint32_t entropy_bytelen,
                        uint8_t *additional_input, uint32_t add_bytelen)
{
    uint8_t seed_material[MAX_SEEDLEN];
    uint8_t *seed_material_in = NULL;
    uint8_t *ptr = NULL;
    uint64_t ret = SUCCESS;
    uint32_t seed_material_len = 0x00;
    uint32_t loop = 0x00;
    uint32_t cnt_i = 0;

    if (add_bytelen > DM->seedlen)
    {
        add_bytelen = DM->seedlen;
    }

    if (DM->derivation_function_flag == USE_DF)
    {
        YBCrypto_memset(seed_material, 0x00, MAX_SEEDLEN);
        seed_material_len = entropy_bytelen;
        if (add_bytelen > 0)
            seed_material_len += (add_bytelen);
        ptr = seed_material_in = (uint8_t *)malloc(seed_material_len);

        memcpy(ptr, entropy_input, entropy_bytelen);
        if (add_bytelen > 0)
        {
            ptr += entropy_bytelen;
            memcpy(ptr, additional_input, add_bytelen);
        }

        if (Blockcipher_df(DM->algo, DM->Key_bytelen * 8, seed_material_in, seed_material_len, seed_material, DM->seedlen) != SUCCESS)
        {
            ret = FAIL_DRBG_INNER_FUNCTION;
            fprintf(stdout, "=*Location : Blockcipher_df             =\n");
            goto EXIT;
        }
    }
    else
    {
        loop = add_bytelen <= entropy_bytelen ? add_bytelen : entropy_bytelen;

        YBCrypto_memset(seed_material, 0x00, MAX_SEEDLEN);

        if (additional_input == NULL || add_bytelen == 0)
        {
            for (cnt_i = 0; cnt_i < entropy_bytelen; cnt_i++)
            {
                seed_material[cnt_i] = entropy_input[cnt_i];
            }
        }
        else
        {
            for (cnt_i = 0; cnt_i < loop; cnt_i++)
            {
                seed_material[cnt_i] = entropy_input[cnt_i] ^ additional_input[cnt_i];
            }
        }
    }

    if (CTR_DRBG_Update(seed_material, DM) != SUCCESS)
    {
        ret = FAIL_DRBG_INNER_FUNCTION;
        fprintf(stdout, "=*Location : CTR_DRBG_Update            =\n");
        goto EXIT;
    }

    DM->reseed_counter = 1;

EXIT:
    if (ret != SUCCESS)
    {
        YBCrypto_memset(DM, 0x00, sizeof(DM));
    }
    if (seed_material_in != NULL)
    {
        YBCrypto_memset(seed_material_in, 0x00, seed_material_len);
        free(seed_material_in);
    }
    YBCrypto_memset(seed_material, 0x00, MAX_SEEDLEN);

    return ret;
}

int32_t CTR_DRBG_Generate(DRBGManager *DM,
                          uint8_t *output, uint64_t requested_num_of_bits,
                          uint8_t *entropy_input, uint32_t entropy_bytelen,
                          uint8_t *addtional_input, uint32_t add_bytelen,
                          uint32_t prediction_resistance_flag)
{
    uint8_t addtional_input_for_seed[MAX_SEEDLEN];
    int32_t request_num_of_bytes;

    uint32_t ret = SUCCESS;
    uint8_t *temp = NULL;
    uint8_t *ptr = NULL;
    uint32_t templen = 0x00;

    if (add_bytelen > DM->seedlen)
    {
        add_bytelen = DM->seedlen;
    }

    request_num_of_bytes = requested_num_of_bits / 8 + ((requested_num_of_bits % 8) != 0 ? 1 : 0);

    DM->prediction_resistance_flag = prediction_resistance_flag;

    if ((DM->prediction_resistance_flag == NO_PR) || DM->reseed_counter >= MAX_RESEED_COUNTER)
    {
        if ((addtional_input != NULL) && (add_bytelen > 0))
        {
            if (DM->derivation_function_flag == USE_DF)
            {
                if (Blockcipher_df(DM->algo, DM->Key_bytelen * 8, addtional_input, add_bytelen, addtional_input_for_seed, DM->seedlen) != SUCCESS)
                {
                    YBCrypto_memset(addtional_input_for_seed, 0x00, MAX_SEEDLEN);
                    ret = FAIL_DRBG_INNER_FUNCTION;
                    fprintf(stdout, "=*Location : Blockcipher_df             =\n");
                    goto EXIT;
                }

                if (CTR_DRBG_Update(addtional_input_for_seed, DM) != SUCCESS)
                {
                    YBCrypto_memset(addtional_input_for_seed, 0x00, MAX_SEEDLEN);
                    ret = FAIL_DRBG_INNER_FUNCTION;
                    fprintf(stdout, "=*Location : CTR_DRBG_Update            =\n");
                    goto EXIT;
                }
            }
            else
            {
                YBCrypto_memset(addtional_input_for_seed, 0x00, MAX_SEEDLEN);
                memcpy(addtional_input_for_seed, addtional_input, add_bytelen);

                if (CTR_DRBG_Update(addtional_input_for_seed, DM) != SUCCESS)
                {
                    YBCrypto_memset(addtional_input_for_seed, 0x00, MAX_SEEDLEN);
                    ret = FAIL_DRBG_INNER_FUNCTION;
                    fprintf(stdout, "=*Location : CTR_DRBG_Update            =\n");
                    goto EXIT;
                }
            }
        }
        else
        {
            YBCrypto_memset(addtional_input_for_seed, 0x00, MAX_SEEDLEN);
        }
    }
    else
    {
        //!CTR_DRBG_Reseed
        if (YBCrypto_CTR_DRBG_Reseed(DM, entropy_input, entropy_bytelen, addtional_input, add_bytelen) != SUCCESS)
        {
            ret = FAIL_DRBG_INNER_FUNCTION;
            fprintf(stdout, "=*Location : YBCrypto_CTR_DRBG_Reseed   =\n");
            goto EXIT;
        }
        YBCrypto_memset(addtional_input_for_seed, 0x00, MAX_SEEDLEN);
    }

    templen = request_num_of_bytes + (MAX_V_LEN_IN - (request_num_of_bytes % MAX_V_LEN_IN));
    temp = (uint8_t *)malloc(templen);
    ptr = temp;
    templen = 0;

    while (templen < request_num_of_bytes)
    {
        ctr_increase(DM->V);
        YBCrypto_BlockCipher(&CM, DM->algo, ECB_MODE, ENCRYPT, DM->Key, DM->Key_bytelen * 8, DM->V, BC_MAX_BLOCK_SIZE, NULL, ptr);
        ptr += BC_MAX_BLOCK_SIZE;
        templen += BC_MAX_BLOCK_SIZE;
    }

    memcpy(output, temp, request_num_of_bytes);
    if (requested_num_of_bits % 8 != 0)
    {
        output[request_num_of_bytes - 1] = temp[request_num_of_bytes - 1] & (0x000000FF & (0xFF << (8 - (requested_num_of_bits % 8))));
    }

    if (CTR_DRBG_Update(addtional_input_for_seed, DM) != SUCCESS)
    {
        ret = FAIL_DRBG_INNER_FUNCTION;
        fprintf(stdout, "=*Location : CTR_DRBG_Update            =\n");
        goto EXIT;
    }

    (DM->reseed_counter)++;

EXIT:
    if (ret != SUCCESS)
    {
        YBCrypto_memset(DM, 0x00, sizeof(DRBGManager));
    }
    if (temp != NULL)
    {
        YBCrypto_memset(temp, 0x00, templen);
        free(temp);
    } 
    YBCrypto_memset(addtional_input_for_seed, 0x00, MAX_SEEDLEN);

    return ret;
}
// EOF
