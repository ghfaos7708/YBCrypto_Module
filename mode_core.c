#include "YBCrypto.h"
#include "blockcipher.h"
#include "mode.h"

int ECB_Init(CipherManager *c, int32_t ALG, int32_t direct, uint8_t *userkey, uint64_t key_bitlen)
{
    int ret = SUCCESS;

    switch (ALG)
    {
    case AES:
        // 1. set informations in CipherManager
        // 2. key scheduling
        YBCrypto_memset(c, 0x00, sizeof(CipherManager));

        c->block_cipher = AES;
        c->key_bitsize = key_bitlen;
        c->block_size = BC_MAX_BLOCK_SIZE;
        c->direct = direct;

        if (direct == ENCRYPT)
        {
            ret = AES_set_encrypt_key(userkey, key_bitlen, &(c->aes_key));
        }
        else
        {
            ret = AES_set_decrypt_key(userkey, key_bitlen, &(c->aes_key));
        }
        break;

    case ARIA:
        /* code */
        break;

    default:
        return FAIL_CORE;
        break;
    }

    return ret;
}

int ECB_Update(CipherManager *c, uint8_t *in, uint64_t in_byteLen, uint8_t *out, uint64_t out_byteLen)
{
    int ret = SUCCESS;
    int count_loop = 0;
    uint64_t Update_bytelen = in_byteLen;
    uint8_t *Update_in = in;

    switch (c->block_cipher)
    {
    case AES:
        while ((Update_bytelen + c->remained_len) >= AES_BLOCK_SIZE)
        {
            memcpy(c->buf + c->remained_len, Update_in, AES_BLOCK_SIZE - c->remained_len);
            if (c->direct == ENCRYPT)
            {
                AES_encrypt(c->buf, out + (count_loop * AES_BLOCK_SIZE), &(c->aes_key));
            }
            else
            {
                AES_decrypt(c->buf, out + (count_loop * AES_BLOCK_SIZE), &(c->aes_key));
            }
            Update_in += (AES_BLOCK_SIZE - c->remained_len);
            Update_bytelen -= (AES_BLOCK_SIZE - c->remained_len);
            c->remained_len = 0;
            count_loop++;
        }
        memcpy(c->buf + c->remained_len, Update_in, Update_bytelen);
        c->remained_len = Update_bytelen;
        c->encrypted_len += AES_BLOCK_SIZE * count_loop;
        out_byteLen = AES_BLOCK_SIZE * count_loop;

        break;

    case ARIA:
        /* code */
        break;

    default:
        if (Update_in != NULL)
            Update_in = NULL;
        Update_bytelen = 0;
        return FAIL_CORE;
        break;
    }

    if (Update_in != NULL)
        Update_in = NULL;
    Update_bytelen = 0;
    return ret;
}

int ECB_Final(CipherManager *c, uint8_t *out, uint64_t out_byteLen)
{
    int ret = SUCCESS;

    switch (c->block_cipher)
    {
    case AES:
        //* zero padding
        if (c->remained_len != 0)
        {
            c->pad_len = AES_BLOCK_SIZE - c->remained_len;
            memcpy(c->lastblock, c->buf, c->remained_len);
            if (c->direct == ENCRYPT)
            {
                AES_encrypt(c->buf, out, &(c->aes_key));
            }
            else
            {
                AES_decrypt(c->buf, out, &(c->aes_key));
            }
            c->encrypted_len += c->remained_len;
            out_byteLen = c->encrypted_len;
        }
        break;

    case ARIA:
        /* code */
        break;

    default:
        return FAIL_CORE;
        break;
    }
    return ret;
}