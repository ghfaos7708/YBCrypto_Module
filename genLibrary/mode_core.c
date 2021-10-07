#include "YBCrypto.h"
#include "blockcipher.h"
#include "mode.h"

static int CiperManager_Clean(CipherManager *c)
{
    int32_t ret = SUCCESS;
    YBCrypto_memset(c, 0x00, sizeof(CipherManager));
    return ret;
}

static void count_increase(uint8_t *ctr)
{
    int32_t cnt_i = 0;
    uint8_t carry = 1;
    uint8_t temp = 0;

    for (cnt_i = 15; cnt_i >= 0; cnt_i--)
    {
        temp = ctr[cnt_i] + carry;
        if (temp < ctr[cnt_i])
        {
            carry = 1;
        }
        else
        {
            carry = 0;
        }
        ctr[cnt_i] = temp;
    }
}

int ECB_Init(CipherManager *c, int32_t ALG, int32_t direct, const uint8_t *userkey, uint32_t key_bitlen)
{
    // 1. set informations in CipherManager
    // 2. key scheduling
    int ret = SUCCESS;
    YBCrypto_memset(c, 0x00, sizeof(CipherManager));

    switch (ALG)
    {
    case AES:

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
        c->block_cipher = ARIA;
        c->key_bitsize = key_bitlen;
        c->block_size = BC_MAX_BLOCK_SIZE;
        c->direct = direct;

        if (direct == ENCRYPT)
        {
            ret = ARIA_EncKeySetup(userkey, key_bitlen, &(c->aria_key));
        }
        else
        {
            ret = ARIA_DecKeySetup(userkey, key_bitlen, &(c->aria_key));
        }
        break;

    default:
        return FAIL_CORE;
        break;
    }

    return ret;
}

int ECB_Update(CipherManager *c, const uint8_t *in, uint64_t in_byteLen, uint8_t *out, uint64_t *out_byteLen)
{
    int ret = SUCCESS;
    int count_loop = 0;
    uint64_t Update_bytelen = in_byteLen;
    uint8_t Update_index = 0;

    while ((Update_bytelen + c->remained_len) >= BC_MAX_BLOCK_SIZE)
    {
        memcpy(c->buf + c->remained_len, in + Update_index, BC_MAX_BLOCK_SIZE - c->remained_len);
        if (c->direct == ENCRYPT)
        {
            if (c->block_cipher == AES)
            {
                AES_encrypt(c->buf, out + (count_loop * BC_MAX_BLOCK_SIZE) + c->encrypted_len, &(c->aes_key));
            }
            else if (c->block_cipher == ARIA)
            {
                ARIA_Crypt(c->buf, c->aria_key.rounds, &(c->aria_key), out + (count_loop * BC_MAX_BLOCK_SIZE) + c->encrypted_len);
            }
        }
        else
        {
            if (c->block_cipher == AES)
            {
                AES_decrypt(c->buf, out + (count_loop * BC_MAX_BLOCK_SIZE) + c->encrypted_len, &(c->aes_key));
            }
            else if (c->block_cipher == ARIA)
            {
                ARIA_Crypt(c->buf, c->aria_key.rounds, &(c->aria_key), out + (count_loop * BC_MAX_BLOCK_SIZE) + c->encrypted_len);
            }
        }
        Update_index += (BC_MAX_BLOCK_SIZE - c->remained_len);
        Update_bytelen -= (BC_MAX_BLOCK_SIZE - c->remained_len);
        c->remained_len = 0;
        count_loop++;
    }
    memcpy(c->buf + c->remained_len, in + Update_index, Update_bytelen);
    c->remained_len = Update_bytelen;
    c->encrypted_len += BC_MAX_BLOCK_SIZE * count_loop;
    *out_byteLen = BC_MAX_BLOCK_SIZE * count_loop;

    Update_index = 0;
    Update_bytelen = 0;
    return ret;
}

int ECB_Final(CipherManager *c, uint8_t *out, uint32_t *pad_bytelen)
{
    int ret = SUCCESS;

    //* zero padding
    if (c->remained_len != 0)
    {
        c->pad_len = AES_BLOCK_SIZE - c->remained_len;
        memcpy(c->lastblock, c->buf, c->remained_len);
        if (c->direct == ENCRYPT)
        {
            if (c->block_cipher == AES)
            {
                AES_encrypt(c->lastblock, out + c->encrypted_len, &(c->aes_key));
            }
            else if (c->block_cipher == ARIA)
            {
                ARIA_Crypt(c->lastblock, c->aria_key.rounds, &(c->aria_key), out + c->encrypted_len);
            }
        }
        else
        {
            //! does not occur
            ret = FAIL_CORE;
        }
        c->encrypted_len += c->remained_len;
        *pad_bytelen = (c->pad_len);
    }

    CiperManager_Clean(c);
    return ret;
}

int CBC_Init(CipherManager *c, int32_t ALG, int32_t direct, const uint8_t *userkey, int32_t key_bitlen, const uint8_t *iv)
{
    int32_t ret = SUCCESS;

    YBCrypto_memset(c, 0x00, sizeof(CipherManager));
    switch (ALG)
    {
    case AES:

        c->block_cipher = AES;
        c->key_bitsize = key_bitlen;
        c->block_size = BC_MAX_BLOCK_SIZE;
        c->direct = direct;
        memcpy(c->iv, iv, BC_MAX_BLOCK_SIZE);

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
        c->block_cipher = ARIA;
        c->key_bitsize = key_bitlen;
        c->block_size = BC_MAX_BLOCK_SIZE;
        c->direct = direct;
        memcpy(c->iv, iv, BC_MAX_BLOCK_SIZE);

        if (direct == ENCRYPT)
        {
            ret = ARIA_EncKeySetup(userkey, key_bitlen, &(c->aria_key));
        }
        else
        {
            ret = ARIA_DecKeySetup(userkey, key_bitlen, &(c->aria_key));
        }
        break;

    default:
        return FAIL_CORE;
        break;
    }

    return ret;
}

int CBC_Update(CipherManager *c, const uint8_t *in, uint64_t in_byteLen, uint8_t *out, uint64_t *out_byteLen)
{
    int ret = SUCCESS;
    int count_loop = 0;
    int cnt_i = 0;
    uint64_t Update_bytelen = in_byteLen;
    uint8_t Update_index = 0;

    while ((Update_bytelen + c->remained_len) >= BC_MAX_BLOCK_SIZE)
    {
        memcpy(c->buf + c->remained_len, in + Update_index, BC_MAX_BLOCK_SIZE - c->remained_len);
        if (c->direct == ENCRYPT)
        {
            //* XoR iv
            for (cnt_i = 0; cnt_i < BC_MAX_BLOCK_SIZE; cnt_i++)
            {
                c->buf[cnt_i] ^= c->iv[cnt_i];
            }
            if (c->block_cipher == AES)
            {
                AES_encrypt(c->buf, out + (count_loop * BC_MAX_BLOCK_SIZE) + c->encrypted_len, &(c->aes_key));
            }
            else if (c->block_cipher == ARIA)
            {
                ARIA_Crypt(c->buf, c->aria_key.rounds, &(c->aria_key), out + (count_loop * BC_MAX_BLOCK_SIZE) + c->encrypted_len);
            }
        }
        else
        {
            if (c->block_cipher == AES)
            {
                AES_decrypt(c->buf, out + (count_loop * BC_MAX_BLOCK_SIZE) + c->encrypted_len, &(c->aes_key));
            }
            else if (c->block_cipher == ARIA)
            {
                ARIA_Crypt(c->buf, c->aria_key.rounds, &(c->aria_key), out + (count_loop * BC_MAX_BLOCK_SIZE) + c->encrypted_len);
            }
            //* XoR iv
            for (cnt_i = 0; cnt_i < BC_MAX_BLOCK_SIZE; cnt_i++)
            {
                out[(count_loop * BC_MAX_BLOCK_SIZE) + c->encrypted_len + cnt_i] ^= c->iv[cnt_i];
            }
        }
        Update_index += (BC_MAX_BLOCK_SIZE - c->remained_len);
        Update_bytelen -= (BC_MAX_BLOCK_SIZE - c->remained_len);
        c->remained_len = 0;
        if (c->direct == ENCRYPT)
        {
            memcpy(c->iv, out + (count_loop * BC_MAX_BLOCK_SIZE) + c->encrypted_len, BC_MAX_BLOCK_SIZE);
        }
        else // c->direct == DECRYPT
        {
            memcpy(c->iv, c->buf, BC_MAX_BLOCK_SIZE);
        }
        count_loop++;
    }
    memcpy(c->buf + c->remained_len, in + Update_index, Update_bytelen);
    c->remained_len = Update_bytelen;
    c->encrypted_len += BC_MAX_BLOCK_SIZE * count_loop;
    *out_byteLen = BC_MAX_BLOCK_SIZE * count_loop;

    Update_index = 0;
    Update_bytelen = 0;
    return ret;
}

int CBC_Final(CipherManager *c, uint8_t *out, uint32_t *pad_bytelen)
{
    int ret = SUCCESS;
    int cnt_i = 0;

    //* zero padding
    if (c->remained_len != 0)
    {
        c->pad_len = BC_MAX_BLOCK_SIZE - c->remained_len;
        memcpy(c->lastblock, c->buf, c->remained_len);
        if (c->direct == ENCRYPT)
        {
            for (cnt_i = 0; cnt_i < BC_MAX_BLOCK_SIZE; cnt_i++)
            {
                c->lastblock[cnt_i] ^= c->iv[cnt_i];
            }
            if (c->block_cipher == AES)
            {
                AES_encrypt(c->lastblock, out + c->encrypted_len, &(c->aes_key));
            }
            else if (c->block_cipher == ARIA)
            {
                ARIA_Crypt(c->lastblock, c->aria_key.rounds, &(c->aria_key), out + c->encrypted_len);
            }
        }
        else
        {
            //! does not occur~
            ret = FAIL_CORE;
        }
        c->encrypted_len += c->remained_len;
        *pad_bytelen = (c->pad_len);
    }
    CiperManager_Clean(c);
    return ret;
}

int CTR_Init(CipherManager *c, int32_t ALG, int32_t direct, const uint8_t *userkey, int32_t key_bitlen, const uint8_t *iv)
{
    int32_t ret = SUCCESS;

    YBCrypto_memset(c, 0x00, sizeof(CipherManager));
    switch (ALG)
    {
    case AES:

        c->block_cipher = AES;
        c->key_bitsize = key_bitlen;
        c->block_size = BC_MAX_BLOCK_SIZE;
        c->direct = direct;
        memcpy(c->iv, iv, BC_MAX_BLOCK_SIZE);
        ret = AES_set_encrypt_key(userkey, key_bitlen, &(c->aes_key));
        break;

    case ARIA:
        c->block_cipher = ARIA;
        c->key_bitsize = key_bitlen;
        c->block_size = BC_MAX_BLOCK_SIZE;
        c->direct = direct;
        memcpy(c->iv, iv, BC_MAX_BLOCK_SIZE);

        ret = ARIA_EncKeySetup(userkey, key_bitlen, &(c->aria_key));
        break;

    default:
        return FAIL_CORE;
        break;
    }

    return ret;
}

int CTR_Update(CipherManager *c, const uint8_t *in, uint64_t in_byteLen, uint8_t *out, uint64_t *out_byteLen)
{
    int ret = SUCCESS;
    int count_loop = 0;
    int cnt_i = 0;
    uint64_t Update_bytelen = in_byteLen;
    uint8_t Update_index = 0;
    uint8_t ciphertext[BC_MAX_BLOCK_SIZE];
    YBCrypto_memset(ciphertext, 0x00, sizeof(ciphertext));

    while ((Update_bytelen + c->remained_len) >= BC_MAX_BLOCK_SIZE)
    {
        memcpy(c->buf + c->remained_len, in + Update_index, BC_MAX_BLOCK_SIZE - c->remained_len);
        //* increase CTR
        if (c->encrypted_len != 0)
        {
            count_increase(c->iv);
        }
        if (c->block_cipher == AES)
        {
            AES_encrypt(c->iv, ciphertext, &(c->aes_key));
        }
        else if (c->block_cipher == ARIA)
        {
            ARIA_Crypt(c->iv, c->aria_key.rounds, &(c->aria_key), ciphertext);
        }
        //* XoR ctr
        for (cnt_i = 0; cnt_i < BC_MAX_BLOCK_SIZE; cnt_i++)
        {
            out[c->encrypted_len + cnt_i] = ciphertext[cnt_i] ^ c->buf[cnt_i];
        }
        Update_index += (BC_MAX_BLOCK_SIZE - c->remained_len);
        Update_bytelen -= (BC_MAX_BLOCK_SIZE - c->remained_len);
        c->remained_len = 0;
        count_loop++;
        c->encrypted_len += BC_MAX_BLOCK_SIZE;

    }
    memcpy(c->buf + c->remained_len, in + Update_index, Update_bytelen);
    c->remained_len = Update_bytelen;
    *out_byteLen = BC_MAX_BLOCK_SIZE * count_loop;
    Update_index = 0;
    Update_bytelen = 0;
    YBCrypto_memset(ciphertext, 0x00, sizeof(ciphertext));
    return ret;
}

int CTR_Final(CipherManager *c, uint8_t *out, uint32_t *pad_bytelen)
{
    int ret = SUCCESS;
    int cnt_i = 0;
    uint8_t ciphertext[BC_MAX_BLOCK_SIZE];
    YBCrypto_memset(ciphertext, 0x00, sizeof(ciphertext));

    //* zero padding
    if (c->remained_len != 0)
    {
        c->pad_len = BC_MAX_BLOCK_SIZE - c->remained_len;
        memcpy(c->lastblock, c->buf, c->remained_len);
        count_increase(c->iv);

        if (c->direct == ENCRYPT)
        {
            if (c->block_cipher == AES)
            {
                AES_encrypt(c->iv, ciphertext, &(c->aes_key));
            }
            else if (c->block_cipher == ARIA)
            {
                ARIA_Crypt(c->iv, c->aria_key.rounds, &(c->aria_key), ciphertext);
            }
            for (cnt_i = 0; cnt_i < BC_MAX_BLOCK_SIZE; cnt_i++)
            {
                out[c->encrypted_len + cnt_i] ^= c->lastblock[cnt_i];
            }
        }
        else
        {
            //! does not occur~
            ret = FAIL_CORE;
        }
        c->encrypted_len += BC_MAX_BLOCK_SIZE;
        *pad_bytelen = (c->pad_len);
    }
    YBCrypto_memset(ciphertext, 0x00, sizeof(ciphertext));
    CiperManager_Clean(c);
    return ret;
}
//EOF