#include "hash.h"
#include "hmac.h"

int HMAC_init(HMACManager *c, int32_t ALG, const uint8_t *key, uint32_t key_bytelen)
{
    int ret = SUCCESS;
    YBCrypto_memset(c, 0x00, sizeof(HMACManager));
    c->keyset = FALSE;
    c->hash_function = ALG;

    if (key_bytelen > MAX_HMAC_KEYSIZE)
    {
        if (ALG == SHA256)
        {
            SHA256_init(&(c->hash_manger));
            SHA256_update(&(c->hash_manger), key, (uint64_t)key_bytelen);
            SHA256_final(&(c->hash_manger), (c->key));
        }
        else if (ALG == SHA3)
        {
            SHA3_init(&(c->hash_manger));
            SHA3_update(&(c->hash_manger), key, (uint64_t)key_bytelen);
            SHA3_final(&(c->hash_manger), (c->key));
        }
        c->keyLen = 32;
    }
    else
    {
        memcpy(c->key, key, key_bytelen);
        c->keyLen = key_bytelen;
    }
    return ret;
}

int HMAC_update(HMACManager *c, const uint8_t *msg, uint64_t msg_bytelen)
{
    int32_t ret = SUCCESS;
    int32_t cnt_i = 0;
    uint8_t K1[MAX_HMAC_KEYSIZE] = {
        0x00,
    };

    for (cnt_i = 0; cnt_i < MAX_HMAC_KEYSIZE; cnt_i++)
    {
        K1[cnt_i] = IPAD ^ c->key[cnt_i];
    }

    if (c->keyset == FALSE)
    {
        
        if (c->hash_function == SHA256)
        {
            SHA256_init(&(c->hash_manger));
            SHA256_update(&(c->hash_manger), K1, sizeof(K1));
            SHA256_update(&(c->hash_manger), msg, msg_bytelen);
        }
        else if (c->hash_function == SHA3)
        {
            SHA3_init(&(c->hash_manger));
            SHA3_update(&(c->hash_manger), K1, sizeof(K1));
            SHA3_update(&(c->hash_manger), msg, msg_bytelen);
        }
        c->keyset = TRUE;
    }
    else
    {
        if (c->hash_function == SHA256)
        {
            SHA256_update(&(c->hash_manger), msg, msg_bytelen);
        }
        else if (c->hash_function == SHA3)
        {
            SHA3_update(&(c->hash_manger), msg, msg_bytelen);
        }
    }

    return ret;
}

int HMAC_final(HMACManager *c, uint8_t *mac)
{
    int32_t ret = SUCCESS;
    int32_t cnt_i = 0;
    uint8_t K2[MAX_HMAC_KEYSIZE] = {
        0x00,
    };
    uint8_t firsOut[32] = {
        0x00,
    };

    memset(K2, OPAD, MAX_HMAC_KEYSIZE);

    for (cnt_i = 0; cnt_i < MAX_HMAC_KEYSIZE; cnt_i++)
    {
        K2[cnt_i] = OPAD ^ c->key[cnt_i];
    }

    if (c->hash_function == SHA256)
    {
        SHA256_final(&(c->hash_manger),firsOut);

        SHA256_init(&(c->hash_manger));
        SHA256_update(&(c->hash_manger), K2, sizeof(K2));
        SHA256_update(&(c->hash_manger), firsOut, sizeof(firsOut));
        SHA256_final(&(c->hash_manger), mac);
    }
    else if (c->hash_function == SHA3)
    {
        SHA3_final(&(c->hash_manger),firsOut);

        SHA3_init(&(c->hash_manger));
        SHA3_update(&(c->hash_manger), K2, sizeof(K2));
        SHA3_update(&(c->hash_manger), firsOut, sizeof(firsOut));
        SHA3_final(&(c->hash_manger), mac);
    }
    
    return ret;
}