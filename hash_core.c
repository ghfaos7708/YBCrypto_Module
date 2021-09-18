#include "hash.h"

//! [SHA-2]/////////////////////////////////////////////////////////////////////////////////////////////////////////
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define ROLc(x, y) ((((unsigned int)(x) << (unsigned int)((y)&31)) | (((unsigned int)(x)&0xFFFFFFFFU) >> (unsigned int)(32 - ((y)&31)))) & 0xFFFFFFFFU)
#define RORc(x, y) (((((unsigned int)(x)&0xFFFFFFFFU) >> (unsigned int)((y)&31)) | ((unsigned int)(x) << (unsigned int)(32 - ((y)&31)))) & 0xFFFFFFFFU)
#define OR(x, y) (x | y)
#define AND(x, y) (x & y)
#define XOR(x, y) (x ^ y)
#define S(x, n) RORc((x), (n))
#define R(x, n) ((uint64_t)((x) >> (n)))

#define SHR(x, n)                            \
    ((((x) >> ((uint64_t)((n)&PUT64(63)))) | \
      ((x) << ((uint64_t)(64 - ((n)&PUT64(63)))))))

#define ROTR(x, n) (((uint64_t))((x) >> n))

#define WORK_VAR(a, b, c, d, e, f, g, h, i)                                         \
    t0 = h + (SHR(e, 14) ^ SHR(e, 18) ^ SHR(e, 41)) + F(e, f, g) + K_512[i] + W[i]; \
    t1 = (SHR(a, 28) ^ SHR(a, 34) ^ SHR(a, 39)) + H(a, b, c);                       \
    d += t0;                                                                        \
    h = t0 + t1;

#define F(x, y, z) (XOR(z, (AND(x, (XOR(y, z))))))
#define G(x, y, z) (XOR(x, XOR(y, z)))
#define H(x, y, z) (OR(AND(x, y), AND(z, OR(x, y))))

#define SHA256_BLOCK_SIZEx8 512

static const uint32_t SHA256_K[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL,
    0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
    0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL,
    0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL,
    0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
    0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL,
    0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL,
    0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL,
    0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL,
    0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL};

static int SHA256_compute(HashManager *c, uint8_t *data);

int SHA256_init(HashManager *c)
{

    if (c == NULL)
        return FAIL_CORE;

    c->l1 = 0;
    c->l2 = 0;
    c->data[0] = 0x6A09E667UL;
    c->data[1] = 0xBB67AE85UL;
    c->data[2] = 0x3C6EF372UL;
    c->data[3] = 0xA54FF53AUL;
    c->data[4] = 0x510E527FUL;
    c->data[5] = 0x9B05688CUL;
    c->data[6] = 0x1F83D9ABUL;
    c->data[7] = 0x5BE0CD19UL;

    return SUCCESS;
}

int SHA256_update(HashManager *c, const uint8_t *msg, uint64_t msg_bytelen)
{

    uint32_t n;

    if (c->l2 > SHA256_BLOCK_SIZE)
        return 0;

    while (msg_bytelen > 0)
    {

        if (!c->l2 && msg_bytelen >= SHA256_BLOCK_SIZE)
        {

            if (!(SHA256_compute(c, (uint8_t *)msg)))
                return 0;

            c->l1 += SHA256_BLOCK_SIZEx8;
            msg += SHA256_BLOCK_SIZE;
            msg_bytelen -= SHA256_BLOCK_SIZE;
        }
        else
        {

            n = MIN((SHA256_BLOCK_SIZE - c->l2), msg_bytelen);
            memcpy(c->buf + c->l2, msg, n);
            msg += n;
            c->l2 += n;
            msg_bytelen -= n;

            if (c->l2 == SHA256_BLOCK_SIZE)
            {
                if (!(SHA256_compute(c, c->buf)))
                    return 0;

                c->l2 = 0;
                c->l1 += SHA256_BLOCK_SIZEx8;
            }
        }
    }
    return SUCCESS;
}

int SHA256_final(HashManager *c, uint8_t *out)
{

    int i;
    int off = 0;

    if (c->l2 >= SHA256_BLOCK_SIZE)
        return 0;

    c->l1 += c->l2 << 3;
    c->buf[c->l2++] = (uint8_t)0x80;

    if (c->l2 > 56)
    {
        YBCrypto_memset(c->buf + c->l2, 0, 64 - (c->l2));
        c->l2 = SHA256_BLOCK_SIZE;
        SHA256_compute(c, c->buf);
        c->l2 = 0;
    }

    while (c->l2 < 56)
        c->buf[c->l2++] = 0;

    c->buf[56] = (uint8_t)(c->l1 >> 56);
    c->buf[57] = (uint8_t)(c->l1 >> 48);
    c->buf[58] = (uint8_t)(c->l1 >> 40);
    c->buf[59] = (uint8_t)(c->l1 >> 32);
    c->buf[60] = (uint8_t)(c->l1 >> 24);
    c->buf[61] = (uint8_t)(c->l1 >> 16);
    c->buf[62] = (uint8_t)(c->l1 >> 8);
    c->buf[63] = (uint8_t)(c->l1);

    SHA256_compute(c, c->buf);

    for (i = 0; i < 8; i++)
    {
        off = i << 2;
        (out + off)[3] = (uint8_t)(c->data[i]);
        (out + off)[2] = (uint8_t)(c->data[i] >> 8);
        (out + off)[1] = (uint8_t)(c->data[i] >> 16);
        (out + off)[0] = (uint8_t)(c->data[i] >> 24);
    }
    return SUCCESS;
}

static int SHA256_compute(HashManager *c, uint8_t *data)
{

    int i;
    uint32_t data_temp[8], W[64];
    uint32_t temp, t1, temp2;
    int off = 0;

    data_temp[0] = c->data[0];
    data_temp[1] = c->data[1];
    data_temp[2] = c->data[2];
    data_temp[3] = c->data[3];
    data_temp[4] = c->data[4];
    data_temp[5] = c->data[5];
    data_temp[6] = c->data[6];
    data_temp[7] = c->data[7];

    for (i = 0; i < 16; i++)
    {
        off = i << 2;
        W[i] = (((uint32_t)((data + off)[0] << 24)) |
                ((uint32_t)((data + off)[1] << 16)) |
                ((uint32_t)((data + off)[2] << 8)) |
                ((uint32_t)((data + off)[3])));
    }

    for (i = 16; i < 64; i++)
        W[i] = (S(W[i - 2], 17) ^ S(W[i - 2], 19) ^ R(W[i - 2], 10)) +
               W[i - 7] + (S(W[i - 15], 7) ^ S(W[i - 15], 18) ^ R(W[i - 15], 3)) + W[i - 16];

    for (i = 0; i < 64; ++i)
    {
        t1 = data_temp[7] + (S(data_temp[4], 6) ^ S(data_temp[4], 11) ^ S(data_temp[4], 25)) + F(data_temp[4], data_temp[5], data_temp[6]) + SHA256_K[i] + W[i];
        temp2 = (S(data_temp[0], 2) ^ S(data_temp[0], 13) ^ S(data_temp[0], 22)) + H(data_temp[0], data_temp[1], data_temp[2]);
        data_temp[3] += t1;
        data_temp[7] = t1 + temp2;

        temp = data_temp[7];
        data_temp[7] = data_temp[6];
        data_temp[6] = data_temp[5];
        data_temp[5] = data_temp[4];
        data_temp[4] = data_temp[3];
        data_temp[3] = data_temp[2];
        data_temp[2] = data_temp[1];
        data_temp[1] = data_temp[0];
        data_temp[0] = temp;
    }

    c->data[0] += data_temp[0];
    c->data[1] += data_temp[1];
    c->data[2] += data_temp[2];
    c->data[3] += data_temp[3];
    c->data[4] += data_temp[4];
    c->data[5] += data_temp[5];
    c->data[6] += data_temp[6];
    c->data[7] += data_temp[7];

    return SUCCESS;
}

int SHA256_MD(unsigned char *in, int len, unsigned char *out)
{
    HashManager c;
    if (!SHA256_init(&c))
        return FAIL_CORE;

    if (!SHA256_update(&c, in, len))
        return FAIL_CORE;

    if (!SHA256_final(&c, out))
        return FAIL_CORE;

    return SHA256_DIGEST_LENGTH;
}

//! [SHA-3]/////////////////////////////////////////////////////////////////////////////////////////////////////////
#define KECCAK_SPONGE_BIT 1600
#define KECCAK_ROUND 24
#define KECCAK_SHA3_256 256
#define KECCAK_SHA3_SUFFIX 0x06
#define KECCAK_SHAKE_SUFFIX 0x1F

typedef enum
{
    SHA3_OK = 0,
    SHA3_PARAMETER_ERROR = 1,
} SHA3_RETRUN;

typedef enum
{
    SHA3_SHAKE_NONE = 0,
    SHA3_SHAKE_USE = 1,
} SHA3_USE_SHAKE;

// static unsigned int keccakRate = 0;
// static unsigned int keccakCapacity = 0;
// static unsigned int keccakSuffix = 0;
// static int end_offset;

// static uint8_t keccak_state[KECCAK_STATE_SIZE] = {
//     0x00,
// };

static const uint32_t keccakf_rndc[KECCAK_ROUND][2] =
    {
        {0x00000001, 0x00000000}, {0x00008082, 0x00000000}, {0x0000808a, 0x80000000}, {0x80008000, 0x80000000}, {0x0000808b, 0x00000000}, {0x80000001, 0x00000000}, {0x80008081, 0x80000000}, {0x00008009, 0x80000000}, {0x0000008a, 0x00000000}, {0x00000088, 0x00000000}, {0x80008009, 0x00000000}, {0x8000000a, 0x00000000},

        {0x8000808b, 0x00000000},
        {0x0000008b, 0x80000000},
        {0x00008089, 0x80000000},
        {0x00008003, 0x80000000},
        {0x00008002, 0x80000000},
        {0x00000080, 0x80000000},
        {0x0000800a, 0x00000000},
        {0x8000000a, 0x80000000},
        {0x80008081, 0x80000000},
        {0x00008080, 0x80000000},
        {0x80000001, 0x00000000},
        {0x80008008, 0x80000000}};

static const unsigned keccakf_rotc[KECCAK_ROUND] =
    {
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
        27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};

static const unsigned keccakf_piln[KECCAK_ROUND] =
    {
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

void ROL64(uint32_t *in, uint32_t *out, int offset)
{
    int shift = 0;

    if (offset == 0)
    {
        out[1] = in[1];
        out[0] = in[0];
    }
    else if (offset < 32)
    {
        shift = offset;

        out[1] = (uint32_t)((in[1] << shift) ^ (in[0] >> (32 - shift)));
        out[0] = (uint32_t)((in[0] << shift) ^ (in[1] >> (32 - shift)));
    }
    else if (offset < 64)
    {
        shift = offset - 32;

        out[1] = (uint32_t)((in[0] << shift) ^ (in[1] >> (32 - shift)));
        out[0] = (uint32_t)((in[1] << shift) ^ (in[0] >> (32 - shift)));
    }
    else
    {
        out[1] = in[1];
        out[0] = in[0];
    }
}

void keccakf(uint8_t *state)
{
    uint32_t t[2], bc[5][2], s[25][2] = {
                                 0x00,
                             };
    int i, j, round;

    for (i = 0; i < 25; i++)
    {
        s[i][0] = (uint32_t)(state[i * 8 + 0]) |
                  (uint32_t)(state[i * 8 + 1] << 8) |
                  (uint32_t)(state[i * 8 + 2] << 16) |
                  (uint32_t)(state[i * 8 + 3] << 24);
        s[i][1] = (uint32_t)(state[i * 8 + 4]) |
                  (uint32_t)(state[i * 8 + 5] << 8) |
                  (uint32_t)(state[i * 8 + 6] << 16) |
                  (uint32_t)(state[i * 8 + 7] << 24);
    }

    for (round = 0; round < KECCAK_ROUND; round++)
    {
        /* Theta */
        for (i = 0; i < 5; i++)
        {
            bc[i][0] = s[i][0] ^ s[i + 5][0] ^ s[i + 10][0] ^ s[i + 15][0] ^ s[i + 20][0];
            bc[i][1] = s[i][1] ^ s[i + 5][1] ^ s[i + 10][1] ^ s[i + 15][1] ^ s[i + 20][1];
        }

        for (i = 0; i < 5; i++)
        {
            ROL64(bc[(i + 1) % 5], t, 1);

            t[0] ^= bc[(i + 4) % 5][0];
            t[1] ^= bc[(i + 4) % 5][1];

            for (j = 0; j < 25; j += 5)
            {
                s[j + i][0] ^= t[0];
                s[j + i][1] ^= t[1];
            }
        }

        /* Rho & Pi */
        t[0] = s[1][0];
        t[1] = s[1][1];

        for (i = 0; i < KECCAK_ROUND; i++)
        {
            j = keccakf_piln[i];

            bc[0][0] = s[j][0];
            bc[0][1] = s[j][1];

            ROL64(t, s[j], keccakf_rotc[i]);

            t[0] = bc[0][0];
            t[1] = bc[0][1];
        }

        /* Chi */
        for (j = 0; j < 25; j += 5)
        {
            for (i = 0; i < 5; i++)
            {
                bc[i][0] = s[j + i][0];
                bc[i][1] = s[j + i][1];
            }

            for (i = 0; i < 5; i++)
            {
                s[j + i][0] ^= (~bc[(i + 1) % 5][0]) & bc[(i + 2) % 5][0];
                s[j + i][1] ^= (~bc[(i + 1) % 5][1]) & bc[(i + 2) % 5][1];
            }
        }

        /* Iota */
        s[0][0] ^= keccakf_rndc[round][0];
        s[0][1] ^= keccakf_rndc[round][1];
    }

    for (i = 0; i < 25; i++)
    {
        state[i * 8 + 0] = (uint8_t)(s[i][0]);
        state[i * 8 + 1] = (uint8_t)(s[i][0] >> 8);
        state[i * 8 + 2] = (uint8_t)(s[i][0] >> 16);
        state[i * 8 + 3] = (uint8_t)(s[i][0] >> 24);
        state[i * 8 + 4] = (uint8_t)(s[i][1]);
        state[i * 8 + 5] = (uint8_t)(s[i][1] >> 8);
        state[i * 8 + 6] = (uint8_t)(s[i][1] >> 16);
        state[i * 8 + 7] = (uint8_t)(s[i][1] >> 24);
    }
}

int keccak_absorb(HashManager *c, uint8_t *input, int inLen, int rate, int capacity)
{
    uint8_t *buf = input;
    int iLen = inLen;
    int rateInBytes = rate / 8;
    int blockSize = 0;
    int i = 0;

    if ((rate + capacity) != KECCAK_SPONGE_BIT)
        return SHA3_PARAMETER_ERROR;

    if (((rate % 8) != 0) || (rate < 1))
        return SHA3_PARAMETER_ERROR;

    while (iLen > 0)
    {
        if ((c->end_offset != 0) && (c->end_offset < rateInBytes))
        {
            blockSize = (((iLen + c->end_offset) < rateInBytes) ? (iLen + c->end_offset) : rateInBytes);

            for (i = c->end_offset; i < blockSize; i++)
                c->keccak_state[i] ^= buf[i - c->end_offset];

            buf += blockSize - c->end_offset;
            iLen -= blockSize - c->end_offset;
        }
        else
        {
            blockSize = ((iLen < rateInBytes) ? iLen : rateInBytes);

            for (i = 0; i < blockSize; i++)
                c->keccak_state[i] ^= buf[i];

            buf += blockSize;
            iLen -= blockSize;
        }

        if (blockSize == rateInBytes)
        {
            keccakf(c->keccak_state);
            blockSize = 0;
        }

        c->end_offset = blockSize;
    }

    return SHA3_OK;
}

int keccak_squeeze(HashManager *c, uint8_t *output, int outLen, int rate, int suffix)
{
    uint8_t *buf = output;
    int oLen = outLen;
    int rateInBytes = rate / 8;
    int blockSize = c->end_offset;
    int i = 0;

    c->keccak_state[blockSize] ^= suffix;

    if (((suffix & 0x80) != 0) && (blockSize == (rateInBytes - 1)))
        keccakf(c->keccak_state);

    c->keccak_state[rateInBytes - 1] ^= 0x80;

    keccakf(c->keccak_state);

    while (oLen > 0)
    {
        blockSize = ((oLen < rateInBytes) ? oLen : rateInBytes);
        for (i = 0; i < blockSize; i++)
            buf[i] = c->keccak_state[i];
        buf += blockSize;
        oLen -= blockSize;

        if (oLen > 0)
            keccakf(c->keccak_state);
    }

    return SHA3_OK;
}

int SHA3_init(HashManager *c)
{
    int ret = SUCCESS;

    YBCrypto_memset(c, 0x00, sizeof(HashManager));

    c->keccakCapacity = KECCAK_SHA3_256 * 2;
    c->keccakRate = KECCAK_SPONGE_BIT - c->keccakCapacity;

    c->keccakSuffix = KECCAK_SHA3_SUFFIX;

    YBCrypto_memset(c->keccak_state, 0x00, KECCAK_STATE_SIZE);

    c->end_offset = 0;

    return ret;
}

int SHA3_update(HashManager *c, const uint8_t *msg, uint64_t msg_bytelen)
{
    int ret = SUCCESS;

    uint8_t *msg_buffer = NULL;
    msg_buffer = (uint8_t *)calloc(msg_bytelen,sizeof(uint8_t));
    memcpy(msg_buffer,msg,msg_bytelen);

    return keccak_absorb(c,msg_buffer, msg_bytelen, c->keccakRate, c->keccakCapacity);

    YBCrypto_memset(msg_buffer,0x00,msg_bytelen);
    if(msg_buffer) free(msg_buffer);
    
    return ret;
}

int SHA3_final(HashManager *c, uint8_t *md)
{
    int ret = SUCCESS;

    ret = keccak_squeeze(c, md, KECCAK_SHA3_256/8, c->keccakRate, c->keccakSuffix);

    YBCrypto_memset(c, 0x00, sizeof(HashManager));

    return ret;
}

int SHA3_MD(unsigned char *in, int in_bytelen, unsigned char *out)
{
    int ret = 0;
    HashManager c;

    SHA3_init(&c);

    SHA3_update(&c, in, in_bytelen);

    ret = SHA3_final(&c, out);

    return ret;
}
//EOF