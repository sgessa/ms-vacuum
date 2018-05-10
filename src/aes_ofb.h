#include "aes.h"

uint16_t const MS_VERSION = 62;

// internalfn
void ms_aes_ofb_transform(uint8_t* buf, uint8_t* iv,
    intptr_t nbytes, uint8_t* const aeskey)
{
    uint8_t input[16] = {0};
    uint8_t output[16] = {0};
    uint8_t plaintext[16] = {0};
    uint8_t expanded_iv[16] = {0};

    uint8_t i, j;
    intptr_t chunks;
    intptr_t offset;

    for (i = 0; i < 16; ++i) {
        expanded_iv[i] = iv[i % 4];
    }

    /* first iteration (initializes input) */
    aes_transform(expanded_iv, output, aeskey, 32);

    for (i = 0; i < 16; ++i) {
        plaintext[i] = output[i] ^ buf[i];
    }

    chunks = nbytes / 16 + 1;

    if (chunks == 1)
    {
        memcpy(buf, plaintext, (size_t)nbytes);
        return;
    }

    memcpy(buf, plaintext, 16);
    memcpy(input, output, 16);

    /* all chunks except the last one */
    for (i = 1; i < chunks - 1; ++i)
    {
        aes_transform(input, output, aeskey, 32);
        offset = i * 16;

        for (j = 0; j < 16; ++j) {
            plaintext[j] = output[j] ^ buf[offset + j];
        }

        memcpy(buf + offset, plaintext, 16);
        memcpy(input, output, 16);
    }

    /* last chunk */
    aes_transform(input, output, aeskey, 32);

    offset = (chunks - 1) * 16;

    for (i = 0; i < 16; ++i) {
        plaintext[i] = output[i] ^ buf[offset + i];
    }

    memcpy(buf + offset, plaintext, (size_t)(nbytes % 16));
    memcpy(input, output, 16);
}

// internalfn
void ms_aes_ofb(uint8_t* buf, uint8_t* iv,
    intptr_t nbytes, uint8_t const* key)
{
    intptr_t pos = 0, first = 1;

    /* no idea why this is required or what it does */
    while (nbytes > pos)
    {
        if (nbytes > pos + 1460 - first * 4) {
            ms_aes_ofb_transform(buf, iv, 1460 - first * 4, key);
        }
        else {
            ms_aes_ofb_transform(buf, iv, nbytes - pos, key);
        }

        pos += 1460 - first * 4;

        if (first) {
            first = 0;
        }
    }
}

// internalfn
void ms_shuffle_iv(uint8_t* iv)
{
    uint8_t shit[256] = {
        0xec, 0x3f, 0x77, 0xa4, 0x45, 0xd0, 0x71, 0xbf, 0xb7, 0x98,
        0x20, 0xfc, 0x4b, 0xe9, 0xb3, 0xe1, 0x5c, 0x22, 0xf7, 0x0c,
        0x44, 0x1b, 0x81, 0xbd, 0x63, 0x8d, 0xd4, 0xc3, 0xf2, 0x10,
        0x19, 0xe0, 0xfb, 0xa1, 0x6e, 0x66, 0xea, 0xae, 0xd6, 0xce,
        0x06, 0x18, 0x4e, 0xeb, 0x78, 0x95, 0xdb, 0xba, 0xb6, 0x42,
        0x7a, 0x2a, 0x83, 0x0b, 0x54, 0x67, 0x6d, 0xe8, 0x65, 0xe7,
        0x2f, 0x07, 0xf3, 0xaa, 0x27, 0x7b, 0x85, 0xb0, 0x26, 0xfd,
        0x8b, 0xa9, 0xfa, 0xbe, 0xa8, 0xd7, 0xcb, 0xcc, 0x92, 0xda,
        0xf9, 0x93, 0x60, 0x2d, 0xdd, 0xd2, 0xa2, 0x9b, 0x39, 0x5f,
        0x82, 0x21, 0x4c, 0x69, 0xf8, 0x31, 0x87, 0xee, 0x8e, 0xad,
        0x8c, 0x6a, 0xbc, 0xb5, 0x6b, 0x59, 0x13, 0xf1, 0x04, 0x00,
        0xf6, 0x5a, 0x35, 0x79, 0x48, 0x8f, 0x15, 0xcd, 0x97, 0x57,
        0x12, 0x3e, 0x37, 0xff, 0x9d, 0x4f, 0x51, 0xf5, 0xa3, 0x70,
        0xbb, 0x14, 0x75, 0xc2, 0xb8, 0x72, 0xc0, 0xed, 0x7d, 0x68,
        0xc9, 0x2e, 0x0d, 0x62, 0x46, 0x17, 0x11, 0x4d, 0x6c, 0xc4,
        0x7e, 0x53, 0xc1, 0x25, 0xc7, 0x9a, 0x1c, 0x88, 0x58, 0x2c,
        0x89, 0xdc, 0x02, 0x64, 0x40, 0x01, 0x5d, 0x38, 0xa5, 0xe2,
        0xaf, 0x55, 0xd5, 0xef, 0x1a, 0x7c, 0xa7, 0x5b, 0xa6, 0x6f,
        0x86, 0x9f, 0x73, 0xe6, 0x0a, 0xde, 0x2b, 0x99, 0x4a, 0x47,
        0x9c, 0xdf, 0x09, 0x76, 0x9e, 0x30, 0x0e, 0xe4, 0xb2, 0x94,
        0xa0, 0x3b, 0x34, 0x1d, 0x28, 0x0f, 0x36, 0xe3, 0x23, 0xb4,
        0x03, 0xd8, 0x90, 0xc8, 0x3c, 0xfe, 0x5e, 0x32, 0x24, 0x50,
        0x1f, 0x3a, 0x43, 0x8a, 0x96, 0x41, 0x74, 0xac, 0x52, 0x33,
        0xf0, 0xd9, 0x29, 0x80, 0xb1, 0x16, 0xd3, 0xab, 0x91, 0xb9,
        0x84, 0x7f, 0x61, 0x1e, 0xcf, 0xc5, 0xd1, 0x56, 0x3d, 0xca,
        0xf4, 0x05, 0xc6, 0xe5, 0x08, 0x49
    };

    uint8_t newiv[4] = { 0xf2, 0x53, 0x50, 0xc6 };
    uint32_t* newiv_u32 = (uint32_t*)newiv;
    uint8_t i;

    for (i = 0; i < 4; ++i)
    {
        uint8_t input = iv[i];
        uint8_t value_input = shit[input];
        uint32_t full_iv, shift;

        newiv[0] = (uint8_t)(newiv[0] + shit[newiv[1]] - input);
        newiv[1] = (uint8_t)(newiv[1] - (newiv[2] ^ value_input));
        newiv[2] = (uint8_t)(newiv[2] ^ (shit[newiv[3]] + input));
        newiv[3] = (uint8_t)(newiv[3] - newiv[0] + value_input);

        full_iv = *newiv_u32;
        shift = full_iv >> 0x1D | full_iv << 0x03;

        *newiv_u32 = shift;
    }

    memcpy(iv, newiv, 4);
}

// internalfn
uint8_t rol(uint8_t v, uint32_t n)
{
    uint32_t i;
    uint8_t msb;

    for(i = 0; i < n; ++i)
    {
        msb = v & 0x80 ? 1 : 0;
        v = (uint8_t)(v<<1);
        v |= msb;
    }

    return v;
}

// internalfn
uint8_t ror(uint8_t v, uint32_t n)
{
    uint32_t i;
    uint8_t lsb;

    for(i = 0; i < n; ++i)
    {
        lsb = (uint8_t)(v & 1 ? 0x80 : 0);
        v >>= 1;
        v |= lsb;
    }

    return v;
}

// internalfn
void ms_encrypt(uint8_t* buf, uint32_t nbytes)
{
    uint8_t i;
    uint32_t j;
    uint8_t a, c;

    for (i = 0; i < 3; ++i)
    {
        a = 0;

        for (j = nbytes; j; --j)
        {
            c = buf[nbytes - j];
            c = rol(c, 3);
            c = (uint8_t)(c + j);
            c ^= a;
            a = c;
            c = ror(a, j);
            c ^= 0xFF;
            c = (uint8_t)(c + 0x48);
            buf[nbytes - j] = c;
        }

        a = 0;

        for (j = nbytes; j; --j)
        {
            c = buf[j - 1];
            c = rol(c, 4);
            c = (uint8_t)(c + j);
            c ^= a;
            a = c;
            c ^= 0x13;
            c = ror(c, 3);
            buf[j - 1] = c;
        }
    }
}

// internalfn
void ms_decrypt(uint8_t* buf, uint32_t nbytes)
{
    uint8_t i;
    uint32_t j;
    uint8_t a, b, c;

    for (i = 0; i < 3; ++i)
    {
        a = 0;
        b = 0;

        for (j = nbytes; j; --j)
        {
            c = buf[j - 1];
            c = rol(c, 3);
            c ^= 0x13;
            a = c;
            c ^= b;
            c = (uint8_t)(c - j);
            c = ror(c, 4);
            b = a;
            buf[j - 1] = c;
        }

        a = 0;
        b = 0;

        for (j = nbytes; j; --j)
        {
            c = buf[nbytes - j];
            c = (uint8_t)(c - 0x48);
            c ^= 0xFF;
            c = rol(c, j);
            a = c;
            c ^= b;
            c = (uint8_t)(c - j);
            c = ror(c, 3);
            b = a;
            buf[nbytes - j] = c;
        }
    }
}

// internalfn
uint32_t ms_encrypted_hdr(uint8_t* iv, uint32_t nbytes)
{
    /* the lowest 16 bits are the high part of the send IV,
       xored with ffff - mapleversion or -(mapleversion + 1).

       the highest 16 bits are the low part xored with the size of
       the packet to obtain the packet size we simply hor the low
       part with the high part again */

    uint16_t* high_iv = (uint16_t*)(iv + 2);
    uint16_t lowpart = *high_iv;
    uint16_t hipart;

    uint16_t version = MS_VERSION;
    version = (uint16_t)(0xFFFF - version);
    lowpart ^= version;

    hipart = lowpart ^ nbytes;

    return (uint32_t)(lowpart | hipart << 16);
}
