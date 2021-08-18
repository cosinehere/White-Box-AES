// WhiteboxAES.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "WhiteboxAESTable.h"

void ShiftRows(uint8_t state[16])
{
    constexpr int Shifts[16] = { 0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11 };
    uint8_t temp[16];
    memcpy(temp, state, sizeof(uint8_t)*16);
    for (int i = 0; i < 16; ++i) state[i] = temp[Shifts[i]];
}

void wbAES(uint8_t plain[16], uint8_t cipher[16])
{
    for (int r = 0; r < Nr - 1; ++r)
    {
        ShiftRows(plain);

        for (int i = 0; i < 4; ++i)
        {
            uint32_t a = Tyboxes[r][i * 4][plain[i * 4]],
                b = Tyboxes[r][i * 4 + 1][plain[i * 4 + 1]],
                c = Tyboxes[r][i * 4 + 2][plain[i * 4 + 2]],
                d = Tyboxes[r][i * 4 + 3][plain[i * 4 + 3]];

            for (int j = 0; j < 4; ++j)
            {
                uint8_t n0 = Xor[r][j * 24 + 6 * j + 0][(a >> (28 - 8 * j)) & 0xf][(b >> (28 - 8 * j)) & 0xf];
                uint8_t n1 = Xor[r][i * 24 + 6 * j + 1][(c >> (28 - 8 * j)) & 0xf][(d >> (28 - 8 * j)) & 0xf];
                uint8_t n2 = Xor[r][i * 24 + 6 * j + 2][(a >> (24 - 8 * j)) & 0xf][(b >> (24 - 8 * j)) & 0xf];
                uint8_t n3 = Xor[r][i * 24 + 6 * j + 3][(c >> (24 - 8 * j)) & 0xf][(d >> (24 - 8 * j)) & 0xf];
                plain[i * 4 + j] = (Xor[r][i * 24 + 6 * j + 4][n0][n1] << 4) | (Xor[r][i * 24 + 6 * j + 5][n2][n3]);
            }

            a = MBL[r][i * 4 + 0][plain[i * 4 + 0]];
            b = MBL[r][i * 4 + 1][plain[i * 4 + 1]];
            c = MBL[r][i * 4 + 2][plain[i * 4 + 2]];
            d = MBL[r][i * 4 + 3][plain[i * 4 + 3]];

            for (int j = 0; j < 4; ++j)
            {
                uint8_t n0 = Xor[r][j * 24 + 6 * j + 0][(a >> (28 - 8 * j)) & 0xf][(b >> (28 - 8 * j)) & 0xf];
                uint8_t n1 = Xor[r][i * 24 + 6 * j + 1][(c >> (28 - 8 * j)) & 0xf][(d >> (28 - 8 * j)) & 0xf];
                uint8_t n2 = Xor[r][i * 24 + 6 * j + 2][(a >> (24 - 8 * j)) & 0xf][(b >> (24 - 8 * j)) & 0xf];
                uint8_t n3 = Xor[r][i * 24 + 6 * j + 3][(c >> (24 - 8 * j)) & 0xf][(d >> (24 - 8 * j)) & 0xf];
                plain[i * 4 + j] = (Xor[r][i * 24 + 6 * j + 4][n0][n1] << 4) | (Xor[r][i * 24 + 6 * j + 5][n2][n3]);
            }
        }
    }

    ShiftRows(plain);

    for (int i = 0; i < 16; ++i)
    {
        cipher[i] = TboxesLast[i][plain[i]];
    }
}

void ctr(uint8_t *plain, size_t plainlen, uint8_t *cipher, uint8_t nonce[16])
{
    uint8_t counter[16], buf[16];
    memcpy(counter, nonce, sizeof(uint8_t)*16);

    for (size_t i = 0; i < plainlen; ++i)
    {
        if (!(i & 0xf))
        {
            memcpy(buf, counter, sizeof(uint8_t) * 16);
            wbAES(buf, buf);

            for (int j = 15; j >= 0; --j)
            {
                counter[j]++;
                if (counter[j])
                {
                    break;
                }
            }
        }
        cipher[i] = plain[i] ^ buf[i & 0xf];
    }
}

int main()
{
    uint8_t plain[] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
        0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
        0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
        0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
        0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
        0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10 };
    size_t len = 64;
    uint8_t cipher[64];
    uint8_t nonce[16] = { 0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff };
    ctr(plain, len, cipher, nonce);

    for (size_t i = 0; i < len; ++i)
    {
        printf("%02x ", cipher[i]);
    }
    printf("\n");

    uint8_t c[] = { 0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,
        0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce,
        0x98,0x06,0xf6,0x6b,0x79,0x70,0xfd,0xff,
        0x86,0x17,0x18,0x7b,0xb9,0xff,0xfd,0xff,
        0x5a,0xe4,0xdf,0x3e,0xdb,0xd5,0xd3,0x5e,
        0x5b,0x4f,0x09,0x02,0x0d,0xb0,0x3e,0xab,
        0x1e,0x03,0x1d,0xda,0x2f,0xbe,0x03,0xd1,
        0x79,0x21,0x70,0xa0,0xf3,0x00,0x9c,0xee };
    uint8_t p[64];
    ctr(c, len, p, nonce);
    for (size_t i = 0; i < len; ++i)
    {
        printf("%02x ", p[i]);
    }
    printf("\n");

    for (size_t i = 0; i < len; ++i)
    {
        printf("%02x ", plain[i]);
    }
    printf("\n");
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
