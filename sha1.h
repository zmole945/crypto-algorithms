/*********************************************************************
 * Filename:   sha1.h
 * Author:     Brad Conte (brad AT bradconte.com)
 * Copyright:
 * Disclaimer: This code is presented "as is" without any guarantees.
 * Details:    Defines the API for the corresponding SHA1 implementation.
 *********************************************************************/

#ifndef SHA1_H
#define SHA1_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>

/****************************** MACROS ******************************/
#define SHA1_BLOCK_SIZE 20              // SHA1 outputs a 20 byte digest

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD;             // 32-bit word, change to "long" for 16-bit machines

typedef struct {
    BYTE data[64];
    WORD datalen;
    unsigned long long bitlen;
    WORD state[5];
    WORD k[4];
} SHA1_CTX;

/*********************** FUNCTION DECLARATIONS **********************/

//=================================================
/// -
/// sha1 摘要算法初始化
/// @param ctx    算法上下文，包含算法相關參數，中間結果等
/// @return       des result good/bad
/// -
void sha1_init(SHA1_CTX *ctx);

//=================================================
/// -
/// sha1 摘要加密算法更新分組計算結果
/// @param ctx    算法上下文，包含算法相關參數，中間結果等
/// @param data   分組數據
/// @param len    分組數據長度
/// @return       des result good/bad
/// -
void sha1_update(   SHA1_CTX    *ctx,
                    const BYTE  data[],
                    size_t      len);

//=================================================
/// -
/// sha1 摘要加密算法結果輸出
/// @param ctx    算法上下文，包含算法相關參數，中間結果等
/// @param hash   摘要算法結果哈係數
/// @return       des result good/bad
/// -
void sha1_final(SHA1_CTX *ctx, BYTE hash[]);

#endif   // SHA1_H
