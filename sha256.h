/*********************************************************************
 * Filename:   sha256.h
 * Author:     Brad Conte (brad AT bradconte.com)
 * Copyright:
 * Disclaimer: This code is presented "as is" without any guarantees.
 * Details:    Defines the API for the corresponding SHA1 implementation.
 *********************************************************************/

#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>

/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32    // SHA256輸出結果為32字節哈希數

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;     // 8-bit byte
typedef unsigned int  WORD;     // 32-bit word, change to "long" for 16-bit machines

typedef struct {
    BYTE data[64];
    WORD datalen;
    unsigned long long bitlen;
    WORD state[8];
} SHA256_CTX;

/*********************** FUNCTION DECLARATIONS **********************/

//=================================================
/// -
/// sha256 摘要算法初始化
/// @param ctx    算法上下文，包含算法相關參數，中間結果等
/// @return       des result good/bad
/// -
void sha256_init(SHA256_CTX *ctx);

//=================================================
/// -
/// sha256 摘要加密算法更新分組計算結果
/// @param ctx    算法上下文，包含算法相關參數，中間結果等
/// @param data   分組數據
/// @param len    分組數據長度
/// @return       des result good/bad
/// -
void sha256_update( SHA256_CTX  *ctx,
                    const BYTE  data[],
                    size_t      len);

//=================================================
/// -
/// sha256 摘要加密算法結果輸出
/// @param ctx    算法上下文，包含算法相關參數，中間結果等
/// @param hash   摘要算法結果哈希數
/// @return       des result good/bad
/// -
void sha256_final(SHA256_CTX *ctx, BYTE hash[]);


#endif   // SHA256_H
