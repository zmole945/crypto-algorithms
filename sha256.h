/**
 * \file   sha256.h
 * \brief
 *      SHA256摘要算法的C语言实现 \n
 *
 *      當前维护者：Shiz(zmole945@163.com) \n
 *      感谢創建最初源碼的Brad Conte (brad AT bradconte.com)
 */

#ifndef _SH256_H_
#define _SH256_H_

/*************************** HEADER FILES ***************************/
#include <stddef.h>

/****************************** MACROS ******************************/
/**
 * \def    SHA256_BLOCK_SIZE
 * \brief
 *       SHA256輸出結果為32字節哈希數
 */
#define SHA256_BLOCK_SIZE 32

/**************************** DATA TYPES ****************************/
/**
 * \typedef BYTE
 * \brief  定義8位數據類型
 */
typedef unsigned char BYTE;

/**
 * \typedef WORD
 * \brief  定義32位數據類型,在16位機器上使用long代替int
 */
typedef unsigned int  WORD;

/**
 * \struct SHA256_CTX
 * \brief  定義SHA256摘要算法上下文機構體
 */
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

#endif   // _SH256_H_
