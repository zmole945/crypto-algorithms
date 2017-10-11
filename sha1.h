/**
 * \file   sha1.h
 * \brief
 *       SHA1摘要算法的C语言实现 \n
 *
 *       當前维护者：Shiz(zmole945@163.com) \n
 *       感谢創建最初源碼的Brad Conte (brad AT bradconte.com)
 */

#ifndef _SHA1_H_
#define _SHA1_H_

/*************************** HEADER FILES ***************************/
#include <stddef.h>

/****************************** MACROS ******************************/

/**
 * \def    SHA1_BLOCK_SIZE
 * \brief
 *       SHA1輸出結果為20字節哈希數
 */
#define SHA1_BLOCK_SIZE 20

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
 * \struct sha1_ctx_t
 * \brief  定義SHA1摘要算法上下文機構體
 */
typedef struct {
    BYTE data[64];
    WORD datalen;
    unsigned long long bitlen;
    WORD state[5];
    WORD k[4];
} sha1_ctx_t;

/*********************** FUNCTION DECLARATIONS **********************/
/**
 * \brief
 *      摘要算法初始化
 * 
 * \param ctx    算法上下文，包含算法相關參數，中間結果等
 * \return       初始化是否成功，成功返回0
 */
int sha1_init(sha1_ctx_t *ctx);

/**
 * \brief
 *      摘要算法更新分組計算結果
 * \param ctx    算法上下文，包含算法相關參數，中間結果等
 * \param data   分組數據
 * \param len    分組數據長度
 * \return       更新分組是否成功，成功返回0
 */
int sha1_update(sha1_ctx_t  *ctx,
                const BYTE  data[],
                size_t      len);

/**
 * \brief
 *      摘要算法結果輸出
 * \param ctx    算法上下文，包含算法相關參數，中間結果等
 * \param hash   摘要算法結果哈希數
 * \return       算法輸出結果是否成功，成功返回0
 */
int sha1_final(sha1_ctx_t   *ctx,
               BYTE         hash[]);

#endif   // _SHA1_H_
