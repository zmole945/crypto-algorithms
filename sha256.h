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
#include <stdint.h>

#include "cryptoalg_data_type.h"

/****************************** MACROS ******************************/
/**
 * \def    SHA256_BLOCK_SIZE
 * \brief
 *       SHA256輸出結果為32字節哈希數
 */
#define SHA256_BLOCK_SIZE 32

/**************************** DATA TYPES ****************************/
/**
 * \struct sha256_ctx_t
 * \brief
 *      定義SHA256摘要算法上下文機構體
 */
typedef struct {
    uint8_t     data[64];
    uint32_t    datalen;
    uint64_t    bitlen;
    uint32_t    state[8];
} sha256_ctx_t;

/*********************** FUNCTION DECLARATIONS **********************/
#ifdef __cplusplus
extern "C" {
#endif
/**
 * \brief
 *      SHA256摘要算法初始化
 *
 * \param ctx   算法上下文，包含算法相關參數，中間結果等
 * \return      初始化是否成功，成功返回0
 */
int sha256_init(sha256_ctx_t *ctx);
 
/**
 * \brief
 *      摘要算法更新分組計算結果
 *
 * \param ctx    算法上下文，包含算法相關參數，中間結果等
 * \param data   分組數據
 * \param len    分組數據長度
 *
 * \return       更新分組是否成功，成功返回0
 */
int sha256_update(  sha256_ctx_t    *ctx,
                    const uint8_t   data[],
                    size_t          len);

/**
 * \brief
 *      摘要算法結果輸出
 *
 * \param ctx    算法上下文，包含算法相關參數，中間結果等
 * \param hash   摘要算法結果哈希數
 *
 * \return       算法輸出結果是否成功，成功返回0
 */
int sha256_final(   sha256_ctx_t    *ctx,
                    uint8_t         hash[]);
#ifdef __cplusplus
}
#endif

#endif   // _SH256_H_
