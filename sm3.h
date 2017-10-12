/**
 *  \file   sm3.h
 *  \brief
 *      SM3摘要算法的C语言实现 \n
 *
 *      SM3標準：\n
 *      http://www.oscca.gov.cn/News/201012/News_1199.htm \n
 *
 *      當前维护者：Shiz(zmole945@163.com) \n
 *      感谢創建最初源碼的xyssl以及goldboar(goldboar@163.com)
 */

#ifndef XYSSL_SM3_H
#define XYSSL_SM3_H

/*************************** HEADER FILES ***************************/
#include <stdint.h>

/****************************** MACROS ******************************/

/**************************** DATA TYPES ****************************/
/**
 *  \struct sm3_ctx_t
 *  \brief
 *      SM3摘要算法上下文結構體
 */
typedef struct
{
    uint32_t    total[2];
    uint32_t    state[8];
    uint8_t     buffer[64];

    uint8_t     ipad[64];
    uint8_t     opad[64];
}
sm3_ctx_t;

#ifdef __cplusplus
extern "C" {
#endif

/*********************** FUNCTION DECLARATIONS **********************/
/**
 * \brief
 *      SM3摘要算法初始化
 *
 * \param ctx   算法上下文數據結構
 *
 * \return      初始化是否成功，成功返回0
 */
int sm3_init( sm3_ctx_t *ctx );

/**
 * \brief
 *      SM3摘要算法更新分組計算結果
 *
 * \param ctx       SM3算法上下文數據結構
 * \param input     輸入數據首地址
 * \param ilen      輸入數據長度(字節)
 *
 * \return          更新分組是否成功，成功返回0
 */
int sm3_update( sm3_ctx_t   *ctx,
                uint8_t     *input,
                uint32_t    ilen);

/**
 * \brief
 *      SM3摘要算法輸出計算的結果
 *
 * \param ctx       SM3算法上下文數據結構
 * \param output    摘要算法結果哈希數
 *
 * \return          算法輸出結果是否成功，成功返回0
 */
int sm3_final(  sm3_ctx_t   *ctx,
                uint8_t     output[32]);

/**
 * \brief
 *      SM3摘要算法完整封裝 \n
 *      包含初始化，更新分組，輸出結果整個算法流程
 *
 * \param input     輸入數據首地址
 * \param ilen      輸入數據長度(字節)
 * \param output    摘要算法結果哈希數
 *
 * \return          算法運行是否成功，成功返回0
 */
int sm3_alg(uint8_t     *input,
            uint32_t    ilen,
            uint8_t     output[32]);

#ifdef __cplusplus
}
#endif

#endif /* sm3.h */

