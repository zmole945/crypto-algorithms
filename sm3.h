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

/**
 *  \struct sm3_context
 *  \brief  SM3摘要算法上下文結構體
 */
typedef struct
{
    unsigned long total[2];     /*!< number of bytes processed  */
    unsigned long state[8];     /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */

    unsigned char ipad[64];     /*!< HMAC: inner padding        */
    unsigned char opad[64];     /*!< HMAC: outer padding        */

}
sm3_context;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief       SM3 context setup
 *
 * \param ctx   context to be initialized
 */
void sm3_starts( sm3_context *ctx );

/**
 * \brief          SM3 process buffer
 *
 * \param ctx      SM3 context
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 */
void sm3_update(sm3_context     *ctx,
                unsigned char   *input,
                int             ilen);

/**
 * \brief          SM3 final digest
 *
 * \param ctx      SM3 context
 */
void sm3_finish(sm3_context     *ctx,
                unsigned char   output[32]);

/**
 * \brief          Output = SM3( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   SM3 checksum result
 */
void sm3(   unsigned char   *input,
            int             ilen,
            unsigned char   output[32]);

#ifdef __cplusplus
}
#endif

#endif /* sm3.h */

