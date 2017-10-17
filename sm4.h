/**
 * \file   sm4.h
 * \brief
 *       sm4對稱加密算法算法的C语言实现 \n
 *
 *       當前维护者：Shiz(zmole945@163.com) \n
 *       感谢創建最初源碼的xyssl以及goldboar(goldboar@163.com)
 */

#ifndef XYSSL_SM4_H
#define XYSSL_SM4_H

/*************************** HEADER FILES ***************************/
#include <stdint.h>

/****************************** MACROS ******************************/
#define SM4_ENCRYPT     1
#define SM4_DECRYPT     0
/**
 * \def    SM4_BLOCK_SIZE
 * \brief
 *       SM4加密算法單個分組大小16字節
 */
#define SM4_BLOCK_SIZE 16

/**************************** DATA TYPES ****************************/
/**
 * \brief          SM4加密算法上下文數據結構
 */
typedef struct
{
    int mode;                   /*!<  encrypt/decrypt   */
    unsigned long sk[32];       /*!<  SM4 subkeys       */
}
sm4_context;


/*********************** FUNCTION DECLARATIONS **********************/
#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          SM4 key schedule (128-bit, encryption)
 *
 * \param ctx      SM4 context to be initialized
 * \param key      16-byte secret key
 */
void sm4_setkey_enc(sm4_context     *ctx,
                    unsigned char   key[16]);

/**
 * \brief          SM4 key schedule (128-bit, decryption)
 *
 * \param ctx      SM4 context to be initialized
 * \param key      16-byte secret key
 */
void sm4_setkey_dec(sm4_context     *ctx,
                    unsigned char   key[16]);

/**
 * \brief          SM4-ECB block encryption/decryption
 * \param ctx      SM4 context
 * \param mode     SM4_ENCRYPT or SM4_DECRYPT
 * \param length   length of the input data
 * \param input    input block
 * \param output   output block
 */
void sm4_crypt_ecb( sm4_context     *ctx,
                    int             mode,
                    int             length,
                    unsigned char   *input,
                    unsigned char   *output);

/**
 * \brief          SM4-CBC buffer encryption/decryption
 * \param ctx      SM4 context
 * \param mode     SM4_ENCRYPT or SM4_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 */
void sm4_crypt_cbc( sm4_context     *ctx,
                    int             mode,
                    int             length,
                    unsigned char   iv[16],
                    unsigned char   *input,
                    unsigned char   *output);

#ifdef __cplusplus
}
#endif

#endif /* sm4.h */
