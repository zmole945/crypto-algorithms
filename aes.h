/**
 * \file   aes.h
 * \brief
 *       aes對稱加密算法算法的C语言实现 \n
 *
 *       當前维护者：Shiz(zmole945@163.com) \n
 *       感谢創建最初源碼的Brad Conte (brad AT bradconte.com)
 */

#ifndef AES_H
#define AES_H

/*************************** HEADER FILES ***************************/
#include <stdint.h>

#include "cryptoalg_data_type.h"

/****************************** MACROS ******************************/
/**
 * \def    AES_BLOCK_SIZE
 * \brief
 *       AES加密算法單個分組大小16字節
 */
#define AES_BLOCK_SIZE 16

/**************************** DATA TYPES ****************************/


/*********************** FUNCTION DECLARATIONS **********************/
/**
 * \brief
 *      AES密鑰初始化，加密前需要完成該設置
 *
 * \param key       密鑰首地址，只接受128,192或256位的密鑰 \n
 * \param w         計算出的key schedule加密時使用
 * \param keysize   密鑰位數，可以取128,192,256
 *
 * \return          初始化是否成功，成功返回0
 */
void aes_key_setup(const BYTE   key[],  /*ldskjflkadsjfl;k */
                   WORD         w[],
                   int          keysize);

/**
 * \brief
 *      AES單個分組加密
 *
 * \param in        明文數據輸入首地址，明文長度16字節
 * \param out       密文結果輸出首地址，密文長度16字節
 * \param key       密鑰初始化時，計算出的key schedule
 * \param keysize   密鑰位數，可以取128,192,256
 *
 * \return          加密是否成功，成功返回0
 */
void aes_encrypt(const BYTE     in[],
                 BYTE           out[],
                 const WORD     key[],
                 int            keysize);

/**
 * \brief
 *      AES單個分組解密
 *
 * \param in        密文數據輸入首地址，密文長度16字節
 * \param out       明文結果輸出首地址，明文長度16字節
 * \param key       密鑰初始化時，計算出的key schedule
 * \param keysize   密鑰位數，可以取128,192,256
 *
 * \return          解密是否成功，成功返回0
 */
void aes_decrypt(const BYTE     in[],
                 BYTE           out[],
                 const WORD     key[],
                 int            keysize);

/**
 * \brief
 *      AES加密ECB模式
 *
 * \param in        明文數據輸入首地址
 * \param in_len    明文數據輸入長度，以字節為單位
 * \param out       密文結果輸出首地址
 * \param key       密鑰初始化時，計算出的key schedule
 * \param keysize   密鑰位數，可以取128,192,256
 *
 * \return          AES的ECB模式加密是否成功，成功返回0
 */
int aes_encrypt_ecb(const BYTE  in[],
                    size_t      in_len,
                    BYTE        out[],
                    const WORD  key[],
                    int         keysize);

/**
 * \brief
 *      AES解密ECB模式
 *
 * \param in        密文數據輸入首地址
 * \param in_len    密文數據輸入長度，以字節為單位
 * \param out       明文結果輸出首地址
 * \param key       密鑰初始化時，計算出的key schedule
 * \param keysize   密鑰位數，可以取128,192,256
 *
 * \return          AES的ECB模式解密是否成功，成功返回0
 */
int aes_decrypt_ecb(const BYTE  in[],
                    size_t      in_len,
                    BYTE        out[],
                    const WORD  key[],
                    int         keysize);

/**
 * \brief
 *      AES加密CBC模式
 *
 * \param in        明文數據輸入首地址
 * \param in_len    明文數據輸入長度，以字節為單位
 * \param out       密文結果輸出首地址
 * \param key       密鑰初始化時，計算出的key schedule
 * \param keysize   密鑰位數，可以取128,192,256
 * \param iv        CBC模式初始化向量，長度為16字節
 *
 * \return          AES的CBC模式加密是否成功，成功返回0
 */
int aes_encrypt_cbc(const BYTE  in[],
                    size_t      in_len,
                    BYTE        out[],
                    const WORD  key[],
                    int         keysize,
                    const BYTE  iv[]);

/**
 * \brief
 *      AES解密CBC模式
 *
 * \param in        密文數據輸入首地址
 * \param in_len    密文數據輸入長度，以字節為單位
 * \param out       明文結果輸出首地址
 * \param key       密鑰初始化時，計算出的key schedule
 * \param keysize   密鑰位數，可以取128,192,256
 * \param iv        CBC模式初始化向量，長度為16字節
 *
 * \return          AES的CBC模式解密是否成功，成功返回0
 */
int aes_decrypt_cbc(const BYTE  in[],
                    size_t      in_len,
                    BYTE        out[],
                    const WORD  key[],
                    int         keysize,
                    const BYTE  iv[]);

#endif   // AES_H
