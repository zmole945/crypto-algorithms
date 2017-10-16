/**
 * \file   des.h
 * \brief
 *       des對稱加密算法算法的C语言实现 \n
 *
 *       當前维护者：Shiz(zmole945@163.com) \n
 *       感谢創建最初源碼的Brad Conte (brad AT bradconte.com)
 */

#ifndef DES_H
#define DESH

/*************************** HEADER FILES ***************************/
#include <stdint.h>

#include "cryptoalg_data_type.h"

/****************************** MACROS ******************************/
/**
 * \def    DES_BLOCK_SIZE
 * \brief
 *       DES加密算法單個分組大小8字節
 */
#define DES_BLOCK_SIZE 8

/**************************** DATA TYPES ****************************/
typedef enum {
    DES_ENCRYPT,
    DES_DECRYPT,
} DES_MODE;

typedef enum {
    MODE_ENCRYPT,
    MODE_DECRYPT,
} des_mode_t;

/*********************** FUNCTION DECLARATIONS **********************/

/**
 * \brief
 *      DES加解密算法
 *
 * \param in     輸入數據首地址，數據長度為8字節
 * \param out    輸出數據首地址，數據長度為8字節
 * \param key    密鑰首地址，密鑰長度8字節
 * \param mode   加密/解密
 *
 * \return       DES算法加解密是否成功，成功返回0
 */
int des_alg(    const uint8_t   *in,
                uint8_t         *out,
                const uint8_t   *key,
                des_mode_t      mode);

/**
 * \brief
 *      DES密鑰初始化，加密前需要完成該設置
 *
 * \param key       密鑰首地址，密鑰長度8字節
 * \param schedule  計算出的key schedule加密時使用
 * \param mode      加密/解密
 *
 * \return          初始化是否成功，成功返回0
 */
void des_key_setup( const BYTE  key[],
                    BYTE        schedule[][6],
                    DES_MODE    mode);

/**
 * \brief
 *      DES加解密 \n
 *      加密或者解密由密鑰設置時的模式確定
 *
 * \param in    輸入數據首地址，數據長度為8字節
 * \param out   輸出數據首地址，數據長度為8字節
 * \param key   密鑰初始化時計算出的key schedule
 *
 * \return      加解密是否成功，成功返回0
 */
void des_crypt( const BYTE  in[],
                BYTE        out[],
                BYTE        key[][6]);

/**
 * \brief
 *      3DES加解密算法
 *
 * \param in     輸入數據首地址，數據長度為8字節
 * \param out    輸出數據首地址，數據長度為8字節
 * \param key    密鑰首地址，密鑰長度8字節
 * \param mode   加密/解密
 *
 * \return       3DES算法加解密是否成功，成功返回0
 */
int tdes_alg(   const uint8_t   *in,
                uint8_t         *out,
                const uint8_t   *key,
                des_mode_t      mode);

/**
 * \brief
 *      3DES密鑰初始化，加密前需要完成該設置
 *
 * \param key       密鑰首地址，密鑰長度24字節
 * \param schedule  計算出的key schedule加密時使用
 * \param mode      加密/解密
 *
 * \return          初始化是否成功，成功返回0
 */
void three_des_key_setup(   const BYTE  key[],
                            BYTE        schedule[][16][6],
                            DES_MODE    mode);

/**
 * \brief
 *      3DES加解密 \n
 *      加密或者解密由密鑰設置時的模式確定
 *
 * \param in    輸入數據首地址，數據長度為8字節
 * \param out   輸出數據首地址，數據長度為8字節
 * \param key   密鑰初始化時計算出的key schedule
 *
 * \return      加解密是否成功，成功返回0
 */
void three_des_crypt(   const BYTE  in[],
                        BYTE        out[],
                        BYTE        key[][16][6]);

#endif   // DES_H

