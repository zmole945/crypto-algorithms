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
 * \param key       密鑰首地址，只接受128,192或256位的密鑰
 * \param w         計算出的key schedule加密時使用
 * \param keysize   密鑰位數，可以取128,192,256
 *
 * \return          初始化是否成功，成功返回0
 */
void aes_key_setup(const BYTE   key[],
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

///////////////////
// AES - CBC
///////////////////
int aes_encrypt_cbc(const BYTE in[],          // Plaintext
                    size_t in_len,            // Must be a multiple of AES_BLOCK_SIZE
                    BYTE out[],               // Ciphertext, same length as plaintext
                    const WORD key[],         // From the key setup
                    int keysize,              // Bit length of the key, 128, 192, or 256
                    const BYTE iv[]);         // IV, must be AES_BLOCK_SIZE bytes long

#if 0
// Only output the CBC-MAC of the input.
int aes_encrypt_cbc_mac(const BYTE in[],      // plaintext
                        size_t in_len,        // Must be a multiple of AES_BLOCK_SIZE
                        BYTE out[],           // Output MAC
                        const WORD key[],     // From the key setup
                        int keysize,          // Bit length of the key, 128, 192, or 256
                        const BYTE iv[]);     // IV, must be AES_BLOCK_SIZE bytes long

///////////////////
// AES - CTR
///////////////////
void increment_iv(BYTE iv[],                  // Must be a multiple of AES_BLOCK_SIZE
                  int counter_size);          // Bytes of the IV used for counting (low end)

void aes_encrypt_ctr(const BYTE in[],         // Plaintext
                     size_t in_len,           // Any byte length
                     BYTE out[],              // Ciphertext, same length as plaintext
                     const WORD key[],        // From the key setup
                     int keysize,             // Bit length of the key, 128, 192, or 256
                     const BYTE iv[]);        // IV, must be AES_BLOCK_SIZE bytes long

void aes_decrypt_ctr(const BYTE in[],         // Ciphertext
                     size_t in_len,           // Any byte length
                     BYTE out[],              // Plaintext, same length as ciphertext
                     const WORD key[],        // From the key setup
                     int keysize,             // Bit length of the key, 128, 192, or 256
                     const BYTE iv[]);        // IV, must be AES_BLOCK_SIZE bytes long

///////////////////
// AES - CCM
///////////////////
// Returns True if the input parameters do not violate any constraint.
int aes_encrypt_ccm(const BYTE plaintext[],              // IN  - Plaintext.
                    WORD plaintext_len,                  // IN  - Plaintext length.
                    const BYTE associated_data[],        // IN  - Associated Data included in authentication, but not encryption.
                    unsigned short associated_data_len,  // IN  - Associated Data length in bytes.
                    const BYTE nonce[],                  // IN  - The Nonce to be used for encryption.
                    unsigned short nonce_len,            // IN  - Nonce length in bytes.
                    BYTE ciphertext[],                   // OUT - Ciphertext, a concatination of the plaintext and the MAC.
                    WORD *ciphertext_len,                // OUT - The length of the ciphertext, always plaintext_len + mac_len.
                    WORD mac_len,                        // IN  - The desired length of the MAC, must be 4, 6, 8, 10, 12, 14, or 16.
                    const BYTE key[],                    // IN  - The AES key for encryption.
                    int keysize);                        // IN  - The length of the key in bits. Valid values are 128, 192, 256.

// Returns True if the input parameters do not violate any constraint.
// Use mac_auth to ensure decryption/validation was preformed correctly.
// If authentication does not succeed, the plaintext is zeroed out. To overwride
// this, call with mac_auth = NULL. The proper proceedure is to decrypt with
// authentication enabled (mac_auth != NULL) and make a second call to that
// ignores authentication explicitly if the first call failes.
int aes_decrypt_ccm(const BYTE ciphertext[],             // IN  - Ciphertext, the concatination of encrypted plaintext and MAC.
                    WORD ciphertext_len,                 // IN  - Ciphertext length in bytes.
                    const BYTE assoc[],                  // IN  - The Associated Data, required for authentication.
                    unsigned short assoc_len,            // IN  - Associated Data length in bytes.
                    const BYTE nonce[],                  // IN  - The Nonce to use for decryption, same one as for encryption.
                    unsigned short nonce_len,            // IN  - Nonce length in bytes.
                    BYTE plaintext[],                    // OUT - The plaintext that was decrypted. Will need to be large enough to hold ciphertext_len - mac_len.
                    WORD *plaintext_len,                 // OUT - Length in bytes of the output plaintext, always ciphertext_len - mac_len .
                    WORD mac_len,                        // IN  - The length of the MAC that was calculated.
                    int *mac_auth,                       // OUT - TRUE if authentication succeeded, FALSE if it did not. NULL pointer will ignore the authentication.
                    const BYTE key[],                    // IN  - The AES key for decryption.
                    int keysize);                        // IN  - The length of the key in BITS. Valid values are 128, 192, 256.
#endif

#if 0
///////////////////
// Test functions
///////////////////
int aes_test();
int aes_ecb_test();
int aes_cbc_test();
int aes_ctr_test();
int aes_ccm_test();
#endif

#endif   // AES_H
