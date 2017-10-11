[1mdiff --git a/sm3.h b/sm3.h[m
[1mindex 1bc69ca..d13adc7 100644[m
[1m--- a/sm3.h[m
[1m+++ b/sm3.h[m
[36m@@ -1,9 +1,9 @@[m
 /**[m
  * \file sm3.h[m
  * thanks to Xyssl \n[m
[31m- * SM3 standards:http://www.oscca.gov.cn/News/201012/News_1199.htm \n[m
[31m- * author:goldboar \n[m
[31m- * email:goldboar@163.com \n[m
[32m+[m[32m * SM3 standards: http://www.oscca.gov.cn/News/201012/News_1199.htm \n[m
[32m+[m[32m * author: goldboar \n[m
[32m+[m[32m * email: goldboar@163.com \n[m
  * 2011-10-26[m
  */[m
 #ifndef XYSSL_SM3_H[m
[36m@@ -40,17 +40,20 @@[m [mvoid sm3_starts( sm3_context *ctx );[m
  * \brief          SM3 process buffer[m
  *[m
  * \param ctx      SM3 context[m
[31m- * \param input    buffer holding the  data[m
[32m+[m[32m * \param input    buffer holding the data[m
  * \param ilen     length of the input data[m
  */[m
[31m-void sm3_update( sm3_context *ctx, unsigned char *input, int ilen );[m
[32m+[m[32mvoid sm3_update(sm3_context     *ctx,[m
[32m+[m[32m                unsigned char   *input,[m
[32m+[m[32m                int             ilen);[m
 [m
 /**[m
  * \brief          SM3 final digest[m
  *[m
  * \param ctx      SM3 context[m
  */[m
[31m-void sm3_finish( sm3_context *ctx, unsigned char output[32] );[m
[32m+[m[32mvoid sm3_finish(sm3_context     *ctx,[m
[32m+[m[32m                unsigned char   output[32]);[m
 [m
 /**[m
  * \brief          Output = SM3( input buffer )[m
[36m@@ -59,8 +62,9 @@[m [mvoid sm3_finish( sm3_context *ctx, unsigned char output[32] );[m
  * \param ilen     length of the input data[m
  * \param output   SM3 checksum result[m
  */[m
[31m-void sm3( unsigned char *input, int ilen,[m
[31m-           unsigned char output[32]);[m
[32m+[m[32mvoid sm3(   unsigned char   *input,[m
[32m+[m[32m            int             ilen,[m
[32m+[m[32m            unsigned char   output[32]);[m
 [m
 /**[m
  * \brief          Output = SM3( file contents )[m
[36m@@ -71,7 +75,8 @@[m [mvoid sm3( unsigned char *input, int ilen,[m
  * \return         0 if successful, 1 if fopen failed,[m
  *                 or 2 if fread failed[m
  */[m
[31m-int sm3_file( char *path, unsigned char output[32] );[m
[32m+[m[32mint sm3_file(   char            *path,[m
[32m+[m[32m                unsigned char   output[32]);[m
 [m
 /**[m
  * \brief          SM3 HMAC context setup[m
[36m@@ -80,7 +85,9 @@[m [mint sm3_file( char *path, unsigned char output[32] );[m
  * \param key      HMAC secret key[m
  * \param keylen   length of the HMAC key[m
  */[m
[31m-void sm3_hmac_starts( sm3_context *ctx, unsigned char *key, int keylen);[m
[32m+[m[32mvoid sm3_hmac_starts(   sm3_context     *ctx,[m
[32m+[m[32m                        unsigned char   *key,[m
[32m+[m[32m                        int             keylen);[m
 [m
 /**[m
  * \brief          SM3 HMAC process buffer[m
[36m@@ -89,7 +96,9 @@[m [mvoid sm3_hmac_starts( sm3_context *ctx, unsigned char *key, int keylen);[m
  * \param input    buffer holding the  data[m
  * \param ilen     length of the input data[m
  */[m
[31m-void sm3_hmac_update( sm3_context *ctx, unsigned char *input, int ilen );[m
[32m+[m[32mvoid sm3_hmac_update(   sm3_context     *ctx,[m
[32m+[m[32m                        unsigned char   *input,[m
[32m+[m[32m                        int             ilen);[m
 [m
 /**[m
  * \brief          SM3 HMAC final digest[m
[36m@@ -97,7 +106,8 @@[m [mvoid sm3_hmac_update( sm3_context *ctx, unsigned char *input, int ilen );[m
  * \param ctx      HMAC context[m
  * \param output   SM3 HMAC checksum result[m
  */[m
[31m-void sm3_hmac_finish( sm3_context *ctx, unsigned char output[32] );[m
[32m+[m[32mvoid sm3_hmac_finish(   sm3_context     *ctx,[m
[32m+[m[32m                        unsigned char   output[32]);[m
 [m
 /**[m
  * \brief          Output = HMAC-SM3( hmac key, input buffer )[m
[36m@@ -108,9 +118,11 @@[m [mvoid sm3_hmac_finish( sm3_context *ctx, unsigned char output[32] );[m
  * \param ilen     length of the input data[m
  * \param output   HMAC-SM3 result[m
  */[m
[31m-void sm3_hmac( unsigned char *key, int keylen,[m
[31m-                unsigned char *input, int ilen,[m
[31m-                unsigned char output[32] );[m
[32m+[m[32mvoid sm3_hmac(  unsigned char   *key,[m
[32m+[m[32m                int             keylen,[m
[32m+[m[32m                unsigned char   *input,[m
[32m+[m[32m                int             ilen,[m
[32m+[m[32m                unsigned char   output[32]);[m
 [m
 [m
 #ifdef __cplusplus[m
[36m@@ -118,3 +130,4 @@[m [mvoid sm3_hmac( unsigned char *key, int keylen,[m
 #endif[m
 [m
 #endif /* sm3.h */[m
[41m+[m
[1mdiff --git a/sm4.h b/sm4.h[m
[1mindex 971577b..480c3a1 100644[m
[1m--- a/sm4.h[m
[1m+++ b/sm4.h[m
[36m@@ -28,7 +28,8 @@[m [mextern "C" {[m
  * \param ctx      SM4 context to be initialized[m
  * \param key      16-byte secret key[m
  */[m
[31m-void sm4_setkey_enc( sm4_context *ctx, unsigned char key[16] );[m
[32m+[m[32mvoid sm4_setkey_enc(sm4_context     *ctx,[m
[32m+[m[32m                    unsigned char   key[16]);[m
 [m
 /**[m
  * \brief          SM4 key schedule (128-bit, decryption)[m
[36m@@ -36,7 +37,8 @@[m [mvoid sm4_setkey_enc( sm4_context *ctx, unsigned char key[16] );[m
  * \param ctx      SM4 context to be initialized[m
  * \param key      16-byte secret key[m
  */[m
[31m-void sm4_setkey_dec( sm4_context *ctx, unsigned char key[16] );[m
[32m+[m[32mvoid sm4_setkey_dec(sm4_context     *ctx,[m
[32m+[m[32m                    unsigned char   key[16]);[m
 [m
 /**[m
  * \brief          SM4-ECB block encryption/decryption[m
[36m@@ -46,11 +48,11 @@[m [mvoid sm4_setkey_dec( sm4_context *ctx, unsigned char key[16] );[m
  * \param input    input block[m
  * \param output   output block[m
  */[m
[31m-void sm4_crypt_ecb( sm4_context *ctx,[m
[31m-				     int mode,[m
[31m-					 int length,[m
[31m-                     unsigned char *input,[m
[31m-                     unsigned char *output);[m
[32m+[m[32mvoid sm4_crypt_ecb( sm4_context     *ctx,[m
[32m+[m		[32m    int             mode,[m
[32m+[m		[32m    int             length,[m
[32m+[m[32m                    unsigned char   *input,[m
[32m+[m[32m                    unsigned char   *output);[m
 [m
 /**[m
  * \brief          SM4-CBC buffer encryption/decryption[m
[36m@@ -61,12 +63,12 @@[m [mvoid sm4_crypt_ecb( sm4_context *ctx,[m
  * \param input    buffer holding the input data[m
  * \param output   buffer holding the output data[m
  */[m
[31m-void sm4_crypt_cbc( sm4_context *ctx,[m
[31m-                     int mode,[m
[31m-                     int length,[m
[31m-                     unsigned char iv[16],[m
[31m-                     unsigned char *input,[m
[31m-                     unsigned char *output );[m
[32m+[m[32mvoid sm4_crypt_cbc( sm4_context     *ctx,[m
[32m+[m[32m                    int             mode,[m
[32m+[m[32m                    int             length,[m
[32m+[m[32m                    unsigned char   iv[16],[m
[32m+[m[32m                    unsigned char   *input,[m
[32m+[m[32m                    unsigned char   *output);[m
 [m
 #ifdef __cplusplus[m
 }[m
