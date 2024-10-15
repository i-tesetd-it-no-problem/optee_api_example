#ifndef _AES_GCM_CCM_H
#define _AES_GCM_CCM_H


#define TA_AES_GCM_CCM_UUID \
	{ 0x2c62d39b, 0x96d2, 0x4413, \
		{ 0x82, 0xd3, 0x55, 0x57, 0xd0, 0x75, 0x2c, 0x2e} }

#define AES_KEY_BYTES_SIZE (16) /* AES-128 */
#define AES_KEY_BITS_SIZE (AES_KEY_BYTES_SIZE * 8)

#define AES_IV_BYTES_SIZE (12) /* GCM推荐的IV字节为12，CCM推荐的IV字节为7-13，都使用12字节 */
#define AES_IV_BITS_SIZE (AES_IV_BYTES_SIZE * 8)

#define AES_TAG_BYTES_SIZE (16) /* 认证标签长度可以为(12-16字节) */
#define AES_TAG_BITS_SIZE (AES_TAG_BYTES_SIZE * 8)

#define AES_ALGORITHM_GCM 0 /* 使用GCM模式 */
#define AES_ALGORITHM_CCM 1 /* 使用CCM模式 */

#define AES_CIPHER_MODE_ENCRYPT 0 /* 加密模式 */
#define AES_CIPHER_MODE_DECRYPT 1 /* 解密模式 */

/*
 * TA_AES_GCM_CCM_CMD_PREPARE - 初始化加/解密认证环境
 * param[0] (value) algorithm - AES_ALGORITHEM_GCM 或 AES_ALGORITHEM_CCM
 * param[1] (value) cipher_mode - AES_CIPHER_MODE_ENCRYPT 或 AES_CIPHER_MODE_DECRYPT
 * param[2] (memref) key - AES密钥 
 * param[3] (unsued)
 */
#define TA_AES_GCM_CCM_CMD_PREPARE	0 /* 初始化加/解密认证环境 */

/*
 * TA_AES_GCM_CCM_CMD_INIT - 初始化加/解密认证所需参数值
 * param[0] (memref) iv - 初始化向量 
 * param[1] (value) a : tag_len b : aad_len(仅用于AES-CCM)
 * param[2] (value) a : payload_len(仅用于AES-CCM)
 * param[3] (unsued)
 */
#define TA_AES_GCM_CCM_CMD_INIT	1 /* 初始化加/解密认证所需参数值 */

/*
 * TA_AES_GCM_CCM_CMD_ENCRYPT - 认证加密
 * param[0] (memref) - 待加密数据
 * param[1] (memref) - 加密后数据
 * param[2] (memref) - 认证标签
 * param[3] (unsued)
 */
#define TA_AES_GCM_CCM_CMD_ENCRYPT	2 /* 重置IV */

/*
 * TA_AES_GCM_CCM_CMD_DECRYPT - 认证解密
 * param[0] (memref) - 待解密数据
 * param[1] (memref) - 解密后数据
 * param[2] (memref) - 认证标签
 * param[3] (unsued)
 */
#define TA_AES_GCM_CCM_CMD_DECRYPT 3 /* 加解密命令 */

#endif /* _AES_GCM_CCM_H */
