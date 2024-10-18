#ifndef _SYMMETRIC_CIPHER_H
#define _SYMMETRIC_CIPHER_H

#define TA_SYMMETRIC_CIPHER_UUID \
	{ 0xe5415777, 0x7594, 0x446d, \
		{ 0xa9, 0x7f, 0x53, 0x77, 0x22, 0x27, 0x96, 0x27} }

enum symm_cipher_alg {
	SYMM_CIPHER_ALG_AES_ECB_NOPAD,
	SYMM_CIPHER_ALG_AES_CBC_NOPAD,
	SYMM_CIPHER_ALG_AES_CTR,
	SYMM_CIPHER_ALG_AES_CTS,
	SYMM_CIPHER_ALG_AES_XTS,

	SYMM_CIPHER_ALG_MAX,
};

/*
 * SYMM_CIPHER_CMD_GEN - 生成对称密钥
 * param[0] (value) 算法类型，enum symm_cipher_alg
 * param[1] unused
 * param[2] unused
 * param[3] unused
 */
#define SYMM_CIPHER_CMD_GEN 0

/*
 * SYMM_CIPHER_CMD_ENCRYP - 加密
 * param[0] (memref) 明文数据
 * param[1] (memref) 密文数据
 * param[2] unused
 * param[3] unused
 */
#define SYMM_CIPHER_CMD_ENCRYP 1


/*
 * SYMM_CIPHER_CMD_DECRYP - 解密
 * param[0] (memref) 密文数据
 * param[1] (memref) 明文数据
 * param[2] unused
 * param[3] unused
 */
#define SYMM_CIPHER_CMD_DECRYP 2

#endif /* _SYMMETRIC_CIPHER_H */
