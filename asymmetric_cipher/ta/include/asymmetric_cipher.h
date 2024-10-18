#ifndef _AASYMMETRIC_CIPHER_H
#define _AASYMMETRIC_CIPHER_H

#define TA_ASYMMETRIC_CIPHER_UUID \
	{ 0xa808a859, 0x98aa, 0x4123, \
		{ 0xb0, 0x98, 0x01, 0x57, 0x49, 0xd6, 0x5d, 0xc1} }

enum asymm_cipher_alg {
	ASYMM_CIPHER_ALG_RSAES_PKCS1_V1_5,
	ASYMM_CIPHER_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256,

	ASYMM_CIPHER_ALG_MAX,
};

/*
 * ASYMM_CIPHER_CMD_GEN - 生成非对称密钥
 * param[0] (value) 算法类型，enum asymm_cipher_alg
 * param[1] unused
 * param[2] unused
 * param[3] unused
 */
#define ASYMM_CIPHER_CMD_GEN 0

/*
 * ASYMM_CIPHER_CMD_ENCRYP - 加密
 * param[0] (memref) 明文数据
 * param[1] (memref) 密文数据
 * param[2] unused
 * param[3] unused
 */
#define ASYMM_CIPHER_CMD_ENCRYP 1


/*
 * ASYMM_CIPHER_CMD_DECRYP - 解密
 * param[0] (memref) 密文数据
 * param[1] (memref) 明文数据
 * param[2] unused
 * param[3] unused
 */
#define ASYMM_CIPHER_CMD_DECRYP 2

#endif /* _AASYMMETRIC_CIPHER_H */
