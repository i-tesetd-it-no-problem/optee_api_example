#ifndef _SIGN_AND_VERIFY_H
#define _SIGN_AND_VERIFY_H

#define TA_SIGN_AND_VERIFY_UUID \
	{ 0x1e0c1b88, 0xdf73, 0x4eb5, \
		{ 0xb2, 0x3d, 0x36, 0xd5, 0x9f, 0x31, 0xa0, 0x91} }

enum sigh_verify_alg {
	SIGH_VERIFY_ALG_RSASSA_PKCSV1_5_SHA256,
	SIGH_VERIFY_ALG_RSASSA_PKCSV1_PSS_MGF1_SHA256,
	SIGH_VERIFY_ALG_ECDSA_P256,
	SIGH_VERIFY_ALG_ED25519,
	
	SIGH_VERIFY_ALG_MAX,
};

/*
 * SIGH_VERIFY_CMD_GENERATE_KEYPAIR - TA生成一对非对称密钥
 * param[0] value - enum sigh_verify_alg 密钥使用的算法类型
 * param[1] unused
 * param[2] unused
 * param[3] unused
 */
#define SIGH_VERIFY_CMD_GENERATE_KEYPAIR 0

/*
 * SIGH_VERIFY_CMD_DIGEST - 对数据进行摘要
 * param[0] memref - 原始数据
 * param[1] memref - 摘要后的数据
 * param[2] unused
 * param[3] unused
 */
#define SIGH_VERIFY_CMD_DIGEST 1

/*
 * SIGH_VERIFY_CMD_SIGN - 对数据进行签名
 * param[0] memref - 输入摘要后的数据,对于椭圆曲线则是原始数据
 * param[1] memref - 输出签名后的数据
 * param[2] unused
 * param[3] unused
 */
#define SIGH_VERIFY_CMD_SIGN 2

/*
 * SIGH_VERIFY_CMD_VERIFY - 验证签名
 * param[0] memref - 对于 RSA，传入摘要；对于 ECDSA/ED25519，传入原始数据
 * param[1] memref - 传入签名后的数据
 * param[2] unused
 * param[3] unused
 */
#define SIGH_VERIFY_CMD_VERIFY 3

#endif /* _SIGN_AND_VERIFY_H */
