#ifndef _H_MAC_H
#define _H_MAC_H

#define TA_H_MAC_UUID \
	{ 0x0a3e2c88, 0x300b, 0x4dbd, \
		{ 0xb4, 0x83, 0x30, 0x44, 0xae, 0x4b, 0x65, 0x81} }

enum h_mac_alg {
	HMAC_ALGORITHM_MD5,
	HMAC_ALGORITHM_SHA1,
	HMAC_ALGORITHM_SHA224,
	HMAC_ALGORITHM_SHA256,
	HMAC_ALGORITHM_SHA384,
	HMAC_ALGORITHM_SHA512,
	HMAC_ALGORITHM_SM3,

	HMAC_ALGORITHM_MAX,
};

/*
 * TA_MESSAGE_DIGEST_CMD_PREPARE - 初始化认证算法
 * param[0] (value) - 摘要算法类型 参考enum h_mac_alg
 * param[1] (memref) - 密钥
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define HMAC_CMD_INIT			0

/*
 * TA_MESSAGE_DIGEST_CMD_PREPARE - 生成认证码
 * param[0] (memref) - 原始数据
 * param[1] (memref) - 认证码缓冲
 * param[2] (unsued) - IV 初始向量
 * param[3] (unsued)
 */
#define HMAC_CMD_GENERATE_MAC	1

/*
 * TA_MESSAGE_DIGEST_CMD_PREPARE - 生成认证码
 * param[0] (memref) - 待认证的数据
 * param[1] (memref) - 认证码缓冲
 * param[2] (unsued) - IV 初始向量
 * param[3] (unsued)
 */
#define HMACCMD_VERIFY_MAC		2

#endif /* _H_MAC_H */
