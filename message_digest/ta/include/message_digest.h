#ifndef _MESSAGE_DIGEST_H
#define _MESSAGE_DIGEST_H


#define TA_MESSAGE_DIGEST_UUID \
	{ 0x3f3e060f, 0x97ca, 0x41c9, \
		{ 0x9e, 0x93, 0x51, 0x72, 0x74, 0xdb, 0x20, 0x31} }

enum msg_digest_alg {
	MESSAGE_DIGEST_ALG_MD5,
	MESSAGE_DIGEST_ALG_SHA1,
	MESSAGE_DIGEST_ALG_SHA224,
	MESSAGE_DIGEST_ALG_SHA256,
	MESSAGE_DIGEST_ALG_SHA384,
	MESSAGE_DIGEST_ALG_SHA512,
	MESSAGE_DIGEST_ALG_UNUSED,	// 为了对应OP-TEE宏定义的顺序,跳过一个位置
	MESSAGE_DIGEST_ALG_SHA3_224,
	MESSAGE_DIGEST_ALG_SHA3_256,
	MESSAGE_DIGEST_ALG_SHA3_384,
	MESSAGE_DIGEST_ALG_SHA3_512,

	MESSAGE_DIGEST_ALG_MAX,
};

/**
 * @brief 获取对应算法需要的字节数
 * 
 * @param alg 数据摘要算法枚举
 * @return int -1 表示算法不支持, 其他值表示算法对应的字节数
 */
uint8_t get_digest_length(enum msg_digest_alg alg);

/*
 * TA_MESSAGE_DIGEST_CMD_PREPARE - 初始化摘要算法
 * param[0] (value) - 摘要算法类型 参考enum msg_digest_alg
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TA_MESSAGE_DIGEST_CMD_PREPARE		0

/*
 * TA_MESSAGE_DIGEST_CMD_PREPARE - 信息摘要
 * param[0] (memref) - 输入数据
 * param[1] (memref) - 摘要结果
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TA_MESSAGE_DIGEST_CMD_DIGEST		1

#endif /* _MESSAGE_DIGEST_H */
