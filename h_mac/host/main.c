#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include "../ta/include/h_mac.h"

struct h_mac_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

static const char* const hmac_alg_str[HMAC_ALGORITHM_MAX] = {
	[HMAC_ALGORITHM_MD5] = "HMAC_MD5",
	[HMAC_ALGORITHM_SHA1] = "HMAC_SHA1",
	[HMAC_ALGORITHM_SHA224] = "HMAC_SHA224",
	[HMAC_ALGORITHM_SHA256] = "HMAC_SHA256",
	[HMAC_ALGORITHM_SHA384] = "HMAC_SHA384",
	[HMAC_ALGORITHM_SHA512] = "HMAC_SHA512",
	[HMAC_ALGORITHM_SM3] = "HMAC_SM3",
};

static uint8_t get_hmac_output_size(enum h_mac_alg alg) {
    switch (alg) {
        case HMAC_ALGORITHM_MD5:
            return 16;
        case HMAC_ALGORITHM_SHA1:
            return 20;
        case HMAC_ALGORITHM_SHA224:
            return 28; 
        case HMAC_ALGORITHM_SHA256:
            return 32;
        case HMAC_ALGORITHM_SHA384:
            return 48;
        case HMAC_ALGORITHM_SHA512:
            return 64;
        case HMAC_ALGORITHM_SM3:
            return 32;
        default:
            return 0XFF;
    }
}

/**
 * @brief HMAC算法案例
 * 
 * @param ctx 会话上下文
 * @param alg 算法类型
 */
static void hmac_example(struct h_mac_ctx *ctx, enum h_mac_alg alg)
{
	TEEC_Operation op;
	TEEC_Result ret;
	uint32_t error_origin;
	char *origin_data = "Hello World"; /* 原始数据 */
	uint8_t key[64] = {0}; /* 密钥 */
	uint8_t key_size = get_hmac_output_size(alg); /* 使用和算法长度相同的密钥长度，过短会报错 */

	for(uint8_t i = 0; i < key_size; i++) /* 实际替换成自己的密钥 */
		key[i] = 0x5A;

	uint8_t mac_buffer[512]; /* 消息认证码缓冲区 */
	size_t mac_buffer_size = sizeof(mac_buffer); /* 消息认证码缓冲区大小 */

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = alg; // 算法类型
	op.params[1].tmpref.buffer = key; // 密钥
	op.params[1].tmpref.size = key_size; // 密钥长度

	// 初始化HMAC算法
	ret = TEEC_InvokeCommand(&ctx->sess, HMAC_CMD_INIT, &op, &error_origin);
	if(ret != TEEC_SUCCESS) {
		printf("HMAC_CMD_INIT failed with code 0x%x origin 0x%x, algo is %s\n", ret, error_origin, hmac_alg_str[alg]);
		return;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);
	op.params[0].tmpref.buffer = origin_data; // 原始数据
	op.params[0].tmpref.size = strlen(origin_data); // 原始数据长度
	op.params[1].tmpref.buffer = mac_buffer; // 消息认证码缓冲区
	op.params[1].tmpref.size = mac_buffer_size; // 消息认证码缓冲区大小
	op.params[2].tmpref.buffer = NULL; // IV 本案例不需要
	op.params[2].tmpref.size = 0;

	// 生成消息认证码
	ret = TEEC_InvokeCommand(&ctx->sess, HMAC_CMD_GENERATE_MAC, &op, &error_origin);
	if(ret != TEEC_SUCCESS) {
		printf("HMAC_CMD_GENERATE_MAC failed with code 0x%x origin 0x%x, algo is %s\n", ret, error_origin, hmac_alg_str[alg]);
		return;
	}

	size_t actual_mac_size = op.params[1].tmpref.size; // 实际生成的消息认证码长度

	printf("HMAC of %s with %s is:\n", origin_data, hmac_alg_str[alg]);
	for(int i = 0; i < actual_mac_size; i++) {
		printf("%02x", mac_buffer[i]);
	}
	printf("\n");

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);
	op.params[0].tmpref.buffer = origin_data; // 原始数据
	op.params[0].tmpref.size = strlen(origin_data); // 原始数据长度
	op.params[1].tmpref.buffer = mac_buffer; // 消息认证码缓冲区
	op.params[1].tmpref.size = actual_mac_size; // 消息认证码长度
	op.params[2].tmpref.buffer = NULL; // IV 本案例不需要
	op.params[2].tmpref.size = 0;

	// 验证消息认证码
	ret = TEEC_InvokeCommand(&ctx->sess, HMACCMD_VERIFY_MAC, &op, &error_origin);
	if(ret != TEEC_SUCCESS) {
		printf("HMACCMD_VERIFY_MAC failed with code 0x%x origin 0x%x, algo is %s\n", ret, error_origin, hmac_alg_str[alg]);
		return;
	}

	printf("HMAC of %s with %s is verified\n\n", origin_data, hmac_alg_str[alg]);
}

static void prepare_tee_session(struct h_mac_ctx *ctx)
{
	TEEC_UUID uuid = TA_H_MAC_UUID;
	uint32_t origin;
	TEEC_Result res;

	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS) {
	    printf("TEEC_InitializeContext failed with code 0x%x\n", res);
	    exit(0);
	}

	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS) {
	    printf("TEEC_Opensession failed with code 0x%x origin 0x%x\n", res, origin);
	    exit(0);
	}
}

static void terminate_tee_session(struct h_mac_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

int main()
{
    struct h_mac_ctx ctx;

    prepare_tee_session(&ctx);

	// 遍历所有算法类型
	for(enum h_mac_alg alg = HMAC_ALGORITHM_MD5; alg < HMAC_ALGORITHM_MAX; alg++) 
		hmac_example(&ctx, alg);

    terminate_tee_session(&ctx);

    return 0;
}
