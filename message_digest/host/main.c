#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include "../ta/include/message_digest.h"

struct message_digest_ctx {
    TEEC_Context ctx;
    TEEC_Session sess;
};

const char* alg_msg[MESSAGE_DIGEST_ALG_MAX] = {
	[MESSAGE_DIGEST_ALG_MD5] = "MD5",
	[MESSAGE_DIGEST_ALG_SHA1] = "SHA1",
	[MESSAGE_DIGEST_ALG_SHA224] = "SHA224",
	[MESSAGE_DIGEST_ALG_SHA256] = "SHA256",
	[MESSAGE_DIGEST_ALG_SHA384] = "SHA384",
	[MESSAGE_DIGEST_ALG_SHA512] = "SHA512",
	[MESSAGE_DIGEST_ALG_UNUSED] = "UNUSED",
	[MESSAGE_DIGEST_ALG_SHA3_224] = "SHA3_224",
	[MESSAGE_DIGEST_ALG_SHA3_256] = "SHA3_256",
	[MESSAGE_DIGEST_ALG_SHA3_384] = "SHA3_384",
	[MESSAGE_DIGEST_ALG_SHA3_512] = "SHA3_512",
};

static void prepare_tee_session(struct message_digest_ctx *ctx)
{
    TEEC_UUID uuid = TA_MESSAGE_DIGEST_UUID;
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

static void terminate_tee_session(struct message_digest_ctx *ctx)
{
    TEEC_CloseSession(&ctx->sess);
    TEEC_FinalizeContext(&ctx->ctx);
}

/**
 * @brief 消息摘要
 * 
 * @param ctx 会话上下文
 * @param alg 算法
 */
static void message_digest(struct message_digest_ctx *ctx, enum msg_digest_alg alg)
{
    TEEC_Operation op;         // 参数
    TEEC_Result ret;           // 返回结果
    uint32_t error_origin;     // 错误来源信息
    uint8_t buffer[512];       // 存储消息摘要的缓冲区
    size_t buffer_size = sizeof(buffer); // 缓冲区大小

	// 初始化算法命令
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].value.a = alg;

    ret = TEEC_InvokeCommand(&ctx->sess, TA_MESSAGE_DIGEST_CMD_PREPARE, &op, &error_origin);
    if (ret == TEEC_ERROR_NOT_SUPPORTED) {
		// 检查是否支持该算法，包括是否是本案例的枚举以及OPTEE是否支持
        printf("algorithm \"%s\" is not supported\n", alg_msg[alg]);
        return;
    } else if (ret != TEEC_SUCCESS) {
        printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x alg \"%s\"\n", ret, error_origin, alg_msg[alg]);
        exit(0);
    }

    printf("\n");

    // 消息内容
    char message[128] = "Hello, world!";
    
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = message;         // 输入消息
    op.params[0].tmpref.size = strlen(message);   // 输入消息的大小
    op.params[1].tmpref.buffer = buffer;          // 输出缓冲区，用于存储消息摘要
    op.params[1].tmpref.size = buffer_size;       // 输出缓冲区的大小

    ret = TEEC_InvokeCommand(&ctx->sess, TA_MESSAGE_DIGEST_CMD_DIGEST, &op, &error_origin);
    if (ret != TEEC_SUCCESS) {
        printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x alg \"%s\"\n", ret, error_origin, alg_msg[alg]);
        exit(0);  // 计算失败，退出
    }

    // 打印算法的消息摘要结果
    printf("Message is \"%s\"\nalgorithm is : \"%s\"\ndigest is :\n", message, alg_msg[alg]);
    for (int j = 0; j < op.params[1].tmpref.size; j++) {
        printf("%02x ", buffer[j]);
    }
    printf("\n");
}

int main()
{
    struct message_digest_ctx ctx;

    prepare_tee_session(&ctx);

    // 循环遍历所有定义的消息摘要算法
    for (enum msg_digest_alg alg = MESSAGE_DIGEST_ALG_MD5; alg < MESSAGE_DIGEST_ALG_MAX; alg++) {
        if (alg == MESSAGE_DIGEST_ALG_UNUSED)
            continue;
        message_digest(&ctx, alg);
    }

    terminate_tee_session(&ctx);

    return 0;
}
