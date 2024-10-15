#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "include/message_digest.h"

struct message_digest_ctx {
    TEE_OperationHandle operation; /* 操作句柄 */
    uint32_t algorithm; /* 使用的算法 */
};

/**
 * @brief 返回摘要算法从的字节数
 * 
 * @param alg 算法枚举
 * @return uint8_t 字节大小
 */
uint8_t get_digest_length(enum msg_digest_alg alg) {
    switch (alg) {
        case MESSAGE_DIGEST_ALG_MD5:
            return 16;  // MD5 128 位 = 16 字节
        case MESSAGE_DIGEST_ALG_SHA1:
            return 20;  // SHA-1 160 位 = 20 字节
        case MESSAGE_DIGEST_ALG_SHA224:
            return 28;  // SHA-224 224 位 = 28 字节
        case MESSAGE_DIGEST_ALG_SHA256:
            return 32;  // SHA-256 256 位 = 32 字节
        case MESSAGE_DIGEST_ALG_SHA384:
            return 48;  // SHA-384 384 位 = 48 字节
        case MESSAGE_DIGEST_ALG_SHA512:
            return 64;  // SHA-512 512 位 = 64 字节
        case MESSAGE_DIGEST_ALG_SHA3_224:
            return 28;  // SHA3-224 224 位 = 28 字节
        case MESSAGE_DIGEST_ALG_SHA3_256:
            return 32;  // SHA3-256 256 位 = 32 字节
        case MESSAGE_DIGEST_ALG_SHA3_384:
            return 48;  // SHA3-384 384 位 = 48 字节
        case MESSAGE_DIGEST_ALG_SHA3_512:
            return 64;  // SHA3-512 512 位 = 64 字节
        default:
            return 0xFF;  // 未知算法
    }
}

static TEE_Result message_digest_prepare(void *session_ctx, uint32_t param_types, TEE_Param params[4])
{
    TEE_Result ret;
    struct message_digest_ctx *ctx = (struct message_digest_ctx *)session_ctx; /* 会话上下文 */

    // 验证参数类型
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_type) {
        EMSG("param_types is not correct\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 验证是否是本案例支持的算法
    if(params[0].value.a >= MESSAGE_DIGEST_ALG_MAX || params[0].value.a == MESSAGE_DIGEST_ALG_UNUSED) {
        EMSG("algorithm is not supported by example\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ctx->algorithm = params[0].value.a; // 保存算法

    uint32_t algorithm = params[0].value.a + TEE_ALG_MD5; // 替换为 TEE_ALG_xxx 算法

    // 验证OPTEE是否支持该算法
    // 在本案例测试的时候 MESSAGE_DIGEST_ALG_SHA3_224 及以下都不支持
    ret = TEE_IsAlgorithmSupported(algorithm, TEE_CRYPTO_ELEMENT_NONE);
    if(ret != TEE_SUCCESS) {
        EMSG("algorithm is not supported by OP-TEE\n");
        return ret;
    }

    // 申请操作句柄
    if(ctx->operation != TEE_HANDLE_NULL) 
        TEE_FreeOperation(ctx->operation);
    ret = TEE_AllocateOperation(&ctx->operation, algorithm, TEE_MODE_DIGEST, 0);
    if(ret != TEE_SUCCESS) {
        // 申请失败
        EMSG("TEE_AllocateOperation failed with code 0x%x", ret);
        return ret;
    }

    return TEE_SUCCESS;
} 

static TEE_Result do_message_digest(void *session_ctx, uint32_t param_types, TEE_Param params[4])
{
    TEE_Result ret;
    struct message_digest_ctx *ctx = (struct message_digest_ctx *)session_ctx; /* 会话上下文 */

    // 验证参数类型
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_type) {
        EMSG("do_message_digest failed, param_types is not correct\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    size_t output_len = params[1].memref.size; // 传入算法长度

    uint8_t expected_len = get_digest_length(ctx->algorithm); // 当前算法支持的长度

    if (expected_len == 0xFF) {
        // 未知算法
        EMSG("do_message_digest failed, unknown algorithm\n");
        return TEE_ERROR_NOT_SUPPORTED;
    } else if (output_len < expected_len) {
        // 缓冲区太小
        EMSG("do_message_digest failed, output buffer too small: provided %zu, expected at least %u\n", output_len, expected_len);
        return TEE_ERROR_SHORT_BUFFER;
    }

    uint8_t *input_data = params[0].memref.buffer; //输入数据
    size_t input_len = params[0].memref.size; //输入长度

    // 计算消息摘要
    ret = TEE_DigestDoFinal(ctx->operation, input_data, input_len, params[1].memref.buffer, &output_len);
    if(ret != TEE_SUCCESS) {
        EMSG("TEE_DigestDoFinal failed with code 0x%x", ret);
        return ret;
    }

    params[1].memref.size = output_len; //返回实际摘要长度

    return TEE_SUCCESS;
}

/*******************************************************************************
 * Mandatory TA functions.
 ******************************************************************************/

TEE_Result TA_CreateEntryPoint(void)
{
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_type, TEE_Param params[4], void **sess_ctx)
{
    (void)param_type;
    (void)params;

    struct message_digest_ctx *ctx = TEE_Malloc(sizeof(struct message_digest_ctx), TEE_MALLOC_FILL_ZERO);
    if(!ctx) {
        EMSG("TA_OpenSessionEntryPoint failed, out of memory");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ctx->operation = TEE_HANDLE_NULL;
    *sess_ctx = ctx;

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    struct message_digest_ctx *ctx = (struct message_digest_ctx *)sess_ctx;

    if(ctx->operation != TEE_HANDLE_NULL)
        TEE_FreeOperation(ctx->operation);

    TEE_Free(ctx);
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_type, TEE_Param params[4])
{
    switch(cmd) {
        case TA_MESSAGE_DIGEST_CMD_PREPARE:
            return message_digest_prepare(sess_ctx, param_type, params);

        case TA_MESSAGE_DIGEST_CMD_DIGEST:
            return do_message_digest(sess_ctx, param_type, params);

        default:
            return TEE_ERROR_BAD_PARAMETERS;
    }
}
