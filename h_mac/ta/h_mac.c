#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "include/h_mac.h"

// 定义HMAC会话结构体，包含操作句柄、密钥句柄和算法枚举
struct hmac_session {
    TEE_OperationHandle operation; // 操作句柄
    TEE_ObjectHandle key;          // 密钥句柄
};

// 初始化HMAC会话，设置算法和密钥
static TEE_Result hmac_init(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result ret;
    struct hmac_session *ctx = (struct hmac_session *)sess_ctx;

    // 验证参数类型
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    if (param_type != exp_param_type) {
        EMSG("hmac_init failed, param_type is not correct. Error code: 0x%x\n", TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 获取算法类型并验证
    uint8_t input_alg = params[0].value.a;
    if (input_alg >= HMAC_ALGORITHM_MAX) {
        EMSG("hmac_init failed, unsupported algorithm. Error code: 0x%x\n", TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 获取OP-TEE算法类型
    uint32_t optee_alg = input_alg + TEE_ALG_HMAC_MD5;
    ret = TEE_IsAlgorithmSupported(optee_alg, TEE_CRYPTO_ELEMENT_NONE);
    if (ret != TEE_SUCCESS) {
        EMSG("hmac_init failed, algorithm not supported. Error code: 0x%x\n", ret);
        return ret;
    }

    // 如果已经存在密钥对象，释放
    if (ctx->key != TEE_HANDLE_NULL)
        TEE_FreeTransientObject(ctx->key);
    
    // 根据算法类型设置TEE的HMAC类型
    uint32_t tee_type;
    switch (input_alg) {
        case HMAC_ALGORITHM_MD5:
            tee_type = TEE_TYPE_HMAC_MD5;
            break;
        case HMAC_ALGORITHM_SHA1:
            tee_type = TEE_TYPE_HMAC_SHA1;
            break;
        case HMAC_ALGORITHM_SHA224:
            tee_type = TEE_TYPE_HMAC_SHA224;
            break;
        case HMAC_ALGORITHM_SHA256:
            tee_type = TEE_TYPE_HMAC_SHA256;
            break;
        case HMAC_ALGORITHM_SHA384:
            tee_type = TEE_TYPE_HMAC_SHA384;
            break;
        case HMAC_ALGORITHM_SHA512:
            tee_type = TEE_TYPE_HMAC_SHA512;
            break;
        case HMAC_ALGORITHM_SM3:
            tee_type = TEE_TYPE_HMAC_SM3;
            break;
        default:
            EMSG("hmac_init failed, unsupported tee_type. Error code: 0x%x\n", TEE_ERROR_BAD_PARAMETERS);
            return TEE_ERROR_BAD_PARAMETERS;
    }

    // 分配瞬态对象存储密钥
    ret = TEE_AllocateTransientObject(tee_type, params[1].memref.size * 8, &ctx->key);
    if (ret != TEE_SUCCESS) {
        EMSG("hmac_init failed, failed to allocate transient object. Error code: 0x%x\n", ret);
        return ret;
    }

    // 初始化密钥属性
    TEE_Attribute attr;
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, params[1].memref.buffer, params[1].memref.size);
    ret = TEE_PopulateTransientObject(ctx->key, &attr, 1);
    if (ret != TEE_SUCCESS) {
        EMSG("hmac_init failed, failed to populate transient object. Error code: 0x%x\n", ret);
        TEE_FreeTransientObject(ctx->key);
        return ret;
    }

    // 如果已有操作句柄，释放
    if (ctx->operation != TEE_HANDLE_NULL)
        TEE_FreeOperation(ctx->operation);

    // 分配新的操作对象
    ret = TEE_AllocateOperation(&ctx->operation, optee_alg, TEE_MODE_MAC, params[1].memref.size * 8);
    if (ret != TEE_SUCCESS) {
        EMSG("hmac_init failed, failed to allocate operation. Error code: 0x%x\n", ret);
        return ret;
    }

    // 设置操作对象的密钥
    ret = TEE_SetOperationKey(ctx->operation, ctx->key);
    if (ret != TEE_SUCCESS) {
        EMSG("hmac_init failed, failed to set operation key. Error code: 0x%x\n", ret);
        TEE_FreeTransientObject(ctx->key);
        return ret;
    }

    return TEE_SUCCESS;
}

// 生成HMAC
static TEE_Result hmac_generate(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result ret;
    struct hmac_session *ctx = (struct hmac_session *)sess_ctx;

    // 验证参数类型
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                              TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE);

    if (param_type != exp_param_type) {
        EMSG("hmac_generate failed, param_type is not correct. Error code: 0x%x\n", TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    size_t output_size = params[1].memref.size;

    // 初始化MAC操作，不需要IV
    TEE_MACInit(ctx->operation, NULL, 0);

    // 计算HMAC值
    ret = TEE_MACComputeFinal(ctx->operation, params[0].memref.buffer, params[0].memref.size,
                               params[1].memref.buffer, &output_size);
    if (ret != TEE_SUCCESS) {
        EMSG("hmac_generate failed, MACComputeFinal failed. Error code: 0x%x\n", ret);
        return ret;
    }

    // HMAC大小
    params[1].memref.size = output_size;

    return TEE_SUCCESS;
}

// 验证HMAC值
static TEE_Result hmac_verify(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result ret;
    struct hmac_session *ctx = (struct hmac_session *)sess_ctx;

    // 验证参数类型
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                              TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE);

    if (param_type != exp_param_type) {
        EMSG("hmac_verify failed, param_type is not correct. Error code: 0x%x\n", TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 初始化MAC操作，不需要IV
    TEE_MACInit(ctx->operation, NULL, 0);

    // 比较输入的MAC值和生成的HMAC
    ret = TEE_MACCompareFinal(ctx->operation, params[0].memref.buffer, params[0].memref.size,
                               params[1].memref.buffer, params[1].memref.size);
    if (ret != TEE_SUCCESS) {
        EMSG("hmac_verify failed, MACCompareFinal failed. Error code: 0x%x\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

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

    struct hmac_session *ctx = (struct hmac_session *)TEE_Malloc(sizeof(struct hmac_session), TEE_MALLOC_FILL_ZERO);
    if (!ctx) {
        EMSG("TA_OpenSessionEntryPoint failed, out of memory. Error code: 0x%x\n", TEE_ERROR_OUT_OF_MEMORY);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    *sess_ctx = ctx;

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    struct hmac_session *ctx = (struct hmac_session *)sess_ctx;

    if (ctx->operation != TEE_HANDLE_NULL)
        TEE_FreeOperation(ctx->operation);
    
    if (ctx->key != TEE_HANDLE_NULL)
        TEE_FreeTransientObject(ctx->key);

    TEE_Free(sess_ctx);
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_type, TEE_Param params[4])
{
    switch (cmd) {
        case HMAC_CMD_INIT:
            return hmac_init(sess_ctx, param_type, params);

        case HMAC_CMD_GENERATE_MAC:
            return hmac_generate(sess_ctx, param_type, params);

        case HMACCMD_VERIFY_MAC:
            return hmac_verify(sess_ctx, param_type, params);

        default:
            EMSG("Invalid command. Error code: 0x%x\n", TEE_ERROR_BAD_PARAMETERS);
            return TEE_ERROR_BAD_PARAMETERS;
    }
}
