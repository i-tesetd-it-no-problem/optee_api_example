#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "include/symmetric_cipher.h"

/* 初始化向量大小（16字节） */
#define AES_IV_SIZE (16)

/* AES块大小（16字节） */
#define AES_BLOCK_SIZE (16)

/* AES密钥大小（32字节，即256位） */
#define AES_KEY_SIZE (32)

/* AES密钥位数 */
#define AES_KEY_BITS (AES_KEY_SIZE * 8)

struct symmetric_cipher_session {
    TEE_OperationHandle operation;    /* 加密解密操作句柄 */
    TEE_ObjectHandle key;             /* 主密钥对象句柄 */
    TEE_ObjectHandle ext_key;         /* 扩展密钥对象句柄（AES XTS 模式需要两个密钥） */
    uint8_t iv[AES_IV_SIZE];          /* 初始化向量 */
    enum symm_cipher_alg alg;         /* 当前算法 */
};

/**
 * @brief 获取算法对应的单个密钥大小（位）
 *
 * @param alg 选择的加密算法
 * @return uint32_t 返回密钥大小，单位为位
 */
static uint32_t get_key_size(enum symm_cipher_alg alg)
{
    switch(alg) {
        case SYMM_CIPHER_ALG_AES_ECB_NOPAD:
        case SYMM_CIPHER_ALG_AES_CBC_NOPAD:
        case SYMM_CIPHER_ALG_AES_CTR:
        case SYMM_CIPHER_ALG_AES_CTS:
            return 256; // 128 或 192 都可以，根据需要调整
    
        case SYMM_CIPHER_ALG_AES_XTS:
            return 256; // XTS 模式下，每个密钥为256位，共512位
    
        default:
            return 0; // 不支持的算法
    }
}

/**
 * @brief 获取算法对应的TEE算法标识
 *
 * @param alg 选择的加密算法
 * @return uint32_t 返回TEE算法标识，失败时返回0xFFFFFFFF
 */
static uint32_t get_algorithm(enum symm_cipher_alg alg)
{
    switch(alg) {
        case SYMM_CIPHER_ALG_AES_ECB_NOPAD:
            return TEE_ALG_AES_ECB_NOPAD;
        
        case SYMM_CIPHER_ALG_AES_CBC_NOPAD:
            return TEE_ALG_AES_CBC_NOPAD;

        case SYMM_CIPHER_ALG_AES_CTR:
            return TEE_ALG_AES_CTR;

        case SYMM_CIPHER_ALG_AES_CTS:
            return TEE_ALG_AES_CTS;

        case SYMM_CIPHER_ALG_AES_XTS:
            return TEE_ALG_AES_XTS;

        default:
            return 0xFFFFFFFF; // 未定义的算法
    }
}

/**
 * @brief 判断算法是否需要初始化向量（IV）
 *
 * @param alg 选择的加密算法
 * @return true 如果需要IV
 * @return false 如果不需要IV
 */
static bool is_need_iv(enum symm_cipher_alg alg)
{
    return (alg != SYMM_CIPHER_ALG_AES_ECB_NOPAD);
}

/**
 * @brief 释放会话中的操作句柄和密钥对象句柄
 *
 * @param sess_ctx 会话上下文
 */
static void free_handle(struct symmetric_cipher_session *sess_ctx)
{
    if(!sess_ctx)
        return;

    if(sess_ctx->operation)
        TEE_FreeOperation(sess_ctx->operation);

    if(sess_ctx->key)
        TEE_FreeTransientObject(sess_ctx->key);
    
    if(sess_ctx->ext_key)
        TEE_FreeTransientObject(sess_ctx->ext_key);
}

/**
 * @brief 生成对称加密密钥
 *
 * @param sess_ctx 会话上下文
 * @param param_types 参数类型
 * @param params 参数数组
 * @return TEE_Result 返回结果
 */
static TEE_Result generate_key(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    TEE_Result ret;
    struct symmetric_cipher_session *ctx = (struct symmetric_cipher_session *)sess_ctx; /* 会话上下文 */

    /* 验证参数类型是否为值输入 */
    uint32_t exp_param_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_VALUE_INPUT, 
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE, 
        TEE_PARAM_TYPE_NONE
    );

    if (param_types != exp_param_type) {
        EMSG("param_types is not correct");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* 获取选择的加密算法 */
    ctx->alg = params[0].value.a;

    /* 释放之前可能存在的资源 */
    free_handle(ctx);

    /* 获取密钥大小 */
    uint32_t key_size = get_key_size(ctx->alg);
    if (key_size == 0) {
        EMSG("Unsupported algorithm");
        return TEE_ERROR_NOT_SUPPORTED;
    }

    /* 生成主密钥 */
    ret = TEE_AllocateTransientObject(TEE_TYPE_AES, key_size, &ctx->key);
    if(ret != TEE_SUCCESS) {
        EMSG("Failed to allocate transient object for main key");
        return ret;
    }

    ret = TEE_GenerateKey(ctx->key, key_size, NULL, 0);
    if(ret != TEE_SUCCESS) {
        EMSG("Failed to generate main key");
        return ret;
    }

    /* 如果是XTS模式，生成扩展密钥 */
    if(ctx->alg == SYMM_CIPHER_ALG_AES_XTS) {
        ret = TEE_AllocateTransientObject(TEE_TYPE_AES, key_size, &ctx->ext_key);
        if(ret != TEE_SUCCESS) {
            EMSG("Failed to allocate transient object for extended key");
            return ret;
        }

        ret = TEE_GenerateKey(ctx->ext_key, key_size, NULL, 0);
        if(ret != TEE_SUCCESS) {
            EMSG("Failed to generate extended key");
            return ret;
        }
    }

    /* 设置初始化向量（IV） */
    TEE_MemFill(ctx->iv, 0, AES_IV_SIZE);
    if(is_need_iv(ctx->alg)) 
        TEE_GenerateRandom(ctx->iv, AES_IV_SIZE);

    IMSG("Generate key success with size: %u bits\n", key_size);

    return TEE_SUCCESS;
}

/**
 * @brief 执行加密操作
 *
 * @param sess_ctx 会话上下文
 * @param param_types 参数类型
 * @param params 参数数组
 * @return TEE_Result 返回结果
 */
static TEE_Result encrypt(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    TEE_Result ret;
    struct symmetric_cipher_session *ctx = (struct symmetric_cipher_session *)sess_ctx; /* 会话上下文 */

    /* 验证参数类型是否为输入输出的内存引用 */
    uint32_t exp_param_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, 
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE, 
        TEE_PARAM_TYPE_NONE
    );

    if (param_types != exp_param_type) {
        EMSG("param_types is not correct");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* 分配加密操作句柄 */
    ret = TEE_AllocateOperation(&ctx->operation, get_algorithm(ctx->alg), TEE_MODE_ENCRYPT, get_key_size(ctx->alg));
    if(ret != TEE_SUCCESS) {
        EMSG("Failed to allocate encryption operation");
        return ret;
    }

    /* 设置操作密钥，XTS模式需要两个密钥 */
    if(ctx->alg != SYMM_CIPHER_ALG_AES_XTS) 
        ret = TEE_SetOperationKey(ctx->operation, ctx->key);
    else 
        ret = TEE_SetOperationKey2(ctx->operation, ctx->key, ctx->ext_key);
    if(ret != TEE_SUCCESS) {
        EMSG("Failed to set operation key");
        return ret;
    }

    /* 初始化加密操作 */
    if(is_need_iv(ctx->alg)) 
        TEE_CipherInit(ctx->operation, ctx->iv, AES_IV_SIZE);
    else 
        TEE_CipherInit(ctx->operation, NULL, 0);
    
    if(ret != TEE_SUCCESS) {
        EMSG("Failed to initialize cipher operation");
        return ret;
    }

    IMSG("Cipher operation initialized\n");

    /* 执行加密操作 */
    ret = TEE_CipherDoFinal(ctx->operation, params[0].memref.buffer, params[0].memref.size,
                            params[1].memref.buffer, &params[1].memref.size);
    if(ret != TEE_SUCCESS) {
        EMSG("Failed to perform cipher do final");
        return ret;
    }

    IMSG("Encrypt success\n");

    return TEE_SUCCESS;
}

/**
 * @brief 执行解密操作
 *
 * @param sess_ctx 会话上下文
 * @param param_types 参数类型
 * @param params 参数数组
 * @return TEE_Result 返回结果
 */
static TEE_Result decrypt(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    TEE_Result ret;
    struct symmetric_cipher_session *ctx = (struct symmetric_cipher_session *)sess_ctx; /* 会话上下文 */

    /* 验证参数类型是否为输入输出的内存引用 */
    uint32_t exp_param_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, 
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE, 
        TEE_PARAM_TYPE_NONE
    );

    if (param_types != exp_param_type) {
        EMSG("param_types is not correct");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* 分配解密操作句柄 */
    ret = TEE_AllocateOperation(&ctx->operation, get_algorithm(ctx->alg), TEE_MODE_DECRYPT, get_key_size(ctx->alg));
    if(ret != TEE_SUCCESS) {
        EMSG("Failed to allocate decryption operation");
        return ret;
    }

    /* 设置操作密钥，XTS模式需要两个密钥 */
    if(ctx->alg != SYMM_CIPHER_ALG_AES_XTS) 
        ret = TEE_SetOperationKey(ctx->operation, ctx->key);
    else 
        ret = TEE_SetOperationKey2(ctx->operation, ctx->key, ctx->ext_key);
    if(ret != TEE_SUCCESS) {
        EMSG("Failed to set operation key");
        return ret;
    }

    /* 初始化解密操作 */
    if(is_need_iv(ctx->alg)) 
        TEE_CipherInit(ctx->operation, ctx->iv, AES_IV_SIZE);
    else 
        TEE_CipherInit(ctx->operation, NULL, 0);
    if(ret != TEE_SUCCESS) {
        EMSG("Failed to initialize cipher operation");
        return ret;
    }

    /* 执行解密操作 */
    ret = TEE_CipherDoFinal(ctx->operation, params[0].memref.buffer, params[0].memref.size,
                            params[1].memref.buffer, &params[1].memref.size);
    if(ret != TEE_SUCCESS) {
        EMSG("Failed to perform cipher do final");
        return ret;
    }

    IMSG("Decrypt success\n");

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

    /* 分配会话上下文 */
    struct symmetric_cipher_session *ctx = TEE_Malloc(sizeof(struct symmetric_cipher_session), TEE_MALLOC_FILL_ZERO);
    if (!ctx) {
        EMSG("Out of memory");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    *sess_ctx = ctx;

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    struct symmetric_cipher_session *ctx = (struct symmetric_cipher_session *)sess_ctx; /* 会话上下文 */

    free_handle(ctx);

    TEE_Free(sess_ctx);
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_type, TEE_Param params[4])
{
    switch(cmd) {
        case SYMM_CIPHER_CMD_GEN:
            return generate_key(sess_ctx, param_type, params); // 生成密钥

        case SYMM_CIPHER_CMD_ENCRYP:
            return encrypt(sess_ctx, param_type, params);      // 执行加密

        case SYMM_CIPHER_CMD_DECRYP:
            return decrypt(sess_ctx, param_type, params);      // 执行解密

        default:
            EMSG("Invalid command");
            return TEE_ERROR_BAD_PARAMETERS;
    }
}
