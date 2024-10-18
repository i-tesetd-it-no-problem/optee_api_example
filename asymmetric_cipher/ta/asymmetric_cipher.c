#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "include/asymmetric_cipher.h"

#define KEY_BYTES_SIZE (128) // 密钥字节长度
#define KEY_BITS_SIZE (KEY_BYTES_SIZE * 8) // 密钥位长度

struct asymm_session {
    TEE_OperationHandle operation; /* 操作句柄 */
    TEE_ObjectHandle keypair; /* 密钥对 */
    enum asymm_cipher_alg alg; /* 当前使用的算法 */
};

// 释放句柄
static void handle_free(struct asymm_session *ctx)
{
    if(ctx->operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(ctx->operation);
        ctx->operation = TEE_HANDLE_NULL;
    }
        
    if(ctx->keypair != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->keypair);
        ctx->keypair = TEE_HANDLE_NULL;
    }   
}

// 获取TEE算法
static uint32_t get_tee_algorithm(enum asymm_cipher_alg alg)
{
    switch(alg) {
        case ASYMM_CIPHER_ALG_RSAES_PKCS1_V1_5:
            return TEE_ALG_RSAES_PKCS1_V1_5;
        case ASYMM_CIPHER_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
            return TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256;
        default:
            return 0xFFFFFFFF;
    }
}

// 生成密钥对
static TEE_Result generate_keypair(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    TEE_Result ret;
    struct asymm_session *ctx = (struct asymm_session *)sess_ctx;

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

    handle_free(ctx); // 清理之前的资源

    // 申请瞬态对象
    ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, KEY_BITS_SIZE, &ctx->keypair);
    if(ret != TEE_SUCCESS) {
        EMSG("TEE_AllocateTransientObject failed with code 0x%x\n", ret);
        return ret;
    }

    // 生成密钥对
    ret = TEE_GenerateKey(ctx->keypair, KEY_BITS_SIZE, NULL, 0);
    if(ret != TEE_SUCCESS) {
        EMSG("TEE_GenerateKey failed with code 0x%x\n", ret);
        return ret;
    }

    IMSG("Generate keypair success\n");

    return TEE_SUCCESS;
}

// 加密
static TEE_Result encrypt(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    TEE_Result ret;
    struct asymm_session *ctx = (struct asymm_session *)sess_ctx;

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

    if(params[1].memref.size < KEY_BYTES_SIZE) {
        EMSG("params[1].memref.size is not enough");
        return TEE_ERROR_SHORT_BUFFER;
    }

    // 申请操作句柄
    ret = TEE_AllocateOperation(&ctx->operation, get_tee_algorithm(ctx->alg), TEE_MODE_ENCRYPT, KEY_BITS_SIZE);
    if(ret != TEE_SUCCESS) {
        EMSG("TEE_AllocateOperation failed with code 0x%x\n", ret);
        return ret;
    }

    // 设置密钥
    ret = TEE_SetOperationKey(ctx->operation, ctx->keypair);
    if (ret != TEE_SUCCESS) {
        EMSG("TEE_SetOperationKey failed with code 0x%x\n", ret);
        return ret;
    }

    // 加密
    ret = TEE_AsymmetricEncrypt(ctx->operation,
                                 NULL, 0,
                                 params[0].memref.buffer, params[0].memref.size,
                                 params[1].memref.buffer, &params[1].memref.size);
    if(ret != TEE_SUCCESS) {
        EMSG("TEE_AsymmetricEncrypt failed with code 0x%x\n", ret);
        return ret;
    }

    IMSG("Encrypt success\n");

    return TEE_SUCCESS;
}

// 解密
static TEE_Result decrypt(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    TEE_Result ret;
    struct asymm_session *ctx = (struct asymm_session *)sess_ctx;

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

    if(params[1].memref.size < KEY_BYTES_SIZE) {
        EMSG("params[1].memref.size is not enough");
        return TEE_ERROR_SHORT_BUFFER;
    }

    // 申请操作句柄
    ret = TEE_AllocateOperation(&ctx->operation, get_tee_algorithm(ctx->alg), TEE_MODE_DECRYPT, KEY_BITS_SIZE);
    if(ret != TEE_SUCCESS) {
        EMSG("TEE_AllocateOperation failed with code 0x%x\n", ret);
        return ret;
    }

    // 设置密钥
    ret = TEE_SetOperationKey(ctx->operation, ctx->keypair);
    if (ret != TEE_SUCCESS) {
        EMSG("TEE_SetOperationKey failed with code 0x%x\n", ret);
        return ret;
    }

    // 解密
    ret = TEE_AsymmetricDecrypt(ctx->operation,
                                 NULL, 0,
                                 params[0].memref.buffer, params[0].memref.size,
                                 params[1].memref.buffer, &params[1].memref.size);
    if(ret != TEE_SUCCESS) {
        EMSG("TEE_AsymmetricDecrypt failed with code 0x%x\n", ret);
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

    struct asymm_session *ctx = TEE_Malloc(sizeof(struct asymm_session), TEE_MALLOC_FILL_ZERO);
    if(!ctx) {
        EMSG("out of memory\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    *sess_ctx = ctx;

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    struct asymm_session *ctx = (struct asymm_session *)sess_ctx;

    handle_free(ctx);

    TEE_Free(sess_ctx);
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_type, TEE_Param params[4])
{
    switch(cmd) {
        case ASYMM_CIPHER_CMD_GEN:
            return generate_keypair(sess_ctx, param_type, params);

        case ASYMM_CIPHER_CMD_ENCRYP:
            return encrypt(sess_ctx, param_type, params);

        case ASYMM_CIPHER_CMD_DECRYP:
            return decrypt(sess_ctx, param_type, params);

        default:
            return TEE_ERROR_BAD_PARAMETERS;
    }
}
