#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "include/aes_xts.h"

#define KEY_BYTES   (32)
#define KEY_BITS    (KEY_BYTES * 8)

#define IV_SIZE 16

struct aes_xts {
    TEE_OperationHandle operation;
    TEE_ObjectHandle key1;
    TEE_ObjectHandle key2;
};

static TEE_Result generate_key(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result res;

    struct aes_xts *ctx = (struct aes_xts *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                            TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if(param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t out_size1 = params[0].memref.size;
    uint32_t out_size2 = params[1].memref.size;
    if(out_size1 < KEY_BYTES || out_size2 < KEY_BYTES) {
        EMSG("key buffer is too small\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = TEE_IsAlgorithmSupported(TEE_ALG_AES_XTS, TEE_CRYPTO_ELEMENT_NONE);
    if(res != TEE_SUCCESS) {
        EMSG("the algorithm is not supported\n");
        return res;
    }

    /* allow re-generate */
    if(ctx->key1 != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->key1);
        ctx->key1 = TEE_HANDLE_NULL;
    }

    if(ctx->key2 != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->key2);
        ctx->key2 = TEE_HANDLE_NULL;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_AES, KEY_BITS, &ctx->key1);
    if(res != TEE_SUCCESS) {
        EMSG("alloc key1 handle failed, res is 0x%x\n", res);
        return res;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_AES, KEY_BITS, &ctx->key2);
    if(res != TEE_SUCCESS) {
        EMSG("alloc key2 handle failed, res is 0x%x\n", res);
        goto err_free_key1;
    }

    res = TEE_GenerateKey(ctx->key1, KEY_BITS, NULL, 0);
    if(res != TEE_SUCCESS) {
        EMSG("generate key1 failed, res is 0x%x\n", res);
        goto err_free_key2;
    }

    res = TEE_GenerateKey(ctx->key2, KEY_BITS, NULL, 0);
    if(res != TEE_SUCCESS) {
        EMSG("generate key2 failed, res is 0x%x\n", res);
        goto err_free_key2;
    }

    res = TEE_GetObjectBufferAttribute(ctx->key1, TEE_ATTR_SECRET_VALUE,
                                        params[0].memref.buffer, &out_size1);
    if(res != TEE_SUCCESS) {
        EMSG("get key failed, res is 0x%x\n", res);
        goto err_free_key2;
    }
    params[0].memref.size = out_size1;

    res = TEE_GetObjectBufferAttribute(ctx->key2, TEE_ATTR_SECRET_VALUE,
                                        params[1].memref.buffer, &out_size2);
    if(res != TEE_SUCCESS) {
        EMSG("get key failed, res is 0x%x\n", res);
        goto err_free_key2;
    }
    params[1].memref.size = out_size2;

    return TEE_SUCCESS;

err_free_key2:
    if(ctx->key2 != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->key2);
        ctx->key2 = TEE_HANDLE_NULL;
    }

err_free_key1:
    if(ctx->key1 != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->key1);
        ctx->key1 = TEE_HANDLE_NULL;
    }

    return res;
}

static TEE_Result generate_iv(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    (void)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
                                            TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if(param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t out_size = params[0].memref.size;
    if(out_size < IV_SIZE) {
        EMSG("iv buffer is too small\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    uint8_t iv[IV_SIZE];
    TEE_GenerateRandom(iv, IV_SIZE);
    TEE_MemMove(params[0].memref.buffer, iv ,IV_SIZE);
    params[0].memref.size = IV_SIZE;

    return TEE_SUCCESS;
}

static TEE_Result encrypt(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result res;

    struct aes_xts *ctx = (struct aes_xts *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE);
    if(param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t in_size = params[0].memref.size;
    if(in_size <= 16) {
        EMSG("the plain text is too small\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t iv_size = params[1].memref.size;
    if(iv_size != IV_SIZE) {
        EMSG("the iv size is not correct\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t out_size = params[2].memref.size;
    if(out_size < in_size) {
        EMSG("cipher text buffer is too small\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if(ctx->operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(ctx->operation);
        ctx->operation = TEE_HANDLE_NULL;
    }

    res = TEE_AllocateOperation(&ctx->operation, TEE_ALG_AES_XTS, TEE_MODE_ENCRYPT, KEY_BITS);
    if(res != TEE_SUCCESS) {
        EMSG("alloc operation failed, res is 0x%x\n", res);
        return res;
    }

    res = TEE_SetOperationKey2(ctx->operation, ctx->key1, ctx->key2);
    if(res != TEE_SUCCESS) {
        EMSG("set key to operation failed, res is 0x%x\n", res);
        goto err_free_operation;
    }

    TEE_CipherInit(ctx->operation, params[1].memref.buffer, IV_SIZE);

    res = TEE_CipherDoFinal(ctx->operation, params[0].memref.buffer, params[0].memref.size,
                            params[2].memref.buffer, &out_size);
    if(res != TEE_SUCCESS) {
        EMSG("encrypt failed, res is 0x%x\n", res);
        goto err_free_operation;
    }

    params[2].memref.size = out_size;

    return TEE_SUCCESS;

err_free_operation:
    if(ctx->operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(ctx->operation);
        ctx->operation = TEE_HANDLE_NULL;
    }

    return res;
}

static TEE_Result decrypt(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
        TEE_Result res;

    struct aes_xts *ctx = (struct aes_xts *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE);
    if(param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t iv_size = params[1].memref.size;
    if(iv_size != IV_SIZE) {
        EMSG("the iv size is not correct\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t in_size = params[0].memref.size;
    uint32_t out_size = params[2].memref.size;
    if(out_size < in_size) {
        EMSG("plain text buffer is too small\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if(ctx->operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(ctx->operation);
        ctx->operation = TEE_HANDLE_NULL;
    }

    res = TEE_AllocateOperation(&ctx->operation, TEE_ALG_AES_XTS, TEE_MODE_DECRYPT, KEY_BITS);
    if(res != TEE_SUCCESS) {
        EMSG("alloc operation failed, res is 0x%x\n", res);
        return res;
    }

    res = TEE_SetOperationKey2(ctx->operation, ctx->key1, ctx->key2);
    if(res != TEE_SUCCESS) {
        EMSG("set key to operation failed, res is 0x%x\n", res);
        goto err_free_operation;
    }

    TEE_CipherInit(ctx->operation, params[1].memref.buffer, IV_SIZE);
    
    res = TEE_CipherDoFinal(ctx->operation, params[0].memref.buffer, params[0].memref.size,
                            params[2].memref.buffer, &out_size);
    if(res != TEE_SUCCESS) {
        EMSG("decrypt failed, res is 0x%x\n", res);
        goto err_free_operation;
    }

    params[2].memref.size = out_size;

    return TEE_SUCCESS;

err_free_operation:
    if(ctx->operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(ctx->operation);
        ctx->operation = TEE_HANDLE_NULL;
    }

    return res;
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

    struct aes_xts *ctx = TEE_Malloc(sizeof(struct aes_xts), TEE_MALLOC_FILL_ZERO);
    if(!ctx) {
        EMSG("TEE_Malloc Failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ctx->operation = TEE_HANDLE_NULL;
    ctx->key1 = TEE_HANDLE_NULL;
    ctx->key2 = TEE_HANDLE_NULL;

    *sess_ctx = ctx;

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    struct aes_xts *ctx = (struct aes_xts *)sess_ctx;

    if(ctx->operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(ctx->operation);
        ctx->operation = TEE_HANDLE_NULL;
    }
        
    if(ctx->key1 != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->key1);
        ctx->key1 = TEE_HANDLE_NULL;
    }

    if(ctx->key2 != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->key2);
        ctx->key2 = TEE_HANDLE_NULL;
    }

    TEE_Free(ctx);
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_type, TEE_Param params[4])
{
    switch(cmd) {
        case TA_AES_XTS_GEN_KEY:
            return generate_key(sess_ctx, param_type, params);

        case TA_AES_XTS_GEN_IV:
            return generate_iv(sess_ctx, param_type, params);

        case TA_AES_XTS_ENCRYPT:
            return encrypt(sess_ctx, param_type, params);

        case TA_AES_XTS_DECRYPT:
            return decrypt(sess_ctx, param_type, params);

        default:
            EMSG("unsurpported command\n");
            return TEE_ERROR_BAD_PARAMETERS;
    }
}

/**
 * @brief 配置到开发板指令

 * 注意: 开发本需提前配置好SSH环境, 
 * 根文件系统也需要支持OPTEE, buildroot自行配置

 * /lib/optee_armtz 是OPTEE寻找TA的默认地址
 * /usr/bin 让CA目标文件可以直接当作命令运行
 
 * scp aes_xts/ta/e53ba603-3110-4fac-94bc-c8d7e37ea26e.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp aes_xts/host/aes_xts wenshuyu@192.168.1.6:/usr/bin
 */

